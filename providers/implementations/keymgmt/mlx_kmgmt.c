/*
 * Copyright 2024-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Key management for X25519MLKEM768, the hybrid TLS group of
 * draft-kwiatkowski-tls-ecdhe-mlkem. See prov/mlx_kem.h for the layout.
 *
 * This is deliberately narrower than the upstream implementation: the key is
 * only ever produced and consumed by the TLS key_share code, so it supports
 * exactly what that path needs - generate, encode the public key, load a peer
 * public key - and nothing else. There is no serialisation to or from
 * SubjectPublicKeyInfo/PKCS#8, because ML-KEM has no object identifiers here.
 */

#include <string.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include <openssl/rand.h>

#include "prov/implementations.h"
#include "prov/mlx_kem.h"
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"

static OSSL_FUNC_keymgmt_new_fn mlx_kem_new;
static OSSL_FUNC_keymgmt_free_fn mlx_kem_free;
static OSSL_FUNC_keymgmt_get_params_fn mlx_kem_get_params;
static OSSL_FUNC_keymgmt_gettable_params_fn mlx_kem_gettable_params;
static OSSL_FUNC_keymgmt_set_params_fn mlx_kem_set_params;
static OSSL_FUNC_keymgmt_settable_params_fn mlx_kem_settable_params;
static OSSL_FUNC_keymgmt_has_fn mlx_kem_has;
static OSSL_FUNC_keymgmt_match_fn mlx_kem_match;
static OSSL_FUNC_keymgmt_gen_init_fn mlx_kem_gen_init;
static OSSL_FUNC_keymgmt_gen_set_params_fn mlx_kem_gen_set_params;
static OSSL_FUNC_keymgmt_gen_settable_params_fn mlx_kem_gen_settable_params;
static OSSL_FUNC_keymgmt_gen_fn mlx_kem_gen;
static OSSL_FUNC_keymgmt_gen_cleanup_fn mlx_kem_gen_cleanup;

typedef struct mlx_kem_gen_ctx_st {
    OSSL_LIB_CTX *libctx;
    char *propq;
    int selection;
} MLX_GEN_CTX;

MLX_KEY *ossl_mlx_kem_key_new(OSSL_LIB_CTX *libctx, const char *propq)
{
    const ML_KEM_VINFO *vinfo = ossl_ml_kem_get_vinfo(EVP_PKEY_ML_KEM_768);
    MLX_KEY *key;

    /* Guards the compile-time sizes in prov/mlx_kem.h */
    if (vinfo == NULL
            || vinfo->pubkey_bytes != MLX_MLKEM768_PUBKEY_BYTES
            || vinfo->ctext_bytes != MLX_MLKEM768_CTEXT_BYTES) {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        return NULL;
    }

    if ((key = OPENSSL_zalloc(sizeof(*key))) == NULL)
        return NULL;

    key->libctx = libctx;
    key->state = MLX_HAVE_NOKEYS;
    if (propq != NULL && (key->propq = OPENSSL_strdup(propq)) == NULL) {
        OPENSSL_free(key);
        return NULL;
    }

    return key;
}

void ossl_mlx_kem_key_free(MLX_KEY *key)
{
    if (key == NULL)
        return;
    ossl_ml_kem_key_free(key->mkey);
    EVP_PKEY_free(key->xkey);
    OPENSSL_free(key->propq);
    OPENSSL_free(key);
}

/* Generate both halves of the hybrid key */
int ossl_mlx_kem_key_keygen(MLX_KEY *key)
{
    EVP_PKEY_CTX *xctx = NULL;
    int ret = 0;

    if (key->state != MLX_HAVE_NOKEYS) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
        return 0;
    }

    key->mkey = ossl_ml_kem_key_new(key->libctx, key->propq,
                                    EVP_PKEY_ML_KEM_768);
    if (key->mkey == NULL)
        goto err;
    /* We keep the expanded key; the encoded form is written out on demand. */
    if (!ossl_ml_kem_genkey(NULL, 0, key->mkey))
        goto err;

    xctx = EVP_PKEY_CTX_new_from_name(key->libctx, "X25519", key->propq);
    if (xctx == NULL
            || EVP_PKEY_keygen_init(xctx) <= 0
            || EVP_PKEY_keygen(xctx, &key->xkey) <= 0)
        goto err;

    key->state = MLX_HAVE_PRVKEY;
    ret = 1;
 err:
    EVP_PKEY_CTX_free(xctx);
    if (!ret) {
        ossl_ml_kem_key_free(key->mkey);
        key->mkey = NULL;
        EVP_PKEY_free(key->xkey);
        key->xkey = NULL;
    }
    return ret;
}

int ossl_mlx_kem_key_encode_pubkey(const MLX_KEY *key, uint8_t *out, size_t len)
{
    size_t xlen = MLX_X25519_PUBKEY_BYTES;

    if (!mlx_kem_have_pubkey(key) || len != MLX_KEM_PUBKEY_BYTES) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
        return 0;
    }

    /* ML-KEM first, then X25519 */
    if (!ossl_ml_kem_encode_public_key(out, MLX_MLKEM768_PUBKEY_BYTES,
                                       key->mkey))
        return 0;

    if (EVP_PKEY_get_raw_public_key(key->xkey, out + MLX_MLKEM768_PUBKEY_BYTES,
                                    &xlen) <= 0
            || xlen != MLX_X25519_PUBKEY_BYTES) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
        return 0;
    }

    return 1;
}

/* Load a peer's public key; the resulting key has no private half. */
int ossl_mlx_kem_key_set_pubkey(MLX_KEY *key, const uint8_t *in, size_t len)
{
    ML_KEM_KEY *mkey = NULL;
    EVP_PKEY *xkey = NULL;

    if (len != MLX_KEM_PUBKEY_BYTES) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
        return 0;
    }

    mkey = ossl_ml_kem_key_new(key->libctx, key->propq, EVP_PKEY_ML_KEM_768);
    if (mkey == NULL)
        return 0;
    if (!ossl_ml_kem_parse_public_key(in, MLX_MLKEM768_PUBKEY_BYTES, mkey))
        goto err;

    xkey = EVP_PKEY_new_raw_public_key_ex(key->libctx, "X25519", key->propq,
                                          in + MLX_MLKEM768_PUBKEY_BYTES,
                                          MLX_X25519_PUBKEY_BYTES);
    if (xkey == NULL)
        goto err;

    ossl_ml_kem_key_free(key->mkey);
    EVP_PKEY_free(key->xkey);
    key->mkey = mkey;
    key->xkey = xkey;
    key->state = MLX_HAVE_PUBKEY;
    return 1;

 err:
    ossl_ml_kem_key_free(mkey);
    EVP_PKEY_free(xkey);
    return 0;
}

static void *mlx_kem_new(void *provctx)
{
    if (!ossl_prov_is_running())
        return NULL;
    return ossl_mlx_kem_key_new(PROV_LIBCTX_OF(provctx), NULL);
}

static void mlx_kem_free(void *vkey)
{
    ossl_mlx_kem_key_free(vkey);
}

static int mlx_kem_has(const void *vkey, int selection)
{
    const MLX_KEY *key = vkey;

    if (key == NULL)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 1;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        return mlx_kem_have_prvkey(key);
    return mlx_kem_have_pubkey(key);
}

static int mlx_kem_match(const void *vkey1, const void *vkey2, int selection)
{
    const MLX_KEY *key1 = vkey1, *key2 = vkey2;
    uint8_t enc1[MLX_KEM_PUBKEY_BYTES], enc2[MLX_KEM_PUBKEY_BYTES];

    if (key1 == NULL || key2 == NULL)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 1;
    if (!mlx_kem_have_pubkey(key1) || !mlx_kem_have_pubkey(key2))
        return 0;
    if (!ossl_mlx_kem_key_encode_pubkey(key1, enc1, sizeof(enc1))
            || !ossl_mlx_kem_key_encode_pubkey(key2, enc2, sizeof(enc2)))
        return 0;

    return memcmp(enc1, enc2, sizeof(enc1)) == 0;
}

static const OSSL_PARAM mlx_kem_known_gettable_params[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *mlx_kem_gettable_params(void *provctx)
{
    return mlx_kem_known_gettable_params;
}

static int mlx_kem_get_params(void *vkey, OSSL_PARAM params[])
{
    MLX_KEY *key = vkey;
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL
            && !OSSL_PARAM_set_int(p, MLX_KEM_PUBKEY_BYTES * 8))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL
            && !OSSL_PARAM_set_int(p, ML_KEM_768_SECBITS))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL
            && !OSSL_PARAM_set_int(p, MLX_KEM_CTEXT_BYTES))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (p != NULL) {
        uint8_t enc[MLX_KEM_PUBKEY_BYTES];

        if (!ossl_mlx_kem_key_encode_pubkey(key, enc, sizeof(enc)))
            return 0;
        if (!OSSL_PARAM_set_octet_string(p, enc, sizeof(enc)))
            return 0;
    }

    return 1;
}

static const OSSL_PARAM mlx_kem_known_settable_params[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *mlx_kem_settable_params(void *provctx)
{
    return mlx_kem_known_settable_params;
}

static int mlx_kem_set_params(void *vkey, const OSSL_PARAM params[])
{
    MLX_KEY *key = vkey;
    const OSSL_PARAM *p;

    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING)
            return 0;
        if (!ossl_mlx_kem_key_set_pubkey(key, p->data, p->data_size))
            return 0;
    }

    return 1;
}

static void *mlx_kem_gen_init(void *provctx, int selection,
                              const OSSL_PARAM params[])
{
    MLX_GEN_CTX *gctx;

    if (!ossl_prov_is_running())
        return NULL;

    if ((gctx = OPENSSL_zalloc(sizeof(*gctx))) == NULL)
        return NULL;
    gctx->libctx = PROV_LIBCTX_OF(provctx);
    gctx->selection = selection;

    if (!mlx_kem_gen_set_params(gctx, params)) {
        mlx_kem_gen_cleanup(gctx);
        return NULL;
    }

    return gctx;
}

static const OSSL_PARAM mlx_kem_known_gen_settable_params[] = {
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *mlx_kem_gen_settable_params(void *vgctx, void *provctx)
{
    return mlx_kem_known_gen_settable_params;
}

static int mlx_kem_gen_set_params(void *vgctx, const OSSL_PARAM params[])
{
    MLX_GEN_CTX *gctx = vgctx;
    const OSSL_PARAM *p;

    if (gctx == NULL)
        return 0;
    if (params == NULL)
        return 1;

    /*
     * ssl_generate_pkey_group() always sets the group name from the TLS group
     * table. There is one group behind this algorithm, so the only job here is
     * to reject a name that is not ours.
     */
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING
                || (OPENSSL_strcasecmp(p->data, "X25519MLKEM768") != 0
                    && ((char *)p->data)[0] != '\0')) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
            return 0;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PROPERTIES);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;
        OPENSSL_free(gctx->propq);
        if ((gctx->propq = OPENSSL_strdup(p->data)) == NULL)
            return 0;
    }

    return 1;
}

static void *mlx_kem_gen(void *vgctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    MLX_GEN_CTX *gctx = vgctx;
    MLX_KEY *key;

    if (!ossl_prov_is_running() || gctx == NULL)
        return NULL;

    key = ossl_mlx_kem_key_new(gctx->libctx, gctx->propq);
    if (key == NULL)
        return NULL;

    /*
     * A "parameter generation" produces the empty key that the server fills in
     * from the peer's key_share; only a keypair selection generates material.
     */
    if ((gctx->selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return key;

    if (!ossl_mlx_kem_key_keygen(key)) {
        ossl_mlx_kem_key_free(key);
        return NULL;
    }

    return key;
}

static void mlx_kem_gen_cleanup(void *vgctx)
{
    MLX_GEN_CTX *gctx = vgctx;

    if (gctx == NULL)
        return;
    OPENSSL_free(gctx->propq);
    OPENSSL_free(gctx);
}

const OSSL_DISPATCH ossl_mlx_x25519_kem_kmgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))mlx_kem_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))mlx_kem_free },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))mlx_kem_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
      (void (*)(void))mlx_kem_gettable_params },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void))mlx_kem_set_params },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,
      (void (*)(void))mlx_kem_settable_params },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))mlx_kem_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))mlx_kem_match },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))mlx_kem_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
      (void (*)(void))mlx_kem_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
      (void (*)(void))mlx_kem_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))mlx_kem_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))mlx_kem_gen_cleanup },
    OSSL_DISPATCH_END
};
