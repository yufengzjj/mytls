/*
 * Copyright 2024-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Encapsulate/decapsulate for X25519MLKEM768
 * (draft-kwiatkowski-tls-ecdhe-mlkem).
 *
 * Both halves run independently and their outputs are concatenated: the
 * ciphertext is the ML-KEM ciphertext followed by the ephemeral X25519 public
 * key, and the shared secret is the ML-KEM shared secret followed by the
 * X25519 one. The X25519 half is a plain ephemeral-static ECDH turned into a
 * KEM: "encapsulation" generates a fresh X25519 key, sends its public key as
 * part of the ciphertext, and derives against the peer's key.
 */

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/proverr.h>

#include "prov/implementations.h"
#include "prov/mlx_kem.h"
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"

static OSSL_FUNC_kem_newctx_fn mlx_kem_newctx;
static OSSL_FUNC_kem_freectx_fn mlx_kem_freectx;
static OSSL_FUNC_kem_encapsulate_init_fn mlx_kem_encapsulate_init;
static OSSL_FUNC_kem_encapsulate_fn mlx_kem_encapsulate;
static OSSL_FUNC_kem_decapsulate_init_fn mlx_kem_decapsulate_init;
static OSSL_FUNC_kem_decapsulate_fn mlx_kem_decapsulate;

typedef struct {
    OSSL_LIB_CTX *libctx;
    MLX_KEY *key;
    int op;
} PROV_MLX_CTX;

static void *mlx_kem_newctx(void *provctx)
{
    PROV_MLX_CTX *ctx;

    if (!ossl_prov_is_running())
        return NULL;
    if ((ctx = OPENSSL_zalloc(sizeof(*ctx))) == NULL)
        return NULL;
    ctx->libctx = PROV_LIBCTX_OF(provctx);
    return ctx;
}

static void mlx_kem_freectx(void *vctx)
{
    OPENSSL_free(vctx);
}

static int mlx_kem_init(void *vctx, void *vkey, const OSSL_PARAM params[],
                        int op)
{
    PROV_MLX_CTX *ctx = vctx;
    MLX_KEY *key = vkey;

    if (!ossl_prov_is_running() || ctx == NULL || key == NULL)
        return 0;
    if (!mlx_kem_have_pubkey(key)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
        return 0;
    }
    ctx->key = key;
    ctx->op = op;
    return 1;
}

static int mlx_kem_encapsulate_init(void *vctx, void *vkey,
                                    const OSSL_PARAM params[])
{
    return mlx_kem_init(vctx, vkey, params, EVP_PKEY_OP_ENCAPSULATE);
}

static int mlx_kem_decapsulate_init(void *vctx, void *vkey,
                                    const OSSL_PARAM params[])
{
    return mlx_kem_init(vctx, vkey, params, EVP_PKEY_OP_DECAPSULATE);
}

/* X25519 half of encapsulation: fresh key, its public value is the ciphertext */
static int mlx_x25519_encap(const MLX_KEY *key, unsigned char *ct,
                            unsigned char *ss)
{
    EVP_PKEY_CTX *gctx = NULL, *dctx = NULL;
    EVP_PKEY *eph = NULL;
    size_t len = MLX_X25519_PUBKEY_BYTES;
    size_t sslen = MLX_X25519_SHSEC_BYTES;
    int ret = 0;

    gctx = EVP_PKEY_CTX_new_from_name(key->libctx, "X25519", key->propq);
    if (gctx == NULL
            || EVP_PKEY_keygen_init(gctx) <= 0
            || EVP_PKEY_keygen(gctx, &eph) <= 0)
        goto err;

    if (EVP_PKEY_get_raw_public_key(eph, ct, &len) <= 0
            || len != MLX_X25519_PUBKEY_BYTES)
        goto err;

    dctx = EVP_PKEY_CTX_new_from_pkey(key->libctx, eph, key->propq);
    if (dctx == NULL
            || EVP_PKEY_derive_init(dctx) <= 0
            || EVP_PKEY_derive_set_peer(dctx, key->xkey) <= 0
            || EVP_PKEY_derive(dctx, ss, &sslen) <= 0
            || sslen != MLX_X25519_SHSEC_BYTES)
        goto err;

    ret = 1;
 err:
    EVP_PKEY_free(eph);
    EVP_PKEY_CTX_free(gctx);
    EVP_PKEY_CTX_free(dctx);
    return ret;
}

static int mlx_x25519_decap(const MLX_KEY *key, const unsigned char *ct,
                            unsigned char *ss)
{
    EVP_PKEY_CTX *dctx = NULL;
    EVP_PKEY *peer = NULL;
    size_t sslen = MLX_X25519_SHSEC_BYTES;
    int ret = 0;

    peer = EVP_PKEY_new_raw_public_key_ex(key->libctx, "X25519", key->propq,
                                          ct, MLX_X25519_PUBKEY_BYTES);
    if (peer == NULL)
        goto err;

    dctx = EVP_PKEY_CTX_new_from_pkey(key->libctx, key->xkey, key->propq);
    if (dctx == NULL
            || EVP_PKEY_derive_init(dctx) <= 0
            || EVP_PKEY_derive_set_peer(dctx, peer) <= 0
            || EVP_PKEY_derive(dctx, ss, &sslen) <= 0
            || sslen != MLX_X25519_SHSEC_BYTES)
        goto err;

    ret = 1;
 err:
    EVP_PKEY_free(peer);
    EVP_PKEY_CTX_free(dctx);
    return ret;
}

static int mlx_kem_encapsulate(void *vctx, unsigned char *ct, size_t *ctlen,
                               unsigned char *ss, size_t *sslen)
{
    PROV_MLX_CTX *ctx = vctx;

    if (ctx == NULL || ctx->key == NULL)
        return 0;

    if (ct == NULL || ss == NULL) {
        if (ctlen != NULL)
            *ctlen = MLX_KEM_CTEXT_BYTES;
        if (sslen != NULL)
            *sslen = MLX_KEM_SHSEC_BYTES;
        return 1;
    }

    if (ctlen == NULL || sslen == NULL
            || *ctlen < MLX_KEM_CTEXT_BYTES || *sslen < MLX_KEM_SHSEC_BYTES) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    if (!ossl_ml_kem_encap_rand(ct, MLX_MLKEM768_CTEXT_BYTES,
                                ss, ML_KEM_SHARED_SECRET_BYTES,
                                ctx->key->mkey))
        return 0;

    if (!mlx_x25519_encap(ctx->key, ct + MLX_MLKEM768_CTEXT_BYTES,
                          ss + ML_KEM_SHARED_SECRET_BYTES)) {
        OPENSSL_cleanse(ss, MLX_KEM_SHSEC_BYTES);
        return 0;
    }

    *ctlen = MLX_KEM_CTEXT_BYTES;
    *sslen = MLX_KEM_SHSEC_BYTES;
    return 1;
}

static int mlx_kem_decapsulate(void *vctx, unsigned char *ss, size_t *sslen,
                               const unsigned char *ct, size_t ctlen)
{
    PROV_MLX_CTX *ctx = vctx;

    if (ctx == NULL || ctx->key == NULL)
        return 0;

    if (ss == NULL) {
        if (sslen != NULL)
            *sslen = MLX_KEM_SHSEC_BYTES;
        return 1;
    }

    if (sslen == NULL || *sslen < MLX_KEM_SHSEC_BYTES) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }
    if (ctlen != MLX_KEM_CTEXT_BYTES) {
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_LENGTH);
        return 0;
    }
    if (!mlx_kem_have_prvkey(ctx->key)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY);
        return 0;
    }

    /*
     * ML-KEM decapsulation is designed never to fail: on a malformed
     * ciphertext it returns an implicit-rejection secret instead. Only the
     * X25519 half can report an error here.
     */
    if (!ossl_ml_kem_decap(ss, ML_KEM_SHARED_SECRET_BYTES,
                           ct, MLX_MLKEM768_CTEXT_BYTES, ctx->key->mkey))
        return 0;

    if (!mlx_x25519_decap(ctx->key, ct + MLX_MLKEM768_CTEXT_BYTES,
                          ss + ML_KEM_SHARED_SECRET_BYTES)) {
        OPENSSL_cleanse(ss, MLX_KEM_SHSEC_BYTES);
        return 0;
    }

    *sslen = MLX_KEM_SHSEC_BYTES;
    return 1;
}

const OSSL_DISPATCH ossl_mlx_kem_asym_kem_functions[] = {
    { OSSL_FUNC_KEM_NEWCTX, (void (*)(void))mlx_kem_newctx },
    { OSSL_FUNC_KEM_ENCAPSULATE_INIT,
      (void (*)(void))mlx_kem_encapsulate_init },
    { OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))mlx_kem_encapsulate },
    { OSSL_FUNC_KEM_DECAPSULATE_INIT,
      (void (*)(void))mlx_kem_decapsulate_init },
    { OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))mlx_kem_decapsulate },
    { OSSL_FUNC_KEM_FREECTX, (void (*)(void))mlx_kem_freectx },
    OSSL_DISPATCH_END
};
