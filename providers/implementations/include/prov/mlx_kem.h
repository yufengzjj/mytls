/*
 * Copyright 2024-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_MLX_KEM_H
# define OSSL_MLX_KEM_H
# pragma once

# include <openssl/evp.h>
# include "crypto/ml_kem.h"

/*
 * X25519MLKEM768, the hybrid key exchange of draft-kwiatkowski-tls-ecdhe-mlkem.
 *
 * Upstream reaches ML-KEM through a full EVP_PKEY algorithm and composes the
 * two halves generically. This branch has no ML-KEM object identifiers,
 * encoders or keymgmt - ML-KEM is only ever used as half of this one TLS
 * group - so the ML-KEM half talks to crypto/ml_kem.c directly and only the
 * X25519 half goes through EVP.
 *
 * Concatenation order is the one the draft assigns to X25519MLKEM768: the
 * ML-KEM component comes first in both the public key and the ciphertext, and
 * the shared secret is ML-KEM's followed by X25519's. (SecP256r1MLKEM768 uses
 * the opposite order; we do not implement it.)
 */

# define MLX_X25519_PUBKEY_BYTES 32
# define MLX_X25519_SHSEC_BYTES 32

/*
 * Fixed by FIPS 203 for ML-KEM-768: an encapsulation key is 384*k + 32 bytes
 * and a ciphertext is 32*(du*k + dv) bytes, with k=3, du=10, dv=4. The
 * ML_KEM_VINFO for the variant carries the same numbers; mlx_kem_key_new()
 * checks that they agree.
 */
# define MLX_MLKEM768_PUBKEY_BYTES 1184
# define MLX_MLKEM768_CTEXT_BYTES 1088

# define MLX_KEM_PUBKEY_BYTES \
    (MLX_MLKEM768_PUBKEY_BYTES + MLX_X25519_PUBKEY_BYTES)   /* 1216 */
# define MLX_KEM_CTEXT_BYTES \
    (MLX_MLKEM768_CTEXT_BYTES + MLX_X25519_PUBKEY_BYTES)    /* 1120 */
# define MLX_KEM_SHSEC_BYTES \
    (ML_KEM_SHARED_SECRET_BYTES + MLX_X25519_SHSEC_BYTES)   /* 64 */

# define MLX_HAVE_NOKEYS 0
# define MLX_HAVE_PUBKEY 1
# define MLX_HAVE_PRVKEY 2

typedef struct mlx_key_st {
    OSSL_LIB_CTX *libctx;
    char *propq;
    ML_KEM_KEY *mkey;
    EVP_PKEY *xkey;
    unsigned int state;
} MLX_KEY;

/* Both halves always carry the same amount of key material */
# define mlx_kem_have_pubkey(key) ((key)->state > MLX_HAVE_NOKEYS)
# define mlx_kem_have_prvkey(key) ((key)->state > MLX_HAVE_PUBKEY)

MLX_KEY *ossl_mlx_kem_key_new(OSSL_LIB_CTX *libctx, const char *propq);
void ossl_mlx_kem_key_free(MLX_KEY *key);
__owur int ossl_mlx_kem_key_keygen(MLX_KEY *key);
__owur int ossl_mlx_kem_key_encode_pubkey(const MLX_KEY *key, uint8_t *out,
                                          size_t len);
__owur int ossl_mlx_kem_key_set_pubkey(MLX_KEY *key, const uint8_t *in,
                                       size_t len);

#endif /* OSSL_MLX_KEM_H */
