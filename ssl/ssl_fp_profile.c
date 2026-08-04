/*
 * Client fingerprint profiles.
 *
 * Everything this fork does to make a ClientHello look like a particular
 * browser's - the advertised signature algorithms, the cipher order, which
 * extensions are offered at all, whether their order is randomised - is
 * selected through a profile rather than compiled in. Without that there is
 * exactly one fingerprint per build, and teaching the library a second browser
 * means deleting the first.
 *
 * A profile is chosen per SSL_CTX and may be overridden per SSL, because one
 * process routinely wants both at once: a program that keeps two HTTP clients
 * around, one pretending to be Chrome and one Safari, would otherwise have to
 * be two processes.
 *
 * Profiles are static const and never freed, so a pointer to one is safe to
 * hand out and cheap to copy.
 *
 * The lists here are transcribed from ClientHellos captured off the real
 * browsers (python/hpack_probe.py in this repo records them verbatim). Where a
 * list looks wrong, it is not: browsers do send duplicate entries and
 * codepoints they cannot verify, and reproducing that is the entire point.
 */

#include <openssl/ssl.h>
#include "ssl_local.h"

static int fp_apply_ssl(SSL *s, const SSL_FP_PROFILE *prof);

/*
 * signature_algorithms exactly as Chrome advertises it. Order is significant:
 * unlike the cipher and extension lists, JA4 hashes these in wire order.
 * 0x0904..0x0906 are ML-DSA-44/65/87 (draft-ietf-tls-mldsa), which we cannot
 * verify - see tls_construct_ctos_sig_algs().
 */
static const uint16_t chrome_sigalgs[] = {
    0x0904, 0x0905, 0x0906,
    TLSEXT_SIGALG_ecdsa_secp256r1_sha256,
    TLSEXT_SIGALG_rsa_pss_rsae_sha256,
    TLSEXT_SIGALG_rsa_pkcs1_sha256,
    TLSEXT_SIGALG_ecdsa_secp384r1_sha384,
    TLSEXT_SIGALG_rsa_pss_rsae_sha384,
    TLSEXT_SIGALG_rsa_pkcs1_sha384,
    TLSEXT_SIGALG_rsa_pss_rsae_sha512,
    TLSEXT_SIGALG_rsa_pkcs1_sha512
};

/*
 * The same list from Safari 604.1 on iOS 18.5, read out of the raw
 * ClientHello. rsa_pss_rsae_sha384 genuinely appears twice - both the capture
 * and tls.peet.ws agree - so it is written twice here. Removing the duplicate
 * would change the length of the extension and the JA4 hash with it.
 */
static const uint16_t safari_ios_sigalgs[] = {
    TLSEXT_SIGALG_ecdsa_secp256r1_sha256,
    TLSEXT_SIGALG_rsa_pss_rsae_sha256,
    TLSEXT_SIGALG_rsa_pkcs1_sha256,
    TLSEXT_SIGALG_ecdsa_secp384r1_sha384,
    TLSEXT_SIGALG_rsa_pss_rsae_sha384,
    TLSEXT_SIGALG_rsa_pss_rsae_sha384,
    TLSEXT_SIGALG_rsa_pkcs1_sha384,
    TLSEXT_SIGALG_rsa_pss_rsae_sha512,
    TLSEXT_SIGALG_rsa_pkcs1_sha512,
    TLSEXT_SIGALG_rsa_pkcs1_sha1
};

/*
 * supported_versions, after the GREASE entry. Chrome offers only what it will
 * speak; Safari still lists TLSv1.1 and TLSv1.0. See the struct comment: this
 * is what goes on the wire, not what will be accepted.
 */
static const uint16_t chrome_versions[] = {
    TLS1_3_VERSION, TLS1_2_VERSION
};

static const uint16_t safari_ios_versions[] = {
    TLS1_3_VERSION, TLS1_2_VERSION, TLS1_1_VERSION, TLS1_VERSION
};

/* compress_certificate. Chromium ships brotli, Apple ships zlib. */
static const uint16_t chrome_cert_comp[] = { TLSEXT_comp_cert_brotli };
static const uint16_t safari_ios_cert_comp[] = { TLSEXT_comp_cert_zlib };

/*
 * supported_groups. Chrome leads with the post-quantum hybrid; Safari offers
 * four plain curves and no hybrid, but does still offer P-521, which Chrome
 * dropped.
 */
static const char chrome_groups[] = "X25519MLKEM768:X25519:P-256:P-384";
static const char safari_ios_groups[] = "X25519:P-256:P-384:P-521";

/* TLSv1.3 suites. Both browsers offer the same three in the same order. */
static const char tls13_ciphers_common[] =
    "TLS_AES_128_GCM_SHA256:"
    "TLS_AES_256_GCM_SHA384:"
    "TLS_CHACHA20_POLY1305_SHA256";

/* TLSv1.2 and below, in Chrome's order. */
static const char chrome_ciphers[] =
    "ECDHE-ECDSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:"
    "ECDHE-RSA-CHACHA20-POLY1305:"
    "ECDHE-RSA-AES128-SHA:"
    "ECDHE-RSA-AES256-SHA:"
    "AES128-GCM-SHA256:"
    "AES256-GCM-SHA384:"
    "AES128-SHA:"
    "AES256-SHA";

/*
 * Safari's, which is both longer and differently ordered: ECDSA before RSA at
 * every strength, then CBC, then static RSA, then 3DES. The three 3DES suites
 * at the end need a build configured with enable-weak-ssl-ciphers; without one
 * they are silently dropped and the JA4 cipher count comes out at 17 instead
 * of 20, which the self-test reports.
 */
static const char safari_ios_ciphers[] =
    "ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:"
    "ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-CHACHA20-POLY1305:"
    "ECDHE-ECDSA-AES256-SHA:"
    "ECDHE-ECDSA-AES128-SHA:"
    "ECDHE-RSA-AES256-SHA:"
    "ECDHE-RSA-AES128-SHA:"
    "AES256-GCM-SHA384:"
    "AES128-GCM-SHA256:"
    "AES256-SHA:"
    "AES128-SHA:"
    "ECDHE-ECDSA-DES-CBC3-SHA:"
    "ECDHE-RSA-DES-CBC3-SHA:"
    "DES-CBC3-SHA";

static const SSL_FP_PROFILE fp_profile_chrome = {
    "chrome",
    chrome_sigalgs, OSSL_NELEM(chrome_sigalgs),
    chrome_versions, OSSL_NELEM(chrome_versions),
    chrome_cert_comp, OSSL_NELEM(chrome_cert_comp),
    /*
     * Two key shares: the post-quantum hybrid and plain X25519, so a server
     * supporting either can answer without a HelloRetryRequest.
     */
    2,
    chrome_groups, tls13_ciphers_common, chrome_ciphers,
    /*
     * No SSL_FP_PADDING: Chrome's ClientHello is far past 512 bytes anyway, so
     * the padding extension would never fire - saying so is clearer than
     * relying on that.
     */
    SSL_FP_SHUFFLE_EXTS | SSL_FP_ALPS | SSL_FP_ECH_GREASE | SSL_FP_EMPTY_TICKET
};

/*
 * Safari 604.1 on iOS 18.5. It offers none of the four flags: no shuffling
 * (its extension order is fixed, so its JA3 is stable), no ALPS, no GREASE
 * ECH, and no empty session_ticket.
 */
static const SSL_FP_PROFILE fp_profile_safari_ios = {
    "safari_ios",
    safari_ios_sigalgs, OSSL_NELEM(safari_ios_sigalgs),
    safari_ios_versions, OSSL_NELEM(safari_ios_versions),
    safari_ios_cert_comp, OSSL_NELEM(safari_ios_cert_comp),
    1,                                  /* X25519 only - no hybrid */
    safari_ios_groups, tls13_ciphers_common, safari_ios_ciphers,
    SSL_FP_PADDING
};

/*
 * The profile used when nothing has selected one. Chrome, because that is what
 * this fork imitated before profiles existed and an unchanged program must
 * keep producing the bytes it produced yesterday.
 */
static const SSL_FP_PROFILE *const fp_profile_default = &fp_profile_chrome;

static const SSL_FP_PROFILE *const fp_profiles[] = {
    &fp_profile_chrome,
    &fp_profile_safari_ios
};

const SSL_FP_PROFILE *ossl_ssl_fp_profile_by_name(const char *name)
{
    size_t i;

    if (name == NULL)
        return NULL;

    for (i = 0; i < OSSL_NELEM(fp_profiles); i++) {
        if (OPENSSL_strcasecmp(name, fp_profiles[i]->name) == 0)
            return fp_profiles[i];
    }

    return NULL;
}

const SSL_FP_PROFILE *ossl_ssl_fp(const SSL_CONNECTION *s)
{
    const SSL_CTX *ctx;

    if (s == NULL)
        return fp_profile_default;
    if (s->fp_profile != NULL)
        return s->fp_profile;

    ctx = SSL_CONNECTION_GET_CTX(s);
    if (ctx != NULL && ctx->fp_profile != NULL)
        return ctx->fp_profile;

    return fp_profile_default;
}

int SSL_CTX_set_fp_profile(SSL_CTX *ctx, const char *name)
{
    const SSL_FP_PROFILE *prof = ossl_ssl_fp_profile_by_name(name);

    if (ctx == NULL || prof == NULL) {
        ERR_raise(ERR_LIB_SSL, SSL_R_INVALID_CONFIGURATION_NAME);
        return 0;
    }

    if (!ossl_ssl_fp_apply_ctx(ctx, prof))
        return 0;

    ctx->fp_profile = prof;
    return 1;
}

int SSL_set_fp_profile(SSL *s, const char *name)
{
    SSL_CONNECTION *sc = SSL_CONNECTION_FROM_SSL(s);
    const SSL_FP_PROFILE *prof = ossl_ssl_fp_profile_by_name(name);

    if (sc == NULL || prof == NULL) {
        ERR_raise(ERR_LIB_SSL, SSL_R_INVALID_CONFIGURATION_NAME);
        return 0;
    }

    if (!fp_apply_ssl(s, prof))
        return 0;

    sc->fp_profile = prof;
    return 1;
}

const char *SSL_get_fp_profile(const SSL *s)
{
    const SSL_CONNECTION *sc = SSL_CONNECTION_FROM_CONST_SSL(s);

    if (sc == NULL)
        return NULL;

    return ossl_ssl_fp(sc)->name;
}

const char *SSL_CTX_get_fp_profile(const SSL_CTX *ctx)
{
    if (ctx == NULL)
        return NULL;

    return ctx->fp_profile != NULL ? ctx->fp_profile->name
                                   : fp_profile_default->name;
}

const SSL_FP_PROFILE *ossl_ssl_fp_default(void)
{
    return fp_profile_default;
}

/*
 * Install a profile's cipher and group lists.
 *
 * The cipher lists are normally pinned so that an application cannot overwrite
 * the fingerprint by accident (see ossl_ssl_ciphers_pinned()); changing
 * profiles is the one case where overwriting them is the whole point, so the
 * pin is lifted for the duration. Like the rest of SSL_CTX configuration this
 * is not safe to race against another thread using the same context.
 */
int ossl_ssl_fp_apply_ctx(SSL_CTX *ctx, const SSL_FP_PROFILE *prof)
{
    int pinned, ok;

    if (ctx == NULL || prof == NULL)
        return 0;

    pinned = ctx->ciphers_pinned;
    ctx->ciphers_pinned = 0;
    ok = SSL_CTX_set_ciphersuites(ctx, prof->tls13_ciphers)
         && SSL_CTX_set_cipher_list(ctx, prof->ciphers);
    ctx->ciphers_pinned = pinned;

    return ok && SSL_CTX_set1_groups_list(ctx, prof->groups) > 0;
}

static int fp_apply_ssl(SSL *s, const SSL_FP_PROFILE *prof)
{
    int pinned, ok;

    if (s->ctx == NULL)
        return 0;

    pinned = s->ctx->ciphers_pinned;
    s->ctx->ciphers_pinned = 0;
    ok = SSL_set_ciphersuites(s, prof->tls13_ciphers)
         && SSL_set_cipher_list(s, prof->ciphers);
    s->ctx->ciphers_pinned = pinned;

    return ok && SSL_set1_groups_list(s, prof->groups) > 0;
}

const char *SSL_fp_profile_name(size_t idx)
{
    return idx < OSSL_NELEM(fp_profiles) ? fp_profiles[idx]->name : NULL;
}
