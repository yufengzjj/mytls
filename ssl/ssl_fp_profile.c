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
#include "internal/cryptlib.h"          /* ossl_safe_getenv */
#include "internal/thread_once.h"       /* RUN_ONCE */

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
 * Chrome 149 on Android. It differs from the desktop capture in exactly one
 * place - the three ML-DSA codepoints are absent - and in nothing else: same
 * fifteen cipher suites, same sixteen extensions, same groups including the
 * hybrid, same versions, same brotli. The HTTP/2 layer is identical too, down
 * to the akamai hash.
 *
 * Whether that difference belongs to the platform or to the version is not
 * established: the desktop capture is Chrome 140 and this one Chrome 149, so
 * the two are confounded. Settling it would need a Chrome 149 desktop capture.
 * What is written here is the capture, not a theory about its cause.
 */
static const uint16_t chrome_android_sigalgs[] = {
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
 * The same list from iOS 18.5, read out of the raw ClientHello.
 * rsa_pss_rsae_sha384 genuinely appears twice - both the capture and
 * tls.peet.ws agree - so it is written twice here. Removing the duplicate
 * would change the length of the extension and the JA4 hash with it.
 *
 * iOS 26 sends this list unchanged, entry for entry, and shares it below -
 * which is worth knowing given how much else it did change.
 */
static const uint16_t ios18_sigalgs[] = {
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
 * iOS 16.7.12, and the only place the two iOS profiles differ: one extra
 * entry, ecdsa_sha1, between ecdsa_secp384r1_sha384 and the first
 * rsa_pss_rsae_sha384. Everything else was compared field by field against
 * three captures off one 16.7.12 device - WhatsApp, App Store images and the
 * App Store API - and is identical to the 18.5 capture: the same 21 cipher
 * suites in the same order, the same extensions in the same order, the same
 * four groups, the same versions, zlib certificate compression, one X25519
 * key share, padding to 512 bytes.
 *
 * Note the same 11-entry list was also measured on iOS 18.1.1, so this list
 * is not unique to iOS 16 - the name says which capture it came from, not
 * which range of releases it covers.
 */
static const uint16_t ios16_sigalgs[] = {
    TLSEXT_SIGALG_ecdsa_secp256r1_sha256,
    TLSEXT_SIGALG_rsa_pss_rsae_sha256,
    TLSEXT_SIGALG_rsa_pkcs1_sha256,
    TLSEXT_SIGALG_ecdsa_secp384r1_sha384,
    TLSEXT_SIGALG_ecdsa_sha1,
    TLSEXT_SIGALG_rsa_pss_rsae_sha384,
    TLSEXT_SIGALG_rsa_pss_rsae_sha384,
    TLSEXT_SIGALG_rsa_pkcs1_sha384,
    TLSEXT_SIGALG_rsa_pss_rsae_sha512,
    TLSEXT_SIGALG_rsa_pkcs1_sha512,
    TLSEXT_SIGALG_rsa_pkcs1_sha1
};

/*
 * supported_versions, after the GREASE entry. Chrome offers only what it will
 * speak; iOS 16 and 18 still list TLSv1.1 and TLSv1.0, and iOS 26 stopped.
 * See the struct comment: this is what goes on the wire, not what will be
 * accepted.
 */
static const uint16_t chrome_versions[] = {
    TLS1_3_VERSION, TLS1_2_VERSION
};

static const uint16_t ios_versions[] = {
    TLS1_3_VERSION, TLS1_2_VERSION, TLS1_1_VERSION, TLS1_VERSION
};

/*
 * iOS 26 stopped offering TLSv1.1 and TLSv1.0. The list is now the same two
 * entries Chrome sends, and is still written out rather than shared with
 * chrome_versions: the two agree by coincidence, not by common origin, and a
 * later Chrome capture must not be able to change what iOS advertises.
 */
static const uint16_t ios26_versions[] = {
    TLS1_3_VERSION, TLS1_2_VERSION
};

/* compress_certificate. Chromium ships brotli, Apple ships zlib. */
static const uint16_t chrome_cert_comp[] = { TLSEXT_comp_cert_brotli };
static const uint16_t ios_cert_comp[] = { TLSEXT_comp_cert_zlib };

/*
 * supported_groups. Chrome leads with the post-quantum hybrid; iOS 16 and 18
 * offer four plain curves and no hybrid, but do still offer P-521, which
 * Chrome dropped. iOS 26 has the hybrid too - see ios26_groups.
 */
static const char chrome_groups[] = "X25519MLKEM768:X25519:P-256:P-384";
static const char ios_groups[] = "X25519:P-256:P-384:P-521";

/*
 * iOS 26 puts the same post-quantum hybrid Chrome leads with in front of the
 * four curves iOS has always offered, and keeps all four - so this is not
 * Chrome's list either, which dropped P-521.
 */
static const char ios26_groups[] = "X25519MLKEM768:X25519:P-256:P-384:P-521";

/*
 * TLSv1.3 suites. The same three in the same order for Chrome, Chrome on
 * Android and iOS 16 and 18 - but not for iOS 26, which reorders them below.
 */
static const char tls13_ciphers_common[] =
    "TLS_AES_128_GCM_SHA256:"
    "TLS_AES_256_GCM_SHA384:"
    "TLS_CHACHA20_POLY1305_SHA256";

/*
 * iOS 26 leads with AES-256 and puts AES-128 last. Nothing else about the
 * cipher list moved: the seventeen TLSv1.2-and-below suites below follow in
 * exactly the order iOS 16 and 18 send them.
 */
static const char ios26_tls13_ciphers[] =
    "TLS_AES_256_GCM_SHA384:"
    "TLS_CHACHA20_POLY1305_SHA256:"
    "TLS_AES_128_GCM_SHA256";

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
 * iOS's, which is both longer and differently ordered: ECDSA before RSA at
 * every strength, then CBC, then static RSA, then 3DES. The three 3DES suites
 * at the end need a build configured with enable-weak-ssl-ciphers; without one
 * they are silently dropped and the JA4 cipher count comes out at 17 instead
 * of 20, which the self-test reports.
 */
static const char ios_ciphers[] =
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
    SSL_FP_GREASE | SSL_FP_SHUFFLE_EXTS | SSL_FP_ALPS | SSL_FP_ECH_GREASE
    | SSL_FP_EMPTY_TICKET
};

/*
 * Everything but the signature algorithms is shared with the desktop profile,
 * deliberately by reference rather than by copy: the two came from the same
 * Chromium, and a later capture that changes one of these lists should not
 * leave the other silently stale.
 */
static const SSL_FP_PROFILE fp_profile_chrome_android = {
    "chrome_android",
    chrome_android_sigalgs, OSSL_NELEM(chrome_android_sigalgs),
    chrome_versions, OSSL_NELEM(chrome_versions),
    chrome_cert_comp, OSSL_NELEM(chrome_cert_comp),
    2,
    chrome_groups, tls13_ciphers_common, chrome_ciphers,
    SSL_FP_GREASE | SSL_FP_SHUFFLE_EXTS | SSL_FP_ALPS | SSL_FP_ECH_GREASE
    | SSL_FP_EMPTY_TICKET
};

/*
 * iOS 18.5, captured from Safari 604.1. Named for the OS and not the browser
 * because none of it belongs to the browser: every app that goes through
 * NSURLSession or CFNetwork produces this ClientHello, which was checked by
 * capturing five unrelated clients on one device - Safari, WhatsApp, the App
 * Store, and Apple's own telemetry and weather daemons - and finding no
 * difference in the handshake at all.
 *
 * It offers none of the four flags: no shuffling (its extension order is
 * fixed, so its JA3 is stable), no ALPS, no GREASE ECH, and no empty
 * session_ticket - though that last one is the caller's to override, see
 * ossl_ssl_fp_empty_ticket().
 */
static const SSL_FP_PROFILE fp_profile_ios18 = {
    "ios18",
    ios18_sigalgs, OSSL_NELEM(ios18_sigalgs),
    ios_versions, OSSL_NELEM(ios_versions),
    ios_cert_comp, OSSL_NELEM(ios_cert_comp),
    1,                                  /* X25519 only - no hybrid */
    ios_groups, tls13_ciphers_common, ios_ciphers,
    SSL_FP_GREASE | SSL_FP_PADDING
};

/*
 * iOS 16.7.12. Everything but the signature algorithms is shared with the
 * 18.5 profile by reference rather than by copy, for the same reason the two
 * Chrome profiles share theirs: the two were measured to be identical, and a
 * later capture that changes one list should not leave the other silently
 * stale.
 */
static const SSL_FP_PROFILE fp_profile_ios16 = {
    "ios16",
    ios16_sigalgs, OSSL_NELEM(ios16_sigalgs),
    ios_versions, OSSL_NELEM(ios_versions),
    ios_cert_comp, OSSL_NELEM(ios_cert_comp),
    1,
    ios_groups, tls13_ciphers_common, ios_ciphers,
    SSL_FP_GREASE | SSL_FP_PADDING
};

/*
 * iOS 26. The first Apple capture that is not a variation on the other two:
 * where 16 and 18 differ by one signature algorithm, this one moved four
 * things at once, and its ClientHello is 1541 bytes where theirs are 517.
 *
 *   - the post-quantum hybrid X25519MLKEM768 leads supported_groups and
 *     carries a 1216-byte key_share, so two real shares go out rather than one
 *   - TLSv1.1 and TLSv1.0 are no longer advertised
 *   - the three TLSv1.3 suites are reordered, AES-256 first
 *   - no padding extension: at 1541 bytes it would never have fired anyway
 *
 * Unchanged from iOS 18, and shared here by reference: the signature
 * algorithms entry for entry, the seventeen older cipher suites in the same
 * order, zlib certificate compression, and the extension order once padding
 * is gone. Still no shuffling, no ALPS, no GREASE ECH and no empty
 * session_ticket - that last one remains the caller's to override.
 */
static const SSL_FP_PROFILE fp_profile_ios26 = {
    "ios26",
    ios18_sigalgs, OSSL_NELEM(ios18_sigalgs),
    ios26_versions, OSSL_NELEM(ios26_versions),
    ios_cert_comp, OSSL_NELEM(ios_cert_comp),
    2,                                  /* X25519MLKEM768 and X25519 */
    ios26_groups, ios26_tls13_ciphers, ios_ciphers,
    SSL_FP_GREASE
};

/*
 * Not a browser: upstream OpenSSL, with every fingerprint behaviour off.
 *
 * All six lists are NULL, which is the signal each consumer reads - the
 * extension constructors fall back to the upstream code path they always had,
 * and SSL_CTX_new_ex() leaves the library's own cipher and group lists in place
 * instead of installing and pinning a browser's.
 *
 * It exists so that `make test` means something. Upstream's own tests assert
 * the exact shape of a ClientHello, which every profile above deliberately
 * violates - GREASE codepoints in four places, a shuffled extension order, a
 * GREASE ECH - so with a browser as the only possible default the whole suite
 * is red no matter what anybody changes, and stops being able to catch a
 * regression. Select it with MYTLS_FP_PROFILE=stock, which is what
 * test/run_tests.pl does.
 *
 * SSL_FP_ALLOW_RESUME because upstream resumes; the reasoning for withholding
 * it from the browser profiles is about captures we do not have, and does not
 * apply to a profile that is not imitating anything.
 */
static const SSL_FP_PROFILE fp_profile_stock = {
    "stock",
    NULL, 0,                            /* signature_algorithms */
    NULL, 0,                            /* supported_versions */
    NULL, 0,                            /* compress_certificate */
    1,                                  /* one key_share, as upstream sends */
    NULL, NULL, NULL,                   /* groups, TLSv1.3 and TLSv1.2 ciphers */
    SSL_FP_STOCK | SSL_FP_ALLOW_RESUME | SSL_FP_EMPTY_TICKET
};

/*
 * The profile used when nothing has selected one. Chrome, because that is what
 * this fork imitated before profiles existed and an unchanged program must
 * keep producing the bytes it produced yesterday.
 */
static const SSL_FP_PROFILE *const fp_profile_builtin_default =
    &fp_profile_chrome;

static const SSL_FP_PROFILE *const fp_profiles[] = {
    &fp_profile_chrome,
    &fp_profile_chrome_android,
    &fp_profile_ios18,
    &fp_profile_ios16,
    &fp_profile_ios26,
    &fp_profile_stock
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
        return ossl_ssl_fp_default();
    if (s->fp_profile != NULL)
        return s->fp_profile;

    ctx = SSL_CONNECTION_GET_CTX(s);
    if (ctx != NULL && ctx->fp_profile != NULL)
        return ctx->fp_profile;

    return ossl_ssl_fp_default();
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
                                   : ossl_ssl_fp_default()->name;
}

/*
 * The default profile, once, honouring MYTLS_FP_PROFILE.
 *
 * An environment override rather than a build option because the thing that
 * needs it is a *test run* of programs this library only links into - the
 * recipes drive `openssl s_client` and the test binaries, none of which have
 * anywhere to pass a profile. The same reasoning, and the same shape, as
 * MYTLS_ALLOW_CIPHER_OVERRIDE in ssl_lib.c.
 *
 * An unset or unrecognised value leaves the compiled-in default alone, so a
 * typo degrades to the behaviour an unchanged program has always had.
 */
static const SSL_FP_PROFILE *fp_env_default = NULL;
static CRYPTO_ONCE fp_env_once = CRYPTO_ONCE_STATIC_INIT;

DEFINE_RUN_ONCE_STATIC(fp_init_env_default)
{
    const char *name = ossl_safe_getenv("MYTLS_FP_PROFILE");

    if (name != NULL && *name != '\0')
        fp_env_default = ossl_ssl_fp_profile_by_name(name);
    if (fp_env_default == NULL)
        fp_env_default = fp_profile_builtin_default;
    return 1;
}

const SSL_FP_PROFILE *ossl_ssl_fp_default(void)
{
    if (!RUN_ONCE(&fp_env_once, fp_init_env_default))
        return fp_profile_builtin_default;
    return fp_env_default;
}

/*
 * Whether this connection offers an empty session_ticket, resolved.
 *
 * The profile is the fallback rather than the answer. A profile records what
 * one browser's network stack does, and this extension turned out not to be
 * the stack's to decide: on one iOS 16.7.12 device, connections from the App
 * Store's amp-api and xp.apple.com sessions carry an empty session_ticket
 * while connections to mzstatic, fpinit and weather-edge - same OS, same
 * stack, same cipher list, same HTTP/2 fingerprint - do not. So the caller
 * gets the last word, per connection or per context.
 */
int ossl_ssl_fp_empty_ticket(const SSL_CONNECTION *s)
{
    const SSL_CTX *ctx;

    if (s != NULL) {
        if (s->fp_empty_ticket != SSL_FP_TICKET_PROFILE)
            return s->fp_empty_ticket != 0;

        ctx = SSL_CONNECTION_GET_CTX(s);
        if (ctx != NULL && ctx->fp_empty_ticket != SSL_FP_TICKET_PROFILE)
            return ctx->fp_empty_ticket != 0;
    }

    return (ossl_ssl_fp(s)->flags & SSL_FP_EMPTY_TICKET) != 0;
}

static int fp_ticket_mode_ok(int mode)
{
    return mode == SSL_FP_TICKET_PROFILE
           || mode == SSL_FP_TICKET_OFF
           || mode == SSL_FP_TICKET_ON;
}

int SSL_CTX_set_fp_empty_ticket(SSL_CTX *ctx, int mode)
{
    if (ctx == NULL || !fp_ticket_mode_ok(mode)) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }

    ctx->fp_empty_ticket = mode;
    return 1;
}

int SSL_set_fp_empty_ticket(SSL *s, int mode)
{
    SSL_CONNECTION *sc = SSL_CONNECTION_FROM_SSL(s);

    if (sc == NULL || !fp_ticket_mode_ok(mode)) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }

    sc->fp_empty_ticket = mode;
    return 1;
}

/*
 * The getters report the effective 0/1, not the stored tri-state: a caller
 * asking "will this offer a ticket" wants the answer, and one that set the
 * value already knows what it set.
 */
int SSL_CTX_get_fp_empty_ticket(const SSL_CTX *ctx)
{
    const SSL_FP_PROFILE *prof;

    if (ctx == NULL)
        return -1;
    if (ctx->fp_empty_ticket != SSL_FP_TICKET_PROFILE)
        return ctx->fp_empty_ticket != 0;

    prof = ctx->fp_profile != NULL ? ctx->fp_profile : ossl_ssl_fp_default();
    return (prof->flags & SSL_FP_EMPTY_TICKET) != 0;
}

int SSL_get_fp_empty_ticket(const SSL *s)
{
    const SSL_CONNECTION *sc = SSL_CONNECTION_FROM_CONST_SSL(s);

    return sc == NULL ? -1 : ossl_ssl_fp_empty_ticket(sc);
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

    /*
     * A profile with no lists of its own - `stock` - leaves the library's in
     * place rather than installing anything, which is the whole of what makes
     * it upstream. Returning success without touching the context also keeps
     * SSL_CTX_new_ex() from pinning: see the caller.
     */
    if (prof->ciphers == NULL)
        return 1;

    /*
     * SSL_CTX_set_cipher_list leaves a stray SSL_R_NO_CIPHER_MATCH on the
     * thread-local error queue whenever @SECLEVEL drops one of the profile's
     * suites - a system openssl.cnf pinning SECLEVEL 2 (Debian's default) is
     * enough - *even though the call succeeds*. The queue is shared by every
     * coroutine on a loop thread, and CPython does not clear it before an
     * SSL_read, so a later benign EOF gets misreported as "no cipher match".
     * Mark the queue and pop back to it on success so a benign residue cannot
     * masquerade as a real failure; on failure leave the errors in place, since
     * that is exactly when the reason matters. This is the source of the
     * residue for every SSL_CTX - SSL_CTX_new applies the default profile
     * through here - so scrubbing it at the source covers callers that never
     * touch the SSL_CTX_set_fp_profile() path.
     */
    ERR_set_mark();
    pinned = ctx->ciphers_pinned;
    ctx->ciphers_pinned = 0;
    ok = SSL_CTX_set_ciphersuites(ctx, prof->tls13_ciphers)
         && SSL_CTX_set_cipher_list(ctx, prof->ciphers)
         && SSL_CTX_set1_groups_list(ctx, prof->groups) > 0;
    ctx->ciphers_pinned = pinned;

    if (ok)
        ERR_pop_to_mark();
    else
        ERR_clear_last_mark();
    return ok;
}

static int fp_apply_ssl(SSL *s, const SSL_FP_PROFILE *prof)
{
    int pinned, ok;

    if (s->ctx == NULL)
        return 0;
    if (prof->ciphers == NULL)
        return 1;

    /* Same benign-residue scrub as ossl_ssl_fp_apply_ctx, per connection. */
    ERR_set_mark();
    pinned = s->ctx->ciphers_pinned;
    s->ctx->ciphers_pinned = 0;
    ok = SSL_set_ciphersuites(s, prof->tls13_ciphers)
         && SSL_set_cipher_list(s, prof->ciphers)
         && SSL_set1_groups_list(s, prof->groups) > 0;
    s->ctx->ciphers_pinned = pinned;

    if (ok)
        ERR_pop_to_mark();
    else
        ERR_clear_last_mark();
    return ok;
}

const char *SSL_fp_profile_name(size_t idx)
{
    return idx < OSSL_NELEM(fp_profiles) ? fp_profiles[idx]->name : NULL;
}
