/*
 * GREASE (RFC 8701) and ClientHello extension-order randomisation.
 *
 * Both are used to make our ClientHello indistinguishable from the one Chrome
 * emits. The values are derived from a single per-connection seed rather than
 * being drawn at each use, because several of them have to agree across
 * extensions (key_share repeats the supported_groups GREASE value) and across
 * messages (the ClientHello sent after a HelloRetryRequest must repeat the
 * values of the first one).
 */

#include <openssl/rand.h>
#include "ssl_local.h"

static int grease_seed(SSL_CONNECTION *s)
{
    if (s->grease_seeded)
        return 1;

    if (RAND_bytes_ex(SSL_CONNECTION_GET_CTX(s)->libctx, s->grease_seed,
                      sizeof(s->grease_seed), 0) <= 0)
        return 0;

    s->grease_seeded = 1;
    return 1;
}

/*
 * Return the GREASE value for |idx|. GREASE values have the form 0x?a?a with
 * both nibbles equal, which is what the masking below produces.
 */
uint16_t ossl_ssl_grease_value(SSL_CONNECTION *s, int idx)
{
    uint16_t val;

    if (idx < 0 || idx >= SSL_GREASE_LAST || !grease_seed(s))
        return 0x0a0a;

    val = (uint16_t)((s->grease_seed[idx] & 0xf0) | 0x0a);
    val |= (uint16_t)(val << 8);

    /*
     * The two ClientHello GREASE extensions must not collide, otherwise we
     * would send the same extension type twice.
     */
    if (idx == SSL_GREASE_EXTENSION2
            && val == ossl_ssl_grease_value(s, SSL_GREASE_EXTENSION1))
        val ^= 0x1010;

    return val;
}

/*
 * Produce a random permutation of [0, num) in |s->ext_permutation|, computed
 * once per connection. Returns 1 on success, 0 on failure (in which case the
 * caller should fall back to the natural order).
 */
int ossl_ssl_ext_permutation(SSL_CONNECTION *s, size_t num)
{
    size_t i;

    if (num > OSSL_NELEM(s->ext_permutation))
        return 0;

    if (s->ext_permutation_len == num)
        return 1;

    for (i = 0; i < num; i++)
        s->ext_permutation[i] = (unsigned char)i;

    /* Fisher-Yates shuffle */
    for (i = num; i > 1; i--) {
        uint32_t rnd;
        size_t j;
        unsigned char tmp;

        if (RAND_bytes_ex(SSL_CONNECTION_GET_CTX(s)->libctx,
                          (unsigned char *)&rnd, sizeof(rnd), 0) <= 0)
            return 0;

        j = (size_t)(rnd % (uint32_t)i);
        tmp = s->ext_permutation[i - 1];
        s->ext_permutation[i - 1] = s->ext_permutation[j];
        s->ext_permutation[j] = tmp;
    }

    s->ext_permutation_len = num;
    return 1;
}
