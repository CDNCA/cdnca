/*
 * Unit test of cdnca_ja4.c against the FoxIO JA4.md worked example and its
 * stated edge cases. Run: sh edge/openresty/native/ja4/test.sh
 */

#include "cdnca_ja4.h"

#include <stdio.h>
#include <string.h>

typedef struct {
    unsigned char  data[16384];
    size_t         len;
} buffer;

static int failures;

static void put8(buffer *b, unsigned v) { b->data[b->len++] = (unsigned char) v; }
static void put16(buffer *b, unsigned v) { put8(b, v >> 8); put8(b, v & 0xff); }
static void putbytes(buffer *b, const void *p, size_t n) { memcpy(b->data + b->len, p, n); b->len += n; }

typedef struct {
    unsigned        type;
    unsigned char   data[512];
    size_t          len;
} extension;

static extension ext_raw(unsigned type) { extension e; memset(&e, 0, sizeof(e)); e.type = type; return e; }

static extension
ext_list16(unsigned type, int length_width, const unsigned *values, size_t n)
{
    extension  e = ext_raw(type);
    buffer     b = { {0}, 0 };
    size_t     i;

    if (length_width == 1) {
        put8(&b, (unsigned) (n * 2));
    } else {
        put16(&b, (unsigned) (n * 2));
    }
    for (i = 0; i < n; i++) {
        put16(&b, values[i]);
    }
    memcpy(e.data, b.data, b.len);
    e.len = b.len;
    return e;
}

static extension
ext_alpn(const unsigned char *first, size_t n)
{
    extension  e = ext_raw(0x0010);
    buffer     b = { {0}, 0 };

    put16(&b, (unsigned) (n + 1 + 9));
    put8(&b, (unsigned) n);
    putbytes(&b, first, n);
    put8(&b, 8);
    putbytes(&b, "http/1.1", 8);
    memcpy(e.data, b.data, b.len);
    e.len = b.len;
    return e;
}

static extension
ext_sni(void)
{
    extension  e = ext_raw(0x0000);
    buffer     b = { {0}, 0 };

    put16(&b, 14);
    put8(&b, 0);
    put16(&b, 11);
    putbytes(&b, "example.com", 11);
    memcpy(e.data, b.data, b.len);
    e.len = b.len;
    return e;
}

static size_t
client_hello(buffer *b, unsigned legacy, const unsigned *ciphers, size_t nc,
    const extension *exts, size_t ne)
{
    size_t  i, length_at;

    b->len = 0;
    put16(b, legacy);
    for (i = 0; i < 32; i++) {
        put8(b, (unsigned) i);
    }
    put8(b, 32);
    for (i = 0; i < 32; i++) {
        put8(b, 0xee);
    }
    put16(b, (unsigned) (nc * 2));
    for (i = 0; i < nc; i++) {
        put16(b, ciphers[i]);
    }
    put8(b, 1);
    put8(b, 0);
    if (exts == NULL) {
        return b->len;
    }
    length_at = b->len;
    put16(b, 0);
    for (i = 0; i < ne; i++) {
        put16(b, exts[i].type);
        put16(b, (unsigned) exts[i].len);
        putbytes(b, exts[i].data, exts[i].len);
    }
    b->data[length_at] = (unsigned char) ((b->len - length_at - 2) >> 8);
    b->data[length_at + 1] = (unsigned char) ((b->len - length_at - 2) & 0xff);
    return b->len;
}

static void
expect(const char *name, const buffer *b, const char *want)
{
    char  got[CDNCA_JA4_LEN + 1];
    int   rc = cdnca_ja4_from_client_hello(b->data, b->len, 't', got);

    if (want == NULL ? (rc != -1 || got[0] != '\0') : (rc != 0 || strcmp(got, want) != 0)) {
        printf("FAIL %s want=%s got=%s rc=%d\n", name, want ? want : "(error)", got, rc);
        failures++;
        return;
    }
    printf("PASS %s %s\n", name, want ? want : "(error)");
}

/* FoxIO JA4.md worked example: lists in wire order. */
static const unsigned fox_ciphers[] = {
    0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,
    0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035 };
static const unsigned fox_extensions[] = {
    0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005,
    0x0023, 0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015 };
static const unsigned fox_sigalgs[] = {
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601 };
static const unsigned fox_versions[] = { 0x0304, 0x0303 };

static extension
fox_extension(unsigned type, int grease_inside)
{
    static const unsigned  grease_versions[] = { 0x7a7a, 0x0304, 0x0303 };
    static const unsigned  grease_sigalgs[] = {
        0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0xdada };

    switch (type) {
    case 0x0000: return ext_sni();
    case 0x0010: return ext_alpn((const unsigned char *) "h2", 2);
    case 0x002b:
        return grease_inside ? ext_list16(type, 1, grease_versions, 3) : ext_list16(type, 1, fox_versions, 2);
    case 0x000d:
        return grease_inside ? ext_list16(type, 2, grease_sigalgs, 9) : ext_list16(type, 2, fox_sigalgs, 8);
    default: return ext_raw(type);
    }
}

int
main(void)
{
    buffer     b;
    extension  exts[200];
    unsigned   ciphers[200];
    size_t     i, n;
    char       out[CDNCA_JA4_LEN + 1];
    const char *fox = "t13d1516h2_8daaf6152771_e5627efa2ab1";

    for (i = 0; i < 16; i++) {
        exts[i] = fox_extension(fox_extensions[i], 0);
    }
    client_hello(&b, 0x0303, fox_ciphers, 15, exts, 16);
    expect("FOXIO-VECTOR", &b, fox);

    /* Chrome 110+: random extension order plus GREASE cipher, extensions and
     * GREASE inside supported_versions and signature_algorithms. */
    {
        static const unsigned  order[] = { 13, 2, 7, 0, 15, 4, 9, 11, 1, 6, 14, 3, 10, 5, 12, 8 };
        unsigned               shuffled_ciphers[17];

        shuffled_ciphers[0] = 0x3a3a;
        for (i = 0; i < 15; i++) {
            shuffled_ciphers[i + 1] = fox_ciphers[(i * 7) % 15];
        }
        shuffled_ciphers[16] = 0xfafa;
        n = 0;
        exts[n++] = ext_raw(0x2a2a);
        for (i = 0; i < 16; i++) {
            exts[n++] = fox_extension(fox_extensions[order[i]], 1);
        }
        exts[n] = ext_raw(0x9a9a);
        exts[n].len = 1;
        n++;
        client_hello(&b, 0x0303, shuffled_ciphers, 17, exts, n);
        expect("GREASE-AND-SHUFFLE", &b, fox);
    }

    /* JA4.md: no signature algorithms -> hash of the sorted extensions alone. */
    for (i = 0; i < 16; i++) {
        exts[i] = fox_extension(fox_extensions[i], 0);
        if (fox_extensions[i] == 0x000d) {
            exts[i] = ext_list16(0x000d, 2, NULL, 0);
        }
    }
    client_hello(&b, 0x0303, fox_ciphers, 15, exts, 16);
    expect("NO-SIGALGS", &b, "t13d1516h2_8daaf6152771_6d807ffa2a79");

    /* No SNI, no ALPN: 'i', "00", counts drop by one each. */
    n = 0;
    for (i = 0; i < 16; i++) {
        if (fox_extensions[i] != 0x0000 && fox_extensions[i] != 0x0010) {
            exts[n++] = fox_extension(fox_extensions[i], 0);
        }
    }
    client_hello(&b, 0x0303, fox_ciphers, 15, exts, n);
    expect("NO-SNI-NO-ALPN", &b, "t13i151400_8daaf6152771_e5627efa2ab1");

    /* TLS 1.2 client without supported_versions and without extensions. */
    client_hello(&b, 0x0303, fox_ciphers + 3, 12, NULL, 0);
    if (cdnca_ja4_from_client_hello(b.data, b.len, 't', out) == 0 && strncmp(out, "t12i1200", 10 - 2) == 0
        && strcmp(out + 23, "_000000000000") == 0)
    {
        printf("PASS TLS12-NO-EXTENSIONS %s\n", out);
    } else {
        printf("FAIL TLS12-NO-EXTENSIONS got=%s\n", out);
        failures++;
    }

    /* Unknown version and more than 99 ciphers. */
    for (i = 0; i < 120; i++) {
        ciphers[i] = 0x0100 + (unsigned) i;
    }
    client_hello(&b, 0x7f17, ciphers, 120, NULL, 0);
    if (cdnca_ja4_from_client_hello(b.data, b.len, 't', out) == 0 && strncmp(out, "t00i9900", 8) == 0) {
        printf("PASS CAP-99-UNKNOWN-VERSION %s\n", out);
    } else {
        printf("FAIL CAP-99-UNKNOWN-VERSION got=%s\n", out);
        failures++;
    }

    /* ALPN first/last characters, JA4.md table (hex fallback). */
    {
        static const struct { unsigned char bytes[4]; size_t len; const char *want; } cases[] = {
            { { 'h', '2' }, 2, "h2" }, { { 'h', 't', 't', 'p' }, 4, "hp" }, { { 'x' }, 1, "xx" },
            { { 0xab }, 1, "ab" }, { { 0x20 }, 1, "20" }, { { 0xab, 0xcd }, 2, "ad" },
            { { 0x20, 0x61 }, 2, "21" }, { { 0x30, 0xab }, 2, "3b" }, { { 0x61, 0x20 }, 2, "60" },
            { { 0x30, 0x31, 0xab, 0xcd }, 4, "3d" }, { { 0x30, 0xab, 0xcd, 0x31 }, 4, "01" },
            { { 0 }, 0, "00" },
        };
        for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            exts[0] = ext_alpn(cases[i].bytes, cases[i].len);
            client_hello(&b, 0x0303, fox_ciphers, 15, exts, 1);
            if (cdnca_ja4_from_client_hello(b.data, b.len, 't', out) != 0 || strncmp(out + 8, cases[i].want, 2) != 0) {
                printf("FAIL ALPN-%zu want=%s got=%s\n", i, cases[i].want, out);
                failures++;
            } else {
                printf("PASS ALPN-%zu %s\n", i, cases[i].want);
            }
        }
    }

    /* Protocol marker. */
    for (i = 0; i < 16; i++) {
        exts[i] = fox_extension(fox_extensions[i], 0);
    }
    client_hello(&b, 0x0303, fox_ciphers, 15, exts, 16);
    if (cdnca_ja4_from_client_hello(b.data, b.len, 'q', out) != 0 || out[0] != 'q'
        || strcmp(out + 1, fox + 1) != 0 || cdnca_ja4_from_client_hello(b.data, b.len, 'x', out) != -1)
    {
        printf("FAIL PROTOCOL got=%s\n", out);
        failures++;
    } else {
        printf("PASS PROTOCOL q-prefix and invalid marker\n");
    }

    /* Malformed messages yield no fingerprint (never a partial one). */
    {
        buffer  bad;

        client_hello(&b, 0x0303, fox_ciphers, 15, exts, 16);
        for (n = 0; n < b.len; n += 7) {
            bad = b;
            bad.len = n;
            if (cdnca_ja4_from_client_hello(bad.data, bad.len, 't', out) != -1 || out[0] != '\0') {
                printf("FAIL TRUNCATED-%zu got=%s\n", n, out);
                failures++;
            }
        }
        printf("PASS TRUNCATED every prefix rejected\n");
        bad = b;
        bad.data[bad.len++] = 0;
        expect("TRAILING-BYTE", &bad, NULL);
        bad = b;
        bad.data[2 + 32] = 33;
        expect("SESSION-ID-TOO-LONG", &bad, NULL);
        client_hello(&bad, 0x0303, fox_ciphers, 0, exts, 16);
        expect("NO-CIPHERS", &bad, NULL);
    }

    printf("%s %d failure(s)\n", failures ? "FAILED" : "OK", failures);
    return failures != 0;
}
