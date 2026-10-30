/*
 * JA4 TLS client fingerprint of one ClientHello (cdnca).
 *
 * Implements only JA4 (the TLS client fingerprint) as specified by FoxIO in
 * https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md, which
 * is licensed under the BSD 3-Clause license (see THIRD_PARTY.md next to this
 * file). JA4+ (JA4S, JA4H, JA4L, JA4X, JA4SSH, ...) are under the FoxIO
 * License 1.1 and are deliberately not implemented here.
 */

#ifndef CDNCA_JA4_H
#define CDNCA_JA4_H

#include <stddef.h>

/* "t13d1516h2_8daaf6152771_e5627efa2ab1": 10 + 1 + 12 + 1 + 12 characters. */
#define CDNCA_JA4_LEN 36

/*
 * Computes JA4 from a ClientHello handshake body (the bytes after the 4-byte
 * handshake header: legacy_version, random, session id, cipher suites,
 * compression methods, extensions). protocol is 't' (TLS over TCP), 'q'
 * (QUIC) or 'd' (DTLS). On success writes CDNCA_JA4_LEN characters and a
 * terminating NUL into out and returns 0; on a malformed or oversized message
 * returns -1 and leaves out as an empty string.
 */
int cdnca_ja4_from_client_hello(const unsigned char *body, size_t len,
    char protocol, char out[CDNCA_JA4_LEN + 1]);

#endif
