/**
 * onvif_soap.c – shared WS-Security header generation for ONVIF requests.
 *
 * This is the single canonical implementation of the ONVIF WS-UsernameToken
 * PasswordDigest security header.  All ONVIF subsystems (device management,
 * PTZ, detection) must use onvif_create_security_header() instead of
 * maintaining their own copies.
 */

#include "video/onvif_soap.h"
#include "core/logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/random.h>

#include <mbedtls/sha1.h>
#include <mbedtls/base64.h>

char *onvif_create_security_header(const char *username, const char *password) {
    if (!username || !password || username[0] == '\0' || password[0] == '\0') {
        log_error("onvif_create_security_header: username and password must be non-empty");
        return NULL;
    }

    /* ------------------------------------------------------------------ *
     * 1. Generate a 16-byte random nonce                                  *
     * ------------------------------------------------------------------ */
    const int nonce_len = 16;
    unsigned char nonce_bytes[16];

    if (getrandom(nonce_bytes, nonce_len, 0) < 0) {
        /* Fallback to /dev/urandom if getrandom(2) is unavailable */
        FILE *urandom = fopen("/dev/urandom", "rb");
        if (!urandom) {
            log_error("onvif_create_security_header: cannot obtain random bytes");
            return NULL;
        }
        (void)fread(nonce_bytes, 1, nonce_len, urandom);
        fclose(urandom);
    }

    /* ------------------------------------------------------------------ *
     * 2. Base64-encode the nonce                                          *
     * ------------------------------------------------------------------ */
    size_t base64_nonce_buf_len = ((4 * nonce_len) / 3) + 5; /* +5: padding + NUL */
    char *base64_nonce = malloc(base64_nonce_buf_len);
    if (!base64_nonce) {
        return NULL;
    }
    size_t base64_nonce_len = 0;
    mbedtls_base64_encode((unsigned char *)base64_nonce, base64_nonce_buf_len,
                          &base64_nonce_len, nonce_bytes, nonce_len);
    base64_nonce[base64_nonce_len] = '\0';

    /* ------------------------------------------------------------------ *
     * 3. Build the ISO-8601 UTC timestamp                                 *
     * ------------------------------------------------------------------ */
    char created[30];
    time_t now;
    struct tm tm_now_buf;
    const struct tm *tm_now;
    time(&now);
    tm_now = gmtime_r(&now, &tm_now_buf);
    strftime(created, sizeof(created), "%Y-%m-%dT%H:%M:%S.000Z", tm_now);

    /* ------------------------------------------------------------------ *
     * 4. Compute PasswordDigest = Base64(SHA-1(nonce_raw || created || password))
     *
     * Per WS-UsernameToken Profile 1.0 §3.1 the concatenation uses the
     * *raw* (decoded) nonce bytes, not the Base64 representation.
     * The null terminator is NOT included in any part of the input.
     * ------------------------------------------------------------------ */
    size_t created_len  = strlen(created);
    size_t password_len = strlen(password);
    size_t concat_len   = (size_t)nonce_len + created_len + password_len;

    char *concatenated = malloc(concat_len + 1); /* +1 to allow safe NUL write */
    if (!concatenated) {
        free(base64_nonce);
        return NULL;
    }
    memcpy(concatenated,                              nonce_bytes, nonce_len);   /* NOLINT */
    memcpy(concatenated + nonce_len,                  created,     created_len); /* NOLINT */
    memcpy(concatenated + nonce_len + created_len,    password,    password_len);/* NOLINT */

    unsigned char digest[20]; /* SHA-1 output is always 20 bytes */
    mbedtls_sha1((unsigned char *)concatenated, concat_len, digest);
    free(concatenated);

    /* ------------------------------------------------------------------ *
     * 5. Base64-encode the digest                                         *
     * ------------------------------------------------------------------ */
    size_t base64_digest_buf_len = ((4 * 20) / 3) + 5;
    char *base64_digest = malloc(base64_digest_buf_len);
    if (!base64_digest) {
        free(base64_nonce);
        return NULL;
    }
    size_t base64_digest_len = 0;
    mbedtls_base64_encode((unsigned char *)base64_digest, base64_digest_buf_len,
                          &base64_digest_len, digest, 20);
    base64_digest[base64_digest_len] = '\0';

    /* ------------------------------------------------------------------ *
     * 6. Assemble the <wsse:Security> XML element                         *
     * ------------------------------------------------------------------ */
    char *header = malloc(1024);
    if (!header) {
        free(base64_nonce);
        free(base64_digest);
        return NULL;
    }
    sprintf(header,
        "<wsse:Security s:mustUnderstand=\"1\" "
            "xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" "
            "xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">"
            "<wsse:UsernameToken wsu:Id=\"UsernameToken-1\">"
                "<wsse:Username>%s</wsse:Username>"
                "<wsse:Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest\">%s</wsse:Password>"
                "<wsse:Nonce EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">%s</wsse:Nonce>"
                "<wsu:Created>%s</wsu:Created>"
            "</wsse:UsernameToken>"
        "</wsse:Security>",
        username, base64_digest, base64_nonce, created);

    free(base64_nonce);
    free(base64_digest);

    return header;
}

