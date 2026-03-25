#ifndef ONVIF_SOAP_H
#define ONVIF_SOAP_H

/**
 * Create a WS-Security SOAP header element for ONVIF digest authentication.
 *
 * Generates a random 16-byte nonce, computes the PasswordDigest as
 * Base64(SHA-1(nonce_raw || created || password)) per the WS-UsernameToken
 * Profile 1.0 specification, and returns the complete
 * <wsse:Security> ... </wsse:Security> XML fragment ready to embed
 * inside a SOAP <s:Header> element.
 *
 * @param username  Camera username.  Must be non-NULL and non-empty.
 * @param password  Camera password.  Must be non-NULL and non-empty.
 * @return          Heap-allocated XML string for the WS-Security element,
 *                  or NULL on allocation / crypto failure.
 *                  The caller is responsible for free()ing the returned string.
 */
char *onvif_create_security_header(const char *username, const char *password);

#endif /* ONVIF_SOAP_H */

