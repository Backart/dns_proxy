/**
 * @file test_dns_utils.c
 * @brief Unit tests for DNS proxy utility functions.
 *
 * This file provides standalone functional tests for the DNS utility functions
 * implemented in `dns_utils.c`. Each test verifies a specific component of the
 * DNS proxy system, such as blacklist checking, response generation, and error codes.
 *
 * The tests use simple assertions to ensure that the expected behavior
 * matches the actual output. Run them using:
 *
 * ```
 * make test
 * ```
 * or directly:
 * ```
 * ./test_dns_utils
 * ```
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>

#include "../include/dns_utils.h"
#include "../include/config.h"

/**
 * @brief Main function running all unit tests.
 *
 * Tests include:
 *  - **Blacklist check**: ensures domains are correctly detected.
 *  - **Fake A record response**: verifies that the proxy builds a valid fake response.
 *  - **NXDOMAIN and REFUSED responses**: checks correct RCODE handling.
 *
 * @return 0 on success, non-zero on assertion failure.
 */
int main() {
    Config cfg;
    strcpy(cfg.response, "FAKE");
    strcpy(cfg.fake_ip, "1.2.3.4");
    cfg.blacklist_count = 2;
    strcpy(cfg.blacklist[0], "example.com");
    strcpy(cfg.blacklist[1], "ads.badsite.net");

    /*** Test 1: Blacklist function ***/
    assert(is_blacklisted("example.com", &cfg) == 1);
    assert(is_blacklisted("google.com", &cfg) == 0);
    printf("is_blacklisted() passed\n");

    /*** Test 2: Fake A record response builder ***/
    unsigned char query[] = {
        0x12, 0x34,  // ID
        0x01, 0x00,  // Flags (RD)
        0x00, 0x01,  // QDCOUNT
        0x00, 0x00,  // ANCOUNT
        0x00, 0x00,  // NSCOUNT
        0x00, 0x00,  // ARCOUNT
        0x07, 'e','x','a','m','p','l','e',
        0x03, 'c','o','m',
        0x00,        // end of QNAME
        0x00, 0x01,  // TYPE A
        0x00, 0x01   // CLASS IN
    };

    unsigned char response[512];
    int rlen = build_fake_a_response(query, sizeof(query), response, sizeof(response), "1.2.3.4", 60);
    assert(rlen > 0);
    printf("build_fake_a_response() produced %d bytes\n", rlen);

    // Verify the last 4 bytes of the response contain the fake IP
    struct in_addr addr;
    memcpy(&addr.s_addr, response + rlen - 4, 4);
    char ipbuf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, ipbuf, sizeof(ipbuf));
    assert(strcmp(ipbuf, "1.2.3.4") == 0);
    printf("Fake A record IP correct\n");

    /*** Test 3: NXDOMAIN response builder ***/
    unsigned char nxd[512];
    int nlen = build_nxdomain_response(query, sizeof(query), nxd, sizeof(nxd));
    assert(nlen > 0);
    assert((nxd[3] & 0x0F) == 3); // RCODE=3
    printf("build_nxdomain_response() passed\n");

    /*** Test 4: REFUSED response builder ***/
    unsigned char ref[512];
    int rflen = build_refused_response(query, sizeof(query), ref, sizeof(ref));
    assert(rflen > 0);
    assert((ref[3] & 0x0F) == 5); // RCODE=5
    printf("build_refused_response() passed\n");

    printf("\nAll tests passed!\n");
    return 0;
}
