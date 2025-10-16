/**
 * @file dns_utils.c
 * @brief Implementation of DNS message parsing, filtering, and response generation utilities.
 *
 * This module provides functions for parsing DNS queries, checking domain names
 * against a blacklist, constructing DNS response packets (FAKE, NXDOMAIN, REFUSED),
 * and forwarding queries to an upstream DNS server.
 */

#include "dns_utils.h"
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <sys/time.h>
#include <strings.h>

#define BUF_SIZE 1500

/**
 * @brief Parses a DNS query and extracts the queried domain name, type, and class.
 *
 * This function decodes the domain name from a DNS query buffer and
 * extracts the query type (e.g., A, AAAA) and class (usually IN).
 *
 * @param buffer Pointer to the raw DNS query packet.
 * @param len Length of the DNS query buffer.
 * @param domain Buffer to store the extracted domain name.
 * @param type Pointer to store the DNS query type.
 * @param class Pointer to store the DNS query class.
 * @return 0 on success, -1 if parsing fails.
 */
int parse_dns_query(const unsigned char *buffer, int len, char *domain, int *type, int *class) {
    int qend;
    extract_domain(buffer, len, domain, 256, type, class, &qend);
    return (domain[0] != '\0') ? 0 : -1;
}

/**
 * @brief Extracts the queried domain name from a DNS packet.
 *
 * Reads the QNAME section from a DNS request and reconstructs the domain name
 * in dotted notation (e.g., "example.com").
 *
 * @param buf Pointer to the DNS packet buffer.
 * @param buf_len Length of the packet buffer.
 * @param domain Output buffer for the domain name.
 * @param maxlen Maximum number of bytes to write into @p domain.
 * @param qtype Pointer to store the query type (e.g., A = 1).
 * @param qclass Pointer to store the query class (e.g., IN = 1).
 * @param qend Optional pointer to store the byte offset after the query section.
 */
void extract_domain(const unsigned char *buf, int buf_len, char *domain, 
                   int maxlen, int *qtype, int *qclass, int *qend) {
    int i = 12;
    int pos = 0;
    
    while (i < buf_len && buf[i] != 0) {
        int len = (unsigned char)buf[i++];
        if (len == 0) break;
        if (pos + len + 1 >= maxlen) break;
        
        for (int j = 0; j < len && i < buf_len; j++) {
            domain[pos++] = buf[i++];
        }
        domain[pos++] = '.';
    }
    
    if (pos > 0) domain[pos-1] = '\0';
    else domain[0] = '\0';

    if (i + 4 <= buf_len) {
        i++;
        *qtype = (buf[i] << 8) | buf[i+1];
        *qclass = (buf[i+2] << 8) | buf[i+3];
        if (qend) *qend = i + 4;
    } else {
        *qtype = *qclass = 0;
        if (qend) *qend = i;
    }
}

/**
 * @brief Checks whether a given domain name is blacklisted.
 *
 * Compares the provided domain name (case-insensitive) against entries
 * in the blacklist loaded from the configuration.
 *
 * @param name The queried domain name.
 * @param cfg Pointer to the current configuration structure.
 * @return 1 if the domain is blacklisted, 0 otherwise.
 */
int is_blacklisted(const char *name, Config *cfg) {
    for (int i = 0; i < cfg->blacklist_count; i++) {
        if (strcasecmp(name, cfg->blacklist[i]) == 0) return 1;
    }
    return 0;
}

/**
 * @brief Builds a fake DNS "A" record response for a blacklisted domain.
 *
 * Generates a complete DNS response containing a single fake IPv4 address (A record).
 * Used when the configured response mode is `FAKE`.
 *
 * @param req Pointer to the original DNS query packet.
 * @param req_len Length of the query packet.
 * @param resp Output buffer for the generated response.
 * @param resp_cap Capacity of the response buffer.
 * @param fake_ip IPv4 address (as string) to use in the fake answer.
 * @param ttl Time-to-live value (in seconds) for the fake record.
 * @return The total length of the generated response, or -1 on error.
 */
int build_fake_a_response(const unsigned char *req, int req_len, unsigned char *resp, 
                         int resp_cap, const char *fake_ip, int ttl) {
    if (req_len < 12) return -1;
    
    memcpy(resp, req, 12);
    
    unsigned char flags2 = 0x84 | (req[2] & 0x01);
    unsigned char flags3 = 0x80; 
    
    resp[2] = flags2;
    resp[3] = flags3;

    resp[6] = 0x00;
    resp[7] = 0x01;

    resp[8] = 0x00;
    resp[9] = 0x00;

    resp[10] = 0x00;
    resp[11] = 0x00;

    int i = 12;
    while (i < req_len && req[i] != 0) i++;
    if (i >= req_len - 4) return -1;

    int qd_len = (i - 12) + 1 + 4;
    if (12 + qd_len > resp_cap) return -1;
    memcpy(resp + 12, req + 12, qd_len);

    int offset = 12 + qd_len;

    if (offset + 16 > resp_cap) return -1;
    
    resp[offset++] = 0xC0;
    resp[offset++] = 0x0C;

    // TYPE A
    resp[offset++] = 0x00;
    resp[offset++] = 0x01;

    // CLASS IN
    resp[offset++] = 0x00;
    resp[offset++] = 0x01;

    // TTL
    uint32_t net_ttl = htonl((uint32_t)ttl);
    memcpy(resp + offset, &net_ttl, 4);
    offset += 4;

    // RDLENGTH = 4
    resp[offset++] = 0x00;
    resp[offset++] = 0x04;

    // RDATA (IPv4)
    struct in_addr addr;
    if (inet_pton(AF_INET, fake_ip, &addr) != 1) return -1;
    memcpy(resp + offset, &addr.s_addr, 4);
    offset += 4;

    return offset;
}

/**
 * @brief Builds an NXDOMAIN response for a blacklisted domain.
 *
 * Constructs a DNS packet indicating that the requested domain does not exist.
 *
 * @param req Pointer to the original DNS query.
 * @param req_len Length of the query.
 * @param resp Output buffer for the response.
 * @param resp_cap Capacity of the response buffer.
 * @return Length of the generated response, or -1 on error.
 */
int build_nxdomain_response(const unsigned char *req, int req_len, unsigned char *resp, int resp_cap) {
    if (req_len < 12) return -1;

    memcpy(resp, req, 2);
    resp[2] = 0x81;
    resp[3] = 0x83;
    
    resp[4] = 0x00;
    resp[5] = 0x01;
    resp[6] = resp[7] = resp[8] = resp[9] = resp[10] = resp[11] = 0x00;

    int i = 12;
    while (i < req_len && req[i] != 0) i++;
    if (i >= req_len - 4) return -1;
    
    int qd_len = (i - 12) + 1 + 4;
    if (12 + qd_len > resp_cap) return -1;
    
    memcpy(resp + 12, req + 12, qd_len);
    
    return 12 + qd_len;
}

/**
 * @brief Builds a REFUSED response for a blacklisted domain.
 *
 * Constructs a DNS response indicating that the query was refused by the server.
 *
 * @param req Pointer to the original DNS query.
 * @param req_len Length of the query.
 * @param resp Output buffer for the response.
 * @param resp_cap Capacity of the response buffer.
 * @return Length of the generated response, or -1 on error.
 */
int build_refused_response(const unsigned char *req, int req_len, unsigned char *resp, int resp_cap) {
    if (req_len < 12) return -1;
    
    memcpy(resp, req, 2);
    resp[2] = 0x81;
    resp[3] = 0x85;
    
    resp[4] = 0x00;
    resp[5] = 0x01;
    resp[6] = resp[7] = resp[8] = resp[9] = resp[10] = resp[11] = 0x00;

    int i = 12;
    while (i < req_len && req[i] != 0) i++;
    if (i >= req_len - 4) return -1;
    
    int qd_len = (i - 12) + 1 + 4;
    if (12 + qd_len > resp_cap) return -1;
    
    memcpy(resp + 12, req + 12, qd_len);
    
    return 12 + qd_len;
}

/**
 * @brief Forwards a DNS query to an upstream server and relays the response back to the client.
 *
 * Opens a temporary UDP socket, sends the DNS query to the configured upstream server,
 * waits for a reply, and forwards the response back to the original client.
 *
 * @param sock The UDP socket of the proxy server.
 * @param buffer Pointer to the received DNS query.
 * @param len Length of the query.
 * @param upstream_dns IP address of the upstream DNS server.
 * @param upstream_port Port of the upstream DNS server.
 * @param client Pointer to the client address structure.
 * @param client_len Length of the client address structure.
 */
void forward_to_upstream(int sock, unsigned char *buffer, int len, 
                        const char *upstream_dns, int upstream_port,
                        struct sockaddr_in *client, socklen_t client_len) {
    int usock = socket(AF_INET, SOCK_DGRAM, 0);
    if (usock < 0) { 
        perror("upstream socket"); 
        return; 
    }

    struct sockaddr_in upstream;
    memset(&upstream, 0, sizeof(upstream));
    upstream.sin_family = AF_INET;
    upstream.sin_port = htons(upstream_port);
    
    if (inet_pton(AF_INET, upstream_dns, &upstream.sin_addr) != 1) {
        fprintf(stderr, "Invalid upstream IP: %s\n", upstream_dns);
        close(usock);
        return;
    }

    if (sendto(usock, buffer, len, 0, (struct sockaddr *)&upstream, sizeof(upstream)) < 0) {
        perror("sendto upstream");
        close(usock);
        return;
    }

    unsigned char response[BUF_SIZE];
    struct timeval tv;
    tv.tv_sec = 2; 
    tv.tv_usec = 0;
    setsockopt(usock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    ssize_t rlen = recvfrom(usock, response, sizeof(response), 0, NULL, NULL);
    if (rlen < 0) {
        perror("recvfrom upstream");
        close(usock);
        return;
    }

    if (sendto(sock, response, rlen, 0, (struct sockaddr *)client, client_len) < 0) {
        perror("sendto client");
    }
    
    close(usock);
}
