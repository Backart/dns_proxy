#ifndef DNS_UTILS_H
#define DNS_UTILS_H

#include <netinet/in.h>
#include "config.h"

/**
 * @brief DNS message header structure.
 *
 * Represents the standard DNS header fields as defined in RFC 1035.
 * Bitfields are used to represent flags and control bits.
 */
typedef struct {
    unsigned short id;    /**< Identifier to match requests and responses. */
    unsigned char qr : 1; /**< Query/Response flag: 0 = query, 1 = response. */
    unsigned char opcode : 4; /**< Operation code (usually 0 for standard query). */
    unsigned char aa : 1; /**< Authoritative Answer flag. */
    unsigned char tc : 1; /**< Truncated message flag. */
    unsigned char rd : 1; /**< Recursion Desired flag. */
    unsigned char ra : 1; /**< Recursion Available flag. */
    unsigned char z : 3;  /**< Reserved bits (must be zero). */
    unsigned char rcode : 4; /**< Response code (0 = no error). */
    unsigned short qdcount; /**< Number of entries in the question section. */
    unsigned short ancount; /**< Number of resource records in the answer section. */
    unsigned short nscount; /**< Number of name server resource records. */
    unsigned short arcount; /**< Number of additional resource records. */
} DNSHeader;

/**
 * @brief Parses a DNS query and extracts the domain name, type, and class.
 *
 * @param buffer Input buffer containing the DNS query.
 * @param len Length of the buffer.
 * @param domain Output buffer for the extracted domain name.
 * @param type Output pointer for the query type (e.g., A, AAAA, MX).
 * @param class Output pointer for the query class (usually IN).
 * @return 0 on success, -1 on failure.
 */
int parse_dns_query(const unsigned char *buffer, int len, char *domain, int *type, int *class);

/**
 * @brief Builds a fake DNS A record response with a specified IP.
 *
 * @param req Original DNS request buffer.
 * @param req_len Length of the request.
 * @param resp Output buffer for the generated response.
 * @param resp_cap Capacity of the response buffer.
 * @param fake_ip The fake IPv4 address to include in the response.
 * @param ttl Time-to-live value for the fake record.
 * @return Number of bytes written to resp, or -1 on failure.
 */
int build_fake_a_response(const unsigned char *req, int req_len, unsigned char *resp, 
                         int resp_cap, const char *fake_ip, int ttl);

/**
 * @brief Builds an NXDOMAIN (non-existent domain) response.
 *
 * @param req Original DNS request buffer.
 * @param req_len Length of the request.
 * @param resp Output buffer for the generated response.
 * @param resp_cap Capacity of the response buffer.
 * @return Number of bytes written to resp, or -1 on failure.
 */
int build_nxdomain_response(const unsigned char *req, int req_len, unsigned char *resp, int resp_cap);

/**
 * @brief Builds a REFUSED response indicating the query was rejected.
 *
 * @param req Original DNS request buffer.
 * @param req_len Length of the request.
 * @param resp Output buffer for the generated response.
 * @param resp_cap Capacity of the response buffer.
 * @return Number of bytes written to resp, or -1 on failure.
 */
int build_refused_response(const unsigned char *req, int req_len, unsigned char *resp, int resp_cap);

/**
 * @brief Extracts the queried domain name, type, and class from a DNS message.
 *
 * @param buf Input DNS message buffer.
 * @param buf_len Length of the buffer.
 * @param domain Output buffer for the extracted domain.
 * @param maxlen Maximum allowed length of the domain string.
 * @param qtype Output pointer for the question type.
 * @param qclass Output pointer for the question class.
 * @param qend Output pointer to the position after the question section.
 */
void extract_domain(const unsigned char *buf, int buf_len, char *domain, 
                   int maxlen, int *qtype, int *qclass, int *qend);

/**
 * @brief Checks if a domain name is in the blacklist.
 *
 * @param name Domain name to check.
 * @param cfg Pointer to the loaded configuration containing the blacklist.
 * @return 1 if blacklisted, 0 otherwise.
 */
int is_blacklisted(const char *name, Config *cfg);

/**
 * @brief Forwards a DNS query to the upstream server and sends back the response.
 *
 * @param sock UDP socket used for communication.
 * @param buffer DNS query buffer to forward.
 * @param len Length of the query.
 * @param upstream_dns IP address or hostname of the upstream DNS server.
 * @param upstream_port Port of the upstream DNS server.
 * @param client Client address to send the response to.
 * @param client_len Length of the client address structure.
 */
void forward_to_upstream(int sock, unsigned char *buffer, int len, 
                        const char *upstream_dns, int upstream_port,
                        struct sockaddr_in *client, socklen_t client_len);

#endif
