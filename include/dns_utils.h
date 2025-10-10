#ifndef DNS_UTILS_H
#define DNS_UTILS_H

#include <netinet/in.h>
#include "config.h"

typedef struct {
    unsigned short id;
    unsigned char qr : 1;
    unsigned char opcode : 4;
    unsigned char aa : 1;
    unsigned char tc : 1;
    unsigned char rd : 1;
    unsigned char ra : 1;
    unsigned char z : 3;
    unsigned char rcode : 4;
    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
} DNSHeader;

int parse_dns_query(const unsigned char *buffer, int len, char *domain, int *type, int *class);
int build_fake_a_response(const unsigned char *req, int req_len, unsigned char *resp, 
                         int resp_cap, const char *fake_ip, int ttl);
int build_nxdomain_response(const unsigned char *req, int req_len, unsigned char *resp, int resp_cap);
int build_refused_response(const unsigned char *req, int req_len, unsigned char *resp, int resp_cap);
void extract_domain(const unsigned char *buf, int buf_len, char *domain, 
                   int maxlen, int *qtype, int *qclass, int *qend);
int is_blacklisted(const char *name, Config *cfg);
void forward_to_upstream(int sock, unsigned char *buffer, int len, 
                        const char *upstream_dns, int upstream_port,
                        struct sockaddr_in *client, socklen_t client_len);

#endif