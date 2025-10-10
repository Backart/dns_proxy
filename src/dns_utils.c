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

int parse_dns_query(const unsigned char *buffer, int len, char *domain, int *type, int *class) {
    int qend;
    extract_domain(buffer, len, domain, 256, type, class, &qend);
    return (domain[0] != '\0') ? 0 : -1;
}

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

int is_blacklisted(const char *name, Config *cfg) {
    for (int i = 0; i < cfg->blacklist_count; i++) {
        if (strcasecmp(name, cfg->blacklist[i]) == 0) return 1;
    }
    return 0;
}

int build_fake_a_response(const unsigned char *req, int req_len, unsigned char *resp, 
                         int resp_cap, const char *fake_ip, int ttl) {
    if (req_len < 12) return -1;
    
    // Копируем весь заголовок запроса
    memcpy(resp, req, 12);
    
    // Устанавливаем флаги ответа: QR=1, AA=1, RA=1
    unsigned char flags2 = 0x84 | (req[2] & 0x01); // QR=1(0x80), AA=1(0x04), RD как в запросе
    unsigned char flags3 = 0x80; // RA=1
    
    resp[2] = flags2;
    resp[3] = flags3;

    // QDCOUNT = 1 (как в запросе)
    // ANCOUNT = 1
    resp[6] = 0x00;
    resp[7] = 0x01;
    // NSCOUNT = 0
    resp[8] = 0x00;
    resp[9] = 0x00;
    // ARCOUNT = 0  
    resp[10] = 0x00;
    resp[11] = 0x00;

    // Копируем секцию вопроса
    int qd_len = 0;
    int i = 12;
    
    // Ищем конец QNAME (заканчивается нулевым байтом)
    while (i < req_len && req[i] != 0) {
        i++;
    }
    if (i >= req_len - 4) return -1;
    
    // Длина секции вопроса: QNAME + null-byte + TYPE + CLASS
    qd_len = (i - 12) + 1 + 4;
    
    if (12 + qd_len > resp_cap) return -1;
    memcpy(resp + 12, req + 12, qd_len);

    int offset = 12 + qd_len;

    // Секция ответа
    if (offset + 16 > resp_cap) return -1;
    
    // NAME - указатель на имя в секции вопроса (0xC00C)
    resp[offset++] = 0xC0;
    resp[offset++] = 0x0C;

    // TYPE A (1)
    resp[offset++] = 0x00;
    resp[offset++] = 0x01;

    // CLASS IN (1)
    resp[offset++] = 0x00;
    resp[offset++] = 0x01;

    // TTL (4 bytes)
    uint32_t net_ttl = htonl((uint32_t)ttl);
    memcpy(resp + offset, &net_ttl, 4);
    offset += 4;

    // RDLENGTH = 4
    resp[offset++] = 0x00;
    resp[offset++] = 0x04;

    // RDATA: IPv4 адрес
    struct in_addr addr;
    if (inet_pton(AF_INET, fake_ip, &addr) != 1) return -1;
    memcpy(resp + offset, &addr.s_addr, 4);
    offset += 4;

    return offset;
}

int build_nxdomain_response(const unsigned char *req, int req_len, unsigned char *resp, int resp_cap) {
    if (req_len < 12) return -1;
    
    // Копируем ID и часть заголовка
    memcpy(resp, req, 2); // ID
    
    // Устанавливаем флаги: QR=1, Opcode, AA=0, TC=0, RD=1, RA=1, RCODE=3
    resp[2] = 0x81; // QR=1, RD=1
    resp[3] = 0x83; // RA=1, RCODE=3
    
    // QDCOUNT = 1
    resp[4] = 0x00;
    resp[5] = 0x01;
    
    // ANCOUNT = 0, NSCOUNT = 0, ARCOUNT = 0
    resp[6] = resp[7] = 0x00; // ANCOUNT
    resp[8] = resp[9] = 0x00; // NSCOUNT  
    resp[10] = resp[11] = 0x00; // ARCOUNT
    
    // Копируем секцию вопроса
    int i = 12;
    while (i < req_len && req[i] != 0) i++;
    if (i >= req_len - 4) return -1;
    
    int qd_len = (i - 12) + 1 + 4; // QNAME + null + TYPE + CLASS
    if (12 + qd_len > resp_cap) return -1;
    
    memcpy(resp + 12, req + 12, qd_len);
    
    return 12 + qd_len; // Только заголовок + вопрос
}

int build_refused_response(const unsigned char *req, int req_len, unsigned char *resp, int resp_cap) {
    if (req_len < 12) return -1;
    
    // Копируем ID и часть заголовка
    memcpy(resp, req, 2); // ID
    
    // Устанавливаем флаги: QR=1, Opcode, AA=0, TC=0, RD=1, RA=1, RCODE=5
    resp[2] = 0x81; // QR=1, RD=1
    resp[3] = 0x85; // RA=1, RCODE=5
    
    // QDCOUNT = 1
    resp[4] = 0x00;
    resp[5] = 0x01;
    
    // ANCOUNT = 0, NSCOUNT = 0, ARCOUNT = 0
    resp[6] = resp[7] = 0x00; // ANCOUNT
    resp[8] = resp[9] = 0x00; // NSCOUNT
    resp[10] = resp[11] = 0x00; // ARCOUNT
    
    // Копируем секцию вопроса
    int i = 12;
    while (i < req_len && req[i] != 0) i++;
    if (i >= req_len - 4) return -1;
    
    int qd_len = (i - 12) + 1 + 4; // QNAME + null + TYPE + CLASS
    if (12 + qd_len > resp_cap) return -1;
    
    memcpy(resp + 12, req + 12, qd_len);
    
    return 12 + qd_len; // Только заголовок + вопрос
}

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