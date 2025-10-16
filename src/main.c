/**
 * @file main.c
 * @brief Main entry point for the DNS proxy server.
 *
 * This module implements a DNS proxy that:
 *  - Reads configuration from a file (`config.txt` by default)
 *  - Filters blacklisted domains
 *  - Returns custom DNS responses (FAKE, NXDOMAIN, REFUSED)
 *  - Forwards other queries to an upstream DNS server
 *
 * The proxy operates over UDP and listens on a configurable port.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "config.h"
#include "dns_utils.h"

#define BUF_SIZE 1500 /**< Maximum DNS packet size */

/**
 * @brief Handle an incoming DNS query from a client.
 *
 * Parses the query, checks for blacklisted domains, and either
 * responds locally (FAKE/NXDOMAIN/REFUSED) or forwards to the
 * upstream DNS server.
 *
 * @param sock          Server socket descriptor.
 * @param client        Pointer to client sockaddr structure.
 * @param client_len    Length of the client sockaddr structure.
 * @param buffer        Pointer to the DNS request data.
 * @param len           Length of the DNS request data.
 * @param cfg           Pointer to loaded configuration structure.
 */
void handle_query(int sock, struct sockaddr_in *client, socklen_t client_len,
                  unsigned char *buffer, int len, Config *cfg) {
    char domain[256];
    int type, class;

    if (parse_dns_query(buffer, len, domain, &type, &class) < 0) {
        fprintf(stderr, "Failed to parse DNS query\n");
        return;
    }

    printf("Query: %s (type=%d class=%d)\n", domain, type, class);

    if (is_blacklisted(domain, cfg)) {
        printf("  -> Blocked, mode: %s\n", cfg->response);

        unsigned char response[BUF_SIZE];
        int response_len = 0;

        if (strcmp(cfg->response, "FAKE") == 0) {
            response_len = build_fake_a_response(buffer, len, response, sizeof(response),
                                               cfg->fake_ip, 300);
        } else if (strcmp(cfg->response, "NXDOMAIN") == 0) {
            response_len = build_nxdomain_response(buffer, len, response, sizeof(response));
        } else if (strcmp(cfg->response, "REFUSED") == 0) {
            response_len = build_refused_response(buffer, len, response, sizeof(response));
        }

        if (response_len > 0) {
            sendto(sock, response, response_len, 0, (struct sockaddr *)client, client_len);
        } else {
            fprintf(stderr, "Failed to build response\n");
        }
        return;
    }

    forward_to_upstream(sock, buffer, len, cfg->upstream_dns, cfg->upstream_port,
                       client, client_len);
}

/**
 * @brief Program entry point.
 *
 * Loads configuration, initializes UDP socket, and enters an infinite
 * loop to receive and process DNS queries.
 *
 * Usage:
 * ```
 * ./dns_proxy [config_file]
 * ```
 *
 * @param argc  Argument count.
 * @param argv  Argument vector.
 * @return int  Exit code (0 on success, non-zero on failure).
 */
int main(int argc, char *argv[]) {
    const char *config_path = "config.txt";
    if (argc >= 2) config_path = argv[1];

    Config cfg;
    if (load_config(config_path, &cfg) != 0) {
        fprintf(stderr, "Failed to load configuration!\n");
        return 1;
    }

    printf("DNS proxy config loaded:\n");
    printf("  Upstream DNS : %s:%d\n", cfg.upstream_dns, cfg.upstream_port);
    printf("  Fake IP      : %s\n", cfg.fake_ip);
    printf("  Listen port  : %d\n", cfg.listen_port);
    printf("  Response mode: %s\n", cfg.response);
    printf("  Blacklist (%d):\n", cfg.blacklist_count);
    for (int i = 0; i < cfg.blacklist_count; i++)
        printf("   - %s\n", cfg.blacklist[i]);

    int sockfd;
    struct sockaddr_in servaddr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        exit(1);
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(cfg.listen_port);

    if (bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("bind failed");
        fprintf(stderr, "Try sudo if port < 1024\n");
        close(sockfd);
        exit(1);
    }

    printf("DNS proxy listening on port %d...\n", cfg.listen_port);

    unsigned char buf[BUF_SIZE];
    struct sockaddr_in cliaddr;
    socklen_t len = sizeof(cliaddr);

    while (1) {
        ssize_t n = recvfrom(sockfd, buf, sizeof(buf), 0,
                           (struct sockaddr *)&cliaddr, &len);
        if (n < 0) {
            perror("recvfrom");
            continue;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &cliaddr.sin_addr, client_ip, sizeof(client_ip));
        printf("Received DNS query from %s:%d\n",
               client_ip, ntohs(cliaddr.sin_port));

        handle_query(sockfd, &cliaddr, len, buf, n, &cfg);
    }

    close(sockfd);
    return 0;
}
