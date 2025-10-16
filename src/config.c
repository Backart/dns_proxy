/**
 * @file config.c
 * @brief Implementation of configuration file parsing for the DNS proxy server.
 *
 * This module provides functions for loading and parsing the configuration
 * file that defines DNS proxy parameters such as the upstream DNS server,
 * blacklist, fake IP, response type, and listening port.
 */

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/**
 * @brief Trims leading and trailing whitespace characters from a string.
 *
 * This function modifies the input string in place, removing spaces, tabs,
 * and newline characters from both ends.
 *
 * @param s Pointer to the string to be trimmed. Must be writable.
 */
static void trim(char *s) {
    char *end = s + strlen(s) - 1;
    while (end >= s && isspace((unsigned char)*end)) {
        *end = '\0';
        end--;
    }
    
    char *start = s;
    while (*start && isspace((unsigned char)*start)) start++;
    if (start != s) memmove(s, start, strlen(start) + 1);
}

/**
 * @brief Loads DNS proxy configuration from a text file.
 *
 * This function reads key-value pairs from a configuration file and fills
 * a `Config` structure with corresponding values. Supported keys include:
 *
 * - `upstream_dns`: IP address of the upstream DNS server.
 * - `upstream_port`: Port of the upstream DNS server (default: 53).
 * - `response`: Type of DNS response for blacklisted domains.
 *   Possible values: `FAKE`, `NXDOMAIN`, `REFUSED`.
 * - `fake_ip`: IP address to use in fake responses (default: 127.0.0.1).
 * - `listen_port`: Port where the proxy listens for DNS queries (default: 5353).
 * - `blacklist`: Comma-separated list of domain names to block.
 *
 * Lines starting with `#` are treated as comments.
 * Whitespace is automatically trimmed from keys and values.
 *
 * @param filename Path to the configuration file to load.
 * @param cfg Pointer to the `Config` structure to populate.
 * @return 0 on success, or -1 if the file cannot be opened.
 */
int load_config(const char *filename, Config *cfg) {
    FILE *f = fopen(filename, "r");
    if (!f) {
        perror("fopen");
        return -1;
    }

    // Default values
    strcpy(cfg->upstream_dns, "8.8.8.8");
    cfg->upstream_port = 53;
    strcpy(cfg->response, "FAKE");
    strcpy(cfg->fake_ip, "127.0.0.1");
    cfg->listen_port = 5353;
    cfg->blacklist_count = 0;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        trim(line);
        if (line[0] == '#' || line[0] == '\0')
            continue;

        char *eq = strchr(line, '=');
        if (!eq) continue;

        *eq = '\0';
        char *key = line;
        char *val = eq + 1;
        trim(key);
        trim(val);

        if (strcmp(key, "upstream_dns") == 0) {
            strncpy(cfg->upstream_dns, val, MAX_STR_LEN - 1);
            cfg->upstream_dns[MAX_STR_LEN - 1] = '\0';
        } else if (strcmp(key, "upstream_port") == 0) {
            cfg->upstream_port = atoi(val);
        } else if (strcmp(key, "response") == 0) {
            for (int i = 0; val[i]; i++) val[i] = toupper((unsigned char)val[i]);
            if (strcmp(val, "NXDOMAIN") == 0 || strcmp(val, "REFUSED") == 0 || strcmp(val, "FAKE") == 0) {
                strncpy(cfg->response, val, MAX_STR_LEN - 1);
                cfg->response[MAX_STR_LEN - 1] = '\0';
            } else {
                fprintf(stderr, "Unknown response mode '%s'. Using FAKE.\n", val);
                strcpy(cfg->response, "FAKE");
            }
        } else if (strcmp(key, "fake_ip") == 0) {
            strncpy(cfg->fake_ip, val, MAX_STR_LEN - 1);
            cfg->fake_ip[MAX_STR_LEN - 1] = '\0';
        } else if (strcmp(key, "listen_port") == 0) {
            cfg->listen_port = atoi(val);
        } else if (strcmp(key, "blacklist") == 0) {
            char *tok = strtok(val, ",");
            while (tok && cfg->blacklist_count < MAX_BLACKLIST) {
                trim(tok);
                strncpy(cfg->blacklist[cfg->blacklist_count], tok, MAX_STR_LEN - 1);
                cfg->blacklist[cfg->blacklist_count][MAX_STR_LEN - 1] = '\0';
                cfg->blacklist_count++;
                tok = strtok(NULL, ",");
            }
        }
    }

    fclose(f);
    return 0;
}
