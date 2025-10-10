#ifndef CONFIG_H
#define CONFIG_H

#define MAX_BLACKLIST 100
#define MAX_STR_LEN 256

typedef struct {
    char upstream_dns[MAX_STR_LEN];
    int upstream_port;
    char response[MAX_STR_LEN]; // NXDOMAIN, REFUSED or FAKE
    char fake_ip[MAX_STR_LEN];
    int listen_port;
    char blacklist[MAX_BLACKLIST][MAX_STR_LEN];
    int blacklist_count;
} Config;

int load_config(const char *filename, Config *cfg);

#endif