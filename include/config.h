#ifndef CONFIG_H
#define CONFIG_H

#define MAX_BLACKLIST 100
#define MAX_STR_LEN 256

/**
 * @brief Configuration structure for the DNS proxy server.
 *
 * Holds runtime parameters loaded from the configuration file,
 * such as upstream DNS server, blacklist entries, fake IP, and response type.
 */
typedef struct {
    char upstream_dns[MAX_STR_LEN];   /**< IP address or hostname of the upstream DNS server. */
    int upstream_port;                /**< Port of the upstream DNS server. */
    char response[MAX_STR_LEN];       /**< Response type for blacklisted domains (NXDOMAIN, REFUSED, or FAKE). */
    char fake_ip[MAX_STR_LEN];        /**< IP address to return in FAKE responses. */
    int listen_port;                  /**< Port on which the proxy server listens for DNS queries. */
    char blacklist[MAX_BLACKLIST][MAX_STR_LEN]; /**< Array of domain names to be filtered. */
    int blacklist_count;              /**< Number of domains currently in the blacklist. */
} Config;

/**
 * @brief Loads configuration parameters from a file.
 *
 * @param filename Path to the configuration file.
 * @param cfg Pointer to the Config structure to be filled.
 * @return 0 on success, -1 on failure.
 */
int load_config(const char *filename, Config *cfg);

#endif
