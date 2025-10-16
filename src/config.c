/**
 * @file config.c
 * @brief Реалізація завантаження конфігурації DNS-проксі сервера.
 *
 * Цей модуль відповідає за:
 * - Зчитування параметрів із текстового конфігураційного файлу.
 * - Парсинг ключів виду `key=value`.
 * - Заповнення структури Config.
 * - Встановлення значень за замовчуванням у разі відсутності параметрів.
 */

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/**
 * @brief Видаляє пробіли з початку і кінця рядка.
 *
 * Функція модифікує рядок **на місці**, видаляючи всі пробіли, табуляції
 * та символи нового рядка з обох кінців.
 *
 * @param s Вказівник на змінюваний рядок.
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
 * @brief Завантажує конфігурацію з файлу у структуру Config.
 *
 * Підтримуються такі ключі у файлі:
 * - `upstream_dns` — IP адреса апстрім DNS сервера (рядок).
 * - `upstream_port` — порт апстрім DNS сервера (число).
 * - `response` — режим відповіді для заблокованих доменів (`FAKE`, `NXDOMAIN`, `REFUSED`).
 * - `fake_ip` — IP адреса, яку буде повертати FAKE-відповідь.
 * - `listen_port` — порт, на якому слухає локальний DNS-проксі.
 * - `blacklist` — список доменів через кому.
 *
 * Усі ключі нечутливі до пробілів. Рядки, що починаються з `#`, ігноруються.
 *
 * Якщо певний параметр відсутній — використовується значення за замовчуванням:
 * - `upstream_dns = 8.8.8.8`
 * - `upstream_port = 53`
 * - `response = FAKE`
 * - `fake_ip = 127.0.0.1`
 * - `listen_port = 5353`
 * - `blacklist_count = 0`
 *
 * @param filename Шлях до конфігураційного файлу.
 * @param cfg Вказівник на структуру, яку буде заповнено параметрами.
 * @return 0 при успіху, -1 якщо файл не вдалося відкрити.
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
