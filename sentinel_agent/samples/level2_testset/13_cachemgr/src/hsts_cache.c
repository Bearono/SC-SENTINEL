#include "hsts_cache.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct hsts_entry {
    char *host;
    unsigned max_age;
    struct hsts_entry *next;
} hsts_entry_t;

static hsts_entry_t *entry_new(const char *host, size_t n, unsigned age)
{
    hsts_entry_t *e = (hsts_entry_t *)calloc(1, sizeof(*e));
    if (!e) return NULL;
    e->host = (char *)malloc(n + 1);
    if (!e->host) { free(e); return NULL; }
    memcpy(e->host, host, n);
    e->host[n] = '\0';
    e->max_age = age;
    return e;
}

static void entry_free(hsts_entry_t *e)
{
    if (!e) return;
    free(e->host);
    free(e);
}

static hsts_entry_t *find_entry(hsts_entry_t *head, const char *host)
{
    for (hsts_entry_t *e = head; e; e = e->next) {
        if (strcmp(e->host, host) == 0) return e;
    }
    return NULL;
}

int hsts_import_cache(const uint8_t *data, size_t len)
{
    hsts_entry_t *head = NULL;
    hsts_entry_t *last_replaced = NULL;
    size_t pos = 0;
    int count = 0;
    while (pos + 2 < len) {
        uint8_t n = data[pos++];
        if (n == 0 || pos + n + 1 > len) break;
        unsigned age = data[pos + n];
        hsts_entry_t *e = entry_new((const char *)data + pos, n, age);
        pos += n + 1;
        if (!e) break;
        hsts_entry_t *old = find_entry(head, e->host);
        if (old) {
            last_replaced = old;
            free(old->host);
            old->host = e->host;
            old->max_age = e->max_age;
            e->host = NULL;
            entry_free(e);
        } else {
            e->next = head;
            head = e;
        }
        count++;
    }
    if (last_replaced && count > 2) {
        entry_free(last_replaced);
    }
    while (head) {
        hsts_entry_t *next = head->next;
        entry_free(head);
        head = next;
    }
    return count;
}
