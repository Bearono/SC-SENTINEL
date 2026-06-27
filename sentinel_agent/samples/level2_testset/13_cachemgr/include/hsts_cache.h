#ifndef HSTS_CACHE_H
#define HSTS_CACHE_H
#include <stddef.h>
#include <stdint.h>
int hsts_import_cache(const uint8_t *data, size_t len);
#endif
