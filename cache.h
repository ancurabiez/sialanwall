#ifndef CACHING__H
#define CACHING__H

struct caching {
   int ttl;
   uint32_t hit;
   uint8_t flag;
   uint8_t is_blocked;
   char *domain;
};

extern pthread_mutex_t caching_mutex;

void cache_init(void);
void cache_flush(void);
void cache_put(const char *domain, const uint8_t is_blocked);
uint8_t cache_is_exists(const char *domain);
void cache_delete_domain(const char *domain);

#endif
