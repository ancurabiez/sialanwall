#ifndef BUFFER__H
#define BUFFER__H

#include <inttypes.h>
#include <db.h>

struct buffer__ {
   struct nfq_q_handle *qh;
   DB *domain_db;
   DB *ip_db;
   int id;
   uint32_t in_device;
   uint16_t packet_len;
   uint8_t *packet;
   uint8_t flag;
};

extern pthread_mutex_t mutex;

typedef enum {
   BUF_MALLOC_ERROR = 0,
   BUF_OK,
   BUF_CONTINUE,
} BufEcode;


void buffer_init(void);
void buffer_flush(void);
BufEcode buffer_put(const int id, struct nfq_q_handle *qh,
   const uint8_t *data, const uint16_t len,
   DB *ip_db, DB *domain_db, const uint32_t in_device);
BufEcode buffer_get(struct buffer__ *data_arg, const uint32_t idx);
void buffer_del(const uint32_t idx);
uint32_t buffer_get_size(void);
int32_t buffer_get_count(void);

void buffer_count_inc(void);

#endif
