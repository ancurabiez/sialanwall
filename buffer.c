#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <inttypes.h>

#include "buffer.h"
#include "defined.h"

static struct buffer__ *buffer = NULL;
static uint32_t buffer_size = BUFFER_SIZE;
static uint32_t count_put = 0;
static int32_t count = 0;

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;


static BufEcode buffer_add(void)
{
   struct buffer__ *tmp = NULL;
   
   tmp = je_realloc(buffer, buffer_size * 2);
   if (!tmp)
      return BUF_MALLOC_ERROR;
      
   buffer_size *= 2;
   buffer = tmp;

   return BUF_OK;
}

void buffer_init(void)
{
   buffer = je_calloc(sizeof(*buffer), buffer_size);
   assert(buffer);
}

void buffer_flush(void)
{
   uint32_t i;
   
   for (i = 0; i < buffer_size; i++)
      FREE((*(buffer +i)).packet);
      
   FREE(buffer);
}

BufEcode buffer_put(const int id, struct nfq_q_handle *qh,
   const uint8_t *data, const uint16_t len,
   DB *ip_db, DB *domain_db, uint32_t in_device)
{
   if ((*(buffer + count_put)).flag == 1) {
      count_put++;
      if (count_put >= buffer_size)
         count_put = 0;
      return BUF_CONTINUE;
   }

   if (count >= (buffer_size - 512)) { //tambah buffer
      pthread_mutex_lock(&mutex);
      buffer_add();
      pthread_mutex_unlock(&mutex);
   }
      
   (*(buffer + count_put)).packet = je_malloc(len +1);
   if (!((*(buffer + count_put)).packet))
      return BUF_MALLOC_ERROR;
   
   memset((*(buffer + count_put)).packet, 0, len +1);
   memcpy((*(buffer + count_put)).packet, data, len);

   (*(buffer + count_put)).packet_len = len;
   (*(buffer + count_put)).ip_db = ip_db;
   (*(buffer + count_put)).domain_db = domain_db;
   (*(buffer + count_put)).in_device = in_device;
   (*(buffer + count_put)).id = id;
   (*(buffer + count_put)).qh = qh;
   (*(buffer + count_put)).flag = 1;

   count_put++;
   if (count_put >= buffer_size)
      count_put = 0;
  
   return BUF_OK;
}

BufEcode buffer_get(struct buffer__ *buf_arg, const uint32_t idx)
{
   if ((*(buffer + idx)).flag == 0)
      return BUF_CONTINUE;
      
   buf_arg->packet = (*(buffer + idx)).packet;
   buf_arg->packet_len = (*(buffer + idx)).packet_len;
   buf_arg->ip_db = (*(buffer + idx)).ip_db;
   buf_arg->domain_db = (*(buffer + idx)).domain_db;
   buf_arg->in_device = (*(buffer + idx)).in_device;
   buf_arg->id = (*(buffer + idx)).id;
   buf_arg->qh = (*(buffer + idx)).qh;
   
   return BUF_OK;
}

void buffer_del(const uint32_t idx)
{
   FREE((*(buffer + idx)).packet);
   (*(buffer + idx)).flag = 0;
   count--;
}

uint32_t buffer_get_size(void)
{
   return buffer_size;
}

int32_t buffer_get_count(void)
{
   return count;
}

void buffer_count_inc(void)
{
   count++;
}
