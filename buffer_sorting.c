#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <assert.h>

#include "defined.h"
#include "buffer_sorting.h"
#include "helper.h"

static struct buffer_sort *buf_s = NULL;
static uint16_t count = 0;
static uint16_t count_get = 0;


static int bcmp__(const void *m1, const void *m2)
{
   struct buffer_sort *mi1 = (struct buffer_sort *) m1;
   struct buffer_sort *mi2 = (struct buffer_sort *) m2;

   if (!mi1->domain)  
      return 1;
   if (!mi2->domain)
      return -1;
         
   return (int) (mi1->len - mi2->len);
}

void buffer_sorting_init(void)
{
   buf_s = je_calloc(sizeof(struct buffer_sort), BUFFER_SORTING_SIZE);
   assert(buf_s);
}

void buffer_sorting_flush(void)
{
   uint16_t i;
   
   for (i = 0; i < BUFFER_SORTING_SIZE; i++)
      FREE((*(buf_s + i)).domain);
      
   FREE(buf_s);
}

uint8_t buffer_sorting_put(const char* domain, const uint8_t flag)
{
   if (count >= BUFFER_SORTING_SIZE)
      return 0;
   
   (*(buf_s + count)).len = strlen(domain);
   (*(buf_s + count)).flag = flag;
   (*(buf_s + count)).domain = strdup__(domain);

   if ((*(buf_s + count)).domain)
      count++;
      
   return 1;
}

uint8_t buffer_sorting_sort(void)
{
   if (count > 0)
      qsort(buf_s, count, sizeof(struct buffer_sort), bcmp__);
   else
      return 0;
   
   return 1;
}

struct buffer_sort* buffer_sorting_get(void)
{
   if (count_get < count) {
      struct buffer_sort *bs = NULL;
      
      bs = (buf_s + count_get);
      count_get++;
      return bs;
   }
   
   return NULL;
}

void buffer_sorting_clear(void)
{
   uint16_t i;
   
   for (i = 0; i < count; i++)
      FREE((*(buf_s + i)).domain);
   
   count = 0;
   count_get = 0;
}
