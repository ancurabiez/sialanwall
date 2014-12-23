/* 
 * 15/07/2012
 * 
 * Copyright (c) 2012 Lulus Wijayakto <l.wijayakto@yahoo.com>
 *
 * Can be freely distributed and used under the terms of the GNU GPL.
 *
*/

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <assert.h>
#include <time.h>
#include <syslog.h>

#include "cache.h"
#include "helper.h"
#include "defined.h"
#include "sialan.h"

static struct caching *cache = NULL;
static uint32_t cache_count = 0;

pthread_mutex_t caching_mutex = PTHREAD_MUTEX_INITIALIZER;


static int bcmp__(const void *m1, const void *m2)
{
   struct caching *mi1 = (struct caching *) m1;
   struct caching *mi2 = (struct caching *) m2;
   
   if (!mi1->domain)
      return 1;
   if (!mi2->domain)
      return -1;
   
   return strcasecmp(mi1->domain, mi2->domain);
}

static int bcmp_hit__(const void *m1, const void *m2)
{
   struct caching *mi1 = (struct caching *) m1;
   struct caching *mi2 = (struct caching *) m2;
   
   if (!mi1->domain)
      return 1;
   if (!mi2->domain)
      return -1;

   return (int) (mi1->hit - mi2->hit);
}

void cache_init(void)
{
   cache = je_calloc(sizeof(struct caching), CACHE_SIZE);
   assert(cache);
}

void cache_flush(void)
{
   uint32_t i;
   
   for (i = 0; i < CACHE_SIZE; i++)
      FREE((*(cache + i)).domain);
      
   FREE(cache);
}

void cache_limit(void)
{
   // hapus "domain" berdasarkan "ttl" dan kalau ternyata jumlah "domain" yang
   // terhapus kurang dari CACHE_LOW, maka hapus berdasarkan "hit" yang terkecil.
   
   if (cache_count >= CACHE_HIGH) {
      syslog(LOG_USER | LOG_INFO, "sialan_fw: begin: cache_limit");
      uint32_t i;
      int t;
       
      t = time(NULL);
      // delete dengan referensi ttl
      for (i = 0; i < CACHE_SIZE; i++) {
         if ((*(cache + i)).flag && (t - ((*(cache + i)).ttl) >= CACHE_TTL)) {
            FREE((*(cache + i)).domain);
            (*(cache + i)).flag = 0;
            
            cache_count--;
         }
         
         if (cache_count < CACHE_LOW)
            break;
      }
      
      if (cache_count > CACHE_LOW) {
         //sort hit dari yang terkecil ke yang terbesar
         qsort(cache, CACHE_SIZE, sizeof(struct caching), bcmp_hit__);
         
         for (i = 0; i < CACHE_LOW; i++) {
            if ((*(cache + i)).flag) {
               FREE((*(cache + i)).domain);
               (*(cache + i)).flag = 0;
               
               cache_count--;
            }
            
            if (cache_count < CACHE_LOW)
               break;
         }
      }
      
      // sorting domain
      qsort(cache, CACHE_SIZE, sizeof(struct caching), bcmp__);
      syslog(LOG_USER | LOG_INFO, "sialan_fw: end: cache_limit");
   }
}

void cache_put(const char *domain, const uint8_t is_blocked)
{
   uint32_t i;
   
   cache_limit();
   
   i = cache_count;
   while (i < CACHE_SIZE) {
      // fill it if flag == 0
      if (! (*(cache + i)).flag) {
         (*(cache + i)).domain = strdup__(domain);
         
         if (! (*(cache + i)).domain) // if domain == NULL
            break;

         (*(cache + i)).hit = 0;
         (*(cache + i)).is_blocked = is_blocked;
         (*(cache + i)).flag = 1;
         
         cache_count++;
         qsort(cache, cache_count, sizeof(struct caching), bcmp__);
         break;
      }
      
      i++;
   }
}

static struct caching* search(const char *domain)
{
   struct caching key, *val = NULL;
   
   memset(&key, 0, sizeof(key));
   
   key.domain = strdup__(domain);
   if (!key.domain)
      return NULL;
   
   val = bsearch(&key, cache, cache_count, sizeof(struct caching), bcmp__);
   FREE(key.domain);
   
   return val;
}

/* return: 0 unblocked
*          1 blocked
*          2 not in the list
* flag: 1 remove from list
*       0 nothing
*/
uint8_t cache_is_exists(const char *domain)
{
   struct caching *val = NULL;
   
   val = search(domain);
   
   if (!val)
      return 2;

   if (val->hit == UINT32_MAX)
      val->hit = 0;

   val->hit++;
   val->ttl = time(NULL);
   
   return val->is_blocked;
}

void cache_delete_domain(const char *domain)
{
   uint32_t i = 0;
   int16_t len = 0, len1 = 0;
   uint8_t f = 0;
   char buf[256];
      
   memset(buf, 0, sizeof(buf));

   i = get_tld(domain, buf, sizeof(buf));
   if (i == 0)
      return;

   len = strlen(buf);
   
   for (i = 0; i < CACHE_SIZE; i++) {
      if ((*(cache + i)).flag) {
         len1 = strlen((*(cache + i)).domain);
         len1 -= len;
         if (len1 < 0)
            len1 = 0;

         if (!memcmp(buf, (*(cache + i)).domain + len1, len)) {
            FREE((*(cache + i)).domain);
            (*(cache + i)).flag = 0;

            cache_count--;
            f = 1;
         }
      }
   }
   
   // sorting domain
   if (f)
      qsort(cache, CACHE_SIZE, sizeof(struct caching), bcmp__);
}
