/* 
 * 15/07/2012
 * 
 * Copyright (c) 2012 Lulus Wijayakto <l.wijayakto@yahoo.com>
 *
 * Can be freely distributed and used under the terms of the GNU GPL.
 *
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <assert.h>

#include "defined.h"
#include "generic_domain.h"
#include "helper.h"


static struct tld__ *tld = NULL;
static uint16_t tld_size = 0;


uint8_t generic_init(void)
{
   FILE *fp = NULL;
   // get count
   fp = fopen(TLD_PATH, "r");
   if (!fp) {
      fprintf(stderr, "TLD file not found.\n");
      return 0;
   }
   
   uint16_t i = 0, j = 0;
   char buf[256];
   
   while (fgets(buf, sizeof(buf), fp)) {
      if ((buf[0] == '#') || !strncmp(buf, "XN--", 4))
         continue;
      tld_size++;
   }
   fclose(fp);
   
   tld = je_calloc(sizeof(struct tld__), tld_size);
   assert(tld);
   
   fp = fopen(TLD_PATH, "r");
   while (fgets(buf, sizeof(buf), fp)) {
      if ((buf[0] == '#') || !strncmp(buf, "XN--", 4))
         continue;
      
      i = strlen(buf);
      memcpy(buf + (i -1), "\0", 1);
      
      (*(tld + j)).tld = strdup__(buf);
      if ((*(tld + j)).tld)
         j++;
   }
   fclose(fp);
   
   return 1;
}

void generic_flush(void)
{
   uint16_t i;
   
   for (i = 0; i < tld_size; i++)
      FREE((*(tld + i)).tld);
      
   FREE(tld);
}

static int bcmp__(const void *m1, const void *m2)
{
   struct tld__ *mi1 = (struct tld__ *) m1;
   struct tld__ *mi2 = (struct tld__ *) m2;
   
   if (!mi1->tld)
      return 1;
   if (!mi2->tld)
      return -1;
   
   return strcasecmp(mi1->tld, mi2->tld);
}

uint8_t generic_is_exist(const char *str)
{
   struct tld__ key, *val;
   
   key.tld = strdup__(str);
   if (!key.tld)
      return 2;
   
   val = bsearch(&key, tld, tld_size, sizeof(struct tld__), bcmp__);
   
   FREE(key.tld);
   
   if (!val)
      return 0;
   return 1;
}
