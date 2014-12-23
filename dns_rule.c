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
#include <sys/types.h>

#include "sialan.h"
#include "defined.h"


u_int8_t parse_dns_question(const u_int8_t *payload, char *buff,
      const int16_t payload_len)
{
   u_int16_t k = 0, len = 0, t = sizeof(struct dns_header);
   
   while (!stop) {
      if (t > payload_len)
         break;
      
      len = *payload;
      payload++;
      t++;
      
      memcpy(buff +k, payload, len);
      k += len;
      payload += len;
      t += len;
      
      if (*payload == 0)
         break;
    
      memset(buff + k, '.', 1);
      k++;
   }

   // proses hanya A IN (type class) ipv4/ipv6
   if (((*(payload +2) == 1) || (*(payload + 2) == 28)) && (*(payload + 4) == 1))
      return 1;
   
   return 0;
}

u_int8_t is_dns_blacklist(const u_int8_t *payload_data, const int16_t len,
      DB *db)
{
   const struct dns_header *dhead = (struct dns_header *) payload_data;
   // hanya query dan query count == 1
   if ((dhead->qr > 0) || (ntohs(dhead->qdcount) > 1))
      return 0;
      
   if ((len - sizeof(struct dns_header)) <= 0)
      return 2;

   char buf[257];
   u_int16_t i = 0;
   const u_int8_t *ll = payload_data + sizeof(struct dns_header);

   memset(buf, '\0', sizeof(buf));

   if (!parse_dns_question(ll, buf, len))
      return 2;

   i = is_exist(buf, DOMAIN, db);
      
   return i;
}
