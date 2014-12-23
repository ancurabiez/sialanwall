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
#include <arpa/inet.h>

#include "sialan.h"
#include "defined.h"


static u_int8_t get_http_host(const u_int8_t *payload,
   const u_int16_t len, char *buf, const u_int16_t blen, u_int8_t *f)
{
   if (len < 2)
      return 0;
   
   u_int16_t i = 0, l = 0;
   int ip[4] = {0};
   *f = 0;
   
   while (!stop) {
      if (l >= len)
         break;
      
      i = strcspn((char*) payload, "\r");

      if ((*(payload + i) == '\r') && (*(payload + (i+1)) == '\n')) {
         if (!memcmp(payload, "Host: ", 6)) {

            payload += 6;
            // jika host > 255 karakter, return error
            if (strcspn((char*) payload, "\r") > 255) {
               i = 1;
               break;
            }
            
            // get "Host: " data
            memccpy(buf, payload, '\r', 255);
            i = strlen(buf);
            memcpy(buf + (i-1), "\0", 1); //remove char '\r'
            
            *f = DOMAIN;

            // cek ip address atau bukan
            if (sscanf(buf, "%d.%d.%d.%d", &ip[0], &ip[1], &ip[2], &ip[3]) == 4) {
               u_int32_t addr = 0;
               // check doted
               while (*buf != '\0') {
                  if (*buf == '.')
                     addr++;
                  buf++;
               }
               
               buf -= (i -1);
                  
               if (addr == 3) {
                  if (inet_pton(AF_INET, buf, &addr) > 0) {
                     memcpy(buf, &addr, sizeof(uint32_t));
                     *f = IP;
                  }
               }
            }
            
            i = 0;
            break;
         }
      
         payload += (i+2);
      }
      
      l += (i +2);
   }
  
   if (i > 0)
      return 0;
   
   return 1;
}

u_int8_t is_http_blacklist(const u_int8_t *tcp_payload,
   const u_int32_t payload_len, DB *ip_db, DB *domain_db)
{
   char buf[332];
   u_int8_t i = 0, f = 0;
   memset(buf, '\0', sizeof(buf));

   if (get_http_host(tcp_payload, payload_len, buf, sizeof(buf), &f)) {

      // cek di db apakah ada di daftar black list
      i = is_exist(buf, f, (f == DOMAIN) ? domain_db : ip_db);
   }
   
   return i;
}
