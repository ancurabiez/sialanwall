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
#include <ctype.h>
#include <inttypes.h>

#include "../defined.h"
#include "generic_domain.h"
#include "sialan_ctl.h"


char *strdup__(const char* str)
{
   if (!*str)
      return NULL;
   
   uint16_t len = 0;
   char *tmp = NULL;
   
   len = strlen(str);
   tmp = je_malloc(len +1);
   
   if(!tmp)
      return NULL;
   
   memset(tmp, '\0', len +1);
   memcpy(tmp, str, len);
   
   return tmp;
}

void printf__(WINDOW *win, const int y, const int x,
      const char *str, const uint8_t f, const uint8_t err)
{
   wattron(win, COLOR_PAIR(f));
   wattrset(win, COLOR_PAIR(f));
   
   mvaddstr(y, x, str);
   wrefresh(win);
   
   if (err) {
      cbreak();
      noecho();
      getch();
      nocbreak();
      echo();
            
      wattron(win, COLOR_PAIR(4));
      wattrset(win, COLOR_PAIR(4));
      wrefresh(win);
   }
}

void to_lower(char *str)
{
   int c;
   char *tmp = NULL;
   
   for (tmp = str; *tmp; tmp++) {
      c = tolower(*tmp);
      *tmp = c;
   }
}

char *mirror(char *string)
{
   char *begin = NULL, *end = NULL, tmp = 0;
   uint8_t len = 0, c = 0;
   
   len = strlen(string);
   begin = string;
   end = string;
   
   end += (len -1);
   
   for (c = 0; c < (len / 2); c++) {
      tmp = *end;
      *end = *begin;
      *begin = tmp;
   
      begin++;
      end--;
   }
     
   return string;
}

uint8_t get_tld(const char* domain, char *buf, const uint16_t blen)
{
   uint8_t i, j, len, dot = 0;
   char *dom = NULL;
   
   dom = strdup__(domain);
   if (!dom)
      return 0;
   
   len = strlen(domain);
   domain += len;
   
   for (i = 0; i < len; i++) {
      domain--;
      if (*domain == '.')
         dot++;
      else
         continue;
      
      if (dot == 2) {
         domain++;
         
         memccpy(buf, domain, '.', blen);
         j = strlen(buf);
         memcpy(buf + (j -1), "\0", 1);
         
         if (!generic_is_exist(buf)) {
            memcpy(buf, domain, blen);
            break;
         }
         
         domain--;
      } else if (dot == 3) {
         domain++;
         memcpy(buf, domain, blen);
         break;  
      }
   }
   
   j = strlen(buf);
   if (j == 0) {
      memcpy(buf, dom, len);
      j = len;
   }
   
   to_lower(buf);
   mirror(buf);
   
   FREE(dom);
   return j;
}
