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
#include <arpa/inet.h>
#include <sys/stat.h>

#include "../defined.h"
#include "sialan_ctl.h"


void main_add(WINDOW *win, DB *ip_db, DB *domain_db)
{
   int y, x, i;
   uint32_t ip, idnum;
   uint8_t type = 0, c;
   char buf[256];
   DBT key, data;
   
   union {
      DOMAIN_LIST dom_list;
      IP_LIST ip_list;
   } u;
   
   memset(buf, 0, sizeof(buf));
   
   getmaxyx(win, y, x);
   // get num_id
   key.data = ID_NUM;
   key.size = 2;
   data.data = &idnum;
   data.ulen = sizeof(uint32_t);
   data.flags = DB_DBT_USERMEM;
         
   i = domain_db->get(domain_db, NULL, &key, &data, 0);
   if (i != 0)
      idnum = 0;
   else
      idnum++;
   
   while (1) {
      wclear(win);
      memset(&key, 0, sizeof(DBT));
      memset(&data, 0, sizeof(DBT));
      
      mvaddstr(y -3, 0, "Message: (ESC:exit 1:porn 2:malware)");
      refresh();
      
      cbreak();
      noecho();
      c = getch();
      if (c == ESC) {
         wclear(win);
         break;
      } else if ((c < '1') || (c > '2'))
         continue;
         
      if (c == '1')
         type = PORN;
      else if (c == '2')
         type = MALWARE;
      
      wclear(win);
      nocbreak();
      echo();
      mvaddstr(y -3, 0, "Domain / IP: ");
      if (wgetnstr(win, buf, 255) == ERR)
         continue;
      if (buf[0] == '\0')
         continue;
         
      if (inet_pton(AF_INET, buf, &ip) > 0) { // ip
         memset(&u.ip_list, 0, sizeof(IP_LIST));
         
         u.ip_list.id = 0;
         u.ip_list.ancount = 0;
         u.ip_list.flag = DB_ENABLE;
         u.ip_list.type = type;
         
         key.data = &ip;
         key.size = sizeof(uint32_t);
         data.data = &u.ip_list;
         data.size = sizeof(IP_LIST);
         
         i = ip_db->put(ip_db, NULL, &key, &data, DB_NOOVERWRITE);
         c = 0;
      } else { // domain
         memset(&u.dom_list, 0, sizeof(DOMAIN_LIST));
         
         mirror(buf);
               
         u.dom_list.id = idnum;
         u.dom_list.ttl = time(NULL);
         u.dom_list.flag = (DB_ENABLE | DB_WHOLE_MATCH);
         u.dom_list.type = type;
         
         key.data = buf;
         key.size = strlen(buf) +1;
         data.data = &u.dom_list;
         data.size = sizeof(DOMAIN_LIST);
         
         i = domain_db->put(domain_db, NULL, &key, &data, DB_NOOVERWRITE);
         c = 1;
         idnum++;
      }
      
      if (i == DB_KEYEXIST)
         printf__(win, y -2, 0, "Domain/IP: already exists", 2, 1);
      else {
         if (c) {
            memset(&key, 0, sizeof(DBT));
            memset(&data, 0, sizeof(DBT));
            
            key.data = ID_NUM;
            key.size = 2;
            data.data = idnum;
            data.size = sizeof(uint32_t);
            
            domain_db->put(domain_db, NULL, &key, &data, DB_OVERWRITE_DUP);
         }
         
         printf__(win, y -2, 0, "Domain/IP: added", 1, 1);
      }
   }
}
