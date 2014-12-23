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
#include <ctype.h>
#include <stdlib.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "../defined.h"
#include "sialan_ctl.h"
#include <math.h>


static void delete_fifo(const char *dom)
{
   int f;
   
   f = open(FIFO_RM_PATH, O_WRONLY);
   write(f, dom, strlen(dom));
   close(f);
}

static void print_ip_menu(WINDOW *win, const int y, const int x)
{
   mvaddstr(y - 2, 0,"Message: Esc:close 3:delete 4:enable 5:disable)");
   refresh();
}

static void print_domain_menu(WINDOW *win, const int y, const int x,
   const uint32_t num_tmp, const uint32_t num_row)
{
   char b1[32];
   
   wattron(win, COLOR_PAIR(4));
   wattrset(win, COLOR_PAIR(4));
   wrefresh(win);
   
   snprintf(b1, sizeof(b1), "Page: %d / %d", num_tmp +1, num_row +1);
   mvaddstr(y - 3, 0, b1);
   mvaddstr(y - 2, 0,"Message: (1:previous 2:next "
                  "Esc:close 3:delete 4:enable 5:disable "
                  "6:match 7:whole)");
   refresh();
}

static char* get_user_input(WINDOW *win, char *buf,
   const int y, const int x)
{
   int c;
   
   while (1) {
      wclear(win);
      mvaddstr(y /2, (x / 2) -10, "1. Search");
      mvaddstr((y/2) +1, (x / 2) -10, "ESC. Exit");
      refresh();
      cbreak();
      noecho();
      
      c = wgetch(win);
      if (c == 27)
         return NULL;
      else if (c != '1')
         continue;
                  
      nocbreak();
      echo();
      wclear(win);
      
      mvaddstr(y - 3, 0, "Domain/IP: ");
      refresh();
               
      if (wgetnstr(win, buf, 255) == ERR)
         return NULL;
       
      if (buf[0] == '\0')
         continue;
                
      break;
   }

   return buf;
}

static uint8_t print_result(WINDOW *win, const uint16_t page,
   struct domain_list *dom_list)
{
   uint16_t i;
   char buf[300];
   uint8_t f = 0, c = 0, len = 0;
   
   memset(buf, '\0', sizeof(buf));
   
   wclear(win);
   for (i = (page *20); i < (20 * (page +1)); i++) {
      if (i >= BUFFER_SORTING_SIZE)
         break;
      
      if (!(*(dom_list + i)).domain)
         continue;
      
      snprintf(buf, sizeof(buf), "%d. %s   ", c +1, (*(dom_list + i)).domain);
      len = strlen(buf);
      
      if ((*(dom_list + i)).flag & DB_MATCH)
         memcpy(buf + len, "MATCH", 5);
      else if ((*(dom_list + i)).flag & DB_WHOLE_MATCH)
         memcpy(buf +len, "WHOLE", 5);
      else if ((*(dom_list + i)).flag == 0) {
         memcpy(buf +len, "DELETED", 7);
         f = 3;
      }
      
      if ((*(dom_list + i)).flag & DB_ENABLE)
         f = 1;
      else if ((*(dom_list + i)).flag & DB_DISABLE)
         f = 2;
            
      printf__(win, c, 0, buf, f, 0);
      c++;
   }
   
   return c;
}


void main_search(WINDOW *win, DB *ip_db, DB *domain_db)
{
   int y, x, i;
   char buf[257];
   DBT key, data;
   uint32_t ip;
   
   union {
      DOMAIN_LIST dom_list;
      IP_LIST ip_list;
   } u;
     
   getmaxyx(win, y, x);
   
   while (1) {
      memset(&key, 0, sizeof(key));
      memset(&data, 0, sizeof(data));
      memset(buf, '\0', sizeof(buf));
   
      if (!get_user_input(win, buf, y, x)) {
         wclear(win);
         return;
      }
      
      if (inet_pton(AF_INET, buf, &ip) > 0) { // ip
         key.data = &ip;
         key.size = sizeof(uint32_t);
         
         data.data = &u.ip_list;
         data.ulen = sizeof(IP_LIST);
         data.flags = DB_DBT_USERMEM;
                 
         i = ip_db->get(ip_db, NULL, &key, &data, 0);
         if (i == DB_NOTFOUND) {
            snprintf(buf, sizeof(buf), "IP Address: %s not found.", buf);
            printf__(win, y-2, 0, buf, 2, 1);
         } else {
            int16_t c;
            struct in_addr addr;
            memset(&addr, 0, sizeof(addr));
         
            addr.s_addr = ip;
            snprintf(buf, sizeof(buf), "1. %s", inet_ntoa(addr));
            if (u.ip_list.flag & DB_ENABLE)
               printf__(win, 1, 0, buf, 1, 0);
            else if (u.ip_list.flag & DB_DISABLE)
               printf__(win, 1, 0, buf, 2, 0);
               
            wattron(win, COLOR_PAIR(4));
            wattrset(win, COLOR_PAIR(4));
            wrefresh(win);
            
            print_ip_menu(win, y, x);
            
            cbreak();
            noecho();
            while (1) {
               i = getch();
               if (i == 27)
                  break;
               else if ((i < '3') || (i > '5'))
                  continue;
                  
               if (i == '3') { //delete
                  key.data = &ip;
                  key.size = sizeof(uint32_t);
                  
                  ip_db->del(ip_db, NULL, &key, 0);
                  
                  sprintf(buf, "1. %s DELETED", inet_ntoa(addr));
                  printf__(win, 1, 0, buf, 3, 0);
               } else if ((i == '4') || (i == '5')) { // enable /disable
                  key.data = &ip;
                  key.size = sizeof(uint32_t);
               
                  data.data = &u.ip_list;
                  data.ulen = sizeof(IP_LIST);
                  data.flags = DB_DBT_USERMEM;
               
                  c = ip_db->get(ip_db, NULL, &key, &data, 0);
                  if (c == 0) {
                     memset(&data, 0, sizeof(DBT));
                     sprintf(buf, "1. %s", inet_ntoa(addr));
                     
                     if (i == '4') {
                        u.ip_list.flag &= ~DB_DISABLE;
                        u.ip_list.flag |= DB_ENABLE;
                        
                        printf__(win, 1, 0, buf, 1, 0);
                     } else if (i == '5') {
                        u.ip_list.flag &= ~DB_ENABLE;
                        u.ip_list.flag |= DB_DISABLE;
                        
                        printf__(win, 1, 0, buf, 2, 0);
                     }

                     data.data = &u.ip_list;
                     data.size = sizeof(IP_LIST);
                  
                     ip_db->put(ip_db, NULL, &key, &data, DB_OVERWRITE_DUP);
                  }
               }
               
               sprintf(buf, "%s", inet_ntoa(addr));
               delete_fifo(buf);
               
               wattron(win, COLOR_PAIR(4));
               wattrset(win, COLOR_PAIR(4));
               wrefresh(win);
            }
     
            nocbreak();
            echo();
         }
      } else { // domain
         struct domain_list *dom_list = NULL;
         char *dom = NULL;
         uint8_t len;
         int c, p, j = 0;
         DBC *cur = NULL;
         char *ptr = NULL;
         
         dom = strdup__(buf);
         if (!dom)
            return;
         if (!get_tld(dom, buf, sizeof(buf)))
            return;
         
         dom_list = je_calloc(sizeof(struct domain_list), BUFFER_SORTING_SIZE);
         if (!dom_list)
            return;
         
         len = strlen(dom);
         mirror(dom);
                 
         p = 0;
         
         key.data = buf;
         key.size = strlen(buf) +1;
         data.data = &u.dom_list;
         data.ulen = sizeof(DOMAIN_LIST);
         data.flags = DB_DBT_USERMEM;
         
         domain_db->cursor(domain_db, NULL, &cur, 0);
         
         i = cur->get(cur, &key, &data, DB_SET_RANGE);
         while (i != DB_NOTFOUND) {
            if (p >= BUFFER_SORTING_SIZE)
               break;
               
            i = strlen((char*) key.data);
            if (i > len)
               break;
            
            if (!memcmp(key.data, dom, i)) {
               (*(dom_list + p)).domain = strdup__((char*) key.data);
               if ((*(dom_list + p)).domain) {
                  (*(dom_list + p)).flag = u.dom_list.flag;
                  mirror((*(dom_list + p)).domain);
               
                  p++;
               }
            }
            
            if (!memcmp(key.data, dom, len))
               break;
            
            i = cur->get(cur, &key, &data, DB_NEXT);
         }
         
         cur->close(cur);

         i = ceil(p / 20.0); // 20 baris
         len = p; //save num result
         p = 0;
         
         while (1) {
            if (i == 0)
               break;
            
            wclear(win);
            cbreak();
            noecho();
            
            ip = print_result(win, p, dom_list);
            print_domain_menu(win, y, x, p, i -1);
            
            c = getch();
            if (c == 27)
               break;
            if ((c < '1') || (c > '7'))
               continue;
               
            if ((c >= '3') && (c <= '7')) {
               nocbreak();
               echo();
               
               mvaddstr(y - 1, 0, "Number: ");
               wrefresh(win);
               
               wgetnstr(win, buf, 5);
               
               j = strtol(buf, &ptr, 10);
               if ((j > ip) || (j == 0)) { // cek no. row
                  printf__(win, y -1, 0, "Out of range/unknown number.", 2, 1);
                  continue;
               }
               
               cbreak();
               noecho();
            }
            
            ip = (p * 20) + (j -1); // lokasi buffer array yang diinput
            char *t = strdup__((*(dom_list + ip)).domain);
            char *dom_buffer = strdup__(mirror(t));
            FREE(t);
            
            if ((c == '1') && (i > 1)) { // prev
               if (p > (i -1))
                  p = i;
               if (p > 0)
                  p--;
            } else if ((c == '2') && (i > 1)) { //next
               if (p < 0)
                  p = 0;
               if (p < (i -1))
                  p++;
            } else if (c == '3') { //delete
               key.data = dom_buffer;
               key.size = strlen(dom_buffer) +1;
               
               data.data = &u.dom_list;
               data.ulen = sizeof(DOMAIN_LIST);
               data.flags = DB_DBT_USERMEM;
               
               // cek ip
               c = domain_db->get(domain_db, NULL, &key, &data, 0);
               if (c != DB_NOTFOUND) {
                  uint16_t cur_count = 0;
                  uint32_t *cur_ip = NULL;
                  
                  cur_ip = je_calloc(sizeof(uint32_t), 32);
                  if (!cur_ip) {
                     printf__(win, y -1, 0, "Delete Error: calloc", 2, 1);
                     break;
                  }
                  
                  c = u.dom_list.id;
                  
                  memset(&key, 0, sizeof(DBT));
                  memset(&data, 0, sizeof(DBT));
                  // copy ip cursor
                  data.data = &u.ip_list;
                  data.ulen = sizeof(IP_LIST);
                  data.flags = DB_DBT_USERMEM;
                  
                  ip_db->cursor(ip_db, NULL, &cur, 0);
                  while (cur->get(cur, &key, &data, DB_NEXT) == 0) {
                     if (u.ip_list.id == c) {
                        memcpy((cur_ip + cur_count), key.data, sizeof(uint32_t));
                        cur_count++;
                        
                        if (cur_count == 32)
                           break;
                     }
                  }
                  cur->close(cur);
                  // delete ip
                  for (c = 0; c < cur_count; c++) {
                     memset(&key, 0, sizeof(DBT));
                     
                     key.data = (cur + c);
                     key.size = sizeof(uint32_t);
                     ip_db->del(ip_db, NULL, &key, 0);
                  }
                  FREE(cur_ip);
                  
                  // delete domain
                  memset(&key, 0, sizeof(DBT));
                  
                  key.data = dom_buffer;
                  key.size = strlen(dom_buffer) +1;
                  domain_db->del(domain_db, NULL, &key, 0);
                  
                  delete_fifo(dom_buffer);
                  (*(dom_list + ip)).flag = 0;
               }
            } else if ((c == '4') || (c == '5') || (c == '6') || (c == '7')) {
               // enable / disable / match / whole
               key.data = dom_buffer;
               key.size = strlen(dom_buffer) +1;
               
               data.data = &u.dom_list;
               data.ulen = sizeof(DOMAIN_LIST);
               data.flags = DB_DBT_USERMEM;
               
               j = domain_db->get(domain_db, NULL, &key, &data, 0);
               if (j == 0) {
                  memset(&data, 0, sizeof(DBT));
                  
                  if (c == '4') {
                     u.dom_list.flag &= ~DB_DISABLE;
                     u.dom_list.flag |= DB_ENABLE;
                  } else if (c == '5') {
                     u.dom_list.flag &= ~DB_ENABLE;
                     u.dom_list.flag |= DB_DISABLE;
                  } else if (c == '6') {
                     u.dom_list.flag &= ~DB_WHOLE_MATCH;
                     u.dom_list.flag |= DB_MATCH;
                  } else if (c == '7') {
                     u.dom_list.flag &= ~DB_MATCH;
                     u.dom_list.flag |= DB_WHOLE_MATCH;
                  }

                  data.data = &u.dom_list;
                  data.size = sizeof(DOMAIN_LIST);
                  
                  domain_db->put(domain_db, NULL, &key, &data, DB_OVERWRITE_DUP);
                  delete_fifo(dom_buffer);
                  (*(dom_list + ip)).flag = u.dom_list.flag;
               }
            }
            
            FREE(dom_buffer);
         }
                  
         nocbreak();
         echo();
         
         for (i = 0; i < len; i++)
            FREE((*(dom_list +i)).domain);
         FREE(dom_list);
         FREE(dom);
      }
   }
 
   wclear(win);
}
