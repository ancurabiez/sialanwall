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
#include <unistd.h>
#include <stdlib.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <net/if.h>
#include <fcntl.h>

#include "sialan_ctl.h"
#include "../defined.h"
#include "generic_domain.h"


static void main_enable_disable(WINDOW *win)
{
   int h, f, fd;
   
   while (1) {
      wclear(win);
      
      fd = open(ENDIS_LOCK_PATH, O_RDONLY);
      if (fd != -1)
         mvaddstr(5, 5, "Sialan Firewall Disabled");
      else
         mvaddstr(5, 5, "Sialan Firewall Enabled");
      
      getmaxyx(win, h, f);
      mvaddstr(h -3, 0, "Message: (ESC:Exit 1:enable/disable)");
      
      refresh();
      cbreak();
      noecho();
      
      h = getch();
      if (h == ESC) {
         wclear(win);
         break;
      } else if (h != '1')
         continue;
  
      if (fd != -1) {
         remove(ENDIS_LOCK_PATH);
         close(fd);
      } else {
         fd = creat(ENDIS_LOCK_PATH, S_IRWXU);
         close(fd);
      }
      
      h = DISABLE;
      
      f = open(FIFO_PATH, O_WRONLY);
      write(f, &h, sizeof(int));
      close(f);
   }           
}

static void main_change(WINDOW *win, DB *config_db, const uint8_t flag)
{
   int x, y;
   uint32_t i;
   DBT key, data;
   char buf[257];
   char b1[17];
   uint8_t f = flag, j;
     
   getmaxyx(win, y, x); // get maximum window coordinate
   
   while (1) {
      wclear(win);
      memset(&key, 0, sizeof(DBT));
      memset(&data, 0, sizeof(DBT));
      memset(buf, '\0', sizeof(buf));
      
      /* 0 -> dns_target_ip
      1 -> nameserver
      2 -> http_server
      3 -> input device
   */
      key.data = &f;
      key.size = sizeof(uint8_t);
      
      data.data = buf;
      data.ulen = sizeof(buf);
      data.flags = DB_DBT_USERMEM;
      
      config_db->get(config_db, NULL, &key, &data, 0);
      if ((f == 0) || (f == 1)) {
         struct in_addr addr;
         
         memcpy(&i, buf, sizeof(uint32_t));
         addr.s_addr = i;
         
         snprintf(buf, sizeof(buf), "%s", inet_ntoa(addr));
      } else if (f == 3) {
         i = 0;
         
         mvaddstr(4, 5, "Device 1: ");
         mvaddstr(5, 5, "Device 2: ");
         mvaddstr(6, 5, "Device 3: ");
                              
         for (j = 0; j < 3; j++) {
            memcpy(b1, buf + i, IFNAMSIZ);
                        
            mvaddstr(4 +j, 15, b1);
            i += IFNAMSIZ;
         }
         
         refresh();
      }
      
      if (f != 3) {
         mvaddstr(3, 5, buf);
         refresh();
      }
      
      cbreak();
      noecho();
      
      if (f != 3)
         mvaddstr(y -3, 0, "Message: (ESC:exit 1:change)");
      else
         mvaddstr(y -3, 0, "Message: (ESC:exit 1:device_1 2:device_2 3:device_3)");
      refresh();
      
      i = getch();
      if (i == ESC) {
         wclear(win);
         break;
      }
      if (f != 3) {
         if (i != '1')
            continue;
      } else if (f == 3) {
         if ((i < '1') || (i > '3'))
            continue;
      }
      
      nocbreak();
      echo();
      
      memset(&key, 0, sizeof(DBT));
      memset(&data, 0, sizeof(DBT));
      
      switch (f) {
         case 0: mvaddstr(y -2, 0, "DNS Target IP: ");
            break;
         case 1: mvaddstr(y -2, 0, "Name Server IP: ");
            break;
         case 2: mvaddstr(y -2, 0, "Http Server: ");
            break;
         case 3: mvaddstr(y -2, 0, "Input Device: ");
            break;
      }
      refresh();
      
      if (wgetnstr(win, buf, 255) == ERR)
         continue;
      if (buf[0] == '\0')
         break;
      
      key.data = &f;
      key.size = sizeof(uint8_t);
      
      if ((f == 0) || (f == 1)) { 
         if (inet_pton(AF_INET, buf, &i) > 0) {
            data.data = &i;
            data.size = sizeof(uint32_t);            
         } else
            printf__(win, y -1, 0, "Must IP Address", 2, 1);
      } else if (f == 2) {
         data.data = buf;
         data.size = strlen(buf) +1;
      } else if (f == 3) {
         int ifindex;
         char *dev = NULL;
         
         dev = strdup__(buf);
         ifindex = if_nametoindex(dev);
         
         if (ifindex == 0) {
            printf__(win, y-1, 0, "Device failed", 2, 1);
            continue;
         }
         
         data.data = buf;
         data.ulen = sizeof(buf);
         data.flags = DB_DBT_USERMEM;
         
         config_db->get(config_db, NULL, &key, &data, 0);
         
         switch (i) {
            case '1':   memset(buf, 0, IFNAMSIZ);
                        memcpy(buf, dev, IFNAMSIZ);
               break;
            case '2':   memset(buf + IFNAMSIZ, 0, IFNAMSIZ);
                        memcpy(buf + IFNAMSIZ, dev, IFNAMSIZ);
               break;
            case '3':   memset(buf + (IFNAMSIZ *2), 0, IFNAMSIZ);
                        memcpy(buf + (IFNAMSIZ *2), dev, IFNAMSIZ);
               break;
         }
         
         FREE(dev);
         
         memset(&data, 0, sizeof(DBT));
         data.data = buf;
         data.size = sizeof(buf);
      }
      
      config_db->put(config_db, NULL, &key, &data, DB_OVERWRITE_DUP);
      sleep(1);
              
      switch (f) {
         case 0: j = DNS_ADDR;
            break;
         case 1: j = NAMESERVER;
            break;
         case 2: j = HTTP_SERVER;
            break;
         case 3: j = INDEV;
            break;
      }
      
      if (f != 1)
         strcpy(buf, FIFO_PATH);
      else
         strcpy(buf, LOOKUP_FIFO);
         
      x = open(buf, O_WRONLY);
      write(x, &j, sizeof(int));
      close(x);
   }
}

static int main_window(WINDOW *win)
{
   int x, y;
   int c;
   
   getmaxyx(win, y, x); // get maximum window coordinate
   cbreak();
   noecho();

   mvaddstr(5, (x / 2) - 10, "1. Search Domain");
   mvaddstr(6, (x / 2) - 10, "2. Add Domain");
   mvaddstr(7, (x / 2) - 10, "3. Change Nameserver");
   mvaddstr(8, (x / 2) - 10, "4. Firewall Enable/Disable");
   mvaddstr(9, (x / 2) - 10, "5. Change Input Device");
   mvaddstr(10, (x / 2) - 10, "6. Change DNS Target Server");
   mvaddstr(11, (x / 2) - 10, "7. Change Http Target Server");
   mvaddstr(12, (x / 2) - 10, "8. Quit");
   refresh();
   
   while ((c = getch()) != '8') {
      if ((c < 49) || (c > 57))
         continue;
      else
         break;
   }
 
   nocbreak();
   echo();
   wclear(win);
   
   return c;
}


int main(void)
{
   if (getuid() != 0) {
      fprintf(stderr, "Permission denied (you must be root)\n");
      return 0;
   }

   int c;
   
   c = open(LOCK_PATH, O_RDONLY);
   if (c < 0) {
      fprintf(stderr, "Sialan Firewall Belum Berjalan\n");
      exit(1);
   }
   close(c);
   
   DB *ip_db = NULL;
   DB *domain_db = NULL;
   DB *config_db = NULL;
   DB_ENV *dbenv = NULL;
   WINDOW *win = NULL;
   
   win = initscr();
   if (!win) {
      fprintf(stderr, "Error initialising ncurses.\n");
      exit(0);
   }
   
   start_color();
   generic_init();

   init_pair(1, COLOR_GREEN, COLOR_WHITE );
   init_pair(2, COLOR_RED, COLOR_WHITE );
   init_pair(3, COLOR_BLUE, COLOR_WHITE );
   init_pair(4, COLOR_BLACK,  COLOR_WHITE );
   attron(COLOR_PAIR(4));
   bkgd(COLOR_PAIR(4));
      
   if ((c = db_env_create(&dbenv, 0)) != 0) {
      fprintf(stderr, "db_input: %s\n", db_strerror(c));
      return 1;
   }
    
   if ((c = dbenv->open(dbenv, DB_ENVIRONMENT,
               DB_CREATE | DB_INIT_CDB | DB_INIT_MPOOL | DB_THREAD, 0)) != 0) {
      fprintf(stderr, "environment open: %s\n", DB_ENVIRONMENT);
      goto err;
   }
   
   if ((c = db_create(&ip_db, dbenv, 0)) != 0) {
      fprintf(stderr, "database create ip\n");
      goto err;
   }
   
   if ((c = ip_db->open(ip_db, NULL, IP_DB_NAME, NULL, DB_BTREE,
               DB_CREATE | DB_THREAD, 0644)) != 0) {
      fprintf(stderr, "DB->open: %s\n", IP_DB_NAME);
      goto err;
   }
   
   if ((c = db_create(&domain_db, dbenv, 0)) != 0) {
      fprintf(stderr, "database create domain\n");
      goto err;
   }
   
   if ((c = domain_db->open(domain_db, NULL, DOMAIN_DB_NAME, NULL, DB_BTREE,
            DB_CREATE | DB_THREAD, 0644)) != 0) {
      fprintf(stderr, "DB->open: %s\n", DOMAIN_DB_NAME);
      goto err;
   }
   
   if ((c = db_create(&config_db, dbenv, 0)) != 0) {
      fprintf(stderr, "database create config\n");
      goto err;
   }
   
   if ((c = config_db->open(config_db, NULL, CONFIG_DB_NAME, NULL, DB_BTREE,
            DB_CREATE | DB_THREAD, 0644)) != 0) {
      fprintf(stderr, "DB->open: %s\n", CONFIG_DB_NAME);
      goto err;
   }
   
   // main loop
   while ((c = main_window(win)) != '8') {
      switch (c) {
         case '1': main_search(win, ip_db, domain_db);
            break;
         case '2': main_add(win, ip_db, domain_db);
            break;
         case '3': main_change(win, config_db, 1);
            break;
         case '4': main_enable_disable(win);
            break;
         case '5': main_change(win, config_db, 3);
            break;
         case '6': main_change(win, config_db, 0);
            break;
         case '7': main_change(win, config_db, 2);
            break;
      
      }
      
   }

   delwin(win);
   endwin();
   refresh();
   
   generic_flush();
   
   err:
   if (ip_db)
      ip_db->close(ip_db, 0);
   if (domain_db)
      domain_db->close(domain_db, 0);
   if (config_db)
      config_db->close(config_db, 0);
   if (dbenv)
      dbenv->close(dbenv, 0);

   return 0;   
}
