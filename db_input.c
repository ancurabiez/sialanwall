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
#include <time.h>
#include <inttypes.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/stat.h>

#include <db.h>

#include "db_input.h"
#include "sialan.h"
#include "helper.h"
#include "defined.h"


void usage(void)
{
   fprintf(stderr, "db_input [type] [file]\n");
   fprintf(stderr, "type: 10 malware\n");
   fprintf(stderr, "      11 porn\n");
}

void config_db(DB_ENV *env)
{
   DB *db;
   DBT key, data;
   u_int8_t i;
   char buf[64];
   
   if (db_create(&db, env, 0) != 0) {
      fprintf(stderr, "database create %s\n", CONFIG_DB_NAME);
      goto exit_1;
   }
   if (db->open(db, NULL, CONFIG_DB_NAME, NULL, DB_BTREE,
            DB_CREATE | DB_EXCL, 0644) != 0) {
      fprintf(stderr, "Failed DB->open: %s\n", CONFIG_DB_NAME);
      goto exit_1;
   }
   
   u_int32_t addr;
   
   for (i = 0; i < 4; i++) {
      memset(&key, 0, sizeof(DBT));
      memset(&data, 0, sizeof(DBT));
      memset(buf, '\0', sizeof(buf));
      
      key.data = &i;
      key.size = sizeof(u_int8_t);
      
      switch (i) {
         case 0: inet_pton(AF_INET, "192.168.10.254", &addr);
                 memcpy(buf, &addr, sizeof(u_int32_t));
            break;
         case 1: inet_pton(AF_INET, "8.8.8.8", &addr);
                 memcpy(buf, &addr, sizeof(u_int32_t));
            break;
         case 2: memcpy(buf, "yahoo.com", sizeof(buf));
            break;
         case 3: memcpy(buf, "eth1", 4);
                 memset(buf + IFNAMSIZ, '0', sizeof(buf) - (IFNAMSIZ + 3));
            break;
      }
      
      data.data = buf;
      data.size = strlen(buf) +1;
      
      db->put(db, NULL, &key, &data, DB_NOOVERWRITE);
   }
    
   exit_1:
   if (db)
      db->close(db, 0);
}

static void insert_db(const char *file, const uint8_t type)
{
   DB *db = NULL;
   DBT key, data;
   DB_ENV *env;
   union {
      IP_LIST ip_list;
      DOMAIN_LIST dom_list;
   } u;
   u_int32_t i, j;
   char buf[350];
   FILE *fd = NULL;
   
   memset(buf, '\0', sizeof(buf));
   
   fd = fopen(file, "r");
   
   if ((i = db_env_create(&env, 0)) != 0) {
        fprintf(stderr, "db_input: %s\n", db_strerror(i));
        return;
   }
    
   if ((i = env->open(env, DB_ENVIRONMENT,
              DB_CREATE | DB_INIT_CDB | DB_INIT_MPOOL | DB_THREAD, 0)) != 0) {
       fprintf(stderr, "environment open: %s\n", DB_ENVIRONMENT);
       goto err;
   }
    
   if ((i = db_create(&db, env, 0)) != 0) {
       fprintf(stderr, "database create\n");
       goto err;
   }
    
   if (!strcmp(file, "ip_list"))
     strncpy(buf, IP_DB_NAME, 32);
   else
     strncpy(buf, DOMAIN_DB_NAME, 32);
    
   if ((i = db->open(db, NULL, buf, NULL, DB_BTREE,
              DB_CREATE | DB_THREAD, 0644)) != 0) {
       fprintf(stderr, "DB->open: %s\n", buf);
       goto err;
   }
   
   uint32_t idnum = 0;
   //get idnum
   memset(&key, 0, sizeof(DBT));
   memset(&data, 0, sizeof(DBT));
   
   if (!strcmp(file, "dom_list")) {
      key.data = ID_NUM;
      key.size = 2;
      data.data = &idnum;
      data.ulen = sizeof(uint32_t);
      data.flags = DB_DBT_USERMEM;
            
      i = db->get(db, NULL, &key, &data, 0);
      if (i != 0)
         idnum = 0;
      else
         idnum++;
   }
      
   while (fgets(buf, 350, fd)) {
      j = strlen(buf);
      memset(buf +(j-1), '\0', 1);
      
      if (!strcmp(file, "ip_list")) {
         memset(&u.ip_list, 0, sizeof(IP_LIST));
         
         u.ip_list.id = 0;
         u.ip_list.type = type;
         u.ip_list.flag = DB_ENABLE | DB_WHOLE_MATCH;
      } else {
         memset(&u.dom_list, 0, sizeof(DOMAIN_LIST));
         idnum++;
         
         u.dom_list.id = idnum;
         u.dom_list.ttl = time(NULL);
         u.dom_list.type = type;
         u.dom_list.flag = DB_ENABLE | DB_WHOLE_MATCH;
      }
            
      memset(&key, 0, sizeof(DBT));
      memset(&data, 0, sizeof(DBT));
           
      if (!strcmp(file, "ip_list")) {
         u_int32_t addr;
         if (inet_pton(AF_INET, buf, &addr)) {
            key.data = &addr;
            key.size = sizeof(uint32_t);
         
            data.data = &u.ip_list;
            data.size = sizeof(IP_LIST);
         }
      } else {
         mirror(buf);
         
         key.data = buf;
         key.size = j;
      
         data.data = &u.dom_list;
         data.size = sizeof(DOMAIN_LIST);
      }
         
      j = db->put(db, NULL, &key, &data, DB_NOOVERWRITE);
      if (j == DB_KEYEXIST)
         fprintf(stderr, "Put failed because key %s already exists\n", buf);
   }
   
   fclose(fd);
   // save ID_NUM
   if (!strcmp(file, "dom_list")) {
      memset(&key, 0, sizeof(DBT));
      memset(&data, 0, sizeof(DBT));
      
      key.data = ID_NUM;
      key.size = 2;
      data.data = &idnum;
      data.size = sizeof(uint32_t);
      
      // cek jika blom ada maka put, kalau sudah ada maka overwrite
      j = db->put(db, NULL, &key, &data, DB_OVERWRITE_DUP);
   }
   
   config_db(env);
   
   err:
   if (db)
      db->close(db, 0);
   if (env)
      env->close(env, 0);
      
   printf("Done.\n");
}

int main(int argc, char **argv)
{
   if (argc != 3) {
      usage();
      return 0;
   }
   
   // create db environment if not exits
   mkdir(DB_ENVIRONMENT,  S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
   
   u_int8_t type = 0;
   if (strcmp(argv[1], "10") && strcmp(argv[1], "11")) {
      usage();
      return 0;
   } else
      type = atoi(argv[1]);
   
   fprintf(stderr, "Checking for domains and ip addresses\n");
   if (!ip_dom(argv[2])) {
      fprintf(stderr, "File not found.\n");
      return 1;
   }
   
   fprintf(stderr, "Insert domains to database...\n");
   insert_db("dom_list", type);
   fprintf(stderr, "Insert ip addresses to database...\n");
   insert_db("ip_list", type);
   
   return 0;
}
