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
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <net/if.h>

#include "sialan.h"
#include "defined.h"


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

u_int32_t pidof(const char *name)
{
   DIR *dir_fd = NULL;
   struct dirent *dir;
   FILE *fd = NULL;
   u_int32_t pid = 0;
   char buf[32];
   
   dir_fd = opendir("/proc");
   
   while ((dir = readdir(dir_fd))) {
      snprintf(buf, 32, "/proc/%s/status", dir->d_name);

      fd = fopen(buf, "r");
      if (!fd)
         continue;
         
      fgets(buf, 32, fd);
      fclose(fd);
      
      buf[strlen(buf) -1] = '\0'; // hapus karakter '\n' diakhir
      
      if (!strcmp(buf +6, name)) {
         pid = atoi(dir->d_name);
         break;
      }
   }
   
   closedir(dir_fd);

   return pid;
}

void ch_server(const u_int8_t f, char *buf, u_int32_t *ret)
{
   DB *db = NULL;
   DBT key, data;
   DB_ENV *dbenv = NULL;
   int r = 0;
   char val[257];
     
   if ((r = db_env_create(&dbenv, 0)) != 0) {
      fprintf(stderr, "db_input: %s\n", db_strerror(r));
      goto exit_1;
   }
   
   if (dbenv->open(dbenv, DB_ENVIRONMENT,
         DB_CREATE | DB_INIT_CDB | DB_INIT_MPOOL | DB_THREAD, 0) != 0) {
      fprintf(stderr, "environment open: %s\n", DB_ENVIRONMENT);
      goto exit_1;
   }
   
   if (db_create(&db, dbenv, 0) != 0) {
      fprintf(stderr, "database create %s\n", CONFIG_DB_NAME);
      goto exit_1;
   }
   if (db->open(db, NULL, CONFIG_DB_NAME, NULL, DB_BTREE,
            DB_CREATE | DB_THREAD, 0644) != 0) {
      fprintf(stderr, "DB->open: %s\n", CONFIG_DB_NAME);
      goto exit_1;
   }
   
   memset(&key, 0, sizeof(DBT));
   memset(&data, 0, sizeof(DBT));
   
   /* 0 -> dns_target_ip
      1 -> nameserver
      2 -> http_server
      3 -> input device
   */
   u_int8_t k = f;
   key.data = &k;
   key.size = sizeof(u_int8_t);
   
   data.data = val;
   data.ulen = sizeof(val);
   data.flags = DB_DBT_USERMEM;
   
   r = db->get(db, NULL, &key, &data, 0);
   if (r != DB_NOTFOUND) {
      switch (f) {
         case 0: 
         case 1: memcpy(ret, val, sizeof(u_int32_t));
            break;
         case 2: *ret = strlen(val);
                 memcpy(buf, val, *ret);
            break;
         case 3: 
                  {
                     k = 0;
                     
                     for (r = 0; r < 3; r++) {
                        memcpy(buf, val + k, IFNAMSIZ);
                        
                        if (strcmp(buf, "0")) // jika != "0"
                           ret[r] = if_nametoindex(buf);
                        else
                           ret[r] = 0;
                           
                        k += IFNAMSIZ;
                     }
                   }
            break;
      }
   }
   
   exit_1:
   if (db)
      db->close(db, 0);
   if (dbenv)
      dbenv->close(dbenv, 0);
}

u_int8_t is_sialan_fw_up(void)
{
   FILE *fd = NULL;
   int f = 0;
   
   fd = fopen(LOCK_PATH, "r");
   if (fd) { // sudah berjalan
      fclose(fd);
      return 1;
   }
   
   // create ipc named fifo
   if (mkfifo(FIFO_PATH, 0600) < 0) {
      fprintf(stderr, "Error create fifo.\n");
      return 1;
   }
   
   if (mkfifo(FIFO_RM_PATH, 0600) < 0) {
      fprintf(stderr, "Error create rm_fifo.\n");
      return 1;
   }
   
   f = creat(LOCK_PATH, S_IRWXU);
   close(f);
   
   return 0;
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

/*
u_int8_t is_database_ok(void)
{
   leveldb_options_t *opt = NULL;
   leveldb_env_t *env = NULL;
   leveldb_cache_t *cache = NULL;
   char *err = NULL;
   u_int8_t i = 0;
   
   env = leveldb_create_default_env();
   cache = leveldb_cache_create_lru(3 * 1048576);
   
   opt = leveldb_options_create();
   leveldb_options_set_create_if_missing(opt, 0);
   leveldb_options_set_write_buffer_size(opt, 10000);
   leveldb_options_set_max_open_files(opt, 10);
   leveldb_options_set_block_size(opt, 1024);
   leveldb_options_set_info_log(opt, NULL);
   leveldb_options_set_paranoid_checks(opt, 1);
   leveldb_options_set_block_restart_interval(opt, 8);
   leveldb_options_set_compression(opt, leveldb_no_compression);
   leveldb_options_set_env(opt, env);
   leveldb_options_set_cache(opt, cache);
   
   leveldb_repair_db(opt, IP_DB_PATH, &err);
   if (err) {
      fprintf(stderr, "Database ip_list corupt.\n");
      i = 1;
   }
   
   leveldb_repair_db(opt, DOMAIN_DB_PATH, &err);
   if (err) {
      fprintf(stderr, "Database domain_list corupt.\n");
      i = 1;
   }
   
   leveldb_options_destroy(opt);
   leveldb_cache_destroy(cache);
   leveldb_env_destroy(env);
   
   return i;
}

void get_count(const char* sql, int *ret)
{
   sqlite3 *db = NULL;
   int r;
   sqlite3_stmt *stmt = NULL;
      
   r = sqlite3_open_v2(DB_PATH, &db,
         SQLITE_OPEN_NOMUTEX | SQLITE_OPEN_READONLY, NULL);
   if (r != SQLITE_OK) {
      *ret = -1;
      return;
   }
   
   sqlite3_exec(db, "PRAGMA journal_mode = WAL", NULL, NULL, NULL);
   sqlite3_exec(db, "PRAGMA synchronous = NORMAL", NULL, NULL, NULL);
   sqlite3_busy_timeout(db, 5000);
   sqlite3_exec(db, "PRAGMA temp_store = MEMORY", NULL, NULL, NULL);
   sqlite3_exec(db, "PRAGMA foreign_keys = ON", NULL, NULL, NULL);
   
   r = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
   if (r == SQLITE_OK) {
      r = sqlite3_step(stmt);
      
      if ((r == SQLITE_ROW) || (r == SQLITE_DONE))
         *ret = sqlite3_column_int(stmt, 0);
      else
         *ret = -1;   
   } else
      *ret = -1;
   
   sqlite3_reset(stmt);
   sqlite3_finalize(stmt);
   sqlite3_close(db);
}
*/
