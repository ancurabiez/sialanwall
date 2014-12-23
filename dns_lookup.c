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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <math.h>
#include <syslog.h>
#include <signal.h>
#include <sys/stat.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#include "sialan.h"
#include "defined.h"

static uint32_t nameserver;
static int fd_fifo;
static int stop__ = 0;


static void sig_term(int sig)
{
   if (sig == SIGINT)
      stop__ = 1;
}

static void sleep_ms(const u_int16_t ms)
{
   struct timeval tv;
   
   tv.tv_sec = 0;
   tv.tv_usec = (1000 * ms);
   select(0, NULL, NULL, NULL, &tv);
}

static void check_fifo(void)
{
   uint8_t buf;
   
   if (read(fd_fifo, &buf, sizeof(uint8_t)) > 0) {
      if (buf == NAMESERVER)
         ch_server(1, NULL, &nameserver);
   }
}

static void send_packet(const int fd, u_int8_t *packet, const u_int16_t len,
   const u_int32_t addr)
{
   struct sockaddr_in send;
   memset(&send, 0, sizeof(struct sockaddr_in));

   send.sin_family = AF_INET;
   send.sin_port = htons(53);
   send.sin_addr.s_addr = addr;
   bzero(&(send.sin_zero), 8);

   sendto(fd, packet, len, 0, (struct sockaddr*) &send, sizeof(send));
}

static void create_question(const char *domain, const int sock,
   const uint32_t nameserver, uint8_t *buf)
{
	struct dns_header *dhead = NULL;
	u_int8_t len = 0, i;
   uint16_t j = 0;
	u_int32_t seed = 0;
	u_int8_t *ll = NULL;
	
	dhead = (struct dns_header*) buf;
	ll = (uint8_t*) buf + sizeof(struct dns_header);
	
	dhead->qid = htons(rand_r(&seed) %3);
	dhead->qr = 0; //query
	dhead->opcode = 0;
	dhead->rd = 0;
	dhead->ra = 0;
	dhead->qdcount = htons(1);

	i = strlen(domain);

   while (!stop__) {
      len = strcspn(domain, ".");

      *ll++ = len;
      j += len;

      memcpy(ll, domain, len);
      domain += (len +1);
      ll += len;

      if (!(*domain))
         break;
   }
   
   //i += 2;
   *ll++ = 0;
   *ll++ = 0;
   *ll++ = 1; // qtype A
   *ll++ = 0;
   *ll++ = 1; // qclass IN
   i += 5;

	send_packet(sock, buf, i + sizeof(struct dns_header), nameserver);
}

static void get_ip_from_answere(struct domain__ *dom__, const uint8_t *data__,
   int16_t len, DB *ip_db, DB *domain_db)
{
   const struct dns_header *dhead = (struct dns_header*) data__;
   // cek jika berisi answer atau tidak
   if (ntohs(dhead->ancount) == 0)
      return;
      
   if (dom__->disable)
      return;
   
   const uint8_t *ll = data__ + sizeof(struct dns_header);
	len -= sizeof(struct dns_header);
	uint16_t i = 0;
   uint8_t f = 0; // 1 jika ada insert/update
	const uint8_t ptr[4] = {0, 1, 0, 1};
   DBC *cur = NULL;
   DBT key, data;
   union {
      IP_LIST ip_list;
      DOMAIN_LIST dom_list;
   } u;
   uint32_t *ip_key = NULL;
   
   ip_key = je_calloc(sizeof(uint32_t), 32);
   if (!ip_key)
      return;
   
   memset(&data, 0, sizeof(DBT));
   memset(&key, 0, sizeof(DBT));
   
   ip_db->cursor(ip_db, NULL, &cur, 0);
   cur->set_priority(cur, DB_PRIORITY_LOW);
   
   data.data = &u.ip_list;
   data.ulen = sizeof(IP_LIST);
   data.flags = DB_DBT_USERMEM;
   
   while (!stop__) {
      if (cur->get(cur, &key, &data, DB_NEXT) == DB_NOTFOUND)
         break;
   
      if (u.ip_list.id == dom__->id) {
         memcpy(ip_key + i, key.data, sizeof(uint32_t));
         i++;
      }
   }
   if (cur)
      cur->close(cur);
      
   if (i > 0) {
      for (f = 0; f < i; f++) {
         memset(&key, 0, sizeof(DBT));
         
         key.data = (ip_key + f);
         key.size = sizeof(uint32_t);
         
         ip_db->del(ip_db, NULL, &key, 0);
      }
   }
   
   FREE(ip_key);
   
   f = strlen(dom__->domain);
   memset(dom__->domain + (f-1), '\0', 1); // buang kar '.'
   mirror(dom__->domain);
   i = 0;

   while (len > 0) {
      if (!memcmp(ll, ptr, 4)) { //cek qtype dan qclass saja
         if (!i) { // skip query
            ll++;
            i++;
            continue;
         }

         ll += 10; //ttl + data_len
         
         memset(&key, 0, sizeof(DBT));
         memset(&data, 0, sizeof(DBT));
         memset(&u.ip_list, 0, sizeof(IP_LIST));
         // insert ip_db
         uint32_t ip;

         ip = htonl(GET_32BIT(ll));
         key.data = &ip;
         key.size = sizeof(uint32_t);
         
         struct in_addr addr;
         addr.s_addr = ip;
         
         u.ip_list.id = dom__->id;
         u.ip_list.type = dom__->type;
         u.ip_list.flag = DB_ENABLE | DB_WHOLE_MATCH;
         
         data.data = &u.ip_list;
         data.size = sizeof(IP_LIST);
         
         f = ip_db->put(ip_db, NULL, &key, &data, DB_NOOVERWRITE);

         // update domain_db
         memset(&key, 0, sizeof(DBT));
         memset(&data, 0, sizeof(DBT));
         memset(&u.dom_list, 0, sizeof(DOMAIN_LIST));
         
         key.data = dom__->domain;
         key.size = strlen(dom__->domain) +1;
         
         u.dom_list.id = dom__->id;
         u.dom_list.ttl = time(NULL);
         u.dom_list.type = dom__->type;
         u.dom_list.flag = dom__->flag;
         
         data.data = &u.dom_list;
         data.size = sizeof(DOMAIN_LIST);
         
         f = domain_db->put(domain_db, NULL, &key, &data, DB_OVERWRITE_DUP);

         ll += 3;
      }

      ll++;
      len--;
   }
}

static u_int8_t send_question(struct domain__ *dom__,
   const uint32_t nameserver, DB *ip_db, DB *domain_db)
{
   int sock;
   struct sockaddr_in saddr_listen, saddr_from;
   struct timeval tv;
   fd_set udp_readfds;
   int16_t len = 0;
   u_int8_t buf[512];
   const int opt = 1;
   
   memset(buf, 0, sizeof(buf));

   if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
      return 0;

   if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void*) &opt, sizeof(opt)) < 0) {
      close(sock);
      return 0;
   }

   memset(&saddr_listen, 0, sizeof(saddr_listen));
   saddr_listen.sin_family = AF_INET;
   saddr_listen.sin_port = htons(0); //random port
   saddr_listen.sin_addr.s_addr = INADDR_ANY;
   bzero(&(saddr_listen.sin_zero), 8);

   if (bind(sock, (struct sockaddr *)&saddr_listen, sizeof(struct sockaddr_in)) < 0) {
      close(sock);
      return 0;
   }
   
   fcntl(sock, F_SETFL, O_NONBLOCK); // non blocking

   //creat question
   create_question(dom__->domain, sock, nameserver, buf);
   
   tv.tv_sec = 5; // 5 sec timeout
   tv.tv_usec = 0;
   
   FD_ZERO(&udp_readfds);
   FD_SET(sock, &udp_readfds);

   select(sock +1, &udp_readfds, NULL, NULL, &tv);

   if (FD_ISSET(sock, &udp_readfds)) { // ada respone dari dns server
      memset(&saddr_from, 0, sizeof(saddr_from));
      socklen_t salen = sizeof(saddr_from);

      len = recvfrom(sock, buf, sizeof(buf), 0,
                  (struct sockaddr*) &saddr_from, &salen);
      if (len < 512) // max udp size
         get_ip_from_answere(dom__, buf, len, ip_db, domain_db);
   }

   close(sock);
   return 1;
}

static void update(DB *ip_db, DB *domain_db, struct domain__ *dom__,
   const uint16_t count)
{
   uint16_t i;
   
   for (i = 0; i < count; i++) {
      if (!(*(dom__ + i)).disable) {
         check_fifo();
         send_question((dom__ + i), nameserver, ip_db, domain_db);
      }
      
      if (stop__)
         break;
   }
}

static void ttl_check(DB *ip_db, struct domain__ *dom__, const uint16_t count)
{
   uint16_t i, c = 0, k = 0;
   uint32_t t, *ip_id = NULL, *ip_key = NULL;
   DBC *cur = NULL;
   DBT key, data;
   IP_LIST ip_list;
   
   memset(&key, 0, sizeof(DBT));
   memset(&data, 0, sizeof(DBT));
   
   ip_id = je_calloc(sizeof(uint32_t), DOMAIN_SIZE);
   if (!ip_id)
      return;
      
   ip_key = je_calloc(sizeof(uint32_t), DOMAIN_SIZE);
   if (!ip_key) {
      FREE(ip_id);
      return;
   }
   
   // check apakah domain_ttl sudah kadaluarsa
   t = time(NULL);
   for (i = 0; i < count; i++) {
      if ((t - (*(dom__ + i)).ttl) >= DOMAIN_TTL) {
         memcpy(ip_id + c, &(*(dom__ + i)).id, sizeof(uint32_t)); // save domain id
         (*(dom__ + i)).disable = 1;
         c++;
         
         if (c == DOMAIN_SIZE)
            break;
      }
   }
   
   if (c > 0) { // jika ada domain ttl yang basi
      // cari ip key berdasarkan data id
      ip_db->cursor(ip_db, NULL, &cur, 0);
      cur->set_priority(cur, DB_PRIORITY_LOW);
      
      data.data = &ip_list;
      data.ulen = sizeof(IP_LIST);
      data.flags = DB_DBT_USERMEM;
      
      k = 0;
      while (!stop__) {
         if (cur->get(cur, &key, &data, DB_NEXT) == DB_NOTFOUND)
            break;
         
         for (i = 0; i < c; i++) {
            if (ip_list.id == *(ip_id + i)) {
               memcpy(ip_key + k, key.data, sizeof(uint32_t));
               k++;
               
               if (k == DOMAIN_SIZE)
                  break;
            }
         }
      }
      
      cur->close(cur);
   }

   if (k > 0) {
      // delete ip
      for (i = 0; i < k; i++) {
         memset(&key, 0, sizeof(DBT));
         
         key.data = (ip_key + i);
         key.size = sizeof(uint32_t);
         
         ip_db->del(ip_db, NULL, &key, 0);
      }
   }
   
   FREE(ip_key);
   FREE(ip_id);
}

static void do_lookup(DB *ip_db, DB *domain_db)
{
   struct domain__ *dom__ = NULL;
   DOMAIN_LIST dom_list;
   
   uint32_t count = 0, count_tmp, j = 0, k = 0;
   DBC *cur = NULL;
   DBT key, data;
   int16_t ret = 0;
   char b1[257];
     
   memset(b1, 0, sizeof(b1));
   
   dom__ = je_calloc(sizeof(struct domain__), DOMAIN_SIZE);
   if (!dom__) {
      syslog(LOG_USER | LOG_INFO, "sialan_fw: error calloc: do_lookup");
      return;
   }

   while (!stop__) {
      memset(&key, 0, sizeof(DBT));
      memset(&data, 0, sizeof(DBT));
      
      domain_db->cursor(domain_db, NULL, &cur, 0);
      cur->set_priority(cur, DB_PRIORITY_LOW);
      
      data.data = &dom_list;
      data.ulen = sizeof(DOMAIN_LIST);
      data.flags = DB_DBT_USERMEM;
      
      j = 0;
      k = 0;
      count_tmp = count;

      while (!stop__) {
         ret = cur->get(cur, &key, &data, DB_NEXT);
         if (ret == DB_NOTFOUND)
            break;

         k++;
         if (k < count_tmp)
            continue;
            
         if (dom_list.flag & DB_ENABLE) {
            (*(dom__ + j)).id = dom_list.id;
            (*(dom__ + j)).ttl = dom_list.ttl;
            (*(dom__ + j)).type = dom_list.type;
            (*(dom__ + j)).flag = dom_list.flag;
            (*(dom__ + j)).disable = 0;
            
            snprintf(b1, sizeof(b1), ".%s", (char*) key.data);
            (*(dom__ + j)).domain = strdup__(b1);
            
            if ((*(dom__ + j)).domain) {
               mirror((*(dom__ + j)).domain);
               
               j++;
               count++;
            }
            
            if (j == DOMAIN_SIZE)
               break;
         }
      }
      cur->close(cur);
            
      ttl_check(ip_db, dom__, j);
      update(ip_db, domain_db, dom__, j);
      
      for (j = 0; j < DOMAIN_SIZE; j++)
         FREE((*(dom__ + j)).domain);
         
      if (ret == DB_NOTFOUND)
         break;
   }
   
   FREE(dom__);
}

static uint8_t init(void)
{
   int f;
   
   f = open(LOOKUP_FIFO, O_RDONLY | O_NONBLOCK);
   if (f > 0) {
      fprintf(stderr, "Sialan Lookup telah berjalan.\n");
      return 0;
   }
   close(f);

   if (mkfifo(LOOKUP_FIFO, 0600) < 0) {
      fprintf(stderr, "Error create sialan_lookup_fifo.\n");
      return 0;
   }
   
   fd_fifo = open(LOOKUP_FIFO, O_RDONLY | O_NONBLOCK);
   if (f > 0) {
      fprintf(stderr, "Sialan Lookup telah berjalan.\n");
      return 0;
   }
   
   return 1;
}

int main(void)
{
   if (getuid() != 0) {
      fprintf(stderr, "Permission denied (you must be root)\n");
      return 0;
   }

   if (!init())
      exit(1);
      
   ch_server(1, NULL, &nameserver);
  
   union {
     uint16_t j;
     uint16_t tick;
   } u;
   
   DB *ip_db = NULL;
   DB *domain_db = NULL;
   DB_ENV *dbenv = NULL;
   
   if ((u.j = db_env_create(&dbenv, 0)) != 0) {
      fprintf(stderr, "db_input: %s\n", db_strerror(u.j));
      goto exit_1;
   }
    
   if (dbenv->open(dbenv, DB_ENVIRONMENT,
         DB_CREATE | DB_INIT_CDB | DB_INIT_MPOOL | DB_THREAD, 0) != 0) {
      fprintf(stderr, "environment open: %s\n", DB_ENVIRONMENT);
      goto exit_1;
   }
 
   if (db_create(&ip_db, dbenv, 0) != 0) {
      fprintf(stderr, "database create %s\n", IP_DB_NAME);
      goto exit_1;
   }
   if (ip_db->open(ip_db, NULL, IP_DB_NAME, NULL, DB_BTREE,
            DB_CREATE | DB_THREAD, 0644) != 0) {
      fprintf(stderr, "DB->open: %s\n", IP_DB_NAME);
      goto exit_1;
   }
    
   if (db_create(&domain_db, dbenv, 0) != 0) {
      fprintf(stderr, "database create %s\n", DOMAIN_DB_NAME);
      goto exit_1;
   }
   if (domain_db->open(domain_db, NULL, DOMAIN_DB_NAME, NULL, DB_BTREE,
            DB_CREATE | DB_THREAD, 0644) != 0) {
      fprintf(stderr, "DB->open: %s\n", DOMAIN_DB_NAME);
      goto exit_1;
   }

   struct sigaction sa;
   
   sa.sa_handler = &sig_term;
   sa.sa_flags = 0;
   
   sigaction(SIGINT, &sa, NULL);
   
   if (daemon(0, 1) < 0)
      exit(1);
   
   u.tick = DOMAIN_LOOKUP;

   while (!stop__) {
      sleep_ms(1000);

      if (u.tick == DOMAIN_LOOKUP) {
         do_lookup(ip_db, domain_db);
         
         u.tick = 0;
      }
      
      u.tick++;
   }
   
   exit_1:
   if (ip_db)
      ip_db->close(ip_db, 0);
   if (domain_db)
      domain_db->close(domain_db, 0);
   if (dbenv)
      dbenv->close(dbenv, 0);
      
   remove(LOOKUP_FIFO);
   close(fd_fifo);
   
   return 0;
}
