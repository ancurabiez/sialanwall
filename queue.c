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
#include <ctype.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <net/if.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <errno.h>
#include <assert.h>

#include <linux/netfilter.h>
#include <libnfnetlink/libnfnetlink.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "buffer.h"
#include "sialan.h"
#include "cache.h"
#include "buffer_sorting.h"
#include "generic_domain.h"
#include "defined.h"
#include "helper.h"


static void to_lower(char *str)
{
   int c;
   char *tmp = NULL;
   
   for (tmp = str; *tmp; tmp++) {
      c = tolower(*tmp);
      *tmp = c;
   }
}

uint8_t get_tld(const char* domain, char *buf, const uint16_t blen)
{
   uint8_t i, j, len, dot = 0;
   char *dom = NULL;
   
   dom = strdup(domain);
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

int is_exist(char *key__, const uint8_t f, DB *db)
{
   int i = 0;
   
   pthread_mutex_lock(&caching_mutex);
   i = (int) cache_is_exists(key__);
   pthread_mutex_unlock(&caching_mutex);
   
   if (i != 2)
      return i;

   union {
      DOMAIN_LIST domain_list;
      IP_LIST ip_list;
   } lst;
      
   DBT key, data;
   
   memset(&key, 0, sizeof(DBT));
   memset(&data, 0, sizeof(DBT));
   
   if (f == DOMAIN) {
      DBC *cur = NULL;
      char buf[257];
      char *buf_key = NULL;
      uint8_t len = 0, tot_len;
      
      memset(buf, '\0', sizeof(buf));
      
      len = get_tld(key__, buf, sizeof(buf));
      if (len == 0)
         return 0;
         
      tot_len = strlen(key__);
      buf_key = strdup(key__);
      mirror(buf_key);
      
      db->cursor(db, NULL, &cur, 0);
      cur->set_priority(cur, DB_PRIORITY_HIGH);
      
      key.data = buf;
      key.size = strlen(buf) +1;
      
      data.data = &lst.domain_list;
      data.ulen = sizeof(DOMAIN_LIST);
      data.flags = DB_DBT_USERMEM;
      
      i = cur->get(cur, &key, &data, DB_SET_RANGE);
      while (i != DB_NOTFOUND) {
         i = strlen((char*) key.data);
         if (i > tot_len)
            break;

         if (!memcmp(key.data, buf_key, i))
            if (!buffer_sorting_put((const char*) key.data, lst.domain_list.flag))
               break;
         
         if (!memcmp(key.data, buf_key, tot_len))
            break;
         
         i = cur->get(cur, &key, &data, DB_NEXT);
      }
      
      if (cur)
         cur->close(cur);
      
      i = 0;
      
      if (buffer_sorting_sort()) {
         struct buffer_sort *bs = NULL;

         while ((bs = buffer_sorting_get()) != NULL) {
            if (!memcmp(bs->domain, buf, bs->len)) {
               if (bs->flag & DB_ENABLE) {
                  if ((bs->len < tot_len) && (bs->flag & DB_MATCH)) {
                     i = 1;
                     break;
                  } else if ((bs->len == tot_len) && (bs->flag & DB_WHOLE_MATCH)) {
                     i = 1;
                     break;
                  }
               }
            }
         }
         
         buffer_sorting_clear();
      }
      
      FREE(buf_key);
   } else {
      key.data = key__;
      key.size = sizeof(uint32_t);
   
      data.data = &lst.ip_list;
      data.ulen = sizeof(IP_LIST);
      data.flags = DB_DBT_USERMEM;
      
      i = db->get(db, NULL, &key, &data, 0);
      
      if (i != DB_NOTFOUND) {
         if (lst.ip_list.flag & DB_ENABLE)
            i = 1;
         else
            i = 0;
      } else
         i = 0;
   }
   
   pthread_mutex_lock(&caching_mutex);
   cache_put(key__, i);
   pthread_mutex_unlock(&caching_mutex);

   return i;
}

void verdict(const int id, struct nfq_q_handle *qh, const uint8_t action)
{
   nfq_set_verdict(qh, id, action, 0, NULL);
}

static BufEcode buffer_put__(const int id, struct nfq_q_handle *qh,
   const uint8_t *payload_data, const uint16_t payload_len,
   DB *ip_db, DB *domain_db, const uint32_t in_device)
{
   BufEcode ecode = 0;

   while(!stop) {
      ecode = buffer_put(id, qh, payload_data, payload_len,
                  ip_db, domain_db, in_device);
      if ((ecode == BUF_MALLOC_ERROR) || (ecode == BUF_OK))
         break;
      else if (ecode == BUF_CONTINUE)
         continue;
   }
   
   if (ecode == BUF_OK) {
      pthread_mutex_lock(&mutex);
      buffer_count_inc();
      pthread_mutex_unlock(&mutex);
   }
   
   return ecode;
}

static int queue_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
   struct nfq_data *nfa, void *data)
{
   struct nfqnl_msg_packet_hdr *ph = NULL;
   struct iphdr *ip_header = NULL;
   struct data_arg *darg = (struct data_arg *) data;
   int indev = 0;

   union {
      struct tcphdr *tcp_header;
      struct udphdr *udp_header;
   } u;

   int id = 0;
   int packet_len = 0;
   uint8_t *packet = NULL;
   uint8_t *payload_data = NULL;

   ph = nfq_get_msg_packet_hdr(nfa);
   packet_len = nfq_get_payload(nfa, &packet);
   
   if (!ph || (packet_len < 0))
      return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
   
   id = ntohl(ph->packet_id);
   
   if (disable) // disable packet checking
      return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

   indev = nfq_get_indev(nfa); // checking indev
   if ((indev != *darg->indev) && (indev != *(darg->indev +1)) &&
            (indev != *(darg->indev +2)))
      return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

   ip_header = (struct iphdr *) packet;
   BufEcode ecode = 0;
   
   if (ip_header->protocol == IPPROTO_TCP) {
      u.tcp_header = (struct tcphdr *) (packet + (ip_header->ihl << 2));
      payload_data = (uint8_t *) (packet + (ip_header->ihl << 2 ) +
                           (u.tcp_header->th_off << 2));
     
      if (!memcmp(payload_data, "GET ", 4)) { // http
         ecode = buffer_put__(id, qh, packet, packet_len,
                     darg->ip_db, darg->domain_db, indev);
      }
   } else if (ip_header->protocol == IPPROTO_UDP) {
      u.udp_header = (struct udphdr *) (packet + (ip_header->ihl << 2));
      
      if (ntohs(u.udp_header->uh_dport) == 53) { // dns
         ecode = buffer_put__(id, qh, packet, packet_len,
                     darg->ip_db, darg->domain_db, indev);
      }
   }
   
   if (ecode == BUF_OK)
      return 0;
   
   return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

static uint8_t nfq_init(struct nfq_var *nfq)
{
   struct timeval tv;
   
   memset(&tv, 0, sizeof(tv));
   
   nfq->h = nfq_open();
   if (!nfq->h) {
      syslog(LOG_USER | LOG_INFO, "error during create queue_open");
      return 0;
   }
   
   // unbind queue, jika ada
   nfq_unbind_pf(nfq->h, AF_INET);
   nfq_unbind_pf(nfq->h, AF_INET6);

   if (nfq_bind_pf(nfq->h, AF_INET) < 0) {
      syslog(LOG_USER | LOG_INFO, "sialan_fw: error during nfq_bind_pf(AF_INET)");
      return 0;
   }
   
   if (nfq_bind_pf(nfq->h, AF_INET6) < 0) {
      syslog(LOG_USER | LOG_INFO, "sialan_fw: error during nfq_bind_pf(AF_INET6)");
      return 0;
   }
   
   nfq->qh = nfq_create_queue(nfq->h, 0, &queue_cb, (void*) nfq->darg);
   if (!nfq->qh) {
      syslog(LOG_USER | LOG_INFO, "sialan_fw: error during nfq_create_queue()");
      return 0;
   }
   
   if (nfq_set_mode(nfq->qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
      syslog(LOG_USER | LOG_INFO, "sialan_fw: cannot set packet_copy mode");
      return 0;
   }
   
   if (NFQ_MAX_LEN > 0) {
      if (nfq_set_queue_maxlen(nfq->qh, NFQ_MAX_LEN) < 0)
         fprintf(stderr, "can't set queue maxlen: your kernel probably "
                     "doesn't support setting the queue length");
   }
   
   // socket buffer
   nfnl_rcvbufsiz(nfq_nfnlh(nfq->h), NFQ_MAX_LEN * 1500);
   
   nfq->fd = nfq_fd(nfq->h);
   
   int opt = 1;
   setsockopt(nfq->fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &opt, sizeof(int));
   
   tv.tv_sec = 1;
   tv.tv_usec = 0;

   if(setsockopt(nfq->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1)
      fprintf(stderr, "can't set socket timeout: %s", strerror(errno));

   return 1;
}

void main_queue(void)
{
   int plen;
   char *buf = NULL;
   uint32_t buflen = (67 * 1024);
   struct data_arg data;
   struct nfq_var nfq_q;
	uint32_t indev[3] = {0};
   DB_ENV *dbenv = NULL;
   DB *ip_db = NULL, *domain_db = NULL;
   
   buf = malloc(buflen);
   assert(buf);
  
	memset(&data, 0, sizeof(data));
   memset(&nfq_q, 0, sizeof(nfq_q));
   memset(buf, 0, buflen);
   
   if ((plen = db_env_create(&dbenv, 0)) != 0) {
      fprintf(stderr, "db_input: %s\n", db_strerror(plen));
      stop = 1;
      goto exit_1;
   }
    
   if (dbenv->open(dbenv, DB_ENVIRONMENT,
         DB_CREATE | DB_INIT_CDB | DB_INIT_MPOOL | DB_THREAD, 0) != 0) {
      fprintf(stderr, "environment open: %s\n", DB_ENVIRONMENT);
      stop = 1;
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
   
   data.indev = indev;
   data.ip_db = ip_db;
   data.domain_db = domain_db;
   data.udp_target_ip = &udp_target;
      
   nfq_q.darg = &data;
   
   if (!nfq_init(&nfq_q)) {
      stop = 1;
      goto exit_2;
   }
   
   while (!stop) {
      if (ch_indev) {
         ch_server(3, buf, indev);
         ch_indev = 0;
      }
      
      plen = recv(nfq_q.fd, buf, buflen, 0);
      if (plen == -1) {
         if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
            continue;
         else {
            if (strerror_r(errno, buf, 128) < 0)
               strcpy(buf, "unknown");
            
            syslog(LOG_USER | LOG_INFO, "sialan_fw: Exit with error: %s", buf);
            stop = 1;
            break;
         }
      }
      
      nfq_handle_packet(nfq_q.h, buf, plen);
   }
   
   exit_2:
   nfq_unbind_pf(nfq_q.h, AF_INET);
   nfq_unbind_pf(nfq_q.h, AF_INET6);
   nfq_destroy_queue(nfq_q.qh);
   nfq_close(nfq_q.h);

   exit_1:
      
   if (ip_db)
      ip_db->close(ip_db, 0);
   if (domain_db)
      domain_db->close(domain_db, 0);
   if (dbenv)
      dbenv->close(dbenv, 0);
      
   FREE(buf);
}


