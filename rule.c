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
#include <string.h>
#include <time.h>

#include "buffer.h"
#include "sialan.h"
#include "defined.h"


static void sendto_error_queue(const struct iphdr *iphead, const struct tcphdr *tcphead,
   const struct udphdr *udphead, const uint8_t *payload_data,
   const uint32_t payload_len, const mqd_t msqid, const uint32_t ifindex)
{
   struct msgbuf mbuf;
   memset(&mbuf, 0, sizeof(mbuf));

   mbuf.id = iphead->id;
   mbuf.protocol = iphead->protocol;
   mbuf.saddr = iphead->saddr;
   mbuf.daddr = iphead->daddr;
   mbuf.payload_len = payload_len;
   mbuf.ifindex = ifindex;

   if (iphead->protocol == IPPROTO_TCP) {
      mbuf.sport = tcphead->th_sport;
      mbuf.dport = tcphead->th_dport;
      mbuf.ack = tcphead->th_ack;
      mbuf.seq = tcphead->th_seq;
      //memset(mbuf.payload_data, 0, sizeof(mbuf.payload_data));
   } else if (iphead->protocol == IPPROTO_UDP) {
      mbuf.sport = udphead->uh_sport;
      mbuf.dport = udphead->uh_dport;
      memcpy(mbuf.payload_data, payload_data, sizeof(mbuf.payload_data));
   }

   mq_send(msqid, (char*) &mbuf, sizeof(struct msgbuf), 0);
}

void* main_rules(void *arg)
{
   uint32_t idx = 0;
   struct timeval tv;
   BufEcode ecode = 0;
   struct buffer__ data_arg;
   struct mq_attr mqattr;
   mqd_t msqid;
   uint8_t ret = 0;
   uint8_t *payload_data = NULL;
   uint16_t payload_len = 0;
   struct iphdr *ip_header = NULL;
   union {
      struct tcphdr *tcp_header;
      struct udphdr *udp_header;
   } u;
   
   memset(&tv, 0, sizeof(tv));
   memset(&mqattr, 0, sizeof(mqattr));
   
   mqattr.mq_flags |= O_NONBLOCK;
   mqattr.mq_maxmsg = 512;
   mqattr.mq_msgsize = sizeof(struct msgbuf);
   
   msqid = mq_open("/sialan_firewall",  O_WRONLY | O_CREAT, 0644, &mqattr);
   
   while (!stop) {
      if (disable) {
         tv.tv_sec = 1;
         tv.tv_usec = 0;
         select (0, NULL, NULL, NULL, &tv);
         continue;
      }
      
      memset(&data_arg, 0, sizeof(data_arg));
      ecode = buffer_get(&data_arg, idx);
      
      if (ecode == BUF_CONTINUE) {
         tv.tv_sec = 0;
         tv.tv_usec = 10000;
         select (0, NULL, NULL, NULL, &tv);
         continue;
      }

      ip_header = (struct iphdr *) data_arg.packet;

      if (ip_header->protocol == IPPROTO_TCP) {
         u.tcp_header = (struct tcphdr *) (data_arg.packet + (ip_header->ihl << 2));
         payload_data = (uint8_t *) (data_arg.packet + (ip_header->ihl << 2 ) +
                           (u.tcp_header->th_off << 2));
         payload_len = htons(ip_header->tot_len) - ((ip_header->ihl << 2) +
                           (u.tcp_header->th_off << 2));
         //-------- tcp rules ------------------
         ret = is_http_blacklist(payload_data, payload_len,
                  data_arg.ip_db, data_arg.domain_db);

         if (ret == 1)
            sendto_error_queue(ip_header, u.tcp_header, NULL, NULL,
                        payload_len, msqid, data_arg.in_device);
      } else if (ip_header->protocol == IPPROTO_UDP) {
         u.udp_header = (struct udphdr *) (data_arg.packet + (ip_header->ihl << 2));
         payload_data = (uint8_t *) (data_arg.packet + (ip_header->ihl << 2 ) +
                  sizeof(struct udphdr));
         payload_len = ntohs(u.udp_header->uh_ulen) - sizeof(struct udphdr);
         //-------- udp rules --------------------
         ret = is_dns_blacklist(payload_data, payload_len, data_arg.domain_db);
         
         if (ret == 1)
            sendto_error_queue(ip_header, NULL, u.udp_header,
                  payload_data, payload_len, msqid, data_arg.in_device);
      }

      if ((ret == 2) || (ret == 1))
         verdict(data_arg.id, data_arg.qh, NF_DROP);
      else
         verdict(data_arg.id, data_arg.qh, NF_ACCEPT);
         
      pthread_mutex_lock(&mutex);
      buffer_del(idx);
      pthread_mutex_unlock(&mutex);
      
      idx++;
      if (idx >= buffer_get_size())
         idx = 0;
   }
   
   mq_close(msqid);
   mq_unlink("/sialan_firewall");
   
   pthread_exit(NULL);
}
