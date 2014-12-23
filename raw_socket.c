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
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>

#include <netinet/in.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>

#include "sialan.h"
#include "cache.h"
#include "checksum.h"
#include "defined.h"


static void send_raw_socket(const u_int8_t *packet, const u_int16_t packet_len,
   const int sock, const int ifindex, const u_int8_t *dst)
{
   struct sockaddr_ll to;
      
   memset(&to , 0, sizeof(to));
   to.sll_family = AF_PACKET;
   to.sll_halen = ETH_ALEN;
   to.sll_ifindex = ifindex;
   memcpy(to.sll_addr, dst, ETH_ALEN);
   
   sendto(sock, packet, packet_len, 0,
                   (struct sockaddr *) &to, sizeof(struct sockaddr_ll));
}

static u_int16_t create_dns_answer(u_int8_t *buf, const struct msgbuf *mbuf,
   const u_int32_t daddr)
{
   struct dns_header *dnsh = NULL;
   u_int8_t *answ = NULL;
   const u_int8_t *ll = NULL;
   u_int8_t in_a[4] = {0, 1, 0, 1};
   u_int16_t len = sizeof(struct dns_header);
   
   ll = (mbuf->payload_data + sizeof(struct dns_header));
   
   dnsh = (struct dns_header*) buf;
   answ = (u_int8_t *) (buf + sizeof(struct dns_header));
   
   // dns
   dnsh->qid = htons(GET_16BIT(mbuf->payload_data)); // get dns id
   dnsh->qr = 1; // response
   dnsh->rd = 0;
   dnsh->aa = 0;
   dnsh->opcode = 0;
   dnsh->rcode = 0;
   dnsh->z = 0;
   dnsh->ra = 0;
   dnsh->qdcount = htons(1);
   dnsh->ancount = htons(1);
   dnsh->nscount = htons(0);
   dnsh->arcount = htons(0);
   
   //copy answere to packet
   while (1) {
      if (memcmp(ll, in_a, 4))
         *answ++ = *ll;
      else {
         memcpy(answ, ll, 4);
         answ += 4;
         len += 4;
         
         break;
      }
      
      len++;
      ll++;
   }

   *answ++ = 0xc0;
   *answ++ = 0x0c;
   
   SET_16BIT(answ, 1); // IN
   answ += 2;
   SET_16BIT(answ, 1); // A
   answ += 2;
   SET_32BIT(answ, 1); //ttl
   answ += 4;
   SET_16BIT(answ, 4); // data len
   answ += 2;
   memcpy(answ, &daddr, 4);
   len += 16;

   return len;
}

static struct ether_header* get_device_addr(const u_int32_t ifindex,
   const u_int32_t daddr, u_int8_t *buf, const int sock,
   struct ether_header *eth_head)
{
   char *str = NULL;
   struct ifreq iff;
   struct arpreq areq;
   struct sockaddr_in *sin = NULL;
   
   memset(&iff, 0, sizeof(iff));
   memset(&areq, 0, sizeof(areq));
   
   str = if_indextoname(ifindex, (char*) buf);
   if (!str)
      return NULL;

   // get local(src) hwaddr
   strncpy(iff.ifr_name, str, IFNAMSIZ);
   ioctl(sock, SIOCGIFHWADDR, &iff);
   memcpy(eth_head->ether_shost, (u_int8_t*) &iff.ifr_hwaddr.sa_data, ETH_ALEN);
   // get dst hwaddr
   sin = (struct sockaddr_in *) &areq.arp_pa;
   sin->sin_family = AF_INET;
   sin->sin_addr.s_addr = daddr;
   sin = (struct sockaddr_in *) &areq.arp_ha;
   sin->sin_family = ARPHRD_ETHER;
   
   memcpy(areq.arp_dev, str, IFNAMSIZ);
   if (ioctl(sock, SIOCGARP, (caddr_t) &areq) < 0)
      return NULL;
   memcpy(eth_head->ether_dhost, (u_int8_t*) areq.arp_ha.sa_data, ETH_ALEN);
   
   eth_head->ether_type = ntohs(ETH_P_IP); // protocol type
   
   return eth_head;
}

static void build_ip(u_int8_t *packet, const struct msgbuf *mbuf,
   const u_int16_t len)
{
  struct iphdr iph;
  u_int16_t plen = 0;

  iph.ihl = 5;
  iph.version = 4;
  iph.tos = 0;

  if (mbuf->protocol == IPPROTO_TCP)
    plen = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + len);
  else if (mbuf->protocol == IPPROTO_UDP)
    plen = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + len);

  iph.tot_len = plen;
  iph.id = mbuf->id;
  iph.frag_off = 64; // don't fragment
  iph.ttl = 64;
  iph.protocol = mbuf->protocol;
  iph.check = 0;
  iph.saddr = mbuf->daddr;
  iph.daddr = mbuf->saddr;
  iph.check = in_cksum((u_int16_t *) &iph, sizeof(struct iphdr));

  memcpy(packet, &iph, sizeof(struct iphdr));
}

static u_int16_t build_tcp(u_int8_t *packet, const struct msgbuf *mbuf,
   const char *error_str)
{
  struct help_checksum {  /*struct for checksum calculation*/
    struct pseudo pshd;
    struct tcphdr tcphd;
    char tcpdata[612];
  } tcp_chk_construct;

  struct tcphdr tcph;
  u_int16_t error_len = 0;
  u_int32_t p = 0;
  pseudohead__ pseudohead;

  error_len= strlen(error_str);
  p = ntohl(mbuf->seq) + mbuf->payload_len;

  tcph.th_sport = mbuf->dport;
  tcph.th_dport = mbuf->sport;
  tcph.th_seq = mbuf->ack;
  tcph.th_ack = htonl(p);
  tcph.th_x2 = 0;
  tcph.th_off = 5;
  tcph.th_flags = TH_PUSH | TH_ACK;
  
  tcph.th_win = htons(1024);
  tcph.th_sum = 0;
  tcph.th_urp = 0;

  pseudohead.src_addr = mbuf->daddr;
  pseudohead.dst_addr = mbuf->saddr;
  pseudohead.dummy = 0;
  pseudohead.proto = IPPROTO_TCP;
  pseudohead.length = htons(sizeof(struct tcphdr) + error_len);

  tcp_chk_construct.pshd = pseudohead;
  tcp_chk_construct.tcphd = tcph;
  memcpy(tcp_chk_construct.tcpdata, error_str, error_len);
  
  tcph.th_sum = in_cksum((u_int16_t *) &tcp_chk_construct,
           (sizeof(struct pseudo) + sizeof(struct tcphdr) + error_len));

  memcpy(packet + sizeof(struct iphdr), &tcph, sizeof(struct tcphdr));
  //payload
  memcpy(packet + (sizeof(struct iphdr) + sizeof(struct tcphdr)),
          error_str, error_len);

  return (ETH_HLEN + sizeof(struct iphdr) + sizeof(struct tcphdr) + error_len);
}

static u_int16_t build_udp(u_int8_t *packet, const struct msgbuf *mbuf,
   const u_int32_t target)
{
  struct help_checksum {  /*struct for checksum calculation*/
    struct pseudo pshd;
    struct udphdr udphd;
    char udpdata[300];
  } udp_chk_construct;

  struct udphdr udph;
  u_int8_t data[290];
  u_int16_t payload_len = 0;
  pseudohead__ pseudohead;

  payload_len = create_dns_answer(data, mbuf, target);
  build_ip(packet, mbuf, payload_len);
  
  udph.uh_sport = mbuf->dport;
  udph.uh_dport = mbuf->sport;
  udph.uh_ulen = htons(sizeof(struct udphdr) + payload_len);
  udph.uh_sum = 0;

  pseudohead.src_addr = mbuf->daddr;
  pseudohead.dst_addr = mbuf->saddr;
  pseudohead.dummy = 0;
  pseudohead.proto = IPPROTO_UDP;
  pseudohead.length = htons(sizeof(struct udphdr) + payload_len);

  udp_chk_construct.pshd = pseudohead;
  udp_chk_construct.udphd = udph;
  memcpy(udp_chk_construct.udpdata, data, payload_len);
  
  udph.uh_sum = in_cksum((u_int16_t *) &udp_chk_construct,
                         sizeof(struct pseudo) + sizeof(struct udphdr) + payload_len);

  memcpy(packet + sizeof(struct iphdr), &udph, sizeof(struct iphdr));
  // payload
  memcpy(packet + sizeof(struct iphdr) + sizeof(struct udphdr),
         data, payload_len);

  return (ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr) + payload_len);
}

static void send_raw_msg(const struct msgbuf *mbuf, const u_int32_t target,
   const int sock_raw, const int sock_device, const char *error_str)
{
   u_int8_t packet[700];
   u_int16_t plen = 0;
   struct ether_header *ehead = NULL, eth_buf;

   ehead = get_device_addr(mbuf->ifindex, mbuf->saddr, packet,
               sock_device, &eth_buf);
   if (!ehead)
      return;

   memcpy(packet, ehead, ETH_HLEN);

   if (mbuf->protocol == IPPROTO_TCP) {
      build_ip(packet + ETH_HLEN, mbuf, strlen(error_str));
      plen = build_tcp(packet + ETH_HLEN, mbuf, error_str);
   } else if (mbuf->protocol == IPPROTO_UDP)
      plen = build_udp(packet + ETH_HLEN, mbuf, target);

   send_raw_socket(packet, plen, sock_raw,
         mbuf->ifindex, ehead->ether_dhost);
}

static void check_fifo(int *fifo)
{
   u_int8_t buf;

   if (read(*fifo, &buf, sizeof(u_int8_t)) > 0) {
      if (buf == DISABLE) {
         if (disable)
            disable = 0;
         else
            disable = 1;
      } else if (buf == INDEV)
         ch_indev = 1;
      //else if (buf == NAMESERVER)
      //   ch_nameserver = 1;
      else if (buf == DNS_ADDR)
         ch_dns = 1;
      else if (buf == HTTP_SERVER)
         ch_http = 1;
   }
   
   // remove domain
   if (read(*(fifo +1), domain_rm, 256) > 0) {
      pthread_mutex_lock(&caching_mutex);
      cache_delete_domain(domain_rm);
      pthread_mutex_unlock(&caching_mutex);
   }
}

void *main_raw(void *arg)
{
   mqd_t msqid;
   char buf[sizeof(struct msgbuf)];
   struct msgbuf *mbuf = NULL;
   struct mq_attr mqattr;
   struct timespec ts;
   u_int32_t prio = 0;
   int sock_raw = 0, sock_device = 0;
   char *error_str = NULL;
   int fifo[2] = {0};
   
   memset(&mqattr, 0, sizeof(mqattr));
   
   error_str = (char*) je_malloc(612);
   assert(error_str);
   
   memset(&ts, 0, sizeof(ts));
   memset(error_str, 0, 612);
   memcpy(error_str, "HTTP/1.1 301 Moved Permanently\r\n"
         "Cache-Control: no-store, no-cache, must-revalidate\r\n"
         "Expires: Thu, 01 Jan 1970 00:00:00 GMT\r\nContent-Length: 139\r\n"
         "Content-Type: text/html\r\nConnection: keep-alive\r\n"
         "Location: http://", 211);

   if((sock_raw = socket(PF_PACKET, SOCK_RAW, IPPROTO_RAW)) < 0) {
      stop = 1;
      goto exit_2;
   }
   
   if ((sock_device = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
      stop = 1;
      goto exit_1;
   }
   
   mqattr.mq_flags = 0;
   mqattr.mq_maxmsg = 512;
   mqattr.mq_msgsize = sizeof(struct msgbuf);
   
   msqid = mq_open("/sialan_firewall", O_RDONLY | O_CREAT, 0644, &mqattr);
   assert(msqid != -1);
   
   fifo[0] = open(FIFO_PATH, O_RDONLY | O_NONBLOCK);
   fifo[1] = open(FIFO_RM_PATH, O_RDONLY | O_NONBLOCK);
   
	while (!stop) {
      check_fifo(fifo);
      
		if (ch_dns) {
			ch_server(0, NULL, &udp_target);
        // struct in_addr addr;
         //addr.s_addr = udp_target;
        // printf("ee>%s<\n", inet_ntoa(addr));
         ch_dns = 0;
      }

      if (ch_http) {
         ch_server(2, error_str + 211, &prio);
         memcpy(error_str + prio + 211, "/\r\n\r\n<html><head><title>301 Moved "
               "Permanently</title></head>"
               "<body><bgcolor=\"white\"><center><h1>301 Moved "
               "Permanently</h1></center></body></html>\0", 145);
        // printf("oo>%s<\n", error_str);
         prio = 0;
         ch_http = 0;
      }

      clock_gettime(CLOCK_REALTIME, &ts);
      ts.tv_sec += 1;
      if (mq_timedreceive(msqid, buf, sizeof(struct msgbuf), &prio, &ts) < 0)
         continue;

      mbuf = (struct msgbuf *) buf;
      send_raw_msg(mbuf, udp_target, sock_raw, sock_device, error_str);
   }

   close(*fifo);
   close(*(fifo +1));
   
   mq_close(msqid);
   exit_1:
   close(sock_device);
   exit_2:
   close(sock_raw);
   FREE(error_str);
   
   pthread_exit(NULL);
}
