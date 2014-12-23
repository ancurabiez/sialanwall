#ifndef SIALAN__H
#define SIALAN__H

#include <inttypes.h>
#include <mqueue.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <db.h>

#include "helper.h"


struct dns_header {
	unsigned qid:16;
	
	unsigned rd:1;
	unsigned tc:1;
	unsigned aa:1;
	unsigned opcode:4;
	unsigned qr:1;

	unsigned rcode:4;
	unsigned z:3;
	unsigned ra:1;
	
	unsigned qdcount:16;
	unsigned ancount:16;
	unsigned nscount:16;
	unsigned arcount:16;
};

struct data_arg {
   DB *ip_db;
   DB *domain_db;
   uint32_t *indev;
   uint32_t *udp_target_ip;
};

struct msgbuf {
   uint16_t id;
   uint16_t sport;
   uint16_t dport;
   uint32_t saddr;
   uint32_t daddr;
   uint32_t seq;
   uint32_t ack;
   uint32_t payload_len;
   uint32_t ifindex;
   uint8_t protocol;
   uint8_t payload_data[280];
};

typedef struct pseudo {
   uint32_t src_addr;
   uint32_t dst_addr;
   uint8_t  dummy;
   uint8_t  proto;
   uint16_t length;
} pseudohead__;

struct res1 {
   uint32_t id;
   uint32_t rowid;
   uint8_t ancount;
   char domain[257];
};

struct nfq_var {
   struct nfq_handle *h;
   struct nfq_q_handle *qh;
   struct data_arg *darg;
   int fd;
};

struct domain__ {
   uint32_t id;
   uint32_t ttl;
   char *domain;
   uint8_t flag;
   uint8_t type;
   uint8_t disable;   
};

//char *ip;
typedef struct ip_list__ {
   uint32_t id;
   uint8_t flag;
   uint8_t type;
} IP_LIST;

//char *domain;
typedef struct domain_list__ {
   uint32_t id;
   uint32_t ttl;
   uint8_t type;
   uint8_t flag;
} DOMAIN_LIST;


extern uint8_t stop;
extern uint8_t disable;
//extern uint8_t ch_nameserver;
extern uint8_t ch_indev;
extern uint8_t ch_dns;
extern uint8_t ch_http;
extern char domain_rm[256];
extern uint32_t udp_target;


// raw_socket.c
void *main_raw(void *arg);

// rule.c
void* main_rules(void *arg);

// queue.c
void main_queue(void);
int is_exist(char *key_, const uint8_t f, DB *db);
void verdict(const int id, struct nfq_q_handle *qh, const uint8_t action);
uint8_t get_tld(const char* domain, char *buf, const uint16_t blen);

// http_rule.c
u_int8_t is_http_blacklist(const uint8_t *tcp_payload,
   const uint32_t payload_len, DB *ip_db, DB *domain_db);

// dns_rule.c
u_int8_t is_dns_blacklist(const uint8_t *payload_data,
   const int16_t len, DB *db);

#endif
