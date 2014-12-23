#ifndef SIALAN_CTL__H
#define SIALAN_CTL__H

#include <db.h>
#include <ncurses.h>
#include <jemalloc/jemalloc.h>


struct domain_list {
   uint8_t flag;
   char *domain;
};

//char *ip;
typedef struct ip_list__ {
   int32_t id;
   uint8_t ancount;
   uint8_t flag;
   uint8_t type;
} IP_LIST;

//char *domain;
typedef struct domain_list__ {
   int32_t id;
   uint32_t ttl;
   uint8_t type;
   uint8_t flag;
} DOMAIN_LIST;


void main_search(WINDOW *, DB *, DB *domain_db);
void main_add(WINDOW *win, DB *ip_db, DB *domain_db);

void printf__(WINDOW *win, const int y, const int x,
      const char *str, const uint8_t f, const uint8_t err);
void to_lower(char *str);
char *mirror(char *string);
uint8_t get_tld(const char* domain, char *buf, const uint16_t blen);
char *strdup__(const char* str);


#endif

