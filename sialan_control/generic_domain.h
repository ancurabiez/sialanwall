#ifndef GENERIC_DOMAIN__H
#define GENERIC_DOMAIN__H

struct tld__ {
   char* tld;
};


uint8_t generic_init(void);
void generic_flush(void);
uint8_t generic_is_exist(const char *str);

#endif
