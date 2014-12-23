#ifndef BUFFER_SORTING__H
#define BUFFER_SORTING__H

struct buffer_sort {
   uint8_t len;
   uint8_t flag;
   char *domain;
};

void buffer_sorting_init(void);
void buffer_sorting_flush(void);
uint8_t buffer_sorting_put(const char* domain, const uint8_t flag);
uint8_t buffer_sorting_sort(void);
struct buffer_sort* buffer_sorting_get(void);
void buffer_sorting_clear(void);

#endif
