#ifndef HELPER__H
#define HELPER__H


// helper.c
char *strdup__(const char* str);
void ch_server(u_int8_t, char*, u_int32_t *);
u_int32_t pidof(const char *);
u_int8_t is_sialan_fw_up(void);
char *mirror(char *string);

u_int8_t is_database_ok(void);
void get_count(const char*, int*);

#endif
