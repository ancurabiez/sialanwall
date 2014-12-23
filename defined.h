#ifndef DEFINED__H
#define DEFINED__H

#include <jemalloc/jemalloc.h>


#define PREFIX "/sources/sialan"

/* Maximum queue lenght */
#define NFQ_MAX_LEN (4 * 1024)

/* Buffer size */
#define BUFFER_SIZE (2 * 1024)

/* caching */
#define CACHE_SIZE (8 * 1024)
#define CACHE_HIGH (CACHE_SIZE - 1)
#define CACHE_LOW (CACHE_HIGH - (3 * 1024))

/* caching ttl (time to live) in second */
#define CACHE_TTL 18000

/* Lamanya domain tersimpan di 
* database sebelum di update dalam detik (90 hari) */
#define DOMAIN_TTL 7776000

/* Lookup domain setiap 12jam (detik) */
#define DOMAIN_LOOKUP 43200

/* Database file path */
#define DB_ENVIRONMENT (PREFIX "/sialan_db")
#define IP_DB_NAME "ip.db"
#define DOMAIN_DB_NAME "domain.db"
#define CONFIG_DB_NAME "config.db"

/* Top Level Domain path */
#define TLD_PATH (PREFIX "/domain.txt")

/* Named pipe for communication */
#define FIFO_PATH "/tmp/sialan_fifo"
#define FIFO_RM_PATH "/tmp/sialan_rm_fifo"

/* Locking file path */
#define LOCK_PATH "/tmp/sialan_lock"

/* Disable/Enable loking file */
#define ENDIS_LOCK_PATH "/tmp/sialan_endis_lock"

/* Name pipe for lookup communcation */
#define LOOKUP_FIFO "/tmp/sialan_lookup_fifo"

//**************************************************

#define GET_32BIT(p) (((p)[0] << 24) | ((p)[1] << 16) | ((p)[2] << 8) | (p)[3])
#define GET_16BIT(p) (((p)[0] << 8) | (p)[1])

#define SET_16BIT(p, v)	(((p)[0] = (u_int8_t)(((v) >> 8) & 0xff)), \
                              ((p)[1] = (u_int8_t)((v) & 0xff)))
#define SET_32BIT(p, v)	(((p)[0] = (u_int8_t)(((v) >> 24) & 0xff)), \
                              ((p)[1] = (u_int8_t)(((v) >> 16) & 0xff)), \
                              ((p)[2] = (u_int8_t)(((v) >> 8) & 0xff)), \
                              ((p)[3] = (u_int8_t)((v) & 0xff)))

#define FREE(x) if (x) {je_free(x); x = NULL;}

#define THREAD_NUM 2
#define DOMAIN_SIZE 3000
#define BUFFER_SORTING_SIZE 256

#define DB_ENABLE (1 << 1)
#define DB_DISABLE (1 << 2)
#define DB_MATCH (1 << 3)
#define DB_WHOLE_MATCH (1 << 4)

#define ID_NUM "0\0"
#define IP 100
#define DOMAIN 101

#define MALWARE 10
#define PORN 11
#define ADS 12

#define INDEV 10
#define NAMESERVER 11
#define DISABLE 12
#define DNS_ADDR 13
#define HTTP_SERVER 14

#define NF_DROP 0
#define NF_ACCEPT 1

// Escape button
#define ESC 27


#endif
