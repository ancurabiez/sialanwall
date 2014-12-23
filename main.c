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
#include <signal.h>
#include <syslog.h>

#include "buffer.h"
#include "cache.h"
#include "buffer_sorting.h"
#include "generic_domain.h"
#include "sialan.h"
#include "defined.h"

u_int8_t stop = 0;
u_int8_t disable = 0;
//u_int8_t ch_nameserver = 1;
u_int8_t ch_indev = 1;
u_int8_t ch_dns = 1;
u_int8_t ch_http = 1;
char domain_rm[256];
u_int32_t udp_target = 0;


static void sig_term(int sig)
{
  if (sig == SIGINT)
    stop = 1;
}


int main(int argc, char **argv)
{
  if (getuid() != 0) {
    fprintf(stderr, "Permission denied (you must be root)\n");
    return 0;
  }
   
   /*int i = 0;
   
   // checking db
   if (argc == 2) {
      if (!strcmp(argv[1], "check")) {
         i = open(LOCK_PATH, O_RDONLY);
         if (i > 0) {
            close(i);
            printf("Sialan Firewall still running.\n");
            return 0;
         }
         
         fprintf(stderr, "Checking database...");
         if (is_database_ok())
            return -1;
         printf("     OK\n");
         
         return 0;
      } else if (strcmp(argv[1], ""))
         return 0;
   }
   
*/
  if (is_sialan_fw_up()) {
    fprintf(stderr, "Sialan Firewall telah berjalan.\n");
    exit (0);
  }
 
  pthread_t ptread[THREAD_NUM];
  pthread_attr_t ptattr;
  struct sigaction sa;
   
  sa.sa_handler = &sig_term;
  sa.sa_flags = 0;
   
  sigaction(SIGINT, &sa, NULL);
   
  pthread_attr_init(&ptattr);
  pthread_attr_setdetachstate(&ptattr, PTHREAD_CREATE_DETACHED);
  pthread_attr_setstacksize(&ptattr, 64 * 1024);

  if (daemon(0, 1) == -1)
    return 1;
   
  buffer_init();
  buffer_sorting_init();
  cache_init();
  generic_init();
   
  syslog(LOG_USER | LOG_INFO, "sialan_fw: Started");
  system("/sbin/iptables -t mangle -A PREROUTING -j NFQUEUE --queue-num 0");
      
  pthread_create(&ptread[0], &ptattr, main_rules, (void*) 0);
  pthread_create(&ptread[1], &ptattr, main_raw, (void*) 0);
      
  main_queue();
     
  generic_flush();
  buffer_flush();
  cache_flush();
  buffer_sorting_flush();
  pthread_attr_destroy(&ptattr);
   
  remove(LOCK_PATH);
  remove(FIFO_PATH);
  remove(FIFO_RM_PATH);
  remove(ENDIS_LOCK_PATH);
   
  system("/sbin/iptables -t mangle -D PREROUTING -j NFQUEUE --queue-num 0");
  syslog(LOG_USER | LOG_INFO, "sialan_fw: Exited");

  pthread_exit(NULL);
}
