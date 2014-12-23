/* 
 * 15/07/2012
 * 
 * Copyright (c) 2012 Lulus Wijayakto <l.wijayakto@yahoo.com>
 *
 * Can be freely distributed and used under the terms of the GNU GPL.
 *
*/

#include <stdio.h>
#include <string.h>
#include <inttypes.h>


uint8_t is_domain(const char *str)
{
   uint16_t i, ret = 1;
   int p[4] = {0};
   char buf[257];
   
   strcpy(buf, str);
   
   i = sscanf(buf, "%d.%d.%d.%d", &p[0], &p[1], &p[2], &p[3]);
      
   if (i == 4) { // mungkin ip, cek lagi!!
      // cek doted
      ret = 0;
      for (i = 0; buf[i] != '\n'; i++) {
         if (buf[i] == '.')
            ret++;
      }

      if (ret == 3) {  // kemungkinan ip, cek lagi!!
         if (((p[0] >= 0) && (p[0] <= 255)) &&
               ((p[1] >= 0) && (p[1] <= 255)) &&
               ((p[2] >= 0) && (p[2] <= 255)) &&
               ((p[3] >= 0) && (p[3] <= 255))) // yup ini ip...
         ret =  0;
      } else // ini domain
         ret = 1;
   }

   return ret; //ini domain
}

uint8_t ip_dom(const char *file)
{
   FILE *f_ip;
   FILE *f_dom;
   FILE *f_source;
   char buf[257];
   
   f_source = fopen(file, "r");
   if (!f_source)
      return 0;
     
   f_ip = fopen("ip_list", "w");
   f_dom = fopen("dom_list", "w");
   
   while (fgets(buf, sizeof(buf), f_source)) {
      if (is_domain(buf))
         fputs(buf, f_dom);
      else
        fputs(buf, f_ip);
   }
   
   fclose(f_source);
   fclose(f_ip);
   fclose(f_dom);
   
   return 1;
}
