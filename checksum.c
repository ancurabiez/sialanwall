#include <stdio.h>
#include <sys/types.h>


#include "checksum.h"

u_int16_t in_cksum(u_int16_t *addr, int len)
{
	register int sum = 0;
	u_int16_t answer = 0;
	register u_int16_t *w = addr;
	register int nleft = len;

	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1) {
		*(u_char *)(&answer) = *(u_char *)w ;
		sum += answer;
	}

	/* add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
	sum += (sum >> 16); /* add carry */
	answer = ~sum; /* truncate to 16 bits */

	return(answer);
}


