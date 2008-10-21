/**
 * PING module
 *
 * Copyright (C) 2001 Jeffrey Fulmer <jdfulmer@armstrong.com>
 * This file is part of LIBPING
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>

#define MAXPACKET     65535
#define PKTSIZE       64 
#define HDRLEN        ICMP_MINLEN
#define DATALEN       (PKTSIZE-HDRLEN)
#define ICMP_LEN      (HDRLEN+DATALEN)
#define MAXDATA       (MAXPKT-HDRLEN-TIMLEN)
#define DEF_TIMEOUT   5
#define IDENT_DEFAULT 0
#define TIMO_DEFAULT  2

struct send_icmp {
	struct timeval next_send;
	struct timeval sent_at;
	int timeout;
	struct sockaddr_in addr;
	int id;
	int seq;
};

char *strchr (), *strrchr ();

// socket 
int sock_ping;

#define logmsg(a, b, c...) fprintf(stderr, b, c);

// TODO TODO TODO : taille du ping en parametre

/**
* elapsed_time
* returns an int value for the difference
* between now and starttime in milliseconds.
*/
int elapsed_time( struct timeval *starttime ){
	struct timeval *newtime;
	int elapsed;

	newtime = (struct timeval*)malloc( sizeof(struct timeval));
	gettimeofday(newtime,NULL);
	elapsed = 0;

	if(( newtime->tv_usec - starttime->tv_usec) > 0 ){
		elapsed += (newtime->tv_usec - starttime->tv_usec)/1000 ;
	}
	else{
		elapsed += ( 1000000 + newtime->tv_usec - starttime->tv_usec ) /1000;
		newtime->tv_sec--;
	}
	if(( newtime->tv_sec - starttime->tv_sec ) > 0 ){
		elapsed += 1000 * ( newtime->tv_sec - starttime->tv_sec );
	}
	if( elapsed < 1 )
		elapsed = 1;

	free( newtime );
	return( elapsed );
}

static int in_checksum(u_short *buf, int len){
	register long sum = 0;
	u_short answer = 0;

	while( len > 1 ){
		sum += *buf++;
		len -= 2;
	}

	if( len == 1 ){
		*( u_char* )( &answer ) = *( u_char* )buf;
		sum += answer;
	}
	sum = ( sum >> 16 ) + ( sum & 0xffff );
	sum += ( sum >> 16 );     
	answer = ~sum;     

	return(answer);
} 

/*************************************************************
  enregistrer une machine a pinguer et une ferequence
*************************************************************/
struct send_icmp *ping_register(char *host){
	int ret_code;
	struct send_icmp *host_icmp;
	struct hostent *hp = NULL;
	struct hostent hent;
	int herrno;
	char hbf[9000];
#if defined(_AIX)
	char *aixbuf;
	int rc;
#endif


#if defined(__GLIBC__)
	ret_code = gethostbyname_r(host, &hent, hbf, sizeof(hbf), &hp, &herrno);
	if(ret_code < 0){
		logmsg(LOG_ERR, "gethostbyname_r(%s)[%d]: %s", host, errno, strerror(errno));
		exit(1);
	}

#elif defined(sun)
  /* Solaris 5++ */
	hp = gethostbyname_r(host, &hent, hbf, sizeof(hbf), &herrno);

#elif defined(_AIX)
	aixbuf = (char*)malloc( 9000 );
	if(aixbuf == NULL){
		logmsg(LOG_ERR, "malloc(9000)[%d]: %s", errno, strerror(errno));
		exit(1);
	}
	rc  = gethostbyname_r(host, (struct hostent *)aixbuf,
	                      (struct hostent_data *)(aixbuf + sizeof(struct hostent)));
	hp = (struct hostent*)aixbuf;

#elif ( defined(hpux) || defined(__osf__) )
	hp     = gethostbyname(host);
	herrno = h_errno;

#else // simply hoping that get*byname is thread-safe
	hp     = gethostbyname(host);
	herrno = h_errno;

#endif

	// alloue la memoire pour un element a icmpizer
	host_icmp = (struct send_icmp *)malloc(sizeof(struct send_icmp));
	if(host_icmp == NULL){
		logmsg(LOG_ERR, "malloc[%d]: %s", errno, strerror(errno));
		exit(1);
	}

	// si l'adresse est resolue
	if(hp != NULL ){
		memcpy(&host_icmp->addr.sin_addr,
		       hp->h_addr_list[0],
		       sizeof(host_icmp->addr.sin_addr));
		host_icmp->addr.sin_port = 0;
		host_icmp->addr.sin_family = AF_INET;
	}

	// sinon on espere que c'est une ip
	else {
		ret_code = inet_aton(host, &host_icmp->addr.sin_addr);
		if(ret_code == 0){
			logmsg(LOG_ERR, "inet_aton[%d]: %s", errno, strerror(errno));
			exit(1);
		}
	}

	/* 
	// verifi la validité de l'ip, mais c'est con, ca n'est valable que sur 
	// des reseau en /24 ....
	last = ntohl( taddr->sin_addr.s_addr ) & 0xFF;
	if(( last == 0x00 ) || ( last == 0xFF )){
		return -1;
	}
	*/

	// on a les infos ip ... 
	// il faut passer l'intervalle de temps en parametre
	// et chainer tout ça
}

/*************************************************************
  initialise le systee de ping
*************************************************************/
void ping_init(void){
	struct protoent *proto = NULL;
	const  proto_buf_len = 1024;
	char   proto_buf[proto_buf_len];
	struct protoent proto_datum;

#if defined(__GLIBC__) // for systems using GNU libc
	getprotobyname_r("icmp", &proto_datum, proto_buf, proto_buf_len, &proto);

#elif defined(sun) // Solaris 5++
	proto = getprotobyname_r("icmp", &proto_datum, proto_buf, proto_buf_len);

#elif defined(_AIX)
	probuf = (char*)malloc( 9000 );
	if(probuf == NULL){
		logmsg(LOG_ERR, "malloc(9000)[%d]: %s", errno, strerror(errno));
		exit(1);
	}
	rc  = getprotobyname_r("icmp", &proto,
	                       ( struct protoent_data *)(probuf + sizeof( struct protoent)));

#elif ( defined(hpux) || defined(__osf__) )
	proto = getprotobyname("icmp"); 

#else // simply hoping that get*byname is thread-safe
	proto = getprotobyname("icmp"); 
  
#endif

	// proto validity
	if(proto == NULL){
		logmsg(LOG_ERR, "proto == %s", NULL);
		exit(1);
	}

	// open socket
	sock_ping = socket( AF_INET, SOCK_RAW, proto->p_proto );
	if(sock_ping < 0 ){
  		logmsg(LOG_ERR, "socket[%d]: %s", errno, strerror(errno));
		exit(1);
	}
}

/*************************************************************
  envoi un ping
*************************************************************/
void send_ping(struct send_icmp *client){
	int ret_code;
	struct icmp *icp;
	unsigned char buf[ICMP_LEN];

	unsigned short  last;

	// prepare le paquet ICMP
	icp = (struct icmp *)buf;
	icp->icmp_type  = ICMP_ECHO;
	icp->icmp_code  = 0;
	icp->icmp_id    = htons(client->id);
	icp->icmp_seq   = htons(client->seq);
	/*
	#define  icmp_pptr      icmp_hun.ih_pptr
	#define  icmp_gwaddr    icmp_hun.ih_gwaddr
	#define  icmp_id        icmp_hun.ih_idseq.icd_id
	#define  icmp_seq       icmp_hun.ih_idseq.icd_seq
	#define  icmp_void      icmp_hun.ih_void
	#define  icmp_pmvoid    icmp_hun.ih_pmtu.ipm_void
	#define  icmp_nextmtu   icmp_hun.ih_pmtu.ipm_nextmtu
	#define  icmp_num_addrs icmp_hun.ih_rtradv.irt_num_addrs
	#define  icmp_wpa       icmp_hun.ih_rtradv.irt_wpa
	#define  icmp_lifetime  icmp_hun.ih_rtradv.irt_lifetime
	*/
	icp->icmp_cksum = 0; // le checksum doit etre calculé avec lui meme a 0
	icp->icmp_cksum = in_checksum((u_short *)icp, ICMP_LEN);

	// stocke le temps d'emmission
	gettimeofday(&client->sent_at, (struct timezone *)NULL); 

	// envoi le paquet icmp
	ret_code = sendto(sock_ping, buf, ICMP_LEN, 0,
	                  (struct sockaddr*)&client->addr, sizeof(client->addr));
	if(ret_code < 0 ){
		logmsg(LOG_ERR, "sendto[%d]: %s", errno, strerror(errno));
	}
	else if(ret_code != ICMP_LEN){
		logmsg(LOG_ERR, "sendto: wrong packet sent", "");
	}
}

/*************************************************************
  initialise le systee de ping
*************************************************************/
void recv_ping(void){
	int ret_code;
	unsigned char buf[ICMP_LEN];
	struct sockaddr_in from_addr;
	int from_len;
	struct icmp *icp;

	int response;
	int from;
	int nf, cc;
	struct ip          *ip;
	struct timeval to;
	fd_set readset;

	from_len = sizeof(from_addr);
	ret_code = recvfrom(sock_ping, buf, ICMP_LEN, 0,
	                    (struct sockaddr*)&from_addr, &from_len );
	if(ret_code < 0){
		logmsg(LOG_ERR, "recvfrom[%d]: %s", errno, strerror(errno));
		return;
	}

	icp = (struct icmp *)(buf + ICMP_LEN);

	// recherche qui a repondu

	// calcul le temps de reponse

	// retourne content

	//if( icp->icmp_id   != ( getpid() & 0xFFFF )){
	//  printf( "id: %d\n",  icp->icmp_id );
	//  return 1; 
	//}
}

/*
int myping( const char *hostname, int t , struct ping_priv * datum){
  int to;
  int err;
  int rrt;
  struct sockaddr_in sa;
  struct timeval mytime;
 
  datum->ident = getpid() & 0xFFFF;

  if( t == 0 ) datum->timo = 2; 
  else         datum->timo = t;

  datum->rrt = 0;
  
  (void) gettimeofday( &mytime, (struct timezone *)NULL); 
  if(( err = send_ping( hostname, &sa, datum)) < 0 ){
    close( datum->sock );
    return err;
  }
  do {
    rrt = elapsed_time( &mytime );
    if (datum->rrt < 0)
      return 0;
    datum->rrt = rrt;
    if (datum->rrt > datum->timo * 1000 ) {
      close( datum->sock );
      return 0;
    }
  } while( recv_ping( &sa, datum ));
  close( datum->sock ); 
 
  return 1;
}
*/


int main(int argc, char *argv[]){
	struct send_icmp *data1;
	struct send_icmp *data2;
	struct send_icmp *data3;
	/*
	struct ping_priv datum;
	datum.ident = IDENT_DEFAULT;
	datum.timo = TIMO_DEFAULT;
	*/

	data1 = ping_register("10.0.0.29");
	data2 = ping_register("bore");
	data3 = ping_register("10.0.3.2");
	ping_init();
	send_ping(data1);
	send_ping(data2);
	send_ping(data3);
}

