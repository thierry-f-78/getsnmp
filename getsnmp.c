/* 
 * getsnmp (c) Thierry FOURNIER
 * $Id$
 *
 * un scheduleur qui permet de recupérer du snmp et de le mettre dans les db berkeley
 *
 */

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#ifdef USE_RRD
#include <rrd.h>
#endif
#include <sys/param.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include "getsnmp.h"
#include "log.h"
#include "server.h"
#include "loadfile.h"
#include "loadconfig.h"
#include "expand.h"

// pointeur sur la premiere structure
struct snmp_get *sched = NULL;

// pointe sur les erreurs
extern int errno;

/* gere les reponses SNMP
 */
int asynch_response(int operation, struct snmp_session *sp, int reqid,
		    struct snmp_pdu *pdu, void *magic){

	struct snmp_get *host = (struct snmp_get *)magic;
	char buf[1024];
	struct variable_list *vp;
	int ix;
	#ifdef USE_RRD
	struct stat st;
	#endif
	struct oid_list *cur_oid;
	FILE *fd;
	int code_ret;
	unsigned int value;
	time_t last_date;
	struct tm *tm;
	char cur_date[15];

	// on deverouille le lock du groupe dédié au serveur
	*host->lock = 0;

	// on remet le process passif
	host->actif = 0;
	
	//printf("operation = %d\n",  operation);
	if (operation == NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE){
		if (pdu->errstat == SNMP_ERR_NOERROR) {

			// liste toutes les reponses
			vp = pdu->variables;
			while(vp){
				// recherche la definition d'oid correspondante au retour
				cur_oid = host->first_oid;
				while(cur_oid != NULL &&
				      memcmp(cur_oid->oid,
				             vp->name_loc,
				             vp->name_length * sizeof(oid)) != 0)
					cur_oid = cur_oid->next;

				if(cur_oid == NULL){
					logmsg(LOG_ERR,
					       "[%s %d] unknown oid",
					       __FILE__, __LINE__);
					break;
				}				

				/* #define ASN_BOOLEAN      ((u_char)0x01)
				 * #define ASN_INTEGER      ((u_char)0x02)
				 * #define ASN_BIT_STR      ((u_char)0x03)
				 * #define ASN_OCTET_STR       ((u_char)0x04)
				 * #define ASN_NULL      ((u_char)0x05)
				 * #define ASN_OBJECT_ID       ((u_char)0x06)
				 * #define ASN_SEQUENCE     ((u_char)0x10)
				 * #define ASN_SET          ((u_char)0x11)
				 *
				 * #define ASN_UNIVERSAL       ((u_char)0x00)
				 * #define ASN_APPLICATION     ((u_char)0x40)
				 * #define ASN_CONTEXT      ((u_char)0x80)
				 * #define ASN_PRIVATE      ((u_char)0xC0)
				 *
				 * #define ASN_PRIMITIVE       ((u_char)0x00)
				 * #define ASN_CONSTRUCTOR     ((u_char)0x20)
				 *
				 * #define ASN_LONG_LEN     (0x80)
				 * #define ASN_EXTENSION_ID    (0x1F)
				 * #define ASN_BIT8      (0x80)
				 */

				// recupere la valeur a stocker
				if(vp->val.integer == NULL){
					logmsg(LOG_ERR,
					       "error [%s] %s: type 0x%02x return NULL",
					       host->sess->peername, cur_oid->oidname, vp->type);
					snprintf(buf, sizeof(buf), "N:0");
					value = 0;
				} else {
					switch(vp->type){
						case ASN_OCTET_STR:
							logmsg(LOG_ERR,
							       "err type [0x%02x (string)]: %s",
							       vp->type, cur_oid->oidname);
							snprintf(buf, sizeof(buf), "N:0");
							value = 0;
							break;

						default:
							snprintf(buf, sizeof(buf),
							         "N:%u", (unsigned int)*vp->val.integer);
							value = (unsigned int)*vp->val.integer;
					}
				}

				#ifdef USE_RRD
				// ===========================================================
				// backend RRD
				// ===========================================================
				if((cur_oid->backends & GETSNMP_RRD) != 0){

					// balance la valeur dans une db rrdtool
					optind = 0;
					opterr = 0;
					rrd_clear_error();
					cur_oid->rrd_update[2] = buf;

					#ifdef DEBUG_SCHEDULER
					logmsg(LOG_DEBUG,
					       "store value for %s at %d.%d",
					       host->sess->peername,
					       current_t.tv_sec, current_t.tv_usec);
					#endif

					ix = rrd_update(3, cur_oid->rrd_update);
					if (rrd_test_error() || (ix != 0)) {
						logmsg(LOG_ERR,
						       "rrd_update %s: %s",
						       cur_oid->dbbase, rrd_get_error());

						// le fichier n'existe pas, on le cree
						ix = stat(cur_oid->dbbase, &st);
						if(ix == -1 && errno == ENOENT){
							// initilise rrd
							optind = 0;
							opterr = 0;
							rrd_clear_error();
							logmsg(LOG_ERR,
							       "Create db file: %s %s %s %s %s %s %s",
							       cur_oid->rrd_create[0],
							       cur_oid->rrd_create[1],
							       cur_oid->rrd_create[2],
							       cur_oid->rrd_create[3],
							       cur_oid->rrd_create[4],
							       cur_oid->rrd_create[5],
							       cur_oid->rrd_create[6]);

							ix = rrd_create(7, cur_oid->rrd_create);
							if (rrd_test_error() || (ix != 0)) {
								logmsg(LOG_ERR,
								       "rrd_create %s: %s",
								       cur_oid->dbbase, rrd_get_error());
								exit(1);
							}
						}
						ix = rrd_update(3, cur_oid->rrd_update);
					}
				}
				#endif

				// ===========================================================
				//  balance les valeurs dans un fichier
				// ===========================================================
				if((cur_oid->backends & GETSNMP_FILE) != 0){
					
					// conversion
					
					// open for append
					if(cur_oid->rotate != FALSE) {
						last_date = (time_t)current_t.tv_sec;
						last_date /= cur_oid->rotate;
						last_date *= cur_oid->rotate;
						tm = localtime(&last_date);
						snprintf(cur_date, 15, "%04d%02d%02d%02d%02d%02d",
						         tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
						         tm->tm_hour, tm->tm_min, tm->tm_sec);
						memcpy(cur_oid->date_ptr, cur_date, 14);
					}
					fd = fopen(cur_oid->filename, "a");
					if(fd == NULL){
						logmsg(LOG_ERR, "fopen(%s, \"a\")[%d]: %s",
						       cur_oid->filename, errno, strerror(errno));
						// exit(1);
					}

					// write values
					fprintf(fd, "%u %s %u\n", 
					        (unsigned int)current_t.tv_sec,
					        cur_oid->dataname,
					        (unsigned int)value);

					// close fd
					code_ret = fclose(fd);
					if(code_ret != 0){
						logmsg(LOG_ERR, "fclose(%s)[%d]: %s",
						       cur_oid->filename, errno, strerror(errno));
						// exit(1);
					}
					
				}

				
				// ===========================================================
				//  end of back ends
				// ===========================================================
				vp = vp->next_variable;
			}
		}

		else {
			vp = pdu->variables;
			ix = 1;
			while(vp != NULL && ix != pdu->errindex){
				vp = vp->next_variable;
				ix++;
			}
			if(vp != NULL){
				snprint_objid(buf, sizeof(buf), vp->name, vp->name_length);
			}
			else strcpy(buf, "(none)");
			logmsg(LOG_ERR,
			       "%s: %s: %s",
			       sp->peername, buf, snmp_errstring(pdu->errstat));
		}

		// next request in inter time;
		host->activ_date.tv_sec += host->inter;
	}

	else {
		logmsg(LOG_ERR, "%s get snmp timeout", sp->peername);

		// next request relative at curent hour
		host->activ_date.tv_sec = current_t.tv_sec + host->inter;
		host->activ_date.tv_usec = current_t.tv_usec;
	}

	return 1;
}

/* compare t& et t2
 * si t1 > t2 => 1
 * si t1 = t2 => 0
 * si t1 < t2 =>-1
 */
int time_comp(struct timeval *t1, struct timeval *t2){
	if(t1->tv_sec == t2->tv_sec &&
      t1->tv_usec == t2->tv_usec){
		return 0;
	}

	else if((
	           t1->tv_sec == t2->tv_sec &&
	           t1->tv_usec > t2->tv_usec
	        ) ||
	        (t1->tv_sec > t2->tv_sec)){
		return 1;
	}

	else{
		return -1;
	}
}

/* routine principale
 * contient le scheduler
 */
int main (int argc, char **argv){
	struct snmp_get *cur_snmp;
	int fds = 0;
	int block = 1;
	fd_set fdset;
	int flag_tmout_snmp;
	struct timeval timeout;
	struct timeval ecart;
	struct snmp_pdu *req;
	struct oid_list *cur_oid;
	int i;
	
	// recupere la date
	gettimeofday(&current_t, NULL);

	// init snmp system
	init_snmp("snmp");

	// default config file
	config_file = CONFIG_FILE;

	// init global default values and 
	// parse command line for fiond a config file
	config_load(argc, argv);
	
	// parse config file
	i = parse_conf(config_file, asynch_response);
	if(i == -1){
		exit(1);
	}

	// parse command line
	config_cmd(argc, argv);

	// dump configuration if needed
	if (display_conf == 1)
		dump_config();

	// initilization of log system
	initlog();

	// set application as daemon
	daemonize();

	// quit privileges and chroot
	separe();

	fds = 0;
	
	// on schedule
	while(1){
		// recupere la date
		gettimeofday(&current_t, NULL);

		// si une socket en attente de snmp a braillée ...
		if(fds){
			snmp_read(&fdset);
		}

		else if(flag_tmout_snmp==1){
			snmp_timeout();
		}

		// calcule le timeout et les actions
		timeout.tv_sec = 999999999;

		#ifdef DEBUG_SCHEDULER
		i=0;
		#endif

		cur_snmp = sched;
		while(cur_snmp != NULL){
			// si un lock est posé, on ne traite pas le process
			if(*cur_snmp->lock == 0) {

				// si l'heure actuelle est plus grande que l'heure de reveil
				// on balance la requete

				#ifdef DEBUG_SCHEDULER
				logmsg(LOG_DEBUG,
				       "0x%08x: time_comp(temps_courant, date_de_get) "
				       "= %d (-1: a < b, 1: a > b)",
				       &cur_snmp,
				       time_comp(&current_t, &cur_snmp->activ_date));
				#endif

				if(time_comp(&current_t, &cur_snmp->activ_date)==1){
					// gen the get
					req = snmp_pdu_create(SNMP_MSG_GET);
					cur_oid = cur_snmp->first_oid;
					while(cur_oid != NULL){
						snmp_add_null_var(req, cur_oid->oid, cur_oid->oidlen);
						cur_oid = cur_oid->next;
					}

					#ifdef DEBUG_SCHEDULER
					logmsg(LOG_DEBUG,
					       "SEND request to: %s",
					       cur_snmp->sess->peername);
					#endif

					// send the get
					if(!snmp_send(cur_snmp->sess, req)){
						snmp_perror("snmp_send");
						snmp_free_pdu(req);
					}

					// on verouille le process
					*cur_snmp->lock = 1;

					// on le positionne actif
					cur_snmp->actif = 1;
				}

				// prepare l'heure de sortie de la fonction
				// soustrait l'heure du prochain depart a l'heure actuelle
				ecart.tv_usec = cur_snmp->activ_date.tv_usec -
				                current_t.tv_usec;
				ecart.tv_sec = cur_snmp->activ_date.tv_sec -
				               current_t.tv_sec;
				if(ecart.tv_usec < 0){
					ecart.tv_usec += 1000000;
					ecart.tv_sec -= 1;
				}

				#ifdef DEBUG_SCHEDULER
				logmsg(LOG_DEBUG,
				       "process=%i: (date_de_get) %d.%d - "
				       "(date_courante)%d.%d = "
				       "(timeout)%d.%d", 
				       i, cur_snmp->activ_date.tv_sec,
				       cur_snmp->activ_date.tv_usec,
				       current_t.tv_sec, current_t.tv_usec,
				       ecart.tv_sec, ecart.tv_usec);
				i++;
				logmsg(LOG_DEBUG,
				       "comparaison (timeout calcule)%d.%d "
				       "<=> (plus petit timeout)%d.%d",
				       ecart.tv_sec, ecart.tv_usec,
				       timeout.tv_sec, timeout.tv_usec);
				#endif

				if(time_comp(&ecart, &timeout)==-1){
					timeout.tv_sec = ecart.tv_sec;
					timeout.tv_usec = ecart.tv_usec;
				}

				#ifdef DEBUG_SCHEDULER
				logmsg(LOG_DEBUG,
				       "plus petit timeout = %d.%d",
				       timeout.tv_sec, timeout.tv_usec);
				#endif

			} // fin du controle de verouillage

			// next
			cur_snmp = cur_snmp->next;
		}
		
		// resette le bitfield
		FD_ZERO(&fdset);

		// positionne les fdset du snmp
		snmp_select_info(&fds, &fdset, &ecart, &block);

		// on verifie si le timeout des requetes snmp 
		if(block == 0 && time_comp(&ecart, &timeout)==-1){
			timeout.tv_sec = ecart.tv_sec;
			timeout.tv_usec = ecart.tv_usec;
			flag_tmout_snmp = 1;
		} else {
			flag_tmout_snmp = 0;
		}

		// bloque
		timeout.tv_usec += (1000000 / FREQ); 

		// si suite a une tres grosse charge,
		// le timeout est negatif, on le remet à 0 
		if(timeout.tv_sec < 0 || timeout.tv_usec < 0){
			timeout.tv_usec = 0;
			timeout.tv_sec = 0;
		}

		if(timeout.tv_usec > 999999) {
			timeout.tv_sec += timeout.tv_usec / 1000000;
			timeout.tv_usec %= 1000000;
		}

		#ifdef DEBUG_SCHEDULER
		logmsg(LOG_DEBUG,
		       "select retournera dans: %d.%d",
		       timeout.tv_sec, timeout.tv_usec);
		#endif

		fds = select(fds, &fdset, NULL, NULL, &timeout);

		#ifdef DEBUG_SCHEDULER
		logmsg(LOG_DEBUG,
		       ">>>>>>>>>>>>>> "
		       "select return %d (<0: erreur, =0: timeout, >0: fd) "
		       "<<<<<<<<<<<<", fds);
		#endif

		if (fds < 0) {
			logmsg(LOG_ERR, "select: %s", strerror(errno));
			exit(1);
		}
	}

	return 0;
}

