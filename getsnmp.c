/* 
 * getsnmp (c) Thierry FOURNIER
 * $Id$
 *
 * un scheduleur qui permet de recup�rer du snmp et de le mettre dans les db berkeley
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
#include "loadconfig.h"
#include "expand.h"

#define FREQ 100

#define GETSNMP_RRD            0x00000001
#define GETSNMP_FILE           0x00000002
#define GETSNMP_DEFAULT        0x80000000

// get pour chaque oid
struct oid_list {
	struct oid_list *next;

	// oid
	char * oidname;
	oid oid[MAX_OID_LEN];
	int oidlen;

	// flags de backend
	unsigned int backends;

	// base dans laquelle sera stock� les valeurs
	char *dbbase;

	// fichier dans lequel seront stock�s les valeurs
	int rotate;
	char *prefix;
	char *filename;
	char *dataname;
	char *date_ptr;

	// valeurs pour rrdtool
	char *rrd_create[8];
	char *rrd_update[4];
	// type de donn�e
	char *rrd_type;
};

// structure contenant un process au sens du scheduleur
struct snmp_get {
	// chain
	struct snmp_get *next;

	// oid
	struct oid_list *first_oid;
	int count_oids;

	// intervalle entre deux requetes
	int inter;

	// timeout sur une requete
	int timeout;

	// activit� du process
	//  0: en attente passive
	//  1: attente d'une reponse sur le net
	int actif;

	// next activity
	//   date a laquelle le processus devra etre
	//   reveill�
	struct timeval activ_date;

	// session snmp
	struct snmp_session *sess;

	// indique qu'une requete est en cours
	int * lock;
};

// pointeur sur la premiere structure
struct snmp_get *sched = NULL;

// pointe sur les erreurs
extern int errno;

// displaying configuration
extern int display_conf;

// nombre maximun d'arguments sur une ligne
#define MAX_ARGS 50
// taille du buffer de lecture ligne � ligne
#define MAX_LEN 4096
// comunnity par defaut
static char * def_community = "public";
static char * rrd_type_gauge = "GAUGE";
static char * rrd_type_counter = "COUNTER";
static char * rrd_type_derive = "DERIVE";
static char * rrd_type_absolute = "ABSOLUTE";
static char * rrd_rra_type_average = "AVERAGE";
static char * rrd_rra_type_max = "MAX";

#define DUMP_CONFIG_BLEN 1024
void dump_config(void) {
	struct snmp_get *run;
	struct oid_list *roid;
	char buffer[DUMP_CONFIG_BLEN];
	char *tmp, *c, *b;
	int count = 0;
	int id;
	int i;

	// run all scheduled processes
	for (run = sched;
	     run != NULL;
	     run = run->next) {
		printf("[-] RETRIEVE BLOC %d\n", count);
		printf(" |- INTERVAL    : %d\n", run->inter);
		printf(" |- TIMEOUT     : %d\n", run->timeout);
		printf(" |- RETRIES     : %d\n", run->sess->retries);
		switch(run->sess->version) {
			case SNMP_VERSION_1:  tmp = "v1";      break;
			case SNMP_VERSION_2u: tmp = "v2";      break;
			case SNMP_VERSION_2c: tmp = "v2c";     break;
			case SNMP_VERSION_3:  tmp = "v3";      break;
			default:              tmp = "unknown"; break;
		}
		printf(" |- VERSION     : %s (%ld)\n", tmp, run->sess->version);
		printf(" |- CLIENT      : \"%s\"\n", run->sess->peername);
		printf(" |- PORT        : %d\n", run->sess->remote_port);
		strncpy(buffer, (char *)run->sess->community, run->sess->community_len);
		buffer[run->sess->community_len] = 0;
		printf(" |- COMMUNITY   : \"%s\"\n", buffer);
		printf(" +- OID LIST : %d\n", run->count_oids);

		id = 0;
		for (roid = run->first_oid;
		     roid != NULL;
		     roid = roid->next) {

			if (id + 1 == run->count_oids) {
				c = "+";
				b = " ";
			} else {
				c = "|";
				b = "|";
			}

			printf("   %s- OID %d\n", c, id);
			printf("   %s  |- NAME     : \"%s\"\n", b, roid->oidname);
			printf("   %s  |- OID      : ", b);
			for (i=0; i<roid->oidlen; i++)
				printf(".%ld", roid->oid[i]);
			id++;
			printf("\n");
			if (roid->rotate==1)
				tmp = "yes";
			else
				tmp = "no";
			printf("   %s  |- ROTATE   : %s\n", b, tmp);
			if (roid->prefix == NULL)
				tmp = "<INFORMATION MISSED>";
			else
				tmp = roid->prefix;
			printf("   %s  |- PREFIX   : \"%s\"\n", b, roid->prefix);
			printf("   %s  |- FILENAME : \"%s\"\n", b, roid->filename);
			printf("   %s  |- DATANAME : \"%s\"\n", b, roid->dataname);
			printf("   %s  +- RRDTYPE  : \"%s\"\n", b, roid->rrd_type);
			printf("   %s\n", b);
		}

		printf("\n");
		count++;
	}

	exit(0);
}

/* Parse le fichier de conf
 *
 * fichier a parser en parametre
 * retourne 0 si ok, -1 si erreur
 */
int parse_conf(char *conf_file, void *snmp_callback){
	// descriptor of config file
	FILE *file;
	// contain args on each line
	char *args[MAX_ARGS];
	// buffer de lecture ligne � ligne
	char buf[MAX_LEN];
	// incremente args;
	int arg;
	// pointeur sur le caractere courant
	char *parse;
	// flag qui indique le parsing recent d'un caractere nul
	unsigned char blank;
	// compte les lignes
	int ligne = 0;
	// comteur usuel
	int i, nul, j;
	// used for error storage
	char *error;
	// pour bricoler
	char buff[MAXPATHLEN+1];
	// base de configuration globale
	struct {
		int inter;
		char *community;
		int retry;
		int timeout;
		int version;
		unsigned int backends;
		int rotate;
		char *prefix;
	} cur_global = {
		.inter = 300,
		.community = def_community,
		.retry = 0,
		.timeout = 3,
		.version = SNMP_VERSION_1,
		.backends = GETSNMP_RRD | GETSNMP_DEFAULT,
		.rotate = 0,
		.prefix = NULL
	};
	// base de configuration par machine
	struct {
		char *ip;
		char *community;
		int version;
		int timeout;
		int retry;
		int inter;
		unsigned int backends;
		int rotate;
		char *prefix;
	} cur_base = {
		.ip = NULL,
		.community = NULL,
		.rotate = 0,
		.prefix = NULL
	};
	// config d'une recuperation snmp
	struct snmp_get cur_snmp;
	struct snmp_get *snmpget;
	// liste d'oid;
	//struct oid_list *oidlist;
	struct oid_list cur_oid, *tmp_oid;
	// structure permettant l'ouverture de la session snmp
	struct snmp_session sess;
	// pointeur sur le verrous partag�
	int *lock;
	// valeur de retour
	int return_val = 1;
	// pour l'expanssion des noms
	struct expcell *names;

	file = fopen(conf_file, "r");
	if(file == NULL){
		logmsg(LOG_ERR,
		       "[%s %d] fopen(%s, \"r\"): %s",
		       __FILE__, __LINE__,
		       conf_file, strerror(errno));
		return(-1);
	}

	while(feof(file) == 0){
		bzero(buf, MAX_LEN);
		fgets(buf, MAX_LEN, file);
		ligne ++;
		
		// retourne la liste des arguments
		arg = 0;
		bzero(args, sizeof(char *) * MAX_ARGS);
		blank = 1;
		parse = buf;
		while(*parse != 0){
			// caractere nul:
			if(*parse == ' ' || *parse == '\t'){
				*parse = 0;
				blank = 1;
				parse ++;
			}

			// caracteres final (on quitte la boucle)
			else if( *parse == '#' || *parse == '\n' || *parse == '\r'){
				*parse = 0;
				break;
			}

			// autres caracteres
			else {
				if(blank == 1){
					args[arg] = parse;
					arg ++;
					// on a depass� la limite
					if(arg == MAX_ARGS) {
						logmsg(LOG_ERR, 
						       "file %s, ligne %d: max args number exceed",
						       config_file, ligne);
						goto end_parse_error;
					}
					blank = 0;
				}
				parse ++;
			}
		}

		// traite la liste des arguments
		if(arg == 0) continue;

		/////////////////////////////////////////////////////////////
		// G L O B A L    C O N F
		/////////////////////////////////////////////////////////////
		i = 0;
		while(i < NUM_PARAMS){
			if(strcmp(config[i].attrib, args[0]) == 0){
				if(arg < 2){
					logmsg(LOG_ERR, 
					       "file %s, line %d: %s: value not found",
					       config_file, ligne, args[0]);
					goto end_parse_error;
				}
				switch(config[i].type){
					case 0:
						config[i].valeur.string = strdup(args[1]);
						break;
						
					case 1:
						config[i].valeur.integer = convert_int(args[1]);
						break;
						
					case 2:
						config[i].valeur.integer = convert_boolean(args[1]);
						if ( config[i].valeur.integer == ERROR ) {
							logmsg(LOG_ERR,
							       "file %s, line %d: %s: invalid value for boolean (%s)",
							       config_file, ligne, args[0], args[1]);
							goto end_parse_error;
						}
						break;

					case 3:
						config[i].valeur.integer = convert_octal(args[1]);
						break;

					default:
						logmsg(LOG_ERR, 
						       "file %s, line %d: %s: unknown option",
						       config_file, ligne, args[0]);
						goto end_parse_error;
				}
			}
			i++;
		}
		
		// continue if argument found
		if(i < NUM_PARAMS){
			continue;
		}

		/////////////////////////////////////////////////////////////
		// G L O B A L
		/////////////////////////////////////////////////////////////

		// defini le repertoire qui stocke les DB
		if(strcmp("global", args[0]) == 0){
			if(arg < 2){
				logmsg(LOG_ERR, 
				       "file %s, line %d: value not found",
				       config_file, ligne);
				goto end_parse_error;
			}

			// ajoute un repertoire dans lequel rechercher des mibs
			else if(strcmp("mib_directory", args[1])==0){
				if(arg < 3){
					logmsg(LOG_ERR, 
					       "file %s, line %d: global mib_directory: "
					       "value not found",
					       config_file, ligne);
					goto end_parse_error;
				}
				snprintf(buff, MAXPATHLEN+1, "+%s", args[2]);
				netsnmp_set_mib_directory(buff);
				shutdown_mib();
				init_mib();
			}
			
			// recupere la community par defaut pour toutes les instances
			else if(strcmp("community", args[1])==0){
				if(arg < 3){
					logmsg(LOG_ERR, 
					       "file %s, line %d: global community: "
					       "value not found",
					       config_file, ligne);
					goto end_parse_error;
				}
				if(cur_global.community != def_community){
					free(cur_global.community);
				}
				cur_global.community = strdup(args[2]);
			}

			// recupere l'intervalle entre les requetes global
			else if(strcmp("inter", args[1])==0){
				if(arg < 3){
					logmsg(LOG_ERR, 
					       "file %s, line %d: global inter: value not found",
					       config_file, ligne);
					goto end_parse_error;
				}
				cur_global.inter = atoi(args[2]);
			}

			// set global rotate
			else if(strcmp("rotate", args[1])==0){
				if(arg < 3){
					logmsg(LOG_ERR, 
					       "file %s, line %d: global rotate: value not found",
					       config_file, ligne);
					goto end_parse_error;
				}
				cur_global.rotate = convert_boolean(args[2]);
				if ( cur_global.rotate == ERROR ) {
					cur_global.rotate = convert_int(args[2]);
					/*
					logmsg(LOG_ERR, 
					       "file %s, line %d: global rotate: invalid value (%s)",
					       config_file, ligne, args[2]);
					goto end_parse_error;
					*/
				}
			}

			// set global prefix
			else if(strcmp("prefix", args[1])==0){
				if(arg < 3){
					logmsg(LOG_ERR, 
					       "file %s, line %d: global prefix: value not found",
					       config_file, ligne);
					goto end_parse_error;
				}
				cur_global.prefix = strdup(args[2]);
			}

			// recupere le nombre global de retry
			else if(strcmp("retry", args[1])==0){
				if(arg < 3){
					logmsg(LOG_ERR, 
					       "file %s, line %d: global retry: value not found",
					       config_file, ligne);
					goto end_parse_error;
				}
				cur_global.retry = atoi(args[2]);
			}

			// recupere le timeout global
			else if(strcmp("timeout", args[1])==0){
				if(arg < 3){
					logmsg(LOG_ERR, 
					       "file %s, line %d: global timeout: value not found",
					       config_file, ligne);
					goto end_parse_error;
				}
				cur_global.timeout = atoi(args[2]);
			}

			// recupere le timeout global
			else if(strcmp("version", args[1])==0){
				if(arg < 3){
					logmsg(LOG_ERR, 
					       "file %s, line %d: global version: value not found",
					       config_file, ligne);
					goto end_parse_error;
				}
				if(strcmp("v1", args[2]) == 0)
					cur_global.version = SNMP_VERSION_1;
				else if(strcmp("v2", args[2]) == 0)
					cur_global.version = SNMP_VERSION_2u;
				else if(strcmp("v2c", args[2]) == 0)
					cur_global.version = SNMP_VERSION_2c;
				else if(strcmp("v3", args[2]) == 0)
					cur_global.version = SNMP_VERSION_3;
				else {
					logmsg(LOG_ERR, 
					       "file %s, line %d: "
					       "SNMP protocol version \"%s\" unknown",
					       conf_file, ligne, args[i + 1]);
					goto end_parse_error;
				}
			}

			// positionne les backends
			else if(strcmp("backends", args[1])==0){
				if(arg < 3){
					logmsg(LOG_ERR,
					       "file %s, line %d: global backends: no backend defined",
					       conf_file, ligne);
					goto end_parse_error;
				}
				if((cur_global.backends & GETSNMP_DEFAULT) != 0){
					cur_global.backends = 0;
				}
				i = 2;
				while(i < arg){

					// positionne le backend rrd
					if(strcmp(args[i], "rrd")==0){
						cur_global.backends |= GETSNMP_RRD;
						#ifndef USE_RRD
						logmsg(LOG_ERR,
						       "file %s, line %d: the option \"backend rrd\" dont take effect (RRD unavailable)",
						       config_file, ligne);
						#endif
					}

					// positionne le backend file
					else if(strcmp(args[i], "file")==0){
						cur_global.backends |= GETSNMP_FILE;
					}

					// other: error
					else {
						logmsg(LOG_ERR,
						       "file %s, line %d: unknown backend: \"%s\"",
						       config_file, ligne, args[i]);
						goto end_parse_error;
					}

					// next
					i++;
				}
			}
			
			// si autre option: erreur
			else {
				logmsg(LOG_ERR, 
				       "file %s, line %d: attribut inconnu: %s",
				       config_file, ligne, args[1]);
				goto end_parse_error;
			}
		}

		/////////////////////////////////////////////////////////////
		// S E T
		/////////////////////////////////////////////////////////////

		// nouvelle def de machine
		// set <id> version <snmp proto vers> ip
		// <ip host> timeout <timeout secondes>
		else if(strcmp("set", args[0]) == 0){
			// verif de taille
			if(arg <= 2) {
				logmsg(LOG_ERR, 
				       "file %s, ligne %d: "
				       "minimun number of args are required",
				       config_file, ligne);
				goto end_parse_error;
			}
			if(cur_base.ip != NULL){
				free(cur_base.ip);
				cur_base.ip = NULL;
			}
			if(cur_base.community != NULL){
				free(cur_base.community);
			}
			lock = (int *)calloc(1, sizeof(int));

			// recup de la conf globale
			cur_base.retry = cur_global.retry;
			cur_base.timeout = cur_global.timeout;
			cur_base.inter = cur_global.inter;
			cur_base.version = cur_global.version;
			cur_base.community = strdup(cur_global.community);
			cur_base.backends = cur_global.backends | GETSNMP_DEFAULT;
			cur_base.prefix = cur_global.prefix;
			cur_base.rotate = cur_global.rotate;

			i = 1;
			while(i < arg){
				// recupere la version du proto souhait�e
				if(strcmp("version", args[i])==0){
					if(arg <= i + 1) {
						logmsg(LOG_ERR, 
						       "file %s, line %d: version: value not found",
						       config_file, ligne);
						goto end_parse_error;
					}
					if(strcmp("v1", args[i+1]) == 0)
						cur_base.version = SNMP_VERSION_1;
					else if(strcmp("v2", args[i+1]) == 0)
						cur_base.version = SNMP_VERSION_2u;
					else if(strcmp("v2c", args[i+1]) == 0)
						cur_base.version = SNMP_VERSION_2c;
					else if(strcmp("v3", args[i+1]) == 0)
						cur_base.version = SNMP_VERSION_3;
					else {
						logmsg(LOG_ERR, 
						       "file %s, line %d: "
						       "SNMP protocol version \"%s\" unknown",
						       config_file, ligne, args[i + 1]);
						goto end_parse_error;
					}
					i += 2;
				}

				// positionne les backends
				else if(strcmp("backend_rrd", args[i])==0){
					if((cur_base.backends & GETSNMP_DEFAULT) != 0){
						cur_base.backends = 0;
					}
					#ifndef USE_RRD
					logmsg(LOG_ERR,
					       "file %s, line %d: the option \"backend_rrd\" dont take effect (RRD unavailable)",
					       config_file, ligne);
					#endif
					cur_base.backends |= GETSNMP_RRD;
					i++;
				}
				else if(strcmp("backend_file", args[i])==0){
					if((cur_base.backends & GETSNMP_DEFAULT) != 0){
						cur_base.backends = 0;
					}
					cur_base.backends |= GETSNMP_FILE;
					i++;
				}

				// rotate option
				else if(strcmp("rotate", args[i])==0){
					if(arg <= i + 1) {
						logmsg(LOG_ERR, 
						       "file %s, line %d: rotate: value not found",
						       config_file, ligne);
						goto end_parse_error;
					}
					cur_base.rotate = convert_boolean(args[i+1]);
					if(cur_base.rotate == ERROR) {
						cur_global.rotate = convert_int(args[2]);
						/*
						logmsg(LOG_ERR, 
						       "file %s, line %d: rotate: invalid value (%s)",
						       config_file, ligne, args[i+1]);
						goto end_parse_error;
						*/
					}
					i += 2;
				}

				// prefix option
				else if(strcmp("prefix", args[i])==0){
					if(arg <= i + 1) {
						logmsg(LOG_ERR, 
						       "file %s, line %d: prefix: value not found",
						       config_file, ligne);
						goto end_parse_error;
					}
					if ( cur_base.prefix != NULL) {
						free(cur_base.prefix);
					}
					cur_base.prefix = strdup(args[i+1]);
					i += 2;
				}

				// recupere l'ip de la machine
				else if(strcmp("ip", args[i])==0){
					if(arg <= i + 1) {
						logmsg(LOG_ERR, 
						       "file %s, line %d: ip: value not found",
						       config_file, ligne);
						goto end_parse_error;
					}
					cur_base.ip = strdup(args[i+1]);
					i += 2;
				}

				// recupere l'intervalle par defaut pour cette machine
				else if(strcmp("inter", args[i])==0){
					if(arg <= i + 1){ 
						logmsg(LOG_ERR, 
						       "file %s, line %d: inter: value not found",
						       config_file, ligne);
						goto end_parse_error;
					}
					cur_base.inter = atoi(args[i+1]);
					i += 2;
				}

				// recupere le timeout
				else if(strcmp("timeout", args[i])==0){
					if(arg <= i + 1){ 
						logmsg(LOG_ERR, 
						       "file %s, line %d: timeout: value not found",
						       config_file, ligne);
						goto end_parse_error;
					}
					cur_base.timeout = atoi(args[i+1]);
					i += 2;
				}

				// recupere le nombre de retry avant expiration
				else if(strcmp("retry", args[i])==0){
					if(arg <= i + 1){ 
						logmsg(LOG_ERR, 
						       "file %s, line %d: retry: value not found",
						       config_file, ligne);
						goto end_parse_error;
					}
					cur_base.retry = atoi(args[i+1]);
					i += 2;
				}

				// recupere la community
				else if(strcmp("community", args[i])==0){
					if(arg <= i + 1){
						logmsg(LOG_ERR, 
						       "file %s, line %d: community: value not found",
						       config_file, ligne);
						goto end_parse_error;
					}
					cur_base.community = strdup(args[i+1]);
					i += 2;
				}

				// genere une erreur
				else {
					logmsg(LOG_ERR, 
					       "file %s, line %d: attribute %s unknown",
					       config_file, ligne, args[i]);
					goto end_parse_error;
				}
			}
		}

		/////////////////////////////////////////////////////////////
		// G E T
		/////////////////////////////////////////////////////////////

		// defini une valeur a recup�rer
		// get router oid SNMPv2-MIB::sysDescr.0 inter
		//  5 file router.sysDescr.db
		else if(strcmp("get", args[0]) == 0){

			// controle d'integrit� - valeurs par defaut
			if(cur_base.ip == NULL){
				logmsg(LOG_ERR, 
				       "file %s, line %d: IP address not found",
				       config_file, ligne);
				goto end_parse_error;
			}

			// initialise le systeme
			snmp_sess_init(&sess);
			// positionne la version
			sess.version = cur_base.version;
			// positionne la communaut�
			sess.community = (u_char *)strdup(cur_base.community);
			sess.community_len = strlen(cur_base.community);
			// positionne l'adresse IP
			sess.peername = strdup(cur_base.ip);
			// positionne le callback
			sess.callback = snmp_callback;
			// positionne le timeout
			sess.timeout = cur_base.timeout * 1000000;
			sess.retries = cur_base.retry;
	
			cur_snmp.lock = lock;
			cur_snmp.timeout = cur_base.timeout;
			cur_snmp.actif = 0;
			cur_snmp.first_oid = NULL;
			// default value for inter
			cur_snmp.inter = cur_base.inter;
			// default value for inter
			cur_oid.rrd_type = rrd_type_gauge;
			// flags backend
			cur_oid.backends = cur_base.backends | GETSNMP_DEFAULT;
			// initialise le fichier
			cur_oid.dbbase = NULL;
			cur_oid.filename = NULL;
			cur_oid.dataname = NULL;
			if(cur_base.prefix != NULL) {
				cur_oid.prefix = strdup(cur_base.prefix);
			} else {
				cur_oid.prefix = NULL;
			}
			cur_oid.rotate = cur_base.rotate;
			
			i = 1;
			while(i < arg){
				// recupere l'oid demand�
				if(strcmp("oid", args[i]) == 0){
					if(arg <= i + 1){
						logmsg(LOG_ERR, 
						       "file %s, line %d: oid: value not found",
						       config_file, ligne);
						goto end_parse_error;
					}
					cur_oid.oidname = strdup(args[i+1]);
					i += 2;
				}

				// positionne les backends
				else if(strcmp("backend_rrd", args[i])==0){
					if((cur_oid.backends & GETSNMP_DEFAULT) != 0){
						cur_oid.backends = 0;
					}
					#ifndef USE_RRD
					logmsg(LOG_ERR,
					       "file %s, line %d: the option \"backend_rrd\" dont take effect (RRD unavailable)",
					       config_file, ligne);
					#endif
					cur_oid.backends |= GETSNMP_RRD;
					i++;
				}
				else if(strcmp("backend_file", args[i])==0){
					if((cur_oid.backends & GETSNMP_DEFAULT) != 0){
						cur_oid.backends = 0;
					}
					cur_oid.backends |= GETSNMP_FILE;
					i++;
				}

				// rotate option
				else if(strcmp("rotate", args[i])==0){
					if(arg <= i + 1) {
						logmsg(LOG_ERR, 
						       "file %s, line %d: rotate: value not found",
						       config_file, ligne);
						goto end_parse_error;
					}
					cur_oid.rotate = convert_boolean(args[i+1]);
					if(cur_oid.rotate == ERROR) {
						cur_global.rotate = convert_int(args[2]);
					}
					i += 2;
				}

				// prefix option
				else if(strcmp("prefix", args[i])==0){
					if(arg <= i + 1) {
						logmsg(LOG_ERR, 
						       "file %s, line %d: prefix: value not found",
						       config_file, ligne);
						goto end_parse_error;
					}
					if ( cur_oid.prefix != NULL) {
						free(cur_oid.prefix);
					}
					cur_oid.prefix = strdup(args[i+1]);
					i += 2;
				}

				// recup�re le timeout
				else if(strcmp("timeout", args[i]) == 0){
					if(arg <= i + 1){
						logmsg(LOG_ERR, 
						       "file %s, line %d: timeout: value not found",
						       config_file, ligne);
						goto end_parse_error;
					}
					sess.timeout = atoi(args[i+1]) * 1000000;
					i += 2;
				}
		
				// recup�re le retry
				else if(strcmp("retry", args[i]) == 0){
					if(arg <= i + 1){
						logmsg(LOG_ERR, 
						       "file %s, line %d: retry: value not found",
						       config_file, ligne);
						goto end_parse_error;
					}
					sess.retries = atoi(args[i+1]);
					i += 2;
				}

		
				// recup�re l'intervalle entre deux checks
				else if(strcmp("inter", args[i]) == 0){
					if(arg <= i + 1){
						logmsg(LOG_ERR, 
						       "file %s, line %d: inter: value not found",
						       config_file, ligne);
						goto end_parse_error;
					}
					cur_snmp.inter = atoi(args[i+1]);
					i += 2;
				}

				// get rrd database name
				else if(strcmp("file", args[i]) == 0){
					if(arg <= i + 1){
						logmsg(LOG_ERR, 
						       "file %s, line %d: file: value not found",
						       config_file, ligne);
						goto end_parse_error;
					}
					cur_oid.dbbase = strdup(args[i+1]);
					i += 2;
				}

				// get log file name
				else if(strcmp("filename", args[i]) == 0){
					if(arg <= i + 1){
						logmsg(LOG_ERR, 
						       "file %s, line %d: filename: value not found",
						       config_file, ligne);
						goto end_parse_error;
					}
					cur_oid.filename = strdup(args[i+1]);
					i += 2;
				}

				// get data name
				else if(strcmp("dataname", args[i]) == 0){
					if(arg <= i + 1){
						logmsg(LOG_ERR, 
						       "file %s, line %d: dataname: value not found",
						       config_file, ligne);
						goto end_parse_error;
					}
					cur_oid.dataname = strdup(args[i+1]);
					i += 2;
				}

				// type de donn�es rrdtool
				else if(strcmp("type", args[i]) == 0){
					if(arg <= i + 1){
						logmsg(LOG_ERR, 
						       "file %s, line %d: type: value not found",
						       config_file, ligne);
						goto end_parse_error;
					}
					if(strcmp("gauge", args[i+1]) == 0)
						cur_oid.rrd_type = rrd_type_gauge;
					else if(strcmp("counter", args[i+1]) == 0)
						cur_oid.rrd_type = rrd_type_counter;
					else if(strcmp("derive", args[i+1]) == 0)
						cur_oid.rrd_type = rrd_type_derive;
					else if(strcmp("absolute", args[i+1]) == 0)
						cur_oid.rrd_type = rrd_type_absolute;
					else {
						logmsg(LOG_ERR, 
						       "file %s, line %d: "
						       "rrdtool data type \"%s\" unknown",
						       config_file, ligne, args[i + 1]);
						goto end_parse_error;
					}
					#ifndef USE_RRD
					logmsg(LOG_ERR,
					       "file %s, line %d: the option \"type %s\" dont take effect (RRD unavailable)",
					       config_file, ligne, args[i+1]);
					#endif
					i += 2;
				}

				// genere une erreur
				else {
					logmsg(LOG_ERR, 
					       "file %s, line %d: attribute %s unknown",
					       config_file, ligne, args[i]);
					goto end_parse_error;
				}
			}

			// �tend le nom et l'oid
			names = expand_names(cur_oid.oidname, 
			                     cur_oid.dataname,
										cur_oid.filename,
										cur_oid.dbbase);
			if (names == NULL) {
				logmsg(LOG_ERR,
				       "file %s, line %d: expansion error",
				       config_file, ligne);
			}
			free(cur_oid.oidname);
			if(cur_oid.filename == NULL)
				free(cur_oid.filename);
			if(cur_oid.dataname == NULL)
				free(cur_oid.dataname);
			if(cur_oid.dbbase == NULL)
				free(cur_oid.dbbase);

			while(names != NULL) {

				// fin de parsing GET
				// check timeouts error
				if(sess.timeout > cur_snmp.inter * 1000000){
					logmsg(LOG_WARNING, 
					       "WARNING: [ %s -> %s ] timeout(%d) is biger then "
					       "get interval(%d)",
							 sess.peername, tmp_oid->oidname,
							 sess.timeout / 1000000, cur_snmp.inter);
				}

				// recherche une precedente structure presentant
				// les meme qualit�s
				snmpget = sched;
				while(snmpget != NULL){
					if(snmpget->inter == cur_snmp.inter &&
					   snmpget->timeout == cur_snmp.timeout &&
					   snmpget->lock == cur_snmp.lock &&
						// check if the structur is full
						snmpget->count_oids < config[CF_MAXOID].valeur.integer) {
						break;
					}
					snmpget = snmpget->next;
				}
	
				// create a new paquet of questions
				if(snmpget == NULL){
					// alloc
					snmpget = (struct snmp_get *)
					          calloc(1, sizeof(struct snmp_get));
					if(snmpget == NULL){
						logmsg(LOG_ERR, 
						       "[%s %d] calloc: %s",
						       __FILE__, __LINE__, strerror(errno));
						fclose(file);
						return(-1);
					}
					// copie des valeurs
					memcpy(snmpget, &cur_snmp, sizeof(struct snmp_get));
					snmpget->count_oids = 0;
	
					// chainage
					snmpget->next = sched;
					sched = snmpget;
	
					// passe en parametre l'objet lui meme
					sess.callback_magic = snmpget;
	
					// fin de parsing: ouvre la session
					snmpget->sess = snmp_open(&sess);
					if(snmpget->sess == NULL){
						snmp_error(&sess, &nul, &nul, &error);
						logmsg(LOG_ERR,
						       "[%s %d] snmp_open: %s",
						       __FILE__, __LINE__, error);
						return(-1);
					}
				}
	
				// create oid list node
				tmp_oid = (struct oid_list *)
				          calloc(1, sizeof(struct oid_list));
				memcpy(tmp_oid, &cur_oid, sizeof(struct oid_list));

				// check oid name
				tmp_oid->oidname = names->oid;
				tmp_oid->oidlen = sizeof(tmp_oid->oid) / 
				                  sizeof(tmp_oid->oid[0]);
				if(!read_objid(tmp_oid->oidname, tmp_oid->oid,
				               (size_t *)&tmp_oid->oidlen)){
					logmsg(LOG_ERR, 
					       "file %s, line %d: oid \"%s\" incorrect",
					       config_file, ligne, names->oid);
					goto end_parse_error;
				}

				// copy replicated data
				tmp_oid->filename = names->file;
				tmp_oid->dataname = names->name;
				tmp_oid->dbbase = names->rrd;

				// chain value
				tmp_oid->next = snmpget->first_oid;
				snmpget->first_oid = tmp_oid;
				snmpget->count_oids++;

				// next name
				names = names->next;
			}
		}
	}

	// passe d'initialisation de rrdtool
	snmpget = sched;
	while(snmpget != NULL){

		// parse tous les oids
		tmp_oid = snmpget->first_oid;
		while(tmp_oid != NULL){

			// gere le fichier de db par defaut;
			if(tmp_oid->dbbase == NULL){
				snprintf(buf, MAX_LEN, "%s_%s.db",
				         snmpget->sess->peername, tmp_oid->oidname);
				parse = buf;
				while(*parse != 0){
					if(*parse == ':'){
						*parse='_';
					}
					parse++;
				}
				tmp_oid->dbbase = strdup(buf);
			}

			snprintf(buf, MAX_LEN, "%s/%s",
			         config[CF_DIRDB].valeur.string, tmp_oid->dbbase);
			free(tmp_oid->dbbase);
			tmp_oid->dbbase = strdup(buf);

			// gere le fichier de file par defaut;
			if(tmp_oid->filename == NULL){
				if(tmp_oid->prefix != NULL){
					if(tmp_oid->rotate != FALSE){
						snprintf(buf, MAX_LEN, "%s_%s_%s.\1YYYmmddHHMMSS.log",
						         tmp_oid->prefix, snmpget->sess->peername, tmp_oid->oidname);
					} else {
						snprintf(buf, MAX_LEN, "%s_%s_%s.log",
						         tmp_oid->prefix, snmpget->sess->peername, tmp_oid->oidname);
					}
				} else {
					if(tmp_oid->rotate != FALSE){
						snprintf(buf, MAX_LEN, "%s_%s.\1YYYmmddHHMMSS.log",
						         snmpget->sess->peername, tmp_oid->oidname);
					} else {
						snprintf(buf, MAX_LEN, "%s_%s.log",
						         snmpget->sess->peername, tmp_oid->oidname);
					}
				}
				parse = buf;
				while(*parse != 0){
					if(*parse == ':'){
						*parse='_';
					}
					parse++;
				}
				tmp_oid->filename = strdup(buf);
			} 
			// si le nom de fichier est precis�, mais qu'on veut rotater
			else if (tmp_oid->rotate != FALSE) {
				snprintf(buf, MAX_LEN, "%s_\1YYYmmddHHMMSS.log", tmp_oid->filename);
				free (tmp_oid->filename);
				tmp_oid->filename = strdup(buf);
			}

			// ajoute le suffixe adequat si il doit y avoir de la rotation
			else if (tmp_oid->rotate != FALSE) {
				snprintf(buf, MAX_LEN, "%s.\1YYYmmddHHMMSS.log", tmp_oid->filename);
				free(tmp_oid->filename);
				tmp_oid->filename = strdup(buf);
			}

			// set default dataname
			if (tmp_oid->dataname == NULL)
				tmp_oid->dataname = tmp_oid->filename;

			// set data path
			snprintf(buf, MAX_LEN, "%s/%s",
			         config[CF_DIRDB].valeur.string, tmp_oid->filename);
			free(tmp_oid->filename);
			tmp_oid->filename = strdup(buf);

			// 
			if(tmp_oid->rotate != FALSE){
				j = 0;
				while(tmp_oid->filename[j] != '\1'){
					j++;
				}
				tmp_oid->date_ptr = &tmp_oid->filename[j];
			}

			// initialise rrdtool for create base
			tmp_oid->rrd_create[0] = "rrdcreate";

			// le fichier
			tmp_oid->rrd_create[1] = tmp_oid->dbbase;

			// donne l'espacement entre chaque donn�e entr�e
			snprintf(buf, MAX_LEN, "-s %d", snmpget->inter);
			tmp_oid->rrd_create[2] = strdup(buf);

			// initilize la source de donn�es
			snprintf(buf, MAX_LEN, "DS:value:%s:%d:U:U",
			         tmp_oid->rrd_type, snmpget->inter * 2);
			tmp_oid->rrd_create[3] = strdup(buf);

			// choix de la technique de moyennage
			if(tmp_oid->rrd_type == rrd_type_gauge)
				parse = rrd_rra_type_max;
			else
				parse = rrd_rra_type_average;

			// calcule de la moyenne pour 2 jours
			// 2 jours * 24 heures * 60 minutes * 60 secondes /
			// moyenne de 1 top de "cur_snmp->inter" chacun = 2 jours
			snprintf(buf, MAX_LEN, "RRA:%s:0.5:1:%d",
			         parse, ( 2 * 24 * 60 * 60 ) / ( 1 * snmpget->inter ));
			tmp_oid->rrd_create[4] = strdup(buf);

			// calcule de la moyenne pour 2 semaines
			// 14 jours * 24 heures * 60 minutes * 60 secondes /
			// moyenne de 6 top de "cur_snmp->inter" chacun = 14 jours
			snprintf(buf, MAX_LEN, "RRA:%s:0.5:6:%d",
			         parse, ( 14 * 24 * 60 * 60 ) / ( 6 * snmpget->inter ));
			tmp_oid->rrd_create[5] = strdup(buf);

			// calcul de la moyenne pour 2 mois
			// 62 jours * 24 heures * 60 minutes * 60 secondes /
			// moyenne de 24 top de "cur_snmp->inter" chacun = 62 jours
			snprintf(buf, MAX_LEN, "RRA:%s:0.5:24:%d",
			         parse, ( 62 * 24 * 60 * 60 ) / ( 24 * snmpget->inter));
			tmp_oid->rrd_create[6] = strdup(buf);
		
			// fin
			tmp_oid->rrd_create[7] = NULL;

			// initilise rrdtool for update base
			tmp_oid->rrd_update[0] = "rrdupdate";

			// le fichier
			tmp_oid->rrd_update[1] = tmp_oid->dbbase;

			tmp_oid->rrd_update[2] = NULL;
			tmp_oid->rrd_update[3] = NULL;

			tmp_oid = tmp_oid->next;
		}

		snmpget = snmpget->next;
	}

	return_val = 0;

	end_parse_error:
	if(return_val != 0) {
		return_val = -1;
	}

	// nettoyage de la memoire	
	if(cur_base.ip != NULL) {
		free(cur_base.ip);
		cur_base.ip = NULL;
	}
	if(cur_base.community != NULL) {
		free(cur_base.community);
		cur_base.community = NULL;
	}	
	if(cur_global.community != def_community) free(cur_global.community);

	fclose(file);

	// initilise le timer (prochaine requete)
	gettimeofday(&current_t, NULL);
	snmpget = sched;
	while(snmpget != NULL){
		snmpget->activ_date.tv_sec = current_t.tv_sec + 1;
		snmpget->activ_date.tv_usec = current_t.tv_usec +
		         ( ( random() % FREQ ) * (1000000 / FREQ));
		snmpget = snmpget->next;
	}
	return(return_val);
}

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

	// on deverouille le lock du groupe d�di� au serveur
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

		// si une socket en attente de snmp a braill�e ...
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
			// si un lock est pos�, on ne traite pas le process
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
		// le timeout est negatif, on le remet � 0 
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

