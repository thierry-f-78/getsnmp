#include "config.h"

#include <stdio.h>
#include <errno.h>
#include <sys/param.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include "getsnmp.h"
#include "loadconfig.h"
#include "expand.h"
#include "log.h"

/* nombre maximun d'arguments sur une ligne */
#define MAX_ARGS 50

/* taille du buffer de lecture ligne à ligne */
#define MAX_LEN 4096



/* comunnity par defaut */
static char def_community[] = "public";

/* rrd arguments and methods */
#define RRD_TYPE_GAUGE       "GAUGE"
#define RRD_TYPE_COUNTER     "COUNTER"
#define RRD_TYPE_DERIVE      "DERIVE"
#define RRD_TYPE_ABSOLUTE    "ABSOLUTE"
#define RRD_RRA_TYPE_AVERAGE "AVERAGE"
#define RRD_RRA_TYPE_MAX     "MAX"

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
	// buffer de lecture ligne à ligne
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
		char *filename;
	} cur_global = {
		.inter = 300,
		.community = def_community,
		.retry = 0,
		.timeout = 3,
		.version = SNMP_VERSION_1,
		.backends = GETSNMP_RRD | GETSNMP_DEFAULT,
		.rotate = 0,
		.prefix = NULL,
		.filename = NULL
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
		char *filename;
	} cur_base = {
		.ip = NULL,
		.community = NULL,
		.rotate = 0,
		.prefix = NULL,
		.filename = NULL
	};
	// config d'une recuperation snmp
	struct snmp_get cur_snmp;
	struct snmp_get *snmpget;
	// liste d'oid;
	//struct oid_list *oidlist;
	struct oid_list cur_oid, *tmp_oid;
	// structure permettant l'ouverture de la session snmp
	struct snmp_session sess;
	// pointeur sur le verrous partagé
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
					// on a depassé la limite
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

			/* get global data filename */
			else if(strcmp("filename", args[1])==0){
				if(arg < 3){
					logmsg(LOG_ERR, 
					       "file %s, line %d: global filename: "
					       "value not found",
					       config_file, ligne);
					goto end_parse_error;
				}
				cur_global.filename = strdup(args[2]);
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

			/* inherit global filename */
			if (cur_global.filename != NULL)
				cur_base.filename = strdup(cur_global.filename);
			else
				cur_base.filename = NULL;

			i = 1;
			while(i < arg){
				// recupere la version du proto souhaitée
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

				/* host data filename */
				else if(strcmp("filename", args[i])==0){
					if(arg <= i + 1) {
						logmsg(LOG_ERR, 
						       "file %s, line %d: filename: value not found",
						       config_file, ligne);
						goto end_parse_error;
					}
					if ( cur_base.filename != NULL) {
						free(cur_base.filename);
					}
					cur_base.filename = strdup(args[i+1]);
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

		// defini une valeur a recupérer
		// get router oid SNMPv2-MIB::sysDescr.0 inter
		//  5 file router.sysDescr.db
		else if(strcmp("get", args[0]) == 0){

			// controle d'integrité - valeurs par defaut
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
			// positionne la communauté
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
			cur_oid.rrd_type = RRD_TYPE_GAUGE;
			// flags backend
			cur_oid.backends = cur_base.backends | GETSNMP_DEFAULT;
			// initialise le fichier
			cur_oid.dbbase = NULL;

			/* inherit host filename */
			if (cur_base.filename != NULL)
				cur_oid.filename = strdup(cur_base.filename);
			else
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
				// recupere l'oid demandé
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

				// recupère le timeout
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
		
				// recupère le retry
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

		
				// recupère l'intervalle entre deux checks
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
					if (cur_oid.filename != NULL)
						free(cur_oid.filename);
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

				// type de données rrdtool
				else if(strcmp("type", args[i]) == 0){
					if(arg <= i + 1){
						logmsg(LOG_ERR, 
						       "file %s, line %d: type: value not found",
						       config_file, ligne);
						goto end_parse_error;
					}
					if(strcmp("gauge", args[i+1]) == 0)
						cur_oid.rrd_type = RRD_TYPE_GAUGE;
					else if(strcmp("counter", args[i+1]) == 0)
						cur_oid.rrd_type = RRD_TYPE_COUNTER;
					else if(strcmp("derive", args[i+1]) == 0)
						cur_oid.rrd_type = RRD_TYPE_DERIVE;
					else if(strcmp("absolute", args[i+1]) == 0)
						cur_oid.rrd_type = RRD_TYPE_ABSOLUTE;
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

			// étend le nom et l'oid
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
				// les meme qualités
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



			/* build datafile name if needed */
			if ((tmp_oid->backends & GETSNMP_FILE) != 0) {

				/* if filename is not declared, build default datafile name */
				if(tmp_oid->filename == NULL){

					/* the default name is peername_oidname */
					snprintf(buf, MAX_LEN, "%s_%s.log",
					         snmpget->sess->peername, tmp_oid->oidname);

					/*	remove oid ambiguous character (: and /) */
					parse = buf;
					while (*parse != 0) {
						if (*parse == ':' || *parse == '/')
							*parse='_';
						parse++;
					}
					tmp_oid->filename = strdup(buf);
				} 
	
				/* set default dataname */
				if (tmp_oid->dataname == NULL)
					tmp_oid->dataname = strdup(tmp_oid->oidname);
	
				/* if rotation required, suffix filename with the rotation tag */
				if (tmp_oid->rotate != FALSE) {
					snprintf(buf, MAX_LEN, "%s.\1YYYmmddHHMMSS.log", tmp_oid->filename);
					free(tmp_oid->filename);
					tmp_oid->filename = strdup(buf);
				}

				/* prefix filename with prefix if needed */
				if (tmp_oid->prefix != NULL) {
					snprintf(buf, MAX_LEN, "%s_%s",
					         tmp_oid->prefix, tmp_oid->filename);
					free(tmp_oid->filename);
					tmp_oid->filename = strdup(buf);
				}

				/* prefix filename with data path */
				snprintf(buf, MAX_LEN, "%s/%s",
				         config[CF_DIRDB].valeur.string, tmp_oid->filename);
				free(tmp_oid->filename);
				tmp_oid->filename = strdup(buf);
	
				/* if rotation required, search and store the first character
				 * of rotation pattern */
				if (tmp_oid->rotate != FALSE) {
					for (j=0; tmp_oid->filename[j] != '\1'; j++);
					tmp_oid->date_ptr = &tmp_oid->filename[j];
				}
			}


#ifdef USE_RRD


			/* build defaultrrd tool database name */
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

			/* build rrdtool commands for database initilizing */

			/* commans create */
			tmp_oid->rrd_create[0] = "rrdcreate";

			/* the database file */
			tmp_oid->rrd_create[1] = tmp_oid->dbbase;

			/* data step */
			snprintf(buf, MAX_LEN, "-s %d", snmpget->inter);
			tmp_oid->rrd_create[2] = strdup(buf);

			/* init DS: DataSource */
			snprintf(buf, MAX_LEN, "DS:value:%s:%d:U:U",
			         tmp_oid->rrd_type, snmpget->inter * 2);
			tmp_oid->rrd_create[3] = strdup(buf);

			/* automatic choose average method */ 
			if(tmp_oid->rrd_type == rrd_type_gauge)
				parse = rrd_rra_type_max;
			else
				parse = rrd_rra_type_average;



			/* init RRA: Roud Robin Archives */

			/* 2 days average:
			 * use 1 primary data point (DS) for 1 RRA consolidated data point
			 * use 
			 *   ( 2 days * 24 hour * 60 minuts * 60 seconds ) /
			 *   ( 1 * "cur_snmp->inter" )
			 */
			snprintf(buf, MAX_LEN, "RRA:%s:0.5:1:%d",
			         parse, ( 2 * 24 * 60 * 60 ) / ( 1 * snmpget->inter ));
			tmp_oid->rrd_create[4] = strdup(buf);

			/* 2 weeks average:
			 * use 6 primary data point (DS) for 1 RRA consolidated data point
			 * use
			 *   ( 14 days * 24 hours * 60 minuts * 60 seconds ) /
			 *   ( 6 * "cur_snmp->inter" )
			 */
			snprintf(buf, MAX_LEN, "RRA:%s:0.5:6:%d",
			         parse, ( 14 * 24 * 60 * 60 ) / ( 6 * snmpget->inter ));
			tmp_oid->rrd_create[5] = strdup(buf);

			/* 2months average:
			 * use 24 primary data point (DS) for 1 RRA consolidated data point
			 *   ( 62 days * 24 hours * 60 minuts * 60 seconds ) /
			 *   ( 24 * "cur_snmp->inter" )
			 */
			snprintf(buf, MAX_LEN, "RRA:%s:0.5:24:%d",
			         parse, ( 62 * 24 * 60 * 60 ) / ( 24 * snmpget->inter));
			tmp_oid->rrd_create[6] = strdup(buf);
		
			/* mark end */
			tmp_oid->rrd_create[7] = NULL;



			/* initialize rrdtool command for update data */

			/* initilise rrdtool for update base */
			tmp_oid->rrd_update[0] = "rrdupdate";

			/* data file */
			tmp_oid->rrd_update[1] = tmp_oid->dbbase;

			/* ptr for data */
			tmp_oid->rrd_update[2] = NULL;

			/* mark end */
			tmp_oid->rrd_update[3] = NULL;


#endif /* USE_RRD */


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
	if (cur_base.filename != NULL) {
		free(cur_base.filename);
		cur_base.filename = NULL;
	}
	if (cur_global.filename != NULL) {
		free(cur_global.filename);
		cur_global.filename = NULL;
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
			printf("   %s  |- OID      : [", b);
			for (i=0; i<roid->oidlen; i++) {
				if (i>0)
					printf(".");
				printf("%ld", roid->oid[i]);
			}
			id++;
			printf("]\n");

			printf("   %s  |- BACKENDS : [", b);
			if((roid->backends & GETSNMP_FILE) != 0)
				printf("FILE");
			if((roid->backends & GETSNMP_FILE) != 0 &&
			   (roid->backends & GETSNMP_RRD) != 0)
				printf(",");
			if((roid->backends & GETSNMP_RRD) != 0)
				printf("RRDTOOL");
			printf("]\n");

			if (roid->rotate==1)
				tmp = "yes";
			else
				tmp = "no";
			printf("   %s  |- ROTATE   : %d (%s)\n", b, roid->rotate, tmp);
			if (roid->prefix == NULL)
				tmp = "";
			else
				tmp = roid->prefix;
			printf("   %s  |- PREFIX   : \"%s\"\n", b, tmp);
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

