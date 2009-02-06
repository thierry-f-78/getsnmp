#ifndef __GETSNMP_H__
#define __GETSNMP_H__

#include <sys/time.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

// get pour chaque oid
struct oid_list {
	struct oid_list *next;

	// oid
	char * oidname;
	oid oid[MAX_OID_LEN];
	int oidlen;

	// flags de backend
	unsigned int backends;

	// base dans laquelle sera stocké les valeurs
	char *dbbase;

	// fichier dans lequel seront stockés les valeurs
	int rotate;
	char *prefix;
	char *filename;
	char *dataname;
	char *date_ptr;

	// valeurs pour rrdtool
	char *rrd_create[8];
	char *rrd_update[4];
	// type de donnée
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

	// activité du process
	//  0: en attente passive
	//  1: attente d'une reponse sur le net
	int actif;

	// next activity
	//   date a laquelle le processus devra etre
	//   reveillé
	struct timeval activ_date;

	// session snmp
	struct snmp_session *sess;

	// indique qu'une requete est en cours
	int * lock;
};


// current time
struct timeval current_t;

// config file
char *config_file;

// displaying configuration
extern int display_conf;

/* ptr on the first struct */
extern struct snmp_get *sched;

#define GETSNMP_RRD            0x00000001
#define GETSNMP_FILE           0x00000002
#define GETSNMP_DEFAULT        0x80000000
#define FREQ 100

#endif
