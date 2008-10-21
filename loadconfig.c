/*
 * Copyright (c) 2005-2010 Thierry FOURNIER
 * $Id: loadconfig.c 317 2006-10-16 22:38:35Z thierry $
 *
 */

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "getsnmp.h"
#include "loadconfig.h"
#include "log.h"

char msg[4096];
int dump = 0;

void miseenforme(char*);
void miseenmemoire(char*);
void to_lower(char *);
char lowercase(char);
int convert_octal(char*);
int convert_int(char*);
int convert_boolean(char*);

void usage(){
	printf(
	"\n"
	"getsnmp\n"
	"    [-D log_level] [-v][-h][-d][-f config_file]\n"
	"\n"
	"    -D log level required\n"
	"    -f config file fir this session\n"
	"    -d run as daemon\n"
	"    -h this help\n"
	"    -v version\n"
	"\n");
	exit(1);
}

void config_load(int argc, char *argv[]){
	int i;

	/* loading default values */
	config[CF_DIRDB].type = 0;
	config[CF_DIRDB].attrib = "directorydb";
	config[CF_DIRDB].valeur.string = "./";
	
	config[CF_LOGFILE].type = 0;
	config[CF_LOGFILE].attrib = "logfile";
	config[CF_LOGFILE].valeur.string = NULL;
	
	config[CF_LOCKFILE].type = 0;
	config[CF_LOCKFILE].attrib = "lockfile";
	config[CF_LOCKFILE].valeur.string = PID_FILE;
	
	config[CF_DAEMON].type = 2;
	config[CF_DAEMON].attrib = "daemon";
	config[CF_DAEMON].valeur.integer = FALSE;
	
	config[CF_LOGLEVEL].type = 1;
	config[CF_LOGLEVEL].attrib = "loglevel";
	config[CF_LOGLEVEL].valeur.integer = 6;
	
	config[CF_USESYSLOG].type = 2;
	config[CF_USESYSLOG].attrib = "usesyslog";
	config[CF_USESYSLOG].valeur.integer = TRUE;
	
	config[CF_UMASK].type = 3;
	config[CF_UMASK].attrib = "umask";
	config[CF_UMASK].valeur.integer = 0133;

	config[CF_USER].type = 0;
	config[CF_USER].attrib = "user";
	config[CF_USER].valeur.string = NULL;

	config[CF_CHROOT].type = 0;
	config[CF_CHROOT].attrib = "chrootdir";
	config[CF_CHROOT].valeur.string = NULL;

	for(i=1; i<argc; i++){
		if(argv[i][0]=='-'){
			switch(argv[i][1]){

				case 'f':
					if(i+1 >= argc){
						fprintf(stderr, "Option -f without argument\n");
						usage();
					}
					i++;
					config_file = argv[i];
					break;
			}
		}
	}

}

void config_cmd(int argc, char *argv[]){
	int i;

	/* load command line parameters 
	 * (this supplant config file params) */
	for(i=1; i<argc; i++){
		if(argv[i][0]=='-'){
			switch(argv[i][1]){

				case 'D':
					if(i+1 >= argc){
						fprintf(stderr, "Option -D without argument\n");
						usage();
					}
					i++;
					if(argv[i][0] < 48 || argv[i][0] > 55){
						fprintf(stderr, "Wrong -D parameter\n");
						usage();
					}
					config[CF_LOGLEVEL].valeur.integer = argv[i][0] - 48;
					break;

				case 'f':
					i++;
					break;

				case 'v':
					printf("getsnmp %s\n", PACKAGE_VERSION);
					exit(0);
					break;
				
				case 'd':
					config[CF_DAEMON].valeur.integer = TRUE;
					break;
	
				case 'h':
				default:
					fprintf(stderr, "Wrong option: -%c\n", argv[i][1]);
					usage();
					exit(1);
					break;
			}
		}
	}
}

int convert_octal(char *buf){
	int res = 0;
	char *b;
	
	int i;

	b = buf;
	while(*buf != 0){
		if(*buf<'0' || *buf>'7'){
			fprintf(stderr, "error in config file in "
			        "string \"%s\": octal value expected\n",
			        b);
			exit(1);
		}
		i = res;
		res *= 8;
		res += *buf - 48;
		buf++;
	}
	return res;
}

int convert_int(char *buf){
	int res = 0;
	char *b;

	b = buf;
	while(*buf != 0){
		if(*buf<'0' || *buf>'9'){
			fprintf(stderr, "error in config file in "
			        "string \"%s\": integer value expected\n",
			        b);
			exit(1);
		}
		res *= 10;
		res += *buf - 48;
		buf++;
	}	
	return res;
}

int convert_boolean(char *buf){
	to_lower(buf);

	if(strcmp("oui",   buf) == 0) return(TRUE);
	if(strcmp("yes",   buf) == 0) return(TRUE);
	if(strcmp("true",  buf) == 0) return(TRUE);
	if(strcmp("1",     buf) == 0) return(TRUE);
	
	if(strcmp("non",   buf) == 0) return(FALSE);
	if(strcmp("no",    buf) == 0) return(FALSE);
	if(strcmp("false", buf) == 0) return(FALSE);
	if(strcmp("0",     buf) == 0) return(FALSE);

	fprintf(stderr, "error in config file: boolean value expected [%s]\n",
		buf);
	exit(1);	 
}

void to_lower(char *in){
	while(*in != 0){
		if(*in > 64 && *in < 91)*in+=32;
		in++;
	}
}

char lowercase(char in){
	if(in > 64 && in < 91)in+=32;
	return in;
}

