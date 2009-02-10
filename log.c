/*
 * Copyright (c) 2005-2010 Thierry FOURNIER
 * $Id: log.c 292 2006-10-15 14:31:06Z thierry $
 *
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef USE_SYSLOG
#include <syslog.h>
#endif

#include "getsnmp.h"
#include "log.h"
#include "loadconfig.h"

extern int errno;

int syslog_opened = 0;
int file_opened = 0;

FILE *lf;
const char *mois[12] = {
	"Jan",
	"Feb",
	"Mar",
	"Apr",
	"May",
	"Jun",
	"Jul",
	"Aug",
	"Sep",
	"Oct",
	"Nov",
	"Dec"
};

void initlog(void){
	#ifdef USE_SYSLOG
	if(config[CF_USESYSLOG].valeur.integer == TRUE){
		openlog(PACKAGE_NAME, LOG_CONS, LOG_DAEMON);
		syslog_opened = 1;
	}
	#endif
	if(config[CF_LOGFILE].valeur.string != NULL && 
	   config[CF_LOGFILE].valeur.string[0] != 0){
		lf = fopen(config[CF_LOGFILE].valeur.string, "a");
		if(lf == NULL){
			fprintf(stderr, "[%s %d] fopen(%s)[%d]: %s\n",
			        __FILE__, __LINE__, config[CF_LOGFILE].valeur.string,
			        errno, strerror(errno));
			exit(1);
		}
		file_opened = 1;
	}
}

void logmsg(int priority, const char *fmt, ...){
	va_list ap;
	char msg[4096];
	struct tm *tm;
	int do_log = 0;

	// return if do not log in file or on standard output
	if(
		// check if I do log this priority
		priority > config[CF_LOGLEVEL].valeur.integer ||

		(
			( config[CF_LOGFILE].valeur.string == NULL || 
			  config[CF_LOGFILE].valeur.string[0] == 0
			)&&
			config[CF_DAEMON].valeur.integer == TRUE
			#ifdef USE_SYSLOG
			&& config[CF_USESYSLOG].valeur.integer == FALSE
			#endif
		)
	){
		return;
	}

	//get current tim 
	tm = localtime((time_t *)(&current_t.tv_sec));

	va_start(ap, fmt);
	vsnprintf(msg, 4096, fmt, ap);
	va_end(ap);

	#ifdef USE_SYSLOG
	if(syslog_opened == 1 &&
	   config[CF_USESYSLOG].valeur.integer == TRUE){
		syslog(priority, msg); 
		do_log = 1;
	}
	#endif

	if(file_opened == 1 &&
	   config[CF_LOGFILE].valeur.string != NULL &&
	   config[CF_LOGFILE].valeur.string[0] != 0){
		fprintf(lf, "%s % 2d %02d:%02d:%02d " PACKAGE_NAME ": %s\n",
		        mois[tm->tm_mon],
		        tm->tm_mday,
		        tm->tm_hour,
		        tm->tm_min,
		        tm->tm_sec, 
		        //for year: tm->tm_year+1900,
		        msg);
		fflush(lf);
		do_log = 1;
	}

	if(config[CF_DAEMON].valeur.integer == FALSE || do_log == 0){
		printf("%s % 2d %02d:%02d:%02d " PACKAGE_NAME ": %s\n", 
		        mois[tm->tm_mon],
		        tm->tm_mday,
		        tm->tm_hour,
		        tm->tm_min,
		        tm->tm_sec, 
		        msg);
	}
}

