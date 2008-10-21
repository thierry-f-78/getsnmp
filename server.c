/*
 * Copyright (c) 2005-2010 Thierry FOURNIER
 * $Id: serveur.c 324 2006-10-17 10:19:26Z thierry $
 *
 */

#include "config.h"

#include <signal.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <sys/stat.h>

#include "loadconfig.h"
#include "log.h"

extern int errno;

void daemonize(void){
	int pid;
	int descriptor;

	if(config[CF_DAEMON].valeur.integer == FALSE){
		return;
	}

	pid = fork();
	if(pid < 0){
		logmsg(LOG_ERR, "[%s %i] fork[%d]: %s",
		       __FILE__, __LINE__, errno, strerror(errno));
		exit(1);
	}
	if(pid > 0){
		exit(0);
	}

	if( setsid() == -1 ){
		logmsg(LOG_ERR, "[%s %i] setsid[%d]: %s",
		       __FILE__, __LINE__, errno, strerror(errno));
		exit(1);
	}

	pid = fork();
	if(pid < 0){
		logmsg(LOG_ERR, "[%s %i] fork[%d]: %s",
		       __FILE__, __LINE__, errno, strerror(errno));
		exit(1);
	}
	if(pid > 0){
		exit(0);
	}

	// close standard file descriptors
	close(0);
	close(1);
	close(2);

	// open standard descriptors on /dev/null
	descriptor = open("/dev/null", O_RDWR);
	if(descriptor < 0){
		logmsg(LOG_ERR, "[%s %i] open[%d]: %s",
		       __FILE__, __LINE__, errno, strerror(errno));
		exit(1);
	}
	if(dup(descriptor) == -1){
		logmsg(LOG_ERR, "[%s %i] dup[%d]: %s",
		       __FILE__, __LINE__, errno, strerror(errno));
		exit(1);
	}
	if(dup(descriptor) == -1){
		logmsg(LOG_ERR, "[%s %i] dup[%d]: %s",
		       __FILE__, __LINE__, errno, strerror(errno));
		exit(1);
	}
}

void separe(void){
	struct passwd *pwd = NULL;
	uid_t uid = 0;
	gid_t gid = 0;
	char str[8]; // max process number = 9999999
	int fd;

	// open lock/pid file
	fd = open(config[CF_LOCKFILE].valeur.string, O_RDWR | O_CREAT, 0640);
	if(fd < 0){
		logmsg(LOG_ERR, "[%s %i] open[%d]: %s",
		       __FILE__, __LINE__, errno, strerror(errno));
		exit(1);
	}
	
	// lock file during program execution
	if(lockf(fd, F_TLOCK, 0)<0){
		logmsg(LOG_ERR,
		       "Daemon instance already running (file: %s locked)",
		       config[CF_LOCKFILE].valeur.string);
		exit(1);
	}
	
	// write pid in lock file
	snprintf(str, 8, "%d\n", (int)getpid());
	write(fd, str, strlen(str));

	// privilege separation
	if(config[CF_USER].valeur.string != NULL) { 

		// get uid and gid by username 
		pwd = getpwnam(config[CF_USER].valeur.string);
		if (pwd == NULL){
			logmsg(LOG_ERR, "[%s %i] getpwnam[%d]: %s",
			       __FILE__, __LINE__, errno, strerror(errno));
			exit(1);
		}
		uid = pwd->pw_uid;
		gid = pwd->pw_gid;

		// set default group of user
		if (setgid(gid) == -1){
			logmsg(LOG_ERR, "[%s %i] setgid[%d]: %s",
			       __FILE__, __LINE__, errno, strerror(errno));
			exit(1);
		}

		// use all groups assigned to user
		if (initgroups(config[CF_USER].valeur.string, gid) == -1){
			logmsg(LOG_ERR, "[%s %i] initgroups[%d]: %s",
			       __FILE__, __LINE__, errno, strerror(errno));
			exit(1);
		}

		// close passwd and groups
		endpwent();
		endgrent();
	}

	// chrooting
	if (config[CF_CHROOT].valeur.string != NULL) {
			  
		// chrooting
		if (chroot(config[CF_CHROOT].valeur.string)){
			logmsg(LOG_ERR, "[%s %i] chroot[%d]: %s",
			       __FILE__, __LINE__, errno, strerror(errno));
			exit(1);
		}

		// change current directory
		if (chdir("/")){
			logmsg(LOG_ERR, "[%s %i] chdir[%d]: %s",
			       __FILE__, __LINE__, errno, strerror(errno));
			exit(1);
		}
	}

	// change user
	if(config[CF_USER].valeur.string != NULL) {
		if (setuid(uid) == -1){
			logmsg(LOG_ERR, "[%s %i] setuid[%d]: %s",
			       __FILE__, __LINE__, errno, strerror(errno));
			exit(1);
		}
	}

	// create file rights
	umask(config[CF_UMASK].valeur.integer);
}

void (*setsignal (int signal, void (*function)(int)))(int) {    
	struct sigaction old, new;

	memset(&new, 0, sizeof(struct sigaction));
	new.sa_handler = function;
	new.sa_flags = SA_RESTART;
	sigemptyset(&(new.sa_mask));
	if (sigaction(signal, &new, &old)){ 
		logmsg(LOG_ERR, "[%s %i] sigaction[%d]: %s",
		       __FILE__, __LINE__, errno, strerror(errno));
		exit(1);
	}
	return(old.sa_handler);
}


