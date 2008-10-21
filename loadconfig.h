/*
 * Copyright (c) 2005-2010 Thierry FOURNIER
 * $Id: loadconfig.h 255 2006-10-09 22:33:59Z thierry $
 *
 */

#ifndef __LOADCONFIG_H__
#define __LOADCONFIG_H__

/*
 * types:
 *  0: char
 *  1: int
 *  2: boolean
 *  3: octal
 *
 * attrib:
 *  parameter value in config file
 *
 * value:
 *  valeur du parametre de type indefini
 */

#define TRUE                1
#define FALSE               0
#define CONFIGFILE_LEN      512

enum {
	CF_LOGFILE,
	CF_LOCKFILE,
	CF_DAEMON,
	CF_LOGLEVEL,
	CF_UMASK,
	CF_USER,
	CF_CHROOT,
	CF_USESYSLOG,
	CF_DIRDB,

	// total number of arguments
	NUM_PARAMS
};

typedef struct {
	int		type;
	char		*attrib;
	union {
		char	*string;
		int	integer;
	} valeur;
} config_cell;

config_cell config[NUM_PARAMS];

// load default values and parse command line
void config_load(int argc, char **argv);

// parse command line
// (if command line params overwrite config file params)
void config_cmd(int argc, char **argv);

// convert string parameter to specified type
int convert_boolean(char *buf);
int convert_int(char *buf);
int convert_octal(char *buf);

#endif
