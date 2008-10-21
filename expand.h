#ifndef __EXPAND_H__
#define __EXPAND_H__

struct expcell {
	char *oid;
	char *name;
	char *file;
	char *rrd;
	struct expcell *next;
};

struct expcell *expand_names(char *oid, char *name, char *file, char *rrdname);

#endif
