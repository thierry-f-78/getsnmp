#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "expand.h"

/*
 * this function expand this:
  Toto(Ab,Cd)Paf(1-2,4):
 *   TotoAbPaf1
 *   TotoAbPaf1
 *   TotoCdPaf2
 *   TotoCdPaf2
 *   TotoCdPaf4
 *   TotoCdPaf4
 * and
 * Name{1}Voila{2}
 *   NameAbVoila1
 *   NameAbVoila1
 *   NameCdVoila2
 *   NameCdVoila2
 *   NameCdVoila4
 *   NameCdVoila4
 */
struct items {
	char *item;
	struct items *next;
};
struct col_items {
	struct items *start;
	struct items *count;
};
#define TYPE_ITEM 1
#define TYPE_STR 2
struct name {
	int type;
	int item;
	char *data;
	struct name *next;
};

#define NEXT \
	{ \
		parse++; \
		if (*parse == '\0') break; \
	}

#define NEWITEM \
	{ \
		col_count++; \
		if (col == NULL) { \
			col = (struct col_items*) \
			      malloc(sizeof(struct col_items)); \
		} else { \
			col = (struct col_items*) \
			      realloc(col, col_count * sizeof(struct col_items)); \
		} \
		if (col == NULL) { \
			goto end_with_error; \
		} \
		col[col_count-1].count = NULL; \
		col[col_count-1].start = NULL; \
	}

#define NEWCELL(Za) \
	{ \
		if ((Za) != NULL) { \
			struct items *itmp = calloc(1, sizeof(struct items)); \
			itmp->item = strdup((Za)); \
			itmp->next = col[col_count-1].start; \
			col[col_count-1].start = itmp; \
		} \
	}

#define NEWSTR(Za, Zb) \
	{ \
		if ((Zb) != NULL) { \
			struct name *ntmp = (struct name *) \
			       calloc(1, sizeof(struct name)); \
			ntmp->type = TYPE_STR; \
			ntmp->data = strdup((Zb)); \
			ntmp->next = NULL; \
			struct name *tmp = name_##Za; \
			if ( tmp == NULL ) \
				name_##Za = ntmp; \
			else { \
				while ( tmp->next != NULL ) \
					tmp = tmp->next; \
				tmp->next = ntmp; \
			} \
		} \
	}

#define NEWINDEX(Za, Zb) \
	{ \
		struct name *ntmp = (struct name *) \
		       calloc(1, sizeof(struct name)); \
		ntmp->type = TYPE_ITEM; \
		ntmp->item = (Zb); \
		ntmp->next = NULL; \
		struct name *tmp = name_##Za; \
		if ( tmp == NULL ) \
			name_##Za = ntmp; \
		else { \
			while ( tmp->next != NULL ) \
				tmp = tmp->next; \
			tmp->next = ntmp; \
		} \
	}

// must be upper than max oid, dataname and filename len
#define BUFSIZE 1024
struct expcell *expand_names(char *oid, char *name, char *file, char *rrd) {
	char *_oid = NULL;
	char *_name = NULL;
	char *_file = NULL;
	char *_rrd = NULL;
	char *parse,*start, *error;
	long long int a, b, c;
	int col_count = 0;
	struct col_items *col = NULL;
	struct name *tmp = NULL;
	struct name *name_oid = NULL;
	struct name *name_name = NULL;
	struct name *name_file = NULL;
	struct name *name_rrd = NULL;
	int flag_in = 0;
	char *buffer = NULL;
	int i;
	struct expcell *first = NULL;
	struct expcell *insert = NULL;
	struct items *cur, *del;

	if (oid == NULL)
		goto end_with_error;
	buffer = malloc(BUFSIZE * sizeof(char));

	/***********************************************************
	* 
	* parse OID
	*
	***********************************************************/
	_oid  = strdup(oid);
	parse = _oid;
	start = _oid;
	while(1){

		// start variable parameter
		if (flag_in == 0 && *parse == '{') {
			*parse = 0;
			NEWSTR(oid, start)
			start = parse + 1;
			NEXT
			NEWITEM
			NEWINDEX(oid, col_count)
			flag_in = 1;
		}

		// stop variable parameter
		else if (flag_in == 1 && *parse == '}') {
			*parse = 0;
			NEWCELL(start);
			flag_in = 0;
			start = parse + 1;
			NEXT
		}

		// variable parameter separator
		else if (flag_in == 1 && *parse == ',') {
			*parse = 0;
			NEWCELL(start);
			start = parse + 1;
			NEXT
		}

		// range definition separator
		else if (flag_in == 1 && *parse == '-') {

			// convert the first number
			// continue if is not a number
			a = strtoull(start, &error, 10);
			NEXT
			if (*error != '-') {
				continue;
			}

			// convert the second number
			// continue if is not a number
			b = strtoull(parse, &parse, 10);
			if (*parse == '}' || *parse == ',') {
				start = NULL;
			}
			else {
				continue;
			}

			// check count order
			if (a > b) {
				c = a;
				a = b;
				b = c;
			}

			// check counter size
			if (b - a > 1000)
				goto end_with_error;

			// expand range
			while(a <= b) {
				snprintf(buffer, BUFSIZE, "%lld", a);
				NEWCELL(buffer);
				a++;
			}
		}
		// normal character
		else {
			NEXT
		}
	}

	// check correct loop output
	if (flag_in == 0 && start != NULL && *start != '\0' )
		NEWSTR(oid, start)
	else if (flag_in == 1 && start != NULL && *start != '\0' )
		NEWCELL(start)


	/***********************************************************
	* 
	* parse NAME
	*
	***********************************************************/
	if (name != NULL) {
		_name = strdup(name);
		parse = _name;
		start = _name;
		while(1){
			if (*parse == '$' && *(parse+1) == '{' ) {
				*parse = '\0';
				NEXT
				NEXT
				// convert and check error
				i = strtol(parse, &error, 10);
				if ( *error!='}' || i>col_count )
					*parse = '{';
				else {
					NEWSTR(name, start)
					NEWINDEX(name, i)
					parse = error;
					start = error + 1;
				}
				NEXT
			}
			else {
				NEXT
			}
		}

		if ( *start != '\0' )
			NEWSTR(name, start);
	}

	/***********************************************************
	* 
	* parse FILE
	*
	***********************************************************/
	if (file != NULL) {
		_file = strdup(file);
		parse = _file;
		start = _file;
		while(1){
			if (*parse == '$' && *(parse+1) == '{' ) {
				*parse = '\0';
				NEXT
				NEXT
				// convert and check error
				i = strtol(parse, &error, 10);
				if ( *error!='}' || i>col_count )
					*parse = '{';
				else {
					NEWSTR(file, start)
					NEWINDEX(file, i)
					parse = error;
					start = error + 1;
				}
				NEXT
			}
			else {
				NEXT
			}
		}

		if ( *start != '\0' )
			NEWSTR(file, start);
	}


	/***********************************************************
	* 
	* parse RRD base name
	*
	***********************************************************/
	if (rrd != NULL) {
		_rrd = strdup(rrd);
		parse = _rrd;
		start = _rrd;
		while(1){
			if (*parse == '$' && *(parse+1) == '{' ) {
				*parse = '\0';
				NEXT
				NEXT
				// convert and check error
				i = strtol(parse, &error, 10);
				if ( *error!='}' || i>col_count )
					*parse = '{';
				else {
					NEWSTR(rrd, start)
					NEWINDEX(rrd, i)
					parse = error;
					start = error + 1;
				}
				NEXT
			}
			else {
				NEXT
			}
		}

		if ( *start != '\0' )
			NEWSTR(rrd, start);
	}

	/***********************************************************
	* 
	* build expanded strings
	*
	***********************************************************/
	// init strings counter
	for (i=0; i<col_count; i++)
		col[i].count = col[i].start;
	
	// create all strings
	while(1) {

		// new storage support
		insert = (struct expcell *)
		         calloc(1, sizeof(struct expcell));

		// create oid strings
		buffer[0] = '\0';
		tmp = name_oid;
		while(tmp != NULL) {
			if (tmp->type == TYPE_STR) {
				strncat(buffer, tmp->data, BUFSIZE);
			} else {
				strncat(buffer, col[tmp->item - 1].count->item, BUFSIZE);
			}
			tmp = tmp->next;
		}
		insert->oid = strdup(buffer);

		// create name strings
		if (name != NULL) {
			buffer[0] = '\0';
			tmp = name_name;
			while(tmp != NULL) {
				if (tmp->type == TYPE_STR) {
					strncat(buffer, tmp->data, BUFSIZE);
				} else {
					strncat(buffer, col[tmp->item - 1].count->item, BUFSIZE);
				}
				tmp = tmp->next;
			}
			insert->name = strdup(buffer);
		}

		// create file strings
		if (file != NULL) {
			buffer[0] = '\0';
			tmp = name_file;
			while(tmp != NULL) {
				if (tmp->type == TYPE_STR) {
					strncat(buffer, tmp->data, BUFSIZE);
				} else {
					strncat(buffer, col[tmp->item - 1].count->item, BUFSIZE);
				}
				tmp = tmp->next;
			}
			insert->file = strdup(buffer);
		}

		// create rrd database name string
		if (rrd != NULL) {
			buffer[0] = '\0';
			tmp = name_rrd;
			while(tmp != NULL) {
				if (tmp->type == TYPE_STR) {
					strncat(buffer, tmp->data, BUFSIZE);
				} else {
					strncat(buffer, col[tmp->item - 1].count->item, BUFSIZE);
				}
				tmp = tmp->next;
			}
			insert->rrd = strdup(buffer);
		}

		// chain
		insert->next = first;
		first = insert;

		// next strings combinaisons
		if (col_count == 0) {
			goto dump_end;
		}
		i = 0;
		col[i].count = col[i].count->next;
		while(1) {
			// nothing to do
			if (col[i].count != NULL) {
				break;
			}
			// if this is a last counter is the end
			if (i == col_count - 1) {
				goto dump_end;
			}
			// reset counter
			col[i].count = col[i].start;
			// increment next variable
			col[i+1].count = col[i+1].count->next;
			// next
			i++;
		}
	}
	dump_end:

	/***********************************************************
	* 
	* free memory
	*
	***********************************************************/
	end_with_error:
	for(i=0; i<col_count; i++) {
		cur = col[i].start;
		while(cur != NULL) {
			del = cur;
			cur = cur->next;
			free(del);
		}
	}
	while(name_oid != NULL) {
		tmp = name_oid;
		name_oid = name_oid->next;
		if(tmp->type == TYPE_STR)
			free(tmp->data);
		free(tmp);
	}
	while(name_name != NULL) {
		tmp = name_name;
		name_name = name_name->next;
		if(tmp->type == TYPE_STR)
			free(tmp->data);
		free(tmp);
	}
	while(name_file != NULL) {
		tmp = name_file;
		name_file = name_file->next;
		if(tmp->type == TYPE_STR)
			free(tmp->data);
		free(tmp);
	}
	if (col != NULL)
		free(col);
	if (buffer != NULL)
		free(buffer);
	if (_oid != NULL)
		free(_oid);
	if (_name != NULL)
		free(_name);
	if (_file != NULL)
		free(_file);
	if (_rrd != NULL)
		free(_rrd);

	return first;
}

