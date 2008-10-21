#!/bin/bash
#
# Copyright (c) 2005-2010 Thierry FOURNIER
# $Id: tool_code.sh 305 2006-10-16 10:15:04Z  $
#

case $1 in
	pdf)
		enscript -c -j -f Courier7 -E --header "\$n||Page $% of $=" --color -T 4 -p - *.h *.c | ps2pdf - getsnmp-sources.pdf
		;;

	stats)
		for files in *.c *.h; do
			printf "%15s:% 5d lines\n" $files "$( cat $files | wc -l )"
		done | sort -n +1
		echo
		printf "%15s:% 5d lines\n" "Total" "$( ( cat *.c ; cat *.h ) | wc -l )"
		;;

	dep)
		for files in $(ls *.c); do
			printf "%15s: %s\n" $files "$(cat $files | grep "#include \"" | sed -e "s/#include \"//; s/\"//" | xargs echo )";
		done
		;;
						
	check)
		grep "#.*include <" *.c *.h | \
		sed -e "s/^.* <//; s/>//" | \
		sort -u | \
		sed -e "s/^\(.*\)/AC_CHECK_HEADERS(\1, , echo \"didn't find \1\"; exit 1)/" | \
		while read; do
			TEST=$( cat configure.in 2>/dev/null | grep "$REPLY" )
			test -z "$TEST" && echo $REPLY
		done
		;;

#	funcs)
#		cat *.c | \
#		grep ".*(" | \
#		sed -e "s/\([a-zA-Z0-9_]\+\)(/---\1---\n/g" | \
#		grep -- "---.*---" | \
#		sed -e "s/^.*---\([a-zA-Z0-9_]\+\)---$/\1/" | \
#		sort -u | \
#		grep -v "\(^data_\|^sens_\|[A-Z]\+\|^maclist_\|^maclist_\|^time_\|^mod_\|^module_\|^index_\|^cap_\|^alerte_\|^if\|^for\|^unindex_ip\|^to_lower\|^unindex_ip\|^\)"
#		;;
		
	*)
		echo "Syntax: $0 {pdf|stats|dep|check|funcs}"
		exit 1
esac


