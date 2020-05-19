#!/bin/sh
if [ ! -f 'files_cache' ]; then
	files=`find . -exec file {} \; | grep -i elf | awk -F":" '{print $1}' | tee files_cache`
else
	files=`cat files_cache`
fi
for f in $files
do
	elements=`strings $f | grep '[0-9]\.[0-9]' | awk 'match($0, /[0-9].*[0-9]/) {print substr($0, RSTART, RLENGTH)}'`
	ver_candidates=""
	for i in $elements
	do
		ver_candidates=$ver_candidates" "$i
	done
	if [ ! -z "$ver_candidates" ]; then
		echo $f
		echo $elements
		echo ""
	fi
done
