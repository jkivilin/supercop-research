#!/bin/bash

machine="$1"
find_text="$2"

console_width=$(tput cols)

zcat "supercop-data/$machine/data.gz" \
| grep "$find_text" \
| while read line
do
	printf "%.${console_width}s\n" "$line"
done
