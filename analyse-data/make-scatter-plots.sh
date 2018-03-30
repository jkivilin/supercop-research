#!/bin/bash

machine="$1"

if ! [ -d "$machine" ]; then
	echo "No data for $machine"
	exit 1
fi

(
	cd "$machine" || exit 1

	for algo in *; do
		if ! [ -d "$algo" ]; then
			continue
		fi

		(
			cd "$algo"

			for impl in *; do
				if ! [ -d "$impl" ]; then
					continue
				fi
				if ! [ -e "$impl/xor_cycles-full.dat" ]; then
					continue
				fi

				echo $machine/$algo/$impl
			done
		)
	done
) | while read datafile; do
	algo=$(awk -F"/" '{print $2}' <<< "$datafile")
	impl=$(awk -F"/" '{print $3}' <<< "$datafile")
	input="$machine/${algo}/${impl}/xor_cycles-full.dat"
	output="$machine/${algo}/scatter_${impl}.png"
	echo "-------------"
	echo "input : $input"
	echo "output: $output"
	./make_full_data_png "$input" "$output"
done
