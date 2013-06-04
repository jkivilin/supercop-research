#!/bin/bash -e

work="work_$$"

first_from_sorted() {
  local args=(${@})
  echo ${args[0]}
}

# integer median, input values already sorted
median_from_sorted() {
  local args=(${@})
  local mid=$(( $#/2 ))

  if (( $#%2 == 0 )); then
    echo $(( (${args[mid]} + ${args[mid-1]}) / 2 ))
  else
    echo ${args[mid]}
  fi
}

machine=$1
arch=amd64

path="supercop-data/$machine/$arch"

if ! [ -d "$path" ]; then
  echo "no such machine: $machine"
  exit 0
fi

rm -fr $work
mkdir $work
rm -fr $machine
mkdir $machine

machine_name="$machine"
if [ "$machine_name" = "oioi" ]; then
  machine_name="nano"
fi

## copy machine info
if [ -e "supercop-data/$machine/log" ]; then
  cp "supercop-data/$machine/log" "$machine/info.txt"
fi

## prepare aes128ctr/estream
if [ -d $path/try/c/*/crypto_stream/aes128ctr ]; then
  (
    cd $path/try/c/*/crypto_stream/aes128ctr

    make_link() {
      if [ -d "$1" ] && ! [ -e "estream_$(basename $1)" ] ; then
        ln -s "$1" "estream_$(basename $1)"
      fi
    }

    ## hardcoded for now
    make_link ../aes128estream/e/schwabe/core2
    make_link ../aes128estream/e/schwabe/athlon64-1
    make_link ../aes128estream/e/schwabe/athlon64-2
    make_link ../aes128estream/ssse3
  )
fi


cat algorithms \
| while read algorithm; do
  for datapath in $path/try/*/*/crypto_stream/$algorithm/*; do
    if ! [ -d "$datapath" ] ||
       ! [ -e "$datapath/CYCLES" ] ||
       ! [ -e "$datapath/data" ]; then
      continue
    fi

    if ! [ -d "$machine/$algorithm" ]; then
      mkdir $machine/$algorithm
    fi

    ## use multiple cpus for data parsing part
    (
      implementation=$(basename $datapath)

      case "$implementation" in
        ## skip AES implementations not taken as part of study
        *-3kbtables ) exit 0;;
        ## skip the other blowfish 1-way implementation
        amd64-1way-1 ) exit 0;;
      esac

      echo Processing "$machine/$algorithm/$implementation"...
      mkdir $machine/$algorithm/$implementation

      for datatype in cycles xor_cycles; do
        ## get implementation information
        cycles_file=$work/$datatype-$implementation.dat
        touch $cycles_file
        echo "#$implementation" >> $cycles_file
        echo "#bytes $datatype" >> $cycles_file

        ## get median of measurement runs
        cat "$datapath/data" \
        | grep " $datatype " \
        | awk '{print $8 " " $9}' \
        | sort -k 1n -k 2n \
        | (
          unset -v values
          declare -a values

          while read cycles value; do
            ## add new array to values array, matching cells are merged
            values[$cycles]="${values[$cycles]} $value"
          done

          for ((i=0;i<=4096;i++)) do
            ## print median of measurements
            echo -n "$i "
            #median_from_sorted ${values[$i]}
            median_from_sorted ${values[$i]}
	    #first_from_sorted ${values[$i]}
          done
        ) >> $cycles_file

        mv $cycles_file $machine/$algorithm/$implementation/$datatype.dat
      done
    ) &
  done

  wait

  rm -fr $work
  mkdir $work

  # no implementations for this algorithm was found?
  if ! [ -d "$machine/$algorithm" ]; then
    continue
  fi

  if [ "$typef" != "svg" ] && [ "$typef" != "eps" ]; then
    typef="svg"
  fi

  echo "Generating '$typef' plots for $machine/$algorithm..."

  for datatype in cycles xor_cycles; do for xrange in "0:4096" "0:1024" "2048:4096"; do
    if [ "$xrange" != "" ]; then
      xrangename="-${xrange/:/_}"
    else
      xrangename=""
    fi

    touch $work/graph-$datatype$xrangename-1.plot
    (
      cd "$machine/$algorithm"

      #
      # setup plot style
      #
      echo "# plot for $algorithm"

      if [ "$typef" = "svg" ]; then
        echo "set term svg enhanced background '#FFFFFF' " \
             "dynamic solid linewidth 0.1 font 'monospace,9'"
      else
        echo "set terminal postscript eps size 15cm,12cm " \
	     "enhanced color linewidth 1 font 'Helvetica,14'"
      fi

      echo "set title '$algorithm (on $machine_name)'"
      echo "set style data line"
      echo "set ylabel '${datatype/_/\\_}'"
      echo "set xlabel 'message length in bytes'"
      if [ "$xrange" != "" ]; then
        echo "set xrange [$xrange]"
      else
        echo "set xrange [0:4096]"
      fi
      echo "set xtics 512 scale default"
      echo "set mxtics 4"
      echo "set mytics 4"
      echo "set key on box left top"
      echo "set grid xtics mxtics ytics mytics"

      #
      # linear regression and statistics
      #
      echo "f(x) = m*x + b"

      is_first=y
      for implementation in *; do
        if ! [ -e "$implementation/cycles.dat" ]; then
          continue
        fi

        if [ $is_first = y ]; then
          is_first=n
        fi

        impl_prefix="${implementation//-/_}"

        echo "print '+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++'"
        echo "print ' Linear regression for [$algorithm/$implementation/$datatype.dat]'"
        echo "print '+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++'"
        echo "fit f(x) '$implementation/$datatype.dat' via m,b"
        echo "print ' '"

        echo "print '+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++'"
        echo "print ' Statistical information for [$algorithm/$implementation/$datatype.dat]'"
        echo "print '+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++'"
        echo "stats '$implementation/$datatype.dat' prefix '$impl_prefix'"
        echo "print ' '"
      done

      #
      # draw plot
      #
      echo -n "plot "

      coloridx=0
      colors=(
        "#6F0505" #red
        "#066F05" #greed
        "#051B6F" #blue
        "#6D6F05" #olive?
        "#056F6F" #teal
        "#6F056F" #purple
        "#471E03" #brown
        "#132A47" #dark-navy
        "#CF1B93" #pink
        "#000000" #black
        "#555555" #gray
        "ERROR")

      is_first=y
      for implementation in *; do
        if ! [ -e "$implementation/$datatype.dat" ]; then
          continue
        fi

        if [ $is_first = y ]; then
          is_first=n
        else
          echo ", \\"
	  echo -n "     "
        fi

        if [ "${colors[$coloridx]}" = "ERROR" ]; then
          color=""
          echo "ERROR: plot out of colors!" >&2
        else
          color=" lc rgb '${colors[$coloridx]}'"
          coloridx=$(($coloridx + 1))
        fi

        impl_name="${implementation//_/\\_}"
        impl_prefix="${implementation//-/_}"
        title_format="'$impl_name, %.2f cycles/byte'"

        impl_title="title sprintf($title_format, ${impl_prefix}_slope, ${impl_prefix}_intercept)"

        echo "'$implementation/$datatype.dat' $impl_title ls 1 $color, \\"
        echo -n "     ${impl_prefix}_slope * x + ${impl_prefix}_intercept notitle ls 1 lw 0.5 lt 3 $color"
      done

      echo ""
    ) >> $work/graph-$datatype$xrangename-$machine_name.plot

    mv $work/graph-$datatype$xrangename-$machine_name.plot $machine/$algorithm/

    touch $work/$algorithm-$datatype$xrangename-$machine_name.$typef
    touch $work/$algorithm-$datatype$xrangename-$machine_name.txt
    (
      cd $machine/$algorithm
      gnuplot graph-$datatype$xrangename-$machine_name.plot
    ) >> $work/$algorithm-$datatype$xrangename-$machine_name.$typef \
         2>> $work/$algorithm-$datatype$xrangename-$machine_name.txt

    mv $work/$algorithm-$datatype$xrangename-$machine_name.$typef $machine/$algorithm/
    mv $work/$algorithm-$datatype$xrangename-$machine_name.txt $machine/$algorithm/
  done; done

  rm -fr $work
  mkdir $work
done

rm -fr $work

echo "... $machine done."

