#!/bin/sh
## time_benchmark.sh for  in /Users/pouchet
##
## Made by Louis-Noel Pouchet
## Contact: <pouchet@cse.ohio-state.edu>
##
## Started on  Sat Oct 29 00:03:48 2011 Louis-Noel Pouchet
## Last update Fri Apr 22 15:39:13 2016 Louis-Noel Pouchet
##

## Relative standard deviation (RSD) in %, accepted between the N median runs for performance results.
RSD_THRESHOLD=3;

# Batch size (number of runs)
BATCH_SIZE=20
# Batch size (number of runs) after removing the most extremes values
BATCH_SIZE_AFTER_FILTER=20

if [ $# -lt 1 ]; then
    echo "Usage: ./time_benchmarh.sh <binary_name>";
    echo "Example: ./time_benchmarh.sh \"./a.out\"";
    echo "Note: the file must be a Polybench program compiled with -DPOLYBENCH_TIME";
    exit 1;
fi;


compute_mean_exec_time()
{
    file="$1";
    benchcomputed="$2";
    cat "$file" | grep "[0-9]\+" | sort -n | head -n `echo "$BATCH_SIZE_AFTER_FILTER+($BATCH_SIZE - $BATCH_SIZE_AFTER_FILTER)/2" | bc 2>&1` | tail -n $BATCH_SIZE_AFTER_FILTER > avg.out;
    expr="(0";
    while read n; do
	expr="$expr+$n";
    done < avg.out;
    time=`echo "scale=10;$expr)/$BATCH_SIZE_AFTER_FILTER" | bc`;
    tmp=`echo "$time" | cut -d '.' -f 1`;
    if [ -z "$tmp" ]; then
	time="0$time";
    fi;

	SAVEIFS=$IFS   # Save current IFS
	IFS=$'\n'      # Change IFS to new line
	execution_times=(`cat avg.out`) # split to array $names
	IFS=$SAVEIFS   # Restore IFS
	for (( i=0; i<${#execution_times[@]}; i++ ))
	do
		# Make sure each value is a time duration
		val=`echo "${execution_times[$i]}" | bc 2>&1`;
		test_err=`echo "$val" | grep error`;
		if ! [ -z "$test_err" ]; then
			echo "[ERROR] Program output does not match expected single-line with time.";
			echo "[ERROR] The program must be a PolyBench, compiled with -DPOLYBENCH_TIME";
			exit 1;
		fi;

		echo "$i: ${execution_times[$i]}"

		# Compute squared diff from average
		execution_times_diff_square[$i]=`echo "scale=10;a=${execution_times[$i]} - $time;a^2" | bc 2>&1`;
	done

	# Compute standard deviation (SD)
	sum_squared_diffs=0
	for (( i=0; i<${#execution_times_diff_square[@]}; i++ ))
	do
		sum_squared_diffs=`echo "scale=10;$sum_squared_diffs+${execution_times_diff_square[$i]}" | bc 2>&1`
	done
	sd=`echo "scale=10;sqrt($sum_squared_diffs/$BATCH_SIZE_AFTER_FILTER)" | bc 2>&1`
	rsd=`echo "scale=10;$sd*100/$time" | bc 2>&1`
	ci_95=`echo "scale=10;2*$sd" | bc 2>&1`
	lowest_95=`echo "scale=10;$time-$ci_95" | bc 2>&1`
	highest_95=`echo "scale=10;$time+$ci_95" | bc 2>&1`

    compvar=`echo "$rsd $RSD_THRESHOLD" | awk '{ if ($1 < $2) print "ok"; else print "error"; }'`;
    if [ "$compvar" = "error" ]; then
	echo "[WARNING] RSD is above threshold, unsafe performance measurement";
	echo "        => RSD=$rsd%, tolerance=$RSD_THRESHOLD%";
    else
	echo "[INFO] RSD from arithmetic mean of $BATCH_SIZE_AFTER_FILTER average runs: $rsd%";
    fi;
    PROCESSED_TIME="$time";
    #rm -f avg.out;
}

echo "[INFO] Running $BATCH_SIZE times $1..."
echo "[INFO] Maximal RSD authorized on $BATCH_SIZE_AFTER_FILTER average runs: $RSD_THRESHOLD%...";

$@ > ____tempfile.data.polybench;
for ((i=0;i<$BATCH_SIZE-1;i++)); do
	$@ >> ____tempfile.data.polybench;
done

compute_mean_exec_time "____tempfile.data.polybench" "$1";
echo "[INFO] Normalized time: $PROCESSED_TIME";
#rm -f ____tempfile.data.polybench;
