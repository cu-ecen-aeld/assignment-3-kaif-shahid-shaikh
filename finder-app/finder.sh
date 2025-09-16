#!/bin/sh

if [ $# -ne 2 ]; then
	echo "Error:Enter 2 arguments"
	exit 1
fi

filesdir=$1
searchstr=$2

if [ ! -d "$filesdir" ]; then
	echo "Error:No such Directory"
	exit 1
fi

numfiles=$(find "$filesdir" -type f | wc -l)

matchedstr=$(grep -r "$searchstr" "$filesdir"| wc -l)

echo "The number of files are $numfiles and the number of matching lines are $matchedstr"

