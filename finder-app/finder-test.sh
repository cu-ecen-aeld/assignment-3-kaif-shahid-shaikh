#!/bin/sh
# Tester script for assignment 1/2/4
set -eu

# Config files on target
CONF_DIR="/etc/finder-app/conf"
USERNAME_FILE="$CONF_DIR/username.txt"
ASSIGNMENT_FILE="$CONF_DIR/assignment.txt"

# Read config
username="$(cat "$USERNAME_FILE")"
assignment="$(cat "$ASSIGNMENT_FILE")"

# Args/defaults
NUMFILES="${1:-10}"
WRITESTR="${2:-AELD_IS_FUN}"
if [ "${3:-}" ]; then
  WRITEDIR="/tmp/aeld-data/$3"
else
  WRITEDIR="/tmp/aeld-data"
fi

MATCHSTR="The number of files are ${NUMFILES} and the number of matching lines are ${NUMFILES}"

echo "Writing ${NUMFILES} files containing string ${WRITESTR} to ${WRITEDIR}"

# fresh workspace
rm -rf "$WRITEDIR"

# Only create WRITEDIR for non-assignment1 (preserves your original behavior)
if [ "$assignment" != "assignment1" ]; then
  mkdir -p "$WRITEDIR"
  [ -d "$WRITEDIR" ] || exit 1
fi

# Use PATH binaries (/usr/bin on target)
i=1
while [ $i -le $NUMFILES ]; do
  writer "$WRITEDIR/${username}$i.txt" "$WRITESTR"
  i=$((i+1))
done

# finder.sh from PATH, capture output
OUTPUTSTRING="$(finder.sh "$WRITEDIR" "$WRITESTR")"

# A4 requirement: write result file
echo "$OUTPUTSTRING" > /tmp/assignment4-result.txt

# optional cleanup
rm -rf /tmp/aeld-data

# success criteria
if echo "$OUTPUTSTRING" | grep -q "$MATCHSTR"; then
  echo "success"
  exit 0
else
  echo "failed: expected ${MATCHSTR} in ${OUTPUTSTRING} but instead found"
  exit 1
fi

