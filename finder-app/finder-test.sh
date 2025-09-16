#!/bin/sh
CONF_DIR="/etc/finder-app/conf"
USERNAME_FILE="$CONF_DIR/username.txt"
ASSIGNMENT_FILE="$CONF_DIR/assignment.txt"
USERNAME_FILE="$CONF_DIR/username.txt"
ASSIGNMENT_FILE="$CONF_DIR/assignment.txt"

#!/bin/sh
resolve_conf_path() {
  p="$1"; def="$2"
  [ -z "$p" ] && p="$def"
  case "$p" in
    /etc/finder-app/conf/*) printf "%s\n" "$p" ;;
    /etc/finder-app/conf/*)           printf "%s/%s\n" "$CONF_DIR" "$(basename "$p")" ;;
    /*)                     printf "%s\n" "$p" ;;
    *)                      printf "%s/%s\n" "$CONF_DIR" "$p" ;;
  esac
}
USERNAME_FILE="$(resolve_conf_path "$USERNAME_FILE" username.txt)"
ASSIGNMENT_FILE="$(resolve_conf_path "$ASSIGNMENT_FILE" assignment.txt)"

#!/bin/sh
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FINDER_SH="$SCRIPT_DIR/finder.sh"
WRITER_BIN="$SCRIPT_DIR/writer"
CONF_DIR="/etc/finder-app/conf"
#!/bin/sh
# Tester script for assignment 1 and assignment 2
# Author: Siddhant Jajoo

set -e
set -u

NUMFILES=10
WRITESTR=AELD_IS_FUN
WRITEDIR=/tmp/aeld-data
username=$(cat "$USERNAME_FILE")

if [ $# -lt 3 ]
then
	echo "Using default value ${WRITESTR} for string to write"
	if [ $# -lt 1 ]
	then
		echo "Using default value ${NUMFILES} for number of files to write"
	else
		NUMFILES=$1
	fi	
else
	NUMFILES=$1
	WRITESTR=$2
	WRITEDIR=/tmp/aeld-data/$3
fi

MATCHSTR="The number of files are ${NUMFILES} and the number of matching lines are ${NUMFILES}"

echo "Writing ${NUMFILES} files containing string ${WRITESTR} to ${WRITEDIR}"

rm -rf "${WRITEDIR}"

# create $WRITEDIR if not assignment1
assignment=$(cat "$ASSIGNMENT_FILE")

if [ $assignment != 'assignment1' ]
then
	mkdir -p "$WRITEDIR"

	#The WRITEDIR is in quotes because if the directory path consists of spaces, then variable substitution will consider it as multiple argument.
	#The quotes signify that the entire string in WRITEDIR is a single string.
	#This issue can also be resolved by using double square brackets i.e [[ ]] instead of using quotes.
	if [ -d "$WRITEDIR" ]
	then
		echo "$WRITEDIR created"
	else
		exit 1
	fi
fi
#echo "Removing the old writer utility and compiling as a native application"
#make clean
#make

for i in $( seq 1 $NUMFILES)
do
	"$WRITER_BIN" "$WRITEDIR/${username}$i.txt" "$WRITESTR"
done

OUTPUTSTRING=$("$FINDER_SH" "$WRITEDIR" "$WRITESTR")

# remove temporary directories
rm -rf /tmp/aeld-data

set +e
echo ${OUTPUTSTRING} | grep "${MATCHSTR}"
if [ $? -eq 0 ]; then
	echo "success"
	exit 0
else
	echo "failed: expected  ${MATCHSTR} in ${OUTPUTSTRING} but instead found"
	exit 1
fi
