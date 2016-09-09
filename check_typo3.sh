#!/bin/bash
#
# TYPO3 monitoring plugin for Nagios
# Requires TYPO3 Extension "nagios" installed and configured on the
# TYPO3 server and a configuration file of course.
#
# Read the full documentation at: http://schams.net/nagios
# TYPO3 Extension Repository: http://typo3.org/extensions/repository
# Nagios: http://nagios.org/
#
# (c) 2010-2011 Michael Schams <typo3@schams.net>
# All rights reserved
#
# This script is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# The GNU General Public License can be found at
# http://www.gnu.org/copyleft/gpl.html
#
# This script is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# This copyright notice MUST APPEAR in all copies of the script!
#
# Please see TYPO3 and Nagios licenses.
#
# ------------------------------------------------------------------------------
# Revision 1.0.0.1 (see variable REVISION below)
# Date: 07/Apr/2011
#
# This version supports the following checks:
#   - PHP version
#   - TYPO3 version
#   - installed extensions
#
# *NOT* implemented yet:
#   - check basic database details
#   - check status of deprecation log
#   - check status of donation notice popup
#   - timestamp and timezone (TYPO3 server settings)
#   - TYPO3 "Nagios" extension compatibility list
#
# ------------------------------------------------------------------------------

COMMANDS_REQUIRED="awk basename egrep grep head mktemp rm sed wget"

# check if required commands are available and executable:
for COMMAND in $COMMANDS_REQUIRED; do
	TEMP=`which $COMMAND`
	if [ $? -ne 0 -o "$TEMP" = "" ]; then
		echo "Error: \"$COMMAND\" not installed or not in the path"
		exit 1
	elif [ ! -x $TEMP ]; then
		echo "Error: \"$COMMAND\" not executable"
		exit 1
	fi
done

NAGIOS_PATH="/usr/lib/nagios"
SCRIPTNAME=`basename $0`
CONFIGFILE="check_typo3.cfg"
TEMPFILE=`mktemp`

SSL="FALSE"
MESSAGE_TYPO3_VERSION=""
MESSAGE_WARNING=""
MESSAGE_CRITICAL=""
SEARCH_RESULT=""

PROGPATH=`echo $0 | sed -e 's,[\\/][^\\/][^\\/]*$,,'`
REVISION="1.0.0.1"

# USERAGENT: does not work :-(
USERAGENT="Nagios TYPO3 Monitor $REVISION (wget)"

if [ -e $PROGPATH/utils.sh ]; then
	. $PROGPATH/utils.sh
elif [ -e $NAGIOS_PATH/plugins/utils.sh ]; then
	. $NAGIOS_PATH/plugins/utils.sh
else
	echo 'Error: could not find Nagios utils include file!'
#	exit 1
fi

if [ -r $PROGPATH/$CONFIGFILE ]; then
	CONFIGFILE="$PROGPATH/$CONFIGFILE"
elif [ -r $NAGIOS_PATH/etc/$CONFIGFILE ]; then
	CONFIGFILE="$NAGIOS_PATH/$CONFIGFILE"
else
	echo 'Error: unable to read configuration file!'
	exit $STATE_UNKNOWN
fi

# function print_usage()
print_usage() {
	echo "Usage:"
	echo "  $SCRIPTNAME -H <fqhostname> -pid <pageid>"
	echo "              [-c <configfile>] [-e <encryptionkey>] [-t <timeout>] [-u <username>] | [-p <password>]"
	echo
	echo "  $SCRIPTNAME --help"
	echo "  $SCRIPTNAME --version"
	echo
	echo "Informative arguments:"
	echo "  -h, --help"
	echo "       Print detailed help screen"
	echo "  -V, --version, --revision"
	echo "       Print version information"
	echo
	echo "Mandatory arguments:"
	echo "  -H <fqhostname>, --hostname <fqhostname>"
	echo "       Full qualified host name argument of TYPO3 server (used in the GET request)"
	echo "       Append a port to include it in the URL (eg: typo3.org:8080)"
	echo "  -pid <pageid>, --pageid <pageid>"
	echo "       Page ID (numeric value) of TYPO3 instance with TYPO3 extension \"nagios\""
	echo "       See argument --resource and note below"
	echo "  --resource <path>"
	echo "       Request path to page in TYPO3 where TYPO3 extension \"nagios\" is installed"
	echo "       Argument --resource overwrites -pid and --pageid"
	echo
	echo "  Note: request string to TYPO3 instance becomes \"index.php?id=<pageid>\" if argument"
	echo "        -pid or --pageid is given. Alternatively, parameter --resource can be used to"
	echo "        define the path to the page, instead of naming the page ID (may be useful if"
	echo "        TYPO3 instance uses SEO extensions), eg: \"--resource /sysfolder/nagios.html\"."
	echo
	echo "Optional arguments:"
	echo "  -c <configfile>, --config <configfile>"
	echo "       Path and filename to configuration file. Default: \"check_typo3.cfg\""
	echo "       Located in  in Nagios' etc-directory (eg: /usr/local/nagios/etc/check_typo3.cfg)"
	echo "  -e <encryptionkey>, --encryptionkey <encryptionkey>"
	echo "       First 10 characters (at least) of the encryption key defined in TYPO3"
	echo "  -t <timeout>, --timeout <timeout>"
	echo "       Timeout in seconds. Nagios check fails (return: CRITICAL) if timeout exceeded"
	echo "       This timeout value applies to DNS lookup timeout, connect timeout and read timeout"
	echo "  -u <username>, --http-user <username>"
	echo "       HTTP user name (string) for HTTP access authentication (HTTP status code: 401)"
	echo "  -p <password>, --http-password <password>"
	echo "       HTTP password (string) for HTTP access authentication (HTTP status code: 401)"
	echo
	echo "Examples:"
	echo "  $SCRIPTNAME -H typo3.org -pid 42"
	echo "  $SCRIPTNAME -H typo3.org -pid 42 --http-user nagios --http-password MySecretPassword"
	echo "  $SCRIPTNAME --hostname mydomain.com --resource /sysfolder/nagios.html"
	echo "  $SCRIPTNAME -H mydomain.com --pageid 123 --config /etc/nagios/typo3.cfg"
	echo "  $SCRIPTNAME -H example.net --pageid 456 -e c50e820568ff --timeout 5"
	echo ""
}

# function remove_tempfile()
#
# @param $1: path/file (to be removed)
remove_tempfile() {
	if [ -w "$1" ]; then
		rm -f "$1"
	fi
}

# function check_config_general()
#
# @param SEARCH_KEY: keyword to search for as regular expression (e.g. "typo3\-version")
# @param SEARCH_PATTERN: pattern to search for as string (e.g. "4.5.1")
check_config_general() {

	SEARCH_KEY="$1"
	SEARCH_PATTERN="$2"
	SEARCH_RESULT="ok"

	MATCH=""
	VERSION_CHECK=`echo "$SEARCH_KEY" | egrep -w '^extension|version'`

	CONFIG_DATA=`echo "$CONFIGURATION" | egrep "^${SEARCH_KEY}\.(warning|critical)[[:space:]]*=[[:space:]]*" | sed "s/^${SEARCH_KEY}\.\(warning\|critical\)[=[:space:]]*\(.*\)$/\1:,\2,/"`
	for LINE in $CONFIG_DATA; do
		if [ "$VERSION_CHECK" = "" ]; then
			TEMP=`echo "$LINE" | cut -d ':' -f 2 | grep ",${SEARCH_PATTERN},"`
			MATCH="${MATCH}${TEMP}"
		else
			TEMP=`echo "$LINE" | cut -d ':' -f 2 | sed 's/\[^0-9x\.\]/,/g' | sed 's/,/ /g'`
			for VERSION_VALUE in $TEMP; do
				VERSION_VALUE=`echo "${VERSION_VALUE}" | sed 's/\./\\\./g' | sed 's/x/\[0-9\]\{1,3\}/g'`
				TEMP=`echo "${SEARCH_PATTERN}" | egrep "^$VERSION_VALUE\$"`
				MATCH="${MATCH}${TEMP}"
			done
		fi

		if [ ! "$MATCH" = "" -a "$SEARCH_RESULT" = "ok" ]; then
			SEARCH_RESULT=`echo "$LINE" | cut -d ':' -f 1`
		fi
	done
}

# function check_config_extensions()
#
# @param SEARCH_EXTENSION_KEY: keyword (extension key) to search for as regular expression (e.g. "templavoila")
# @param SEARCH_EXTENSION_VERSION: version to search for as string (e.g. "1.2.3")
check_config_extensions() {

	SEARCH_EXTENSION_KEY="$1"
	SEARCH_EXTENSION_VERSION="$2"

	check_config_general "extension\.$SEARCH_EXTENSION_KEY" "$SEARCH_EXTENSION_VERSION"
}

# Ensure at least one argument was given in the command line
if [ $# -lt 1 ]; then

	echo "TYPO3 monitoring plugin for Nagios"
	print_revision $SCRIPTNAME $REVISION
	echo
	print_usage
	echo
	support
	exit $STATE_UNKNOWN
fi

# Set default values
FQHOSTNAME=$NAGIOS_HOSTADDRESS
ENCRYPTIONKEY=""
TIMEOUT="5"
WGET_ARGUMENTS=""
HTTPUSER=""
HTTPPASSWORD=""
HTTPMETHOD="http"
RESOURCE="index.php"

RETURNCODE=$STATE_WARNING

# Overwrite default values with command line arguments
while test -n "$1"; do
	case "$1" in
		--help)
			print_usage
			exit $STATE_OK
		;;
		-h)
			print_usage
			exit $STATE_OK
		;;
		--version)
			print_revision $SCRIPTNAME $REVISION
			exit $STATE_OK
		;;
		--revision)
			print_revision $SCRIPTNAME $REVISION
			exit $STATE_OK
		;;
		-V)
			print_revision $SCRIPTNAME $REVISION
			exit $STATE_OK
		;;
		--hostname)
			FQHOSTNAME=$2
			shift
		;;
		-H)
			FQHOSTNAME=$2
			shift
		;;
		--config)
			CONFIGFILE=$2
			shift
		;;
		-c)
			CONFIGFILE=$2
			shift
		;;
		--encryptionkey)
			ENCRYPTIONKEY=$2
			shift
		;;
		-e)
			ENCRYPTIONKEY=$2
			shift
		;;
		--timeout)
			TIMEOUT=$2
			shift
		;;
		-t)
			TIMEOUT=$2
			shift
		;;
		--http-user)
			HTTPUSER="--http-user=$2"
			shift
		;;
		-u)
			HTTPUSER="--http-user=$2"
			shift
		;;
		--http-password)
			HTTPPASSWORD="--http-password=$2"
			shift
		;;
		-p)
			HTTPPASSWORD="--http-password=$2"
			shift
		;;
		--pageid)
			RESOURCE="index.php?id=$2"
			shift
		;;
		-pid)
			RESOURCE="index.php?id=$2"
			shift
		;;
		--resource)
			RESOURCE=`echo "$2" | sed 's/^\/*//'`
			shift
		;;
		*)
			echo "Unknown argument: $1"
			print_usage
			exit $STATE_UNKNOWN
		esac
	shift
done

if [ ! "$ENCRYPTIONKEY" = "" ]; then
	ENCRYPTIONKEY="--post-data=\"encryptionkey=$2\""
fi

if [ $SSL = "TRUE" ] ; then
	WGET_ARGUMENTS="--no-check-certificate --server-response"
	HTTPMETHOD="https"
fi

if [ ! "$USERAGENT" = "" ]; then
	USERAGENT="--user-agent=\"$USERAGENT\""
fi

USERAGENT=""
COMMAND="wget --save-headers --timeout $TIMEOUT --output-document=- $HTTPUSER $HTTPPASSWORD $USERAGENT $HTTPMETHOD://$FQHOSTNAME/$RESOURCE"

$COMMAND > $TEMPFILE 2>&1
WGET_RETURNCODE=$?

## *TODO* wget saves two HTTP headers when accessing a site with HTTP authentication
## (HTTP code 401 first), so we need to remove the first header from $TEMPFILE.
## This is UNTESTED and not implemented yet.

HTTP=`egrep "^HTTP/1" $TEMPFILE`

if [ $WGET_RETURNCODE -ne 0 ]; then
	echo "Error: wget terminated with code $WGET_RETURNCODE when accessing TYPO3 server $HTTPMETHOD://$FQHOSTNAME/$RESOURCE"
	remove_tempfile $TEMPFILE
	exit $STATE_UNKNOWN
elif [ "$HTTP" = "" ]; then
	echo "Error: invalid response from TYPO3 server $HTTPMETHOD://$FQHOSTNAME/$RESOURCE"
	remove_tempfile $TEMPFILE
	exit $STATE_CRITICAL
fi

HTTP_CODE=`echo "$HTTP" | awk '{print $2}'`
if [ ! "$HTTP_CODE" = "200" ]; then
	echo "TYPO3 web server returned HTTP error code $HTTP_CODE. HTTP: $HTTP"
	remove_tempfile $TEMPFILE
	exit $STATE_CRITICAL
fi

# read data from configuration file
# (better read file once and process data in memory instead of repeated file access)
CONFIGURATION=`egrep '^[^#]' $CONFIGFILE`

# filter data sent by TYPO3 server (and remove unnecessary lines such as comments, etc.)
DATA=`egrep '^[A-Z0-9]{3,}:.{1,}' $TEMPFILE | egrep '[^ ]'`

# process data
for ELEMENT in $DATA; do

	# keyword could be something like "TYPO3", "PHP", "EXT", etc.
	KEY=`echo "$ELEMENT" | cut -d ":" -f 1`

	case $KEY in
		"TYPO3")
			VALUE=`echo "$ELEMENT" | cut -d ":" -f 2`

			TEMP=`echo "$VALUE" | sed 's/^\([a-z]*\)\-.*$/\1/'`
			if [ "$TEMP" = "version" ]; then

				VERSION=`echo "$VALUE" | sed 's/^version\-\(.*\)$/\1/'`
				TEMP=`echo "$VERSION" | egrep '^[1-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'`
				if [ "$TEMP" = "" ]; then

					# alpha/beta/development version of TYPO3 server detected
					TEMP=`echo "$VERSION" | sed 's/[0-9\.\-]//g'`
					SEARCH_RESULT=""
					check_config_general "typo3\-version" "$TEMP"
					if [ "$SEARCH_RESULT" = "warning" ]; then
						MESSAGE_WARNING="$MESSAGE_WARNING,TYPO3 version is alpha/beta/development"
					elif [ "$SEARCH_RESULT" = "critical" ]; then
						MESSAGE_CRITICAL="$MESSAGE_CRITICAL,TYPO3 version is alpha/beta/development"
					fi
					STATUS="$STATUS,$SEARCH_RESULT"
				else
					# TYPO3 version looks pretty standard (e.g. x.yyy.zzz), no alpha, no development
					SEARCH_RESULT=""
					check_config_general "typo3\-version" "$VERSION"
					if [ "$SEARCH_RESULT" = "warning" ]; then
						MESSAGE_WARNING="$MESSAGE_WARNING,TYPO3 version $VERSION"
					elif [ "$SEARCH_RESULT" = "critical" ]; then
						MESSAGE_CRITICAL="$MESSAGE_CRITICAL,TYPO3 version $VERSION"
					fi
					STATUS="$STATUS,$SEARCH_RESULT"
				fi
				MESSAGE_TYPO3_VERSION="$VERSION"
			else
				# format of TYPO3 version data received from TYPO3 server is incorrect/unknown
				MESSAGE_UNKNOWN="$MESSAGE_UNKNOWN,invalid TYPO3 version reported by TYPO3 instance"
				STATUS="$STATUS,unknown"
			fi
		;;
		"PHP")
			VALUE=`echo "$ELEMENT" | cut -d ":" -f 2`
			TEMP=`echo "$VALUE" | sed 's/^\([a-z]*\)\-.*$/\1/'`
			if [ "$TEMP" = "version" ]; then

				VERSION=`echo "$VALUE" | sed 's/^version\-\(.*\)$/\1/'`

				# PHP version is always MAJOR.MINOR.REVISION (xxx.yyy.zzz, e.g. "5.3.2")
				# (additional keywords such as "ubuntu" in "5.3.2-1ubuntu4.5" are already removed by TYPO3 extension)
				TEMP=`echo "$VERSION" | egrep '^[1-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'`
				if [ ! "$TEMP" = "" ]; then

					# PHP version looks pretty standard (e.g. x.yyy.zzz)
					SEARCH_RESULT=""
					check_config_general "php\-version" "$VERSION"
					if [ "$SEARCH_RESULT" = "warning" ]; then
						MESSAGE_WARNING="$MESSAGE_WARNING,PHP version $VERSION"
					elif [ "$SEARCH_RESULT" = "critical" ]; then
						MESSAGE_CRITICAL="$MESSAGE_CRITICAL,PHP version $VERSION"
					fi
					STATUS="$STATUS,$SEARCH_RESULT"
				else
					# format of PHP version data received from TYPO3 server is incorrect/unknown
					MESSAGE_UNKNOWN="$MESSAGE_UNKNOWN,invalid PHP version reported by TYPO3 instance"
					STATUS="$STATUS,unknown"
				fi
			else
				# format of PHP version data received from TYPO3 server is incorrect/unknown
				MESSAGE_UNKNOWN="$MESSAGE_UNKNOWN,invalid PHP version reported by TYPO3 instance"
				STATUS="$STATUS,unknown"
			fi
		;;
		"EXT")
			VALUE=`echo "$ELEMENT" | cut -d ":" -f 2`

			EXTENSION_KEY=`echo "$VALUE" | cut -d "-" -f 1`
			KEYWORD=`echo "$VALUE" | cut -d "-" -f 2`
			VERSION=`echo "$VALUE" | cut -d "-" -f 3`
			if [ "$KEYWORD" = "version" ]; then

				# Extension version is always MAJOR.MINOR.REVISION (xxx.yyy.zzz, e.g. "1.2.3")
				TEMP=`echo "$VERSION" | egrep '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'`
				if [ ! "$TEMP" = "" ]; then

					SEARCH_RESULT=""
					check_config_extensions "$EXTENSION_KEY" "$VERSION"
					if [ "$SEARCH_RESULT" = "warning" ]; then
						MESSAGE_WARNING="$MESSAGE_WARNING,Extension $EXTENSION_KEY-$VERSION"
					elif [ "$SEARCH_RESULT" = "critical" ]; then
						MESSAGE_CRITICAL="$MESSAGE_CRITICAL,Extension $EXTENSION_KEY-$VERSION"
					fi
					STATUS="$STATUS,$SEARCH_RESULT"
				else
					# format of Extension version data received from TYPO3 server is incorrect/unknown
					MESSAGE_UNKNOWN="$MESSAGE_UNKNOWN,invalid extension data ($VALUE)"
					STATUS="$STATUS,unknown"
				fi
			else
				# format of Extension version data received from TYPO3 server is incorrect/unknown
				MESSAGE_UNKNOWN="$MESSAGE_UNKNOWN,invalid extension data ($VALUE)"
				STATUS="$STATUS,unknown"
			fi
		;;
		*)
		;;
	esac

done

# temporary file is not longer required - delete it
remove_tempfile $TEMPFILE

# post-process $STATUS
TEMP=`echo "$STATUS" | sed 's/,/ /g'`
STATUS=""
for SINGLE_STATUS in $TEMP; do

	case $SINGLE_STATUS in
		"ok")
			if [ "$STATUS" = "" ]; then
				STATUS="OK"
				RETURNCODE=$STATE_OK
			fi
		;;
		"unknown")
			if [ "$STATUS" = "" -o "$STATUS" = "OK" ]; then
				STATUS="UNKNOWN:"
				RETURNCODE=$STATE_UNKNOWN
			fi
		;;
		"warning")
			if [ "$STATUS" = "" -o "$STATUS" = "OK" -o "$STATUS" = "UNKNOWN" ]; then
				STATUS="WARNING:"
				RETURNCODE=$STATE_WARNING
			fi
		;;
#		"UNAUTHORIZED")
#			if [ "$STATUS" = "" -o "$STATUS" = "OK" -o "$STATUS" = "UNKNOWN" -o "$STATUS" = "WARNING" ]; then
#				STATUS="UNAUTHORIZED"
#				RETURNCODE=$STATE_CRITICAL
#			fi
#		;;
		"critical")
			STATUS="CRITICAL:"
			RETURNCODE=$STATE_CRITICAL
		;;
	esac
done

if [ "$STATUS" = "OK" ]; then
	STATUS="$MESSAGE_TYPO3_VERSION OK"
fi

# post-process $MESSAGE
MESSAGE="$MESSAGE_CRITICAL,$MESSAGE_WARNING,$MESSAGE_UNKNOWN"
MESSAGE=`echo "$MESSAGE" | sed 's/^[,]*//g' | sed 's/[,]*$//g' | sed 's/,\{2,\}/,/g'`

# Pass further explanations to Nagios and exit with approriate returncode
echo "TYPO3 $STATUS $MESSAGE" | sed 's/ \{1,\}/ /g'
exit $RETURNCODE

# END OF FILE

