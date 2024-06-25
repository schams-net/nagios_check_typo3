#!/bin/bash
#
# TYPO3 monitoring plugin for Nagios
# Requires TYPO3 Extension "nagios" installed and configured on the
# TYPO3 server and a configuration file of course.
#
# Read the full documentation at: https://schams.net/nagios
# TYPO3 Extension Repository: https://extensions.typo3.org/extension/nagios
# Nagios: https://www.nagios.org/
#
# (c) 2010-2024 Michael Schams <schams.net>
# All rights reserved
#
# This script is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# The GNU General Public License can be found at
# https://www.gnu.org/licenses/gpl.html
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
# Revision 1.0.0.8 (see variable REVISION below)
# Date: 25/Jun/2024
#
# This version supports the following checks:
#   - PHP version
#   - TYPO3 version
#   - installed TYPO3 extensions
#   - disk space used by TYPO3 website ("disk usage")
#   - status of deprecation log
#
# *NOT* implemented yet:
#   - customised user agent used for HTTP calls
#   - check basic database details
#   - check status of donation notice popup
#   - timestamp and timezone (TYPO3 server settings)
#   - TYPO3 "Nagios" extension compatibility list
#
# ------------------------------------------------------------------------------

COMMANDS_REQUIRED="awk basename cat cut date dirname egrep grep head mktemp rm sed wget"

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

MESSAGE_VERSION=""
MESSAGE_PHP_VERSION=""
MESSAGE_UNKNOWN_EXTENSION_VERSIONS=""
MESSAGE_WARNING=""
MESSAGE_CRITICAL=""
MESSAGE_UNKNOWN=""
SEARCH_RESULT=""
STATUS=""

PROGPATH=`echo $0 | sed -e 's,[\\/][^\\/][^\\/]*$,,'`
REVISION="1.0.0.8"

# Set default values
FQHOSTNAME=""
IPADDRESS=""
TIMEOUT="5"
WGET_ARGUMENTS=""
HTTPUSER=""
HTTPPASSWORD=""
METHOD="http"
RESOURCE=""
PAGEID=""
NO_CHECK_CERTIFICATE="false"

DISKUSAGEWARNING=""
DISKUSAGECRITICAL=""
SERVER_MESSAGE=""

DEPRECATIONLOG_ACTION="warning"
SERVER_MESSAGE_ACTION="show"
UNKNOWN_EXTENSION_VERSION_ACTION="unknown"
PHP_MESSAGE_ACTION="hide"

# USERAGENT: does not work :-(
USERAGENT="Nagios TYPO3 Monitor Plugin version $REVISION (wget)"

WGET_RESOURCE=""

CONFIGURATION_CURRENT_ID=""

if [ -e $PROGPATH/utils.sh ]; then
	. $PROGPATH/utils.sh
elif [ -e $NAGIOS_PATH/plugins/utils.sh ]; then
	. $NAGIOS_PATH/plugins/utils.sh
else
	echo 'Error: could not find Nagios utils include file!'
	exit 1
fi

#PROGPATH: /home/nagios/nagios/libexec
#NAGIOS_PATH: /usr/lib/nagios
if [ -r $PROGPATH/$CONFIGFILE ]; then
	CONFIGFILE="$PROGPATH/$CONFIGFILE"
elif [ -r $NAGIOS_PATH/etc/$CONFIGFILE ]; then
	CONFIGFILE="$NAGIOS_PATH/etc/$CONFIGFILE"
elif [ -r $PROGPATH/../$CONFIGFILE ]; then
	CONFIGFILE="$PROGPATH/../$CONFIGFILE"
elif [ -r $NAGIOS_PATH/$CONFIGFILE ]; then
	CONFIGFILE="$NAGIOS_PATH/$CONFIGFILE"
else
	echo 'Error: unable to read configuration file!'
	exit $STATE_UNKNOWN
fi

# function print_usage()
print_usage() {

	CONFIGFILE_BASENAME=`basename "$CONFIGFILE"`

	echo "Usage:"
	echo "  $SCRIPTNAME -H <fqhostname>"
	echo "       [ -r <uri> | -pid <pageid> ]"
	echo "       [ -c <configfile> ]"
	echo "       [ -t <timeout> ] [ -u <username>] [ -p <password> ] [ -r <uri> ] [ -I <ip-address> ]"
	echo "       [ -duw <limit> ] [ -duc <limit> ]"
	echo "       [ --deprecationlog-action ignore|warning|critical ]"
	echo "       [ --server-messages-action ignore|show ]"
	echo "       [ --unknown-extension-version-action ignore|show|unknown ]"
	echo "       [ --php-message-action hide|show ]"
	echo "       [ --method http|https ]"
	echo "       [ --no-check-certificate false|true ]"
	echo
	echo "  $SCRIPTNAME --help"
	echo "  $SCRIPTNAME --version"
	echo
	echo "Informative arguments:"
	echo "  -h, --help"
	echo "       Print detailed help screen"
	echo
	echo "  -V, --version, --revision"
	echo "       Print version information"
	echo
	echo "Mandatory arguments:"
	echo "  -H <fqhostname>, --hostname <fqhostname>"
	echo "       Full qualified host name of TYPO3 server (e.g. \"typo3.org\")"
	echo "       A port can be appended if required (e.g.: typo3.org:8080)"
	echo "       This argument is also used to determine the request to the TYPO3 server but can be"
	echo "       overwritten by using the -r (or --resource) argument."
	echo
	echo "       The output of the TYPO3 Nagios extension is expected at:"
	echo "       \"http://<fqhostname>/index.php?eID=nagios\""
	echo
	echo "Optional arguments:"
	echo "  -c <configfile>, --config <configfile>"
	echo "       Path and filename to configuration file. Default: \"$CONFIGFILE_BASENAME\","
	echo "       located in Nagios' etc-directory."
	echo
	echo "  -t <timeout>, --timeout <timeout>"
	echo "       Timeout in seconds. Nagios check fails (return: CRITICAL) if timeout exceeded."
	echo "       This timeout value applies to DNS lookup timeout, connect timeout and read timeout."
	echo "       Default: $TIMEOUT"
	echo
	echo "  -u <username>, --http-user <username>"
	echo "       HTTP user name (string) for HTTP access authentication (HTTP status code: 401)"
	echo
	echo "  -p <password>, --http-password <password>"
	echo "       HTTP password (string) for HTTP access authentication (HTTP status code: 401)"
	echo
	echo "  -r <uri>, --resource <uri>"
	echo "       URI (Uniform Resource Identifier) of TYPO3 server's Nagios extension output."
	echo "       Example: \"-r http://typo3.org/index.php?eID=nagios\""
	echo "       Note that this argument is optional. The Nagios plugin uses --hostname (or -H) to"
	echo "       determine the URI of the TYPO3 server. If <uri> starts with \"/\", <fqhostname> is"
	echo "       prepended. If you use this argument, it overwrites arguments -pid and --pageid"
	echo
	echo "  -I <ip-address>, --ipaddress <ip-address>"
	echo "       IPv4 address of the TYPO3 server (e.g. \"123.45.67.89\")"
	echo "       If this argument is used, the hostname (argument -H or --hostname) is sent as"
	echo "       \"Host:\" in the HTTP header of the request."
	echo
	echo "  -duw <limit>, --diskusagewarning <limit>"
	echo "       Warning level for disk usage (should be less than -duc)."
	echo "       Value MUST have one of these units appended: k, M, G, T or P."
	echo "       A valid value for this argument would be \"512M\" for example."
	echo
	echo "  -duc <limit>, --diskusagecritical <limit>"
	echo "       Critical level for disk usage."
	echo "       Value MUST have one of these units appended: k, M, G, T or P."
	echo "       A valid value for this argument would be \"512M\" for example."
	echo
	echo "  --deprecationlog-action <action>"
	echo "       One of the following actions, if an enabled deprecation log has been detected:"
	echo "       \"ignore\"    do nothing, ignore enabled deprecation logs"
	echo "       \"warning\"   generate a warning condition in Nagios"
	echo "       \"critical\"  generate a critical condition in Nagios"
	echo "       Default: $DEPRECATIONLOG_ACTION"
	echo
	echo "  --server-messages-action <action>"
	echo "       What should the check script do, if TYPO3 server sends an additional message in"
	echo "       the output:"
	echo "       \"ignore\"    do nothing and do not show messages (not recommended)"
	echo "       \"show\"      show messages if they occur (they can be useful)"
	echo "       Default: $SERVER_MESSAGE_ACTION"
	echo
	echo "  --unknown-extension-version-action <action>"
	echo "       What should the check script do, if the TYPO3 server reports an extension with"
	echo "       an invalid version:"
	echo "       \"ignore\"    ignore the extension do not show the extension at all (not recommended)"
	echo "       \"show\"      do not raise a warning/error but show the version string as it is"
	echo "       \"unknown\"   generate a unknown condition in Nagios"
	echo "       Default: $UNKNOWN_EXTENSION_VERSION_ACTION"
	echo
	echo "  --php-message-action <action>"
	echo "       Should the PHP Version be appended in the status message:"
	echo "       \"show\"      show the PHP version that the TYPO3 instance uses"
	echo "       \"hide\"      do not show the PHP version that the TYPO3 instance uses"
	echo "       Default: $PHP_MESSAGE_ACTION"
	echo
	echo "  --method <method>"
	echo "       Use SSL/TLS (https) when accessing the TYPO3 instance:"
	echo "       \"http\"      use HTTP"
	echo "       \"https\"     use HTTPS"
	echo "       Default: $METHOD"
	echo
	echo "  --no-check-certificate <action>"
	echo "       Suppress server certificate checks. This option is only relevant if the option --method"
	echo "       is set to \"https\". Leave this option as \"false\" unless you know what you're doing."
	echo "       \"false\"     check the certificate"
	echo "       \"true\"      do not check the certificate (insecure)"
	echo "       Default: $NO_CHECK_CERTIFICATE"
	echo
	echo "Deprecated (but still supported) arguments:"
	echo "  -pid <pageid>, --pageid <pageid>"
	echo "       Page ID (numeric value) of TYPO3 instance with TYPO3 extension \"nagios\""
	echo "       See argument \"--resource\" and note below."
	echo
	echo "       Note: HTTP request string to TYPO3 server becomes \"index.php?id=<pageid>\" if argument"
	echo "       -pid or --pageid is given. Alternatively, parameter --resource can be used to define"
	echo "       the path to a page (may be useful if TYPO3 instance uses SEO extensions). However,"
	echo "       be aware of the fact that the -pid and --pageid method is DEPRECATED and you should"
	echo "       use the eID method (which is the default behaviour)."
	echo
	echo "Examples:"
	echo "       See official documentation at http://schams.net/nagios for examples"
	echo
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

# function human_readable_to_integer()
#
# @param HR_VALUE: value in human readable style (e.g. 128M)
# @return HR_VALUE: value in non-human readable format (e.g. 129552384)
function human_readable_to_integer {

	HR_VALUE="$1"
	HR_RESULT="ok"

	if [ "`echo $HR_VALUE | egrep ^[[:digit:]]+[kMGTP]$`" = "" ]; then
		HR_RESULT="Unkown value/format: $HR_VALUE"
	fi

	local __hrKey=${HR_VALUE: -1}
	local __multiplicator=1
	local __value=${HR_VALUE%?}

	if [ "`echo $__value | egrep ^[[:digit:]]+$`" = "" ]; then
		HR_RESULT="Unkown value/format: $HR_VALUE"
	fi

	if [ "$HR_RESULT" = "ok" ]; then
		case "$__hrKey" in
			k)
				__multiplicator=1024
				shift
				;;
			M)
				__multiplicator=1048576
				shift
				;;
			G)
				__multiplicator=1073741824
				shift
				;;
			T)
				__multiplicator=1099511627776
				shift
				;;
			P)
				__multiplicator=1125899906842620
				shift
				;;
			*)
				HR_RESULT="Unknown unit in: $HR_VALUE"
				exit
				;;
		esac

		HR_VALUE=$[__value*__multiplicator]
	else
		HR_VALUE=0
	fi
}

# function integer_to_human_readable()
#
# @param VALUE: value in non-human readable format (e.g. 129552384)
# @return VALUE: value in human readable format (e.g. 128M)
function integer_to_human_readable {
	VALUE=`echo "$1" | awk '{x=$1
	if (x<0) {n="-"; x=-x} else n=""
	if (x<1024)                 {d=1;                  s=""}
	if (x>=1024)                {d=1024;               s="k"}
	if (x>=1048576)             {d=1048576;            s="M"}
	if (x>=1073741824)          {d=1073741824;         s="G"}
	if (x>=1099511627776)       {d=1099511627776;      s="T"}
	if (x>=1125899906842624)    {d=1125899906842624;   s="P"}
	print n""x/d""s }' | sed 's/\.\([0-9]*\)//'`
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

FQHOSTNAME=$NAGIOS_HOSTADDRESS
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
			FQHOSTNAME="$2"
			shift
		;;
		-H)
			FQHOSTNAME="$2"
			shift
		;;
		-I)
			TEMP=`echo "$2" | egrep "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$"`
			if [ ! "$TEMP" = "" ]; then
				IPADDRESS="$2"
			fi
			shift
		;;
		--ipaddress)
			TEMP=`echo "$2" | egrep "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$"`
			if [ ! "$TEMP" = "" ]; then
				IPADDRESS="$2"
			fi
			shift
		;;
		--config)
			CONFIGFILE="$2"
			shift
		;;
		-c)
			CONFIGFILE="$2"
			shift
		;;
		--timeout)
			TIMEOUT="$2"
			shift
		;;
		-t)
			TIMEOUT="$2"
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
			TEMP=`echo "$2" | egrep "^[0-9]{1,}$"`
			if [ ! "$TEMP" = "" ]; then
				PAGEID="$2"
			fi
			shift
		;;
		-pid)
			TEMP=`echo "$2" | egrep "^[0-9]{1,}$"`
			if [ ! "$TEMP" = "" ]; then
				PAGEID="$2"
			fi
			shift
		;;
		-r)
			RESOURCE="$2"
			shift
		;;
		--resource)
			RESOURCE="$2"
			shift
		;;
		--duw)
			# *DEPRECATED* please use argument -duw instead (one dash only, see --help)
			TEMP=`echo "$2" | egrep "^[0-9]{1,}[kMGTP]{0,1}$"`
			if [ ! "$TEMP" = "" ]; then
				DISKUSAGEWARNING="$2"
			fi
			shift
		;;
		-duw)
			TEMP=`echo "$2" | egrep "^[0-9]{1,}[kMGTP]{0,1}$"`
			if [ ! "$TEMP" = "" ]; then
				DISKUSAGEWARNING="$2"
			fi
			shift
		;;
		--diskusagewarning)
			TEMP=`echo "$2" | egrep "^[0-9]{1,}[kMGTP]{0,1}$"`
			if [ ! "$TEMP" = "" ]; then
				DISKUSAGEWARNING="$2"
			fi
			shift
		;;
		--duc)
			# *DEPRECATED* please use argument -duc instead (one dash only, see --help)
			TEMP=`echo "$2" | egrep "^[0-9]{1,}[kMGTP]{0,1}$"`
			if [ ! "$TEMP" = "" ]; then
				DISKUSAGECRITICAL="$2"
			fi
			shift
		;;
		-duc)
			TEMP=`echo "$2" | egrep "^[0-9]{1,}[kMGTP]{0,1}$"`
			if [ ! "$TEMP" = "" ]; then
				DISKUSAGECRITICAL="$2"
			fi
			shift
		;;
		--diskusagecritical)
			TEMP=`echo "$2" | egrep "^[0-9]{1,}[kMGTP]{0,1}$"`
			if [ ! "$TEMP" = "" ]; then
				DISKUSAGECRITICAL="$2"
			fi
			shift
		;;
		--deprecationlog-action)
			TEMP=`echo "$2" | egrep "^(ignore|warning|critical)$"`
			if [ ! "$TEMP" = "" ]; then
				DEPRECATIONLOG_ACTION="$2"
			fi
			shift
		;;
		--server-messages-action)
			TEMP=`echo "$2" | egrep "^(show|ignore)$"`
			if [ ! "$TEMP" = "" ]; then
				SERVER_MESSAGE_ACTION="$2"
			fi
			shift
		;;
		--unknown-extension-version-action)
			TEMP=`echo "$2" | egrep "^(show|unknown)$"`
			if [ ! "$TEMP" = "" ]; then
				UNKNOWN_EXTENSION_VERSION_ACTION="$2"
			fi
			shift
		;;
		--php-message-action)
			TEMP=`echo "$2" | egrep "^(show|hide)$"`
			if [ ! "$TEMP" = "" ]; then
				PHP_MESSAGE_ACTION="$2"
			fi
			shift
		;;
		--method)
			TEMP=`echo "$2" | egrep "^(http|https)$"`
			if [ ! "$TEMP" = "" ]; then
				METHOD="$2"
			fi
			shift
		;;
		--no-check-certificate)
			TEMP=`echo "$2" | egrep "^(true|false)$"`
			if [ ! "$TEMP" = "" ]; then
				NO_CHECK_CERTIFICATE="$2"
			fi
			shift
		;;
		*)
			echo "Unknown argument: $1"
			print_usage
			exit $STATE_UNKNOWN
		esac
	shift
done

# check if <fqhostname> is valid
TEMP=`echo "$FQHOSTNAME" | egrep '^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]))*$'`
if [ "$TEMP" = "" ]; then
	echo "Error: invalid hostname $FQHOSTNAME"
	exit $STATE_CRITICAL
fi

# check which HTTP method should be used (HTTP or HTTPS)
if [ $METHOD != "https" ]; then
	METHOD="http"
else
	if [ $NO_CHECK_CERTIFICATE = "true" ]; then
		WGET_ARGUMENTS="$WGET_ARGUMENTS --no-check-certificate"
	fi
fi

# set custom user agent (NOT IMPLEMENTED YET)
USERAGENT=""
if [ ! "$USERAGENT" = "" ]; then
	USERAGENT="--user-agent=\"$USERAGENT\""
fi

# disk usage warning and disk usage critical:
# convert human readable values to integer and check if values are valid
if [ ! "$DISKUSAGEWARNING" = "" ] || [ ! "$DISKUSAGECRITICAL" = "" ]; then
	DISKUSAGEVALUES=($DISKUSAGEWARNING $DISKUSAGECRITICAL)
	for INDEX in ${!DISKUSAGEVALUES[*]}; do
		HR_VALUE=0
		human_readable_to_integer ${DISKUSAGEVALUES[$INDEX]}
		if [ ! "$HR_RESULT" = "ok" ]; then
			echo "Error: invalid value(s) for disk usage check"
			exit $STATE_UNKNOWN
		else
			if [ $INDEX -eq 0 ]; then
				DISKUSAGEWARNING=$HR_VALUE
			elif [ $INDEX -eq 1 ]; then
				DISKUSAGECRITICAL=$HR_VALUE
			fi
		fi
	done

	# check, if values seem to be valid - otherwise set to "0"
	if [ "`echo $DISKUSAGEWARNING | egrep ^[[:digit:]]+$`" = "" ]; then
		DISKUSAGEWARNING=0
	fi
	if [ "`echo $DISKUSAGECRITICAL | egrep ^[[:digit:]]+$`" = "" ]; then
		DISKUSAGECRITICAL=0
	fi
fi

# read minimal data from existing config file
if [ -s "$CONFIGFILE" ]; then
	CONFIGURATION_CURRENT_ID=`cat "$CONFIGFILE" | egrep '^nagios-typo3-configuration\.id\s*=' | sed 's/^.*=\s*\(.*\)$/\1/g'`
else
	echo "Error: could not read configuration file"
	#exit $STATE_UNKNOWN
fi

# prepare HTTP request to TYPO3 server
if [ "$RESOURCE" = "" -a ! "$PAGEID" = "" ]; then
	TEMP=`echo "$PAGEID" | egrep "^[0-9]{1,}$"`
	if [ ! "$TEMP" = "" ]; then
		RESOURCE="/index.php?id=$PAGEID"
	else
		RESOURCE="/index.php?eID=nagios"
	fi
elif [ "$RESOURCE" = "" ]; then
	RESOURCE="/index.php?eID=nagios"
fi

# ensure, <fqhostname> and <resource> is valid
TEMP=`echo "$RESOURCE" | egrep "^\/.*"`
if [ ! "$TEMP" = "" ]; then
	if [ ! "$IPADDRESS" = "" ]; then
		WGET_RESOURCE="$METHOD://$IPADDRESS$RESOURCE"
		#WGET_ARGUMENTS="$WGET_ARGUMENTS --header=\"Host: $FQHOSTNAME\""
		WGET_ARGUMENTS="$WGET_ARGUMENTS --header=Host:$FQHOSTNAME"
	else
		WGET_RESOURCE="$METHOD://$FQHOSTNAME$RESOURCE"
	fi
else
	TEMP=`echo "$RESOURCE" | egrep "^https?:\/\/.*"`
	if [ ! "$TEMP" = "" ]; then
		# if <resource> starts with "http://" or "https://", omit <fqhostname> in wget request
		WGET_RESOURCE="$RESOURCE"
	else
		echo "Error: invalid parameters, check configuration"
		exit $STATE_UNKNOWN
	fi
fi

SERVER_TYPE="TYPO3 server"

# initiate request to TYPO3 server
TEMPFILE=`mktemp`
COMMAND="wget --quiet --save-headers --timeout $TIMEOUT $WGET_ARGUMENTS --output-document - $HTTPUSER $HTTPPASSWORD $USERAGENT $WGET_RESOURCE"
$COMMAND > $TEMPFILE 2>&1
WGET_RETURNCODE=$?

## *TODO* wget saves two HTTP headers when accessing a site with HTTP authentication
## (HTTP code 401 first), so we need to remove the first header from $TEMPFILE.
## This is UNTESTED and not implemented yet.

HTTP=`egrep "^HTTP/1" $TEMPFILE`

if [ $WGET_RETURNCODE -ne 0 ]; then
	echo "Error: wget terminated with code $WGET_RETURNCODE when accessing $SERVER_TYPE $WGET_RESOURCE"
	remove_tempfile $TEMPFILE
	exit $STATE_UNKNOWN
elif [ "$HTTP" = "" ]; then
	echo "Error: invalid response from $SERVER_TYPE $WGET_RESOURCE"
	remove_tempfile $TEMPFILE
	exit $STATE_CRITICAL
fi

HTTP_CODE=`echo "$HTTP" | awk '{print $2}'`
if [ ! "$HTTP_CODE" = "200" ]; then
	echo "$SERVER_TYPE returned HTTP error code $HTTP_CODE. HTTP: $HTTP"
	remove_tempfile $TEMPFILE
	exit $STATE_CRITICAL
fi

if [ -s "$CONFIGFILE" ]; then

	# read data from configuration file
	# (better read file once and process data in memory instead of repeated file access)
	CONFIGURATION=`egrep '^[^#]' $CONFIGFILE`

# *TODO* skip HTTP header lines:
# They do not mess up the result, as longs as they do not match with one of the keywords (see $KEY).
# In a bid to make the script more stable and sustainable, it is better to ignore the header lines.

	# filter data sent by TYPO3 server (and remove unnecessary lines such as comments, etc.)
	DATA=`egrep '^[A-Z0-9]{3,}:.{1,}' $TEMPFILE | sed 's/\r$//' | egrep '[^ ]'`

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
					TEMP=`echo "$VERSION" | egrep '^[1-9][0-9]{0,2}\.[0-9]{1,3}\.[0-9]{1,3}$'`
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
					MESSAGE_VERSION="$VERSION"
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
					TEMP=`echo "$VERSION" | egrep '^[1-9][0-9]{0,2}\.[0-9]{1,3}\.[0-9]{1,3}$'`
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
                    # add the PHP version to the output (e.g. "TYPO3 11.5.20 OK (PHP 7.4.33)")
					if [ "$PHP_MESSAGE_ACTION" = "show" ]; then
						MESSAGE_PHP_VERSION="PHP $VERSION"
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

				# allow extension list with and without keyword "version" between extension key and name
				# see https://github.com/schams-net/nagios/issues/6 for details
				TEMP=`echo "$KEYWORD" | egrep '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'`
				if [ ! "$TEMP" = "" -a "$VERSION" = "" ]; then
					VERSION="$KEYWORD"
					KEYWORD="version"
				fi

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
						# invalid extension version detected
						if [ "$UNKNOWN_EXTENSION_VERSION_ACTION" = "ignore" ]; then
							STATUS="$STATUS"
						elif [ "$UNKNOWN_EXTENSION_VERSION_ACTION" = "show" ]; then
							MESSAGE_UNKNOWN_EXTENSION_VERSIONS="$MESSAGE_UNKNOWN_EXTENSION_VERSIONS,invalid extension data ($VALUE)"
							STATUS="$STATUS,ok"
						else
							MESSAGE_UNKNOWN="$MESSAGE_UNKNOWN,invalid extension data ($VALUE)"
							STATUS="$STATUS,unknown"
						fi
					fi
				else
					# invalid extension version detected
					MESSAGE_UNKNOWN="$MESSAGE_UNKNOWN,invalid extension data ($VALUE)"
					STATUS="$STATUS,unknown"
				fi
			;;
			"DISKUSAGE")
				if [ ! "$DISKUSAGEWARNING" = "" ] || [ ! "$DISKUSAGECRITICAL" = "" ]; then
					VALUE=`echo "$ELEMENT" | cut -d ":" -f 2`
					if [ $DISKUSAGECRITICAL -gt 0 -a $VALUE -ge $DISKUSAGECRITICAL ]; then
						integer_to_human_readable $VALUE
						ACTUAL_DISKUSAGE=$VALUE
						integer_to_human_readable $DISKUSAGECRITICAL
						DISKUSAGECRITICAL=$VALUE
						MESSAGE_CRITICAL="$MESSAGE_CRITICAL,disk usage $ACTUAL_DISKUSAGE/$DISKUSAGECRITICAL"
						STATUS="$STATUS,critical"
					elif [ $DISKUSAGEWARNING -gt 0 -a $VALUE -ge $DISKUSAGEWARNING ]; then
						integer_to_human_readable $VALUE
						ACTUAL_DISKUSAGE=$VALUE
						integer_to_human_readable $DISKUSAGEWARNING
						DISKUSAGEWARNING=$VALUE
						MESSAGE_WARNING="$MESSAGE_WARNING,disk usage $ACTUAL_DISKUSAGE/$DISKUSAGEWARNING"
						STATUS="$STATUS,warning"
					fi
				fi
			;;
			"DEPRECATIONLOG")
				VALUE=`echo "$ELEMENT" | cut -d ":" -f 2`
				if [ "$VALUE" = "enabled" ] && [ "$DEPRECATIONLOG_ACTION" = "warning" ]; then
					MESSAGE_WARNING="deprecation log enabled"
					STATUS="$STATUS,warning"
				elif [ "$VALUE" = "enabled" ] && [ "$DEPRECATIONLOG_ACTION" = "critical" ]; then
					MESSAGE_WARNING="deprecation log enabled"
					STATUS="$STATUS,critical"
				fi
			;;
			"MESSAGE")
				VALUE=`echo "$ELEMENT" | cut -d ":" -f 2`
				if [ ! "$VALUE" = "" ] && [ "$SERVER_MESSAGE_ACTION" = "show" ]; then
					SERVER_MESSAGE=$VALUE
				fi
			;;
			*)
			;;
		esac

	done
else
	echo "Error: could not read configuration file"
fi

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

STATUS_MESSAGE="$STATUS" # default
if [ "$STATUS" = "OK" ]; then
	STATUS_MESSAGE="$MESSAGE_VERSION OK"
	if [ ! "$MESSAGE_PHP_VERSION" = "" ]; then
		STATUS_MESSAGE="$STATUS_MESSAGE ($MESSAGE_PHP_VERSION)"
	fi
fi

# no keywords such as "TYPO3", "PHP", "EXT", etc. found
if [ "$TEMP" = "" ]; then
	STATUS="UNKNOWN:"
	if [ ! "$SERVER_MESSAGE" = "" ]; then
		MESSAGE_UNKNOWN="$SERVER_MESSAGE"
		SERVER_MESSAGE=""
	else
		MESSAGE_UNKNOWN="no valid output from TYPO3 server (check extension and its configuration)"
	fi
	RETURNCODE=$STATE_UNKNOWN
fi

# post-process $MESSAGE
MESSAGE="$MESSAGE_CRITICAL,$MESSAGE_WARNING,$MESSAGE_UNKNOWN,$MESSAGE_UNKNOWN_EXTENSION_VERSIONS"
MESSAGE=`echo "$MESSAGE" | sed 's/^[,]*//g' | sed 's/[,]*$//g' | sed 's/,\{2,\}/,/g'`
MESSAGE="$MESSAGE $SERVER_MESSAGE"

# Pass further explanations to Nagios and exit with approriate returncode
echo "TYPO3 $STATUS_MESSAGE $MESSAGE" | sed 's/ \{1,\}/ /g'
exit $RETURNCODE

# END OF FILE
