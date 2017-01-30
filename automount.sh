#!/usr/bin/env bash
DEBUG="false"
if [ "${DEBUG}" == "false" ]; then
	set +xv
	ExpectDebug="log_user 0"
else
	set -xv
	ExpectDebug="log_user 1"
fi

#${USERHOME}/Library/LaunchAgents/it.niemetz.automount.plist
#<?xml version="1.0" encoding="UTF-8"?>
#<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
#<plist version="1.0">
#<dict>
#	<key>Label</key>
#	<string>it.niemetz.automount</string>
#	<key>ProgramArguments</key>
#	<array>
#		<string>/usr/local/bin/automount.sh</string>
#		<string>--mountall</string>
#	</array>
#	<key>RunAtLoad</key>
#	<true/>
#	<key>WatchPaths</key>
#	<array>
#		<string>/Library/Preferences/SystemConfiguration</string>
#	</array>
#	<key>KeepAlive</key>
#	<dict>
#		<key>NetworkState</key>
#		<true/>
#	</dict>
#</dict>
#</plist>
#chown ${USERNAME}:staff ${USERHOME}/Library/LaunchAgents/it.niemetz.automount.plist
#chmod 644 ${USERHOME}/Library/LaunchAgents/it.niemetz.automount.plist
#launchctl load ${USERHOME}/Library/LaunchAgents/it.niemetz.automount.plist

#${USERHOME}/Library/Preferences/it.niemetz.automount.plist
#<?xml version="1.0" encoding="UTF-8"?>
#<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
#<plist version="1.0">
#<dict>
#	<key>CommonMaxRetryInSeconds</key>
#	<integer>COMMONMAXRETRYINSECONDS (eg. 30)</integer>
#	<key>CommonValidIPRanges</key>
#	<string>COMMONVALIDIPRANGES (eg. 10.0.0,192.168.0)</string>
#	<key>CommonAccount</key>
#	<string>COMMONACCOUNT</string>
#	<key>CommonMountOptions</key>
#	<string>COMMONMOUNTOPTIONS (nodev,nosuid)</string>
#	<key>Mountlist</key>
#	<array>
#		<dict>
#			<key>MaxRetryInSeconds</key>
#			<integer>MAXRETRYINSECONDS</integer>
#			<key>ValidIPRanges</key>
#			<string>VALIDIPRANGES (eg. 10.0.0,192.168.0)</string>
#			<key>MountOptions</key>
#			<string>MOUNTOPTIONS</string>
#			<key>Protocol</key>
#			<string>PROTOCOL (afp/smb/ftp (readonly)/nfs/http/https)</string>
#			<key>Account</key>
#			<string>ACCOUNT</string>
#			<key>Server</key>
#			<string>SERVER</string>
#			<key>Share</key>
#			<string>SHARE</string>
#		</dict>
#	</array>
#</dict>
#</plist>
#chown ${USERNAME}:staff ${USERHOME}/Library/Preferences/it.niemetz.automount.plist
#chmod 644 ${USERHOME}/Library/Preferences/it.niemetz.automount.plist

#security add-internet-password \
#	-a ACCOUNT \
#	-l LABEL (same as SERVER) \
#	-D DESCRIPTION (eg. Networkpassword) \
#	-j COMMENT (${SCRIPTNAME}) \
#	-r PROTOCOL ("afp "/"smb "/"ftp"/"htps"/"http") \
#	-s SERVER \
#	-w PASSWORD \
#	-U \
#	-T /usr/bin/security \
#	-T /System/Library/Extensions/webdav_fs.kext/Contents/Resources/webdavfs_agent \
#	-T /System/Library/CoreServices/NetAuthAgent.app/Contents/MacOS/NetAuthSysAgent \
#	-T /System/Library/CoreServices/NetAuthAgent.app \
#	-T group://NetAuth \
#	${USERHOME}/Library/Keychains/login.keychain

#Server="SERVER"; Label="${Server}"; Description="DESCRIPTION"; Protocol="PROTOCOL"; Account="$(id -p | awk '/^login/ { print $2; exit } /^uid/ { print $2 }')"; Userhome="$(dscl . read /Users/${Account} NFSHomeDirectory | cut -d' ' -f2-)"; security add-internet-password -a "${Account}" -l "${Label}" -D "${Description:-Netzwerkpasswort}" -j "automount" -r "$(printf "%-4s" ${Protocol})" -s "${Server}" -w "$(read -p "Password: " -s && echo "${REPLY}")" -U -T /usr/bin/security -T /System/Library/CoreServices/NetAuthAgent.app/Contents/MacOS/NetAuthSysAgent -T /System/Library/CoreServices/NetAuthAgent.app -T group://NetAuth ${USERHOME}/Library/Keychains/login.keychain
# when error "User interaction is not allowed." occurs, unlock keychain with
#security unlock-keychain -p "USERNAME_PASSWORD" ${USERHOME}/Library/Keychains/login.keychain

#/usr/local/bin/automount.sh
#chown root:admin /usr/local/bin/automount.sh
#chmod 755 /usr/local/bin/automount.sh

# CONSTANTS
declare -r SCRIPTLASTMOD="2017-01-24"
declare -r SCRIPTVERSION="0.90"
declare -ri YES=0
declare -ri SUCCESS=${YES}
declare -ri TRUE=${YES}
declare -ri NO=1
declare -ri ERROR=${NO}
declare -ri FALSE=${NO}
# script path name
SCRIPT_PN="${0%/*}"
if [ "${SCRIPT_PN}" == "." ]; then
	SCRIPT_PN="${PWD}"
elif [ "${SCRIPT_PN:0:1}" != "/" ]; then
	SCRIPT_PN="$(which ${0})"
fi
# script filename
declare -r SCRIPT_FN="${0##*/}"
# script name
SCRIPTNAME="${SCRIPT_FN%.*}"
# script filename extension
SCRIPTEXTENSION=${SCRIPT_FN##*.}
if [ "${SCRIPTNAME}" == "" ]; then
	SCRIPTNAME=".${SCRIPTEXTENSION}"
	SCRIPTEXTENSION=""
fi
declare -r SCRIPT_PN SCRIPTNAME SCRIPTEXTENSION
# user name
declare -r USERNAME="$(id -p | awk '/^uid/ { print $2 }')"
# user id
declare -r USERID="$(dscl . read /Users/${USERNAME} UniqueID | awk -F': ' '{ print $2 }')"
# user home
declare -r USERHOME="$(dscl . read /Users/${USERNAME} NFSHomeDirectory | awk -F': ' '{ print $2 }')"
# login name
LOGINNAME="$(id -p | awk '/^login/ { print $2 }')"
if [ -z "${LOGINNAME}" ]; then
	LOGINNAME="${USERNAME}"
	# login id
	LOGINID="${USERID}"
	# login home
	LOGINHOME="${USERHOME}"
	# launch as user
	LAUNCHASUSER=""
else
	LOGINID="$(dscl . read /Users/${LOGINNAME} UniqueID | awk -F': ' '{ print $2 }')"
	LOGINHOME="$(dscl . read /Users/${LOGINNAME} NFSHomeDirectory | awk -F': ' '{ print $2 }')"
	LAUNCHASUSER="launchctl asuser ${LOGINID}"
fi
declare -r LOGINNAME LOGINID LOGINHOME LAUNCHASUSER
# case $(ps -o state= -p ${$}) in
if [ -t 0 ]; then
		# interactive shell (not started from launch daemon)
		declare -ri INTERACTIVE=${YES}
		# Log the message to standard error
		declare -r LOGGEROPTION="-s"
else
		# background shell
		declare -ri INTERACTIVE=${NO}
		declare -r LOGGEROPTION=""
fi
:<<EOS
if RV="$(pgrep -f -l "${SCRIPT_FN}")"; then
	log "${SCRIPT_FN} is already running, RV=${RV}"
	exit 1
fi
EOS
# log dir (absolute path name)
declare -r LOG_APN="${LOGINHOME}/Library/Logs"
# log file (absolute file name)
declare -r LOG_AFN="${LOG_APN}/${SCRIPTNAME}.log"
# temp dir (absolute path name)
declare -r TMP_APN="/tmp"
# lock dir (absolute path name)
declare -r LOCK_APN="${TMP_APN}/${SCRIPTNAME}.lock"
# lock file (absolute file name)
declare -r LOCK_AFN="${LOCK_APN}/pid"
# log levels
#"Emergency" "Alert" "Critical" "Error" "Warning" "Notice" "Info" "Debug"
declare -a LOG_LEVEL
declare -r LOG_EMERGENCY=${#LOG_LEVEL[@]}
LOG_LEVEL[${#LOG_LEVEL[@]}]="Emergency"
declare -r LOG_ALERT=${#LOG_LEVEL[@]}
LOG_LEVEL[${#LOG_LEVEL[@]}]="Alert"
declare -r LOG_CRITICAL=${#LOG_LEVEL[@]}
LOG_LEVEL[${#LOG_LEVEL[@]}]="Critical"
declare -r LOG_ERROR=${#LOG_LEVEL[@]}
LOG_LEVEL[${#LOG_LEVEL[@]}]="Error"
declare -r LOG_WARNING=${#LOG_LEVEL[@]}
LOG_LEVEL[${#LOG_LEVEL[@]}]="Warning"
declare -r LOG_NOTICE=${#LOG_LEVEL[@]}
LOG_LEVEL[${#LOG_LEVEL[@]}]="Notice"
declare -r LOG_INFO=${#LOG_LEVEL[@]}
LOG_LEVEL[${#LOG_LEVEL[@]}]="Info"
declare -r LOG_DEBUG=${#LOG_LEVEL[@]}
LOG_LEVEL[${#LOG_LEVEL[@]}]="Debug"
declare -r LOG_LEVEL
# automount plist (absolute file name)
declare -r AUTOMOUNTPLIST_AFN="${USERHOME}/Library/Preferences/it.niemetz.automount.plist"
# login keychain (absolute file name)
declare -r LOGINKEYCHAIN_AFN="${USERHOME}/Library/Keychains/login.keychain"
# max pings
declare -ir MAXRETRYINSECONDS=30
# mount options
declare -r MOUNTOPTIONS="nodev,nosuid"
# map protocol to value in keychain
declare -ra PROTOCOLMAPPING=( 'afp="afp "' 'cifs="cifs "' 'ftp="ftp "' 'http="http"' 'https="htps"' 'smb="smb "' )

# Global variables
# index counter
declare -i Idx=0
# retry counter
declare -i Try
# is ip in valid range
declare -i IsInValidRange=0
# exit code
declare -i EC=0
# array of ip addresses
declare -a IPAddresses=()
# late bound variables
declare -i CommonMaxRetryInSeconds
CommonValidIPRanges=""
CommonMountOptions=""
CommonAccount=""
ValidIPRanges=""
MountOptions=""
declare -i MaxRetryInSeconds
Protocol=""
Account=""
Server=""
Share=""
declare -i MountedShares=0
# Action to do
Action=""
# verbose
Verbose=""
# redirect stdout
RedirectStdout="/dev/null"

# Function definitions
function log {
	local _DateFormat='%Y-%m-%d %T %z'
	local _Delimiter="|"
	local -i _Priority=6

	while :; do
		case ${1} in
				-p|--priority)
					if [[ -n "${2}" && "${2:0:1}" != "--" && "${2:0:1}" != "-" ]]; then
						if ! _Priority=${2} 2>/dev/null; then
							printf 'ERROR: "%s" requires a numeric option argument.\n' "${1}" >&2
							exit 1
						fi
						shift
					else
						printf 'ERROR: "%s" requires a non-empty option argument.\n' "${1}" >&2
						exit 1
					fi
					;;
				--priority=?*)
					if ! _Priority=${1#*=} 2>/dev/null; then
						printf 'ERROR: "%s" requires a numeric option argument.\n' "${1}" >&2
						exit 1
					fi
					;;
				--priority=)
					printf 'ERROR: "%s" requires a non-empty option argument.\n' "${1}" >&2
					exit 1
					;;
				--) # End of all options.
					shift
					break
					;;
				-?*)
					printf 'WARN: Unknown option (ignored): %s\n' "${1}" >&2
					;;
				*) # Default case: If no more options then break out of the loop.
					break
		esac
		shift
	done
	set -- "${1:-$(</dev/stdin)}" "${@:2}"

	if [ ${_Priority} -le 3 ]; then
		echo "${1}" | tee -a "${LOG_AFN}" >&2
	else
		echo "${1}" | tee -a "${LOG_AFN}"
	fi
}

function cleanup {
	rm -rf "${LOCK_APN}" >/dev/null 2>&1
	exit ${1}
}

function showUsage {
  cat <<EOH
Usage: ${SCRIPT_FN} (V${SCRIPTVERSION} ${SCRIPTLASTMOD}) (-m|--mountall)|--addpassword (-p|--protocol) protocol (-s|--server) server [(-a|--account) account] [(-d|--description) description]
EOH
}

function getIPAddresses {
	local _IPAddresses=""
	local -i _Sleep=0

	while [[ ( -z "${_IPAddresses}" || "${_IPAddresses}" =~ (^| )169\.[0-9]+\.[0-9]+\.[0-9]+( |$) ) && ${_Sleep} -lt 10 ]]; do
		sleep ${_Sleep}
		((_Sleep++))
		#/usr/libexec/PlistBuddy -c "Print 0:_items:0:IPv4:Addresses:0" /var/folders/5s/prj3y3g13nb9mllltrcg8rcw0000gn/T/SPNetworkDataType.kuCAGYvK
		#system_profiler SPNetworkDataType |awk '/IPv4 Addresses:/ { gsub(/      IPv4 Addresses: /, ""); printf $0 " " }'
		_IPAddresses="$(
			/sbin/ifconfig |\
			/usr/bin/awk \
				'
				BEGIN {
					device=""
				}
				/(^en[0-9]*:|^utun[0-9]*).*UP.*RUNNING/ {
					device=$1
					next
				}
				$1 == "inet" && device != "" {
					output=sprintf("%s%s", (output == "" ? "" : output " "), $2)
					device=""
					next
				}
				END {
					print output
				}
				'
		)"
	done

	if [ -n "${_IPAddresses}" ]; then
		echo "${_IPAddresses}"
		return 0
	else
		return 1
	fi
}

function getKeychainProtocol {
	local _SearchKeychainProtocol="${Protocol:-unknown_protocol}="
	local _Protocol _KeychainProtocol


	for _Protocol in "${PROTOCOLMAPPING[@]}"; do
		if [[ "${_Protocol}" =~ ^${_SearchKeychainProtocol} ]]; then
			_KeychainProtocol="${_Protocol/${_SearchKeychainProtocol}/}"
		fi
	done

	if [ -n "${_KeychainProtocol}" ]; then
		echo "${_KeychainProtocol//\"/}"
		return 0
	else
		return 1
	fi
}

function getPasswordFromKeychain {
	security find-internet-password \
		-w \
		-r "$(getKeychainProtocol)" \
		-a "${Account}" \
		-l "${Server}" \
		-j "${SCRIPTNAME}" \
		"${LOGINKEYCHAIN_AFN}" 2>/dev/null
	return ${?}
}

function mountAll {
	if [ -s "${AUTOMOUNTPLIST_AFN}" ] && [ -s "${LOGINKEYCHAIN_AFN}" ] && IPAddresses=( $(getIPAddresses) ); then
		declare -i CommonMaxRetryInSeconds="$(/usr/libexec/PlistBuddy -c "Print CommonMaxRetryInSeconds" "${AUTOMOUNTPLIST_AFN}" 2>/dev/null)"
		CommonMaxRetryInSeconds="${CommonMaxRetryInSeconds:-${MAXRETRYINSECONDS}}"
		CommonValidIPRanges="$(/usr/libexec/PlistBuddy -c "Print CommonValidIPRanges" "${AUTOMOUNTPLIST_AFN}" 2>/dev/null)"
		CommonMountOptions="$(/usr/libexec/PlistBuddy -c "Print CommonMountOptions" "${AUTOMOUNTPLIST_AFN}" 2>/dev/null)"
		CommonMountOptions="${CommonMountOptions:-${MOUNTOPTIONS}}"
		CommonAccount="$(/usr/libexec/PlistBuddy -c "Print CommonAccount" "${AUTOMOUNTPLIST_AFN}" 2>/dev/null)"
		CommonAccount="${CommonAccount:-${LOGINNAME}}"
		while /usr/libexec/PlistBuddy -c "Print Mountlist:${Idx}" "${AUTOMOUNTPLIST_AFN}" >/dev/null 2>&1; do
			ValidIPRanges="$(/usr/libexec/PlistBuddy -c "Print Mountlist:${Idx}:ValidIPRanges" "${AUTOMOUNTPLIST_AFN}" 2>/dev/null)"
			ValidIPRanges="${ValidIPRanges:-${CommonValidIPRanges}}"
			MountOptions="$(/usr/libexec/PlistBuddy -c "Print Mountlist:${Idx}:MountOptions" "${AUTOMOUNTPLIST_AFN}" 2>/dev/null)"
			MountOptions="${MountOptions:-${CommonMountOptions}}"
			MaxRetryInSeconds="$(/usr/libexec/PlistBuddy -c "Print Mountlist:${Idx}:MaxRetryInSeconds" "${AUTOMOUNTPLIST_AFN}" 2>/dev/null)"
			MaxRetryInSeconds="${MaxRetryInSeconds:-${CommonMaxRetryInSeconds}}"
			Protocol="$(/usr/libexec/PlistBuddy -c "Print Mountlist:${Idx}:Protocol" "${AUTOMOUNTPLIST_AFN}" 2>/dev/null)"
			Account="$(/usr/libexec/PlistBuddy -c "Print Mountlist:${Idx}:Account" "${AUTOMOUNTPLIST_AFN}" 2>/dev/null)"
			Account="${Account:-${CommonAccount}}"
			Server="$(/usr/libexec/PlistBuddy -c "Print Mountlist:${Idx}:Server" "${AUTOMOUNTPLIST_AFN}" 2>/dev/null)"
			Share="$(/usr/libexec/PlistBuddy -c "Print Mountlist:${Idx}:Share" "${AUTOMOUNTPLIST_AFN}" 2>/dev/null)"
			if [[ -n "${Protocol}" && -n "${Account}" && -n "${Server}" && -n "${Share}" ]] && ! mount | egrep -s -q "//.*${Server}/(${Share})? on /Volumes/${Share} \(.*, mounted by ${USERNAME}\)$" 2>/dev/null; then
				if [ -n "${ValidIPRanges}" ]; then
					IsInValidRange=1
					for IPAddress in "${IPAddresses[@]}"; do
						IPAddressPart="$(echo "${IPAddress}" | cut -d'.' -f1-3)"
						if [[ "${ValidIPRanges}" =~ (^|,)"${IPAddressPart}"(,|$) ]]; then
							IsInValidRange=0
							break
						fi
					done
				fi

				if [ ${IsInValidRange} -eq ${TRUE} ]; then
					Try=0
					while ! ping -c 1 -t 1 -o -q "${Server}" >/dev/null 2>&1 && [ ${Try} -le ${MaxRetryInSeconds} ]; do
						((Try++))
					done
					if [ ${Try} -gt ${MaxRetryInSeconds} ]; then
						((Idx++))
						continue
					fi
						
					MountPoint="${Share##*/}"
					if [ ! -d "/Volumes/${MountPoint}" ]; then
						if ! { mkdir -p ${Verbose} "/Volumes/${MountPoint}" && chown "${USERNAME}:staff" "/Volumes/${MountPoint}"; }; then
							rmdir "/Volumes/${MountPoint}" >/dev/null 2>&1
							((Idx++))
							continue
						fi
					fi
							
					case "${Protocol}" in
						http|https)
							RV="$(expect -c '
								set timeout 15
								'"${ExpectDebug}"'
								spawn /sbin/mount_webdav -s -i'"${MountOptions:+ -o ${MountOptions}}"' '"${Protocol}"'://'"${Server}"' /Volumes/'"${MountPoint}"'
								expect "name:" {
									send "'"${Account}"'\r"
								}
								expect timeout {
									exit 1
								} "word:" {
									send "'$(getPasswordFromKeychain)'\r"
									exp_continue
								} eof
								catch wait result
								exit [lindex $result 3]
								' 2>&1)"
							RC=${?}
							;;
						ftp)
							RV="$(expect -c '
								set timeout 15
								'"${ExpectDebug}"'
								spawn /sbin/mount_ftp -i'"${MountOptions:+ -o ${MountOptions}}"' '"${Protocol}"'://'"${Server}"' /Volumes/'"${MountPoint}"'
								expect "name:" {
									send "'"${Account}"'\r"
								}
								expect timeout {
									exit 1
								} "word:" {
									send "'$(getPasswordFromKeychain)'\r"
									exp_continue
								} eof
								catch wait result
								exit [lindex $result 3]
								' 2>&1)"
							RC=${?}
							;;
						nfs)
							RV="$(mount -t ${Protocol}${MountOptions:+ -o ${MountOptions}} "${Server}:/${Share}" "/Volumes/${MountPoint}" 2>&1)"
							RC=${?}
							;;
						afp)
							RV="$(mount_afp -s ${MountOptions:+ -o ${MountOptions}} "${Protocol}://${Account}:$(getPasswordFromKeychain)@${Server}/${Share}" "/Volumes/${MountPoint}" 2>&1)"
							RC=${?}
							;;
						smb)
							RV="$(mount_smb -o soft${MountOptions:+,${MountOptions}} "${Protocol}://${Account}:$(getPasswordFromKeychain)@${Server}/${Share}" "/Volumes/${MountPoint}" 2>&1)"
							RC=${?}
							;;
						cifs)
							RV="$(mount -t ${Protocol}${MountOptions:+ -o ${MountOptions}} "${Protocol}://${Account}:$(getPasswordFromKeychain)@${Server}/${Share}" "/Volumes/${MountPoint}" 2>&1)"
							RC=${?}
							;;
						*)
							log -p ${LOG_ERROR} "Unknown protocol ${Protocol}"
							((Idx++))
							continue
							;;
					esac
					if [ ${RC} -eq ${SUCCESS} ]; then
						log -p ${LOG_INFO} "${Share} mounted successfully"
						((MountedShares++))
					else
						log -p ${LOG_ERROR} "mount of ${Share} failed (RC=${RC}, RV=${RV})"
					fi
					EC=$((EC||RC))
				fi
			fi
			((Idx++))
		done
	else
		log -p${LOG_ERROR} "${AUTOMOUNTPLIST_AFN} or ${LOGINKEYCHAIN_AFN} are missing"
		exit 1
	fi
	if [ ${EC} -eq ${SUCCESS} ]; then
		if [ ${MountedShares} -eq ${Idx} ]; then
			log -p ${LOG_INFO} "automount runned successfully."
		fi
		if [ ${INTERACTIVE} -eq ${NO} ]; then
			${LAUNCHASUSER} /usr/bin/osascript -e "display notification \"automount runned successfully.\" with title \"automount\" subtitle \"\""
		fi
	else
		log -p ${LOG_ERROR} "automount runned with errors."
		if [ ${INTERACTIVE} -eq ${NO} ]; then
			${LAUNCHASUSER} /usr/bin/osascript -e "display notification \"automount runned with errors.\" with title \"automount\" subtitle \"\""
		fi
	fi

	exit ${EC}
}

function addPassword {
	local _Account="${Account:-${LOGINNAME}}"
	local _Userhome="$(dscl . read /Users/${_Account} NFSHomeDirectory | cut -d' ' -f2-)"
	local _AppAccess=""

	if [[ "${Protocol}" =~ ^http(s)+ ]]; then
		_AppAccess="-T /System/Library/Extensions/webdav_fs.kext/Contents/Resources/webdavfs_agent"
	fi
	RV="$(security add-internet-password \
		-a "${_Account}" \
		-l "${Server}" \
		-D "${Description:-Netzwerkpasswort}" \
		-j "${SCRIPTNAME}" \
		-r "$(getKeychainProtocol)" \
		-s "${Server}" \
		-w "$(read -p "Password: " -s && echo "${REPLY}"; unset REPLY)" \
		-U \
		-T /usr/bin/security \
		-T /System/Library/CoreServices/NetAuthAgent.app/Contents/MacOS/NetAuthSysAgent \
		-T /System/Library/CoreServices/NetAuthAgent.app \
		-T group://NetAuth \
		${_AppAccess} \
		"${_Userhome}"/Library/Keychains/login.keychain)"
	RC=${?}

	if [ ${RC} -eq ${SUCCESS} ]; then
		log -p ${LOG_INFO} "successfully added password to keychain."
	else
		log -p ${LOG_ERROR} "error adding password to keychain. (RC=${RC}, RV=${RV})"
	fi
	exit ${RC}
}

function create_lock {
	if ! { mkdir "${LOCK_APN}" && echo "${$}" > "${LOCK_AFN}"; } 2>/dev/null; then
		_RunningPID="$(cat "${LOCK_AFN}")"
		if RV="$(pgrep -f -l -F "${LOCK_AFN}" "${SCRIPT_FN}")"; then
			log -p ${LOG_ERROR} "${SCRIPT_FN} is already running${_RunningPID:+ with PID ${_RunningPID}}"
			exit 1
		else
			if ! { rm -rf "${LOCK_APN}" && mkdir "${LOCK_APN}" && echo "${$}" > "${LOCK_AFN}"; } 2>/dev/null; then
				log -p ${LOG_ERROR} "Could not create \"${LOCK_AFN}\", exiting"
				exit 1
			fi
		fi
	fi
}

# Main
# catch traps
trap 'cleanup' SIGHUP SIGINT SIGQUIT SIGTERM EXIT
create_lock

while :; do
	case ${1} in
			-h|-\?|--help) # Call a "showUsage" function to display a synopsis, then exit.
				showUsage
				exit
				;;
			-a|--account)
				if [[ -n "${2}" && "${2:0:1}" != "--" && "${2:0:1}" != "-" ]]; then
					Account="${2}"
					shift
				else
					printf 'ERROR: "%s" requires a non-empty option argument.\n' "${1}" >&2
					exit 1
				fi
				;;
			--account=?*)
				Account=${1#*=} # Delete everything up to "=" and assign the remainder.
				;;
			--account=) # Handle the case of an empty --account=
				printf 'ERROR: "%s" requires a non-empty option argument.\n' "${1}" >&2
				exit 1
				;;
			-d|--description)
				if [[ -n "${2}" && "${2:0:1}" != "--" && "${2:0:1}" != "-" ]]; then
					Description="${2}"
					shift
				else
					printf 'ERROR: "%s" requires a non-empty option argument.\n' "${1}" >&2
					exit 1
				fi
				;;
			--description=?*)
				Description=${1#*=}
				;;
			--description=)
				printf 'ERROR: "%s" requires a non-empty option argument.\n' "${1}" >&2
				exit 1
				;;
			-p|--protocol)
				if [[ -n "${2}" && "${2:0:1}" != "--" && "${2:0:1}" != "-" ]]; then
					Protocol="${2}"
					shift
				else
					printf 'ERROR: "%s" requires a non-empty option argument.\n' "${1}" >&2
					exit 1
				fi
				;;
			--protocol=?*)
				Protocol=${1#*=}
				;;
			--protocol=)
				printf 'ERROR: "%s" requires a non-empty option argument.\n' "${1}" >&2
				exit 1
				;;
			-s|--server)
				if [[ -n "${2}" && "${2:0:1}" != "--" && "${2:0:1}" != "-" ]]; then
					Server="${2}"
					shift
				else
					printf 'ERROR: "%s" requires a non-empty option argument.\n' "${1}" >&2
					exit 1
				fi
				;;
			--server=?*)
				Server=${1#*=}
				;;
			--server=)
				printf 'ERROR: "%s" requires a non-empty option argument.\n' "${1}" >&2
				exit 1
				;;
			--addpassword)
				Action="addPassword"
				;;
			-m|--mountall)
				Action="mountAll"
				;;
			-v|--verbose)
				Verbose="-v"
				;;
			--) # End of all options.
				shift
				break
				;;
			-?*)
				printf 'WARN: Unknown option (ignored): %s\n' "${1}" >&2
				;;
			*) # Default case: If no more options then break out of the loop.
				break
	esac
	shift
done

case "${Action}" in
	mountAll)
		mountAll
		;;
	addPassword)
		if [[ -z "${Protocol}" || -z "${Server}" ]]; then
			showUsage
			exit
		fi
		addPassword
		;;
	*)
		showUsage
		exit
		;;
esac
