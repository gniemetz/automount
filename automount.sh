#!/usr/bin/env bash
DEBUG="false"
if [ "${DEBUG}" == false ]; then
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

#/usr/local/bin/automount.sh
#chown root:admin /usr/local/bin/automount.sh
#chmod 755 /usr/local/bin/automount.sh

# CONSTANTS
# script path
SCRIPTPATH="${0%/*}"
if [ "${SCRIPTPATH}" == "." ]; then
	SCRIPTPATH="${PWD}"
elif [ "${SCRIPTPATH:0:1}" != "/" ]; then
	SCRIPTPATH="$(which ${0})"
fi
# script filename
declare -r SCRIPTFILENAME="${0##*/}"
# script name
SCRIPTNAME="${SCRIPTFILENAME%.*}"
# script filename extension
SCRIPTEXTENSION=${SCRIPTFILENAME##*.}
if [ "${SCRIPTNAME}" == "" ]; then
	SCRIPTNAME=".${SCRIPTEXTENSION}"
	SCRIPTEXTENSION=""
fi
declare -r SCRIPTPATH SCRIPTNAME SCRIPTEXTENSION
case $(ps -o stat= -p ${$}) in
	*+*)
		# interactive shell
		declare -ri INTERACTIVE=0
		# Log the message to standard error
		declare -r LOGGEROPTION="-s"
		;;
	*)
		# background shell
		declare -ri INTERACTIVE=1
		declare -r LOGGEROPTION=""
		;;
esac
:<<EOS
if RV="$(pgrep -f -l "${SCRIPTFILENAME}")"; then
	logger ${LOGGEROPTION} -p 3 -t "${SCRIPTFILENAME}" "${SCRIPTFILENAME} is already running, RV=${RV}"
	exit 1
fi
EOS
# temp dir (absolute path name)
declare -r TMPAPN="/tmp"
# lock dir (absolute path name)
declare -r LOCKAPN="${TMPAPN}/${SCRIPTNAME}.lock"
# lock file (absolute file name)
declare -r LOCKAFN="${LOCKAPN}/pid"
if ! { mkdir "${LOCKAPN}" && echo "${$}" > "${LOCKAFN}"; } 2>/dev/null; then
	_RunningPID="$(cat "${LOCKAFN}")"
	if RV="$(pgrep -f -l -F "${LOCKAFN}" "${SCRIPTFILENAME}")"; then
		logger ${LOGGEROPTION} -p 3 -t "${SCRIPTFILENAME}" "${SCRIPTFILENAME} is already running${_RunningPID:+ with PID ${_RunningPID}}"
		exit 1
	else
		if ! { rm -rf "${LOCKAPN}" && mkdir "${LOCKAPN}" && echo "${$}" > "${LOCKAFN}"; } 2>/dev/null; then
			logger ${LOGGEROPTION} -p 3 -t "${SCRIPTFILENAME}" "Could not create \"${LOCKAFN}\", exiting"
			exit 1
		fi
	fi
fi
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
# automount plist (absolute file name)
declare -r AUTOMOUNTPLISTAFN="${USERHOME}/Library/Preferences/it.niemetz.automount.plist"
# login keychain (absolute file name)
declare -r LOGINKEYCHAINAFN="${USERHOME}/Library/Keychains/login.keychain"
# max pings
declare -ir MAXRETRYINSECONDS=30
# mount options
declare -r MOUNTOPTIONS="nodev,nosuid"
# map protocol to value in keychain
declare -a PROTOCOLMAPPING=( 'afp="afp "' 'cifs="cifs "' 'ftp="ftp "' 'http="http"' 'https="htps"' 'smb="smb "' )
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
# Action to do
Action=""

# function definitions
function cleanup {
	rm -rf "${LOCKAPN}" >/dev/null 2>&1
	exit ${1}
}

function showUsage {
  cat <<EOH
Usage: ${SCRIPTFILENAME} (-m|--mountall)|--addpassword (-p|--protocol) protocol (-s|--server) server [(-a|--account) account] [(-d|--description) description]
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
		echo "${_KeychainProtocol}"
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
		"${LOGINKEYCHAINAFN}" 2>/dev/null
	return ${?}
}

function mountAll {
	if [ -s "${AUTOMOUNTPLISTAFN}" ] && [ -s "${LOGINKEYCHAINAFN}" ] && IPAddresses=( $(getIPAddresses) ); then
		declare -i CommonMaxRetryInSeconds="$(/usr/libexec/PlistBuddy -c "Print CommonMaxRetryInSeconds" "${AUTOMOUNTPLISTAFN}" 2>/dev/null)"
		CommonMaxRetryInSeconds="${CommonMaxRetryInSeconds:-${MAXRETRYINSECONDS}}"
		CommonValidIPRanges="$(/usr/libexec/PlistBuddy -c "Print CommonValidIPRanges" "${AUTOMOUNTPLISTAFN}" 2>/dev/null)"
		CommonMountOptions="$(/usr/libexec/PlistBuddy -c "Print CommonMountOptions" "${AUTOMOUNTPLISTAFN}" 2>/dev/null)"
		CommonMountOptions="${CommonMountOptions:-${MOUNTOPTIONS}}"
		CommonAccount="$(/usr/libexec/PlistBuddy -c "Print CommonAccount" "${AUTOMOUNTPLISTAFN}" 2>/dev/null)"
		CommonAccount="${CommonAccount:-${LOGINNAME}}"
		while /usr/libexec/PlistBuddy -c "Print Mountlist:${Idx}" "${AUTOMOUNTPLISTAFN}" >/dev/null 2>&1; do
			ValidIPRanges="$(/usr/libexec/PlistBuddy -c "Print Mountlist:${Idx}:ValidIPRanges" "${AUTOMOUNTPLISTAFN}" 2>/dev/null)"
			ValidIPRanges="${ValidIPRanges:-${CommonValidIPRanges}}"
			MountOptions="$(/usr/libexec/PlistBuddy -c "Print Mountlist:${Idx}:MountOptions" "${AUTOMOUNTPLISTAFN}" 2>/dev/null)"
			MountOptions="${MountOptions:-${CommonMountOptions}}"
			MaxRetryInSeconds="$(/usr/libexec/PlistBuddy -c "Print Mountlist:${Idx}:MaxRetryInSeconds" "${AUTOMOUNTPLISTAFN}" 2>/dev/null)"
			MaxRetryInSeconds="${MaxRetryInSeconds:-${CommonMaxRetryInSeconds}}"
			Protocol="$(/usr/libexec/PlistBuddy -c "Print Mountlist:${Idx}:Protocol" "${AUTOMOUNTPLISTAFN}" 2>/dev/null)"
			Account="$(/usr/libexec/PlistBuddy -c "Print Mountlist:${Idx}:Account" "${AUTOMOUNTPLISTAFN}" 2>/dev/null)"
			Account="${Account:-${CommonAccount}}"
			Server="$(/usr/libexec/PlistBuddy -c "Print Mountlist:${Idx}:Server" "${AUTOMOUNTPLISTAFN}" 2>/dev/null)"
			Share="$(/usr/libexec/PlistBuddy -c "Print Mountlist:${Idx}:Share" "${AUTOMOUNTPLISTAFN}" 2>/dev/null)"
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

				if [ ${IsInValidRange} -eq 0 ]; then
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
						if ! { mkdir -p "/Volumes/${MountPoint}" && chown "${USERNAME}:staff" "/Volumes/${MountPoint}"; }; then
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
						afp|cifs|smb)
							RV="$(mount -t ${Protocol}${MountOptions:+ -o ${MountOptions}} "${Protocol}://${Account}:$(getPasswordFromKeychain)@${Server}/${Share}" "/Volumes/${MountPoint}" 2>&1)"
							RC=${?}
							;;
						*)
							logger ${LOGGEROPTION} -p 4 -t "${SCRIPTFILENAME}" "Unknown protocol ${Protocol}"
							((Idx++))
							continue
							;;
					esac
					if [ ${RC} -eq 0 ]; then
						echo "${Share} mounted successfully"
					else
						logger ${LOGGEROPTION} -p 4 -t "${SCRIPTFILENAME}" "mount of ${Share} failed with RC=${RC}, RV=${RV}"
					fi
					EC=$((EC||RC))
				fi
			fi
			((Idx++))
		done
	else
		logger ${LOGGEROPTION} -p 3 -t "${SCRIPTFILENAME}" "${AUTOMOUNTPLISTAFN} or ${LOGINKEYCHAINAFN} are missing"
		exit 1
	fi

	if [ ${EC} -eq 0 ]; then
		logger ${LOGGEROPTION} -p 6 -t "${SCRIPTFILENAME}" "automount runned successfully."
		${LAUNCHASUSER} /usr/bin/osascript -e "display notification \"automount runned successfully.\" with title \"automount\" subtitle \"\""
	else
		logger ${LOGGEROPTION} -p 3 -t "${SCRIPTFILENAME}" "automount runned with errors."
		${LAUNCHASUSER} /usr/bin/osascript -e "display notification \"automount runned with errors.\" with title \"automount\" subtitle \"\""
	fi

	exit ${EC}
}

function addPassword {
	Account="${Account:-$(id -p | awk '/^login/ { print $2; exit } /^uid/ { print $2 }')}"
	Userhome="$(dscl . read /Users/${Account} NFSHomeDirectory | cut -d' ' -f2-)"
	security add-internet-password -a "${Account}" \
		-l "${Server}" \
		-D "${Description:-Netzwerkpasswort}" \
		-j "${SCRIPTNAME}" \
		-r "$(printf "%-4s" ${Protocol})" \
		-s "${Server}" \
		-w "$(read -p "Password: " -s && echo "${REPLY}")" \
		-U \
		-T /usr/bin/security \
		-T /System/Library/CoreServices/NetAuthAgent.app/Contents/MacOS/NetAuthSysAgent \
		-T /System/Library/CoreServices/NetAuthAgent.app \
		-T group://NetAuth ${USERHOME}/Library/Keychains/login.keychain
}

# Main
# catch traps
trap 'cleanup' SIGHUP SIGINT SIGQUIT SIGTERM EXIT

while :; do
	case ${1} in
			-h|-\?|--help)   # Call a "showUsage" function to display a synopsis, then exit.
				showUsage
				exit
				;;
			-a|--account)
				if [[ -n "${2}" && "${2:0:1}" != "--" && "${2:0:1}" != "-" ]]; then
					Account="${2}"
					shift
				else
					echo 'ERROR: "--account" requires a non-empty option argument.\n' >&2
					exit 1
				fi
				;;
			--account=?*)
				Account=${1#*=} # Delete everything up to "=" and assign the remainder.
				;;
			--account=) # Handle the case of an empty --account=
				echo  'ERROR: "--account" requires a non-empty option argument.\n' >&2
				exit 1
				;;
			-d|--description)
				if [[ -n "${2}" && "${2:0:1}" != "--" && "${2:0:1}" != "-" ]]; then
					Description="${2}"
					shift
				else
					echo 'ERROR: "--description" requires a non-empty option argument.\n' >&2
					exit 1
				fi
				;;
			--description=?*)
				Description=${1#*=}
				;;
			--description=)
				echo  'ERROR: "--description" requires a non-empty option argument.\n' >&2
				exit 1
				;;
			-p|--protocol)
				if [[ -n "${2}" && "${2:0:1}" != "--" && "${2:0:1}" != "-" ]]; then
					Protocol="${2}"
					shift
				else
					echo 'ERROR: "--protocol" requires a non-empty option argument.\n' >&2
					exit 1
				fi
				;;
			--protocol=?*)
				Protocol=${1#*=}
				;;
			--protocol=)
				echo  'ERROR: "--protocol" requires a non-empty option argument.\n' >&2
				exit 1
				;;
			-s|--server)
				if [[ -n "${2}" && "${2:0:1}" != "--" && "${2:0:1}" != "-" ]]; then
					Server="${2}"
					shift
				else
					echo 'ERROR: "--server" requires a non-empty option argument.\n' >&2
					exit 1
				fi
				;;
			--server=?*)
				Server=${1#*=}
				;;
			--server=)
				echo  'ERROR: "--server" requires a non-empty option argument.\n' >&2
				exit 1
				;;
			--addpassword)
				Action="addPassword"
				;;
			-m|--mountall)
				Action="mountAll"
				;;
			-v|--verbose)
				((Verbose++)) # Each -v argument adds 1 to verbosity.
				;;
			--) # End of all options.
				shift
				break
				;;
			-?*)
				printf 'WARN: Unknown option (ignored): %s\n' "$1" >&2
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
