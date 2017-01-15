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
#	</array>
#	<key>RunAtLoad</key>
#	<true/>
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
#	<integer>COMMONMAXRETRYINSECONDS (30)</integer>
#	<key>CommonValidIPRanges</key>
#	<string>COMMONVALIDIPRANGES (10.0.0,192.168.0)</string>
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
#			<string>VALIDIPRANGES (10.0.0,192.168.0)</string>
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
#	-l LABEL (eg. same as SERVER) \
#	-D DESCRIPTION (eg. Networkpassword) \
#	-r PROTOCOL ("afp "/"smb "/"ftp"/"htps"/"http") \
#	-s SERVER \
#	-w PASSWORD \
#	-T /usr/bin/security \
#   -T /System/Library/Extensions/webdav_fs.kext/Contents/Resources/webdavfs_agent \
#	-T /System/Library/CoreServices/NetAuthAgent.app/Contents/MacOS/NetAuthSysAgent \
#	-T /System/Library/CoreServices/NetAuthAgent.app \
#	-T group://NetAuth \
#	${USERHOME}/Library/Keychains/login.keychain

#/usr/local/bin/automount.sh
#chown root:admin /usr/local/bin/automount.sh
#chmod 755 /usr/local/bin/automount.sh

# CONSTANTS
SCRIPTPATH="${0%/*}"
if [ "${SCRIPTPATH}" == "." ]; then
	SCRIPTPATH="${PWD}"
elif [ "${SCRIPTPATH:0:1}" != "/" ]; then
	SCRIPTPATH="$(which ${0})"
fi
declare -r SCRIPTFILENAME="${0##*/}"
SCRIPTNAME="${SCRIPTFILENAME%.*}"
SCRIPTEXTENSION=${SCRIPTFILENAME##*.}
if [ "${SCRIPTNAME}" == "" ]; then
	SCRIPTNAME=".${SCRIPTEXTENSION}"
	SCRIPTEXTENSION=""
fi
declare -r SCRIPTPATH SCRIPTNAME SCRIPTEXTENSION
case $(ps -o stat= -p ${$}) in
	*+*)
		declare -ri INTERACTIVE=0
		declare -r LOGGEROPTION="-s"
		;;
	*)
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
declare -r TMPPATH="/tmp"
declare -r LOCKFQDN="${TMPPATH}/${SCRIPTNAME}.lock"
declare -r LOCKFQFN="${LOCKFQDN}/pid"
if mkdir "${LOCKFQDN}" >/dev/null 2>&1; then
	echo "${$}" > "${LOCKFQFN}"
else
	_RunningPID="$(cat "${LOCKFQFN}")"
	logger ${LOGGEROPTION} -p 3 -t "${SCRIPTFILENAME}" "${SCRIPTFILENAME} is already running with PID ${_RunningPID}"
	exit 1
fi
declare -r USERNAME="$(id -p | awk '/^uid/ { print $2 }')"
declare -r USERID="$(dscl . read /Users/${USERNAME} UniqueID | awk -F': ' '{ print $2 }')"
declare -r USERHOME="$(dscl . read /Users/${USERNAME} NFSHomeDirectory | awk -F': ' '{ print $2 }')"
LOGINNAME="$(id -p | awk '/^login/ { print $2 }')"
if [ -z "${LOGINNAME}" ]; then
	LOGINNAME="${USERNAME}"
	LOGINID="${USERID}"
	LOGINHOME="${USERHOME}"
	LAUNCHASUSER=""
else
	LOGINID="$(dscl . read /Users/${LOGINNAME} UniqueID | awk -F': ' '{ print $2 }')"
	LOGINHOME="$(dscl . read /Users/${LOGINNAME} NFSHomeDirectory | awk -F': ' '{ print $2 }')"
	LAUNCHASUSER="launchctl asuser ${LOGINID}"
fi
declare -r LOGINNAME LOGINID LOGINHOME LAUNCHASUSER
declare -r PLAutomount="${USERHOME}/Library/Preferences/it.niemetz.automount.plist"
declare -r KCLogin="${USERHOME}/Library/Keychains/login.keychain"
declare -ir MAXRETRYINSECONDS=30
declare -r MOUNTOPTIONS="nodev,nosuid"
declare -r Ptcl_afp="afp "
declare -r Ptcl_smb="smb "
declare -r Ptcl_ftp="ftp "
declare -r Ptcl_http="http"
declare -r Ptcl_https="htps"
# Global variables
declare -i Idx=0
declare -i Try
declare -i IsInValidRange=0
declare -i EC=0
declare -a IPAddresses=()

# Functions
function cleanup {
	rm -rf "${LOCKFQDN}" >/dev/null 2>&1
	exit ${1}
}

function getIPAddresses {
	local _IPAddresses=""
	local -i _Sleep=0

	while [[ ( -z "${_IPAddresses}" || "${_IPAddresses}" =~ (^| )169\.[0-9]+\.[0-9]+\.[0-9]+( |$) ) && ${_Sleep} -lt 10 ]]; do
		sleep ${_Sleep}
		((_Sleep++))
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
	echo "${_IPAddresses}"
}

function getPasswordFromKeychain {
	security find-internet-password \
		-w \
		-r "$(eval echo "\"\${Ptcl_${PLProtocol}}\"")" \
		-a "${PLAccount}" \
		-l "${PLServer}" \
		-j "${SCRIPTNAME}" \
		"${KCLogin}" # 2>&1 |\
	# awk '
	# /password:/ {
	# 	split($0, val, /: "/)
	# 	val[2]=substr(val[2], 1, length(val[2])-1)
	# 	gsub(/"/, "\\\"", val[2])
	# 	printf("%s", val[2])
	# }'
}

IPAddresses=( $(getIPAddresses) )

trap 'cleanup' SIGHUP SIGINT SIGQUIT SIGTERM EXIT

# Main
if [ -s "${PLAutomount}" ] && [ -s "${KCLogin}" ]; then
	declare -i PLCommonMaxRetryInSeconds="$(/usr/libexec/PlistBuddy -c "Print CommonMaxRetryInSeconds" "${PLAutomount}" 2>/dev/null)"
	PLCommonMaxRetryInSeconds="${PLCommonMaxRetryInSeconds:-${MAXRETRYINSECONDS}}"
	PLCommonValidIPRanges="$(/usr/libexec/PlistBuddy -c "Print CommonValidIPRanges" "${PLAutomount}" 2>/dev/null)"
	PLCommonMountOptions="$(/usr/libexec/PlistBuddy -c "Print CommonMountOptions" "${PLAutomount}" 2>/dev/null)"
	PLCommonMountOptions="${PLCommonMountOptions:-${MOUNTOPTIONS}}"
	PLCommonAccount="$(/usr/libexec/PlistBuddy -c "Print CommonAccount" "${PLAutomount}" 2>/dev/null)"
	PLCommonAccount="${PLCommonAccount:-${LOGINNAME}}"
	while /usr/libexec/PlistBuddy -c "Print Mountlist:${Idx}" "${PLAutomount}" >/dev/null 2>&1; do
		PLValidIPRanges="$(/usr/libexec/PlistBuddy -c "Print Mountlist:${Idx}:ValidIPRanges" "${PLAutomount}" 2>/dev/null)"
		PLValidIPRanges="${PLValidIPRanges:-${PLCommonValidIPRanges}}"
		PLMountOptions="$(/usr/libexec/PlistBuddy -c "Print Mountlist:${Idx}:MountOptions" "${PLAutomount}" 2>/dev/null)"
		PLMountOptions="${PLMountOptions:-${PLCommonMountOptions}}"
		PLMaxRetryInSeconds="$(/usr/libexec/PlistBuddy -c "Print Mountlist:${Idx}:MaxRetryInSeconds" "${PLAutomount}" 2>/dev/null)"
		PLMaxRetryInSeconds="${PLMaxRetryInSeconds:-${PLCommonMaxRetryInSeconds}}"
		PLProtocol="$(/usr/libexec/PlistBuddy -c "Print Mountlist:${Idx}:Protocol" "${PLAutomount}" 2>/dev/null)"
		PLAccount="$(/usr/libexec/PlistBuddy -c "Print Mountlist:${Idx}:Account" "${PLAutomount}" 2>/dev/null)"
		PLAccount="${PLAccount:-${PLCommonAccount}}"
		PLServer="$(/usr/libexec/PlistBuddy -c "Print Mountlist:${Idx}:Server" "${PLAutomount}" 2>/dev/null)"
		PLShare="$(/usr/libexec/PlistBuddy -c "Print Mountlist:${Idx}:Share" "${PLAutomount}" 2>/dev/null)"
		if [[ -n "${PLProtocol}" && -n "${PLAccount}" && -n "${PLServer}" && -n "${PLShare}" ]] && ! mount | egrep -s -q "//.*${PLServer}/(${PLShare})? on /Volumes/${PLShare} \(.*, mounted by ${USERNAME}\)$" 2>/dev/null; then
			if [ -n "${PLValidIPRanges}" ]; then
				IsInValidRange=1
				for IPAddress in "${IPAddresses[@]}"; do
					IPAddressPart="$(echo "${IPAddress}" | cut -d'.' -f1-3)"
					if [[ "${PLValidIPRanges}" =~ (^|,)"${IPAddressPart}"(,|$) ]]; then
						IsInValidRange=0
						break
					fi
				done
			fi

			if [ ${IsInValidRange} -eq 0 ]; then
				Try=0
				while ! ping -c 1 -t 1 -o -q "${PLServer}" >/dev/null 2>&1 && [ ${Try} -le ${PLMaxRetryInSeconds} ]; do
					((Try++))
				done
				if [ ${Try} -gt ${PLMaxRetryInSeconds} ]; then
					((Idx++))
					continue
				fi
					
				MountPoint="${PLShare##*/}"
				if [ ! -d "/Volumes/${MountPoint}" ]; then
					if ! { mkdir -p "/Volumes/${MountPoint}" && chown "${USERNAME}:staff" "/Volumes/${MountPoint}"; }; then
						rmdir "/Volumes/${MountPoint}" >/dev/null 2>&1
						((Idx++))
						continue
					fi
				fi
						
				case "${PLProtocol}" in
					http|https)
						RV="$(expect -c '
							set timeout 15
							'"${ExpectDebug}"'
							spawn /sbin/mount_webdav -s -i'"${PLMountOptions:+ -o ${PLMountOptions}}"' '"${PLProtocol}"'://'"${PLServer}"' /Volumes/'"${MountPoint}"'
							expect "name:" {
								send "'"${PLAccount}"'\r"
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
							spawn /sbin/mount_ftp -i'"${PLMountOptions:+ -o ${PLMountOptions}}"' '"${PLProtocol}"'://'"${PLServer}"' /Volumes/'"${MountPoint}"'
							expect "name:" {
								send "'"${PLAccount}"'\r"
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
						RV="$(mount -t ${PLProtocol}${PLMountOptions:+ -o ${PLMountOptions}} "${PLServer}:/${PLShare}" "/Volumes/${MountPoint}" 2>&1)"
						RC=${?}
						;;
					afp|smb)
						RV="$(mount -t ${PLProtocol}${PLMountOptions:+ -o ${PLMountOptions}} "${PLProtocol}://${PLAccount}:$(getPasswordFromKeychain)@${PLServer}/${PLShare}" "/Volumes/${MountPoint}" 2>&1)"
						RC=${?}
						;;
					*)
						logger ${LOGGEROPTION} -p 4 -t "${SCRIPTFILENAME}" "Unknown protocol ${PLProtocol}"
						((Idx++))
						continue
						;;
				esac
				if [ ${RC} -eq 0 ]; then
					echo "${PLShare} mounted successfully"
				else
					logger ${LOGGEROPTION} -p 4 -t "${SCRIPTFILENAME}" "mount of ${PLShare} failed with RC=${RC}, RV=${RV}"
				fi
				EC=$((EC||RC))
			fi
		fi
		((Idx++))
	done
else
	logger ${LOGGEROPTION} -p 3 -t "${SCRIPTFILENAME}" "${PLAutomount} or ${KCLogin} are missing"
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
