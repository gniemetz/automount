#!/usr/bin/env bash
#set +xv

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
#			<string>PROTOCOL (afp/smb)</string>
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
#	-r PROTOCOL ("afp "/"smb ") \
#	-s SERVER \
#	-w PASSWORD \
#	-T /usr/bin/security \
#	-T /System/Library/CoreServices/NetAuthAgent.app/Contents/MacOS/NetAuthSysAgent \
#	-T /System/Library/CoreServices/NetAuthAgent.app \
#	-T group://NetAuth \
#	${USERHOME}/Library/Keychains/login.keychain

#/usr/local/bin/automount.sh
#chown root:admin /usr/local/bin/automount.sh
#chmod 755 /usr/local/bin/automount.sh

declare -r USERNAME="$(logname)"
declare -r USERID="$(dscl . read /Users/${USERNAME} UniqueID | awk -F': ' '{ print $2 }')"
declare -r USERHOME="$(dscl . read /Users/${USERNAME} NFSHomeDirectory | awk -F': ' '{ print $2 }')"
PLAutomount="${USERHOME}/Library/Preferences/it.niemetz.automount.plist"
KCLogin="${USERHOME}/Library/Keychains/login.keychain"
declare -i Idx=0
declare -i Try
declare -i IsInValidRange=0
declare -ir MAXRETRYINSECONDS=30
declare -r MOUNTOPTIONS="nodev,nosuid"
declare -a IfConfig=()
declare -t DELIMITER="|"
declare -t SUBDELIMITER=","

function cleanup {
	unset KCpassword
	exit ${1}
}

function getIfConfig {
	local _IfConfig=""
	declare -i _Sleep=0

	while [[ ( -z "${_IfConfig}" || "${_IfConfig}" =~ ^169\.[0-9]+\.[0-9]+\.[0-9]+, ) && ${_Sleep} -lt 10 ]]; do
		sleep ${_Sleep}
		((_Sleep++))
		_IfConfig="$(
			while IFS="${DELIMITER}" read PORT DEVICE; do
				/sbin/ifconfig ${DEVICE} 2>/dev/null |\
				/usr/bin/awk -v DELIMITER="${DELIMITER}" \
					-v SUBDELIMITER="${SUBDELIMITER}" \
					-v Device="${DEVICE}" \
					-v Port="${PORT}" \
					'
					BEGIN {
						inet=""
					}
					/inet / {
						printf("%s%s%s%s%s%s", $2, SUBDELIMITER, Device, SUBDELIMITER, Port, DELIMITER)
					}
					'
			done < <(/usr/sbin/networksetup -listnetworkserviceorder |\
				/usr/bin/awk -v DELIMITER="${DELIMITER}" \
					'
					BEGIN {
						FS=":|,"
						OFS=DELIMITER
					}
					/Hardware Port.*(Ethernet|Wi-Fi|IPSec)/ {
						sub(/\)/, "", $NF)
						print substr($2, 2), substr($4, 2)
					}
					'
				) |\
				/usr/bin/sed "s/${DELIMITER}$//g"
		)"
	done
	IFS="${DELIMITER}" read -ra IfConfig <<<"${_IfConfig}"
}

function getIPAddresses {
	local _IPAddresses=""
	declare -i _Sleep=0

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

IPAddresses=( $(getIPAddresses) )

trap 'cleanup' SIGHUP SIGINT SIGQUIT SIGTERM EXIT

if [[ -s "${PLAutomount}" ]] && [[ -s "${KCLogin}" ]]; then
	declare -i PLCommonMaxRetryInSeconds="$(/usr/libexec/PlistBuddy -c "Print CommonMaxRetryInSeconds" "${PLAutomount}" 2>/dev/null)"
	PLCommonMaxRetryInSeconds="${PLCommonMaxRetryInSeconds:-${MAXRETRYINSECONDS}}"
	PLCommonValidIPRanges="$(/usr/libexec/PlistBuddy -c "Print CommonValidIPRanges" "${PLAutomount}" 2>/dev/null)"
	PLCommonMountOptions="$(/usr/libexec/PlistBuddy -c "Print CommonMountOptions" "${PLAutomount}" 2>/dev/null)"
	PLCommonMountOptions="${PLCommonMountOptions:-${MOUNTOPTIONS}}"
	PLCommonAccount="$(/usr/libexec/PlistBuddy -c "Print CommonAccount" "${PLAutomount}" 2>/dev/null)"
	PLCommonAccount="${PLCommonAccount:-${USERNAME}}"
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
		if [[ -n "${PLProtocol}" && -n "${PLAccount}" && -n "${PLServer}" && -n "${PLShare}" ]] && ! mount | egrep -s -q "^//${PLAccount}@${PLServer}/${PLShare} on /Volumes/${PLShare} \(${PLProtocol}fs,.*${USERNAME}\)$" 2>/dev/null; then
			if [[ -n "${PLValidIPRanges}" ]]; then
				IsInValidRange=1
				for IPAddress in "${IPAddresses[@]}"; do
					IPAddressPart="$(echo "${IPAddress}" | cut -d'.' -f1-3)"
					if [[ "${PLValidIPRanges}" =~ (^|,)"${IPAddressPart}"(,|$) ]]; then
						IsInValidRange=0
						break
					fi
				done
			fi

			if [[ ${IsInValidRange} -eq 0 ]]; then
				Try=0
				while ! ping -c 1 -t 1 -o -q "${PLServer}" >/dev/null 2>&1 && [[ ${Try} -le ${PLMaxRetryInSeconds} ]]; do
					((Try++))
				done
				if [[ ${Try} -gt ${PLMaxRetryInSeconds} ]]; then
					((Idx++))
					continue
				fi
				
				if ! eval $(
				security find-internet-password \
					-g \
					-r "$(printf "%-4s" "${PLProtocol}")" \
					-a "${PLAccount}" \
					-l "${PLServer}" \
					"${KCLogin}" 2>&1 |\
				awk '
				/password:/ {
					split($0, val, /: "/)
					val[2]=substr(val[2], 1, length(val[2])-1)
					gsub(/"/, "\\\"", val[2])
					printf("KC%s=\"%s\"\n", val[1], val[2])
				}
				'
				); then
					((Idx++))
					continue
				fi
						
				if [[ ! -d "/Volumes/${PLShare}" ]] && ! { mkdir -p "/Volumes/${PLShare}" && chown "${USERNAME}:staff" "/Volumes/${PLShare}"; } >/dev/null 2>&1;	then
					rmdir "/Volumes/${PLShare}" >/dev/null 2>&1
					((Idx++))
					continue
				fi
						
				mount -t ${PLProtocol}${PLCommonMountOptions:+ -o ${PLCommonMountOptions}} "${PLProtocol}://${PLAccount}:${KCpassword}@${PLServer}/${PLShare}" "/Volumes/${PLShare}" 2>/dev/null
			fi
		fi
		((Idx++))
	done
else
	exit 1
fi

osascript -e "display notification \"automount runned successfully.\" with title \"automount\" subtitle \"\" sound name \"Glass\""
