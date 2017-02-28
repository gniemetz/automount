#!/usr/bin/env bash
# CONSTANTS
declare -r SCRIPTLASTMOD="2017-02-28"
declare -r SCRIPTVERSION="0.90.19"
declare -r DEBUG="false"
if [ "${DEBUG}" == "false" ]; then
	set +xv
	EXPECTDEBUG="log_user 0"
else
	PS4='+(${BASH_SOURCE:-}:${LINENO:-}): ${FUNCNAME[0]:+${FUNCNAME[0]:-}(): }'
	set -xv
	EXPECTDEBUG="log_user 1"
fi
declare -r EXPECTDEBUG
#security add-internet-password \
#	-a ACCOUNT \
#	-l LABEL (same as SERVER) \
#	-D DESCRIPTION (eg. Networkpassword) \
#	-j COMMENT (${SCRIPTNAME}) \
#	-r PROTOCOL ("afp "/"cifs"/"ftp "/"http"/"htps"/"smb ") \
#	-s SERVER \
#	-w PASSWORD \
#	-U \
#	-T /usr/bin/security \
#	-T /System/Library/Extensions/webdav_fs.kext/Contents/Resources/webdavfs_agent \
#	-T /System/Library/CoreServices/NetAuthAgent.app/Contents/MacOS/NetAuthSysAgent \
#	-T /System/Library/CoreServices/NetAuthAgent.app \
#	-T group://NetAuth \
#	${LOGINHOME}/Library/Keychains/login.keychain

#Server="SERVER"; Label="${Server}"; Description="DESCRIPTION"; Protocol="PROTOCOL"; Account="$(id -p | awk '/^login/ { print $2; exit } /^uid/ { print $2 }')"; UserHomeDirectory="$(dscl . read /Users/${Account} NFSHomeDirectory | cut -d' ' -f2-)"; security add-internet-password -a "${Account}" -l "${Label}" -D "${Description:-Netzwerkpasswort}" -j "automount" -r "$(printf "%-4s" ${Protocol})" -s "${Server}" -w "$(read -p "Password: " -s && echo "${REPLY}")" -U -T /usr/bin/security -T /System/Library/CoreServices/NetAuthAgent.app/Contents/MacOS/NetAuthSysAgent -T /System/Library/CoreServices/NetAuthAgent.app -T group://NetAuth ${UserHomeDirectory}/Library/Keychains/login.keychain
# when error "User interaction is not allowed." occurs, unlock keychain
# RC=36 (security error 36 -> Error: 0x00000024 36 CSSM_ERRCODE_OBJECT_ACL_REQUIRED)
#security unlock-keychain -p "LOGINNAME_PASSWORD" ${LOGINHOME}/Library/Keychains/login.keychain

#/usr/local/bin/automount.sh
#chown root:admin /usr/local/bin/automount.sh
#chmod 755 /usr/local/bin/automount.sh

declare -ri YES=0
declare -ri SUCCESS=${YES}
declare -ri TRUE=${YES}
declare -ri FOUND=${YES}
declare -ri NO=1
declare -ri ERROR=${NO}
declare -ri FALSE=${NO}
declare -ri MISSING=${NO}
# os x version array major minor patch
declare -air OSVERSION=( $(sw_vers | awk -F'[: |.]' '/ProductVersion/ { printf("%d %d %d", $2, $3, $4) }') )
# os x version as integer 
declare -ir OSVERSION_INTEGER=10#$(printf '%02d%02d%02d' "${OSVERSION[0]}" "${OSVERSION[1]}" "${OSVERSION[2]}")
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
# function for getting values from Directory Service via dscl
function readDS {
	local _Account _DSKey _DSValue
	local _FS=":"

	while :; do
		case ${1} in
			-a|--account)
				if [[ -n "${2}" && "${2:0:1}" != "--" && "${2:0:1}" != "-" ]]; then
					_Account="${2}"
					shift
				else
					printf 'ERROR: "%s" requires a non-empty option argument.\n' "${1}" >&2
					return ${ERROR}
				fi
				;;
			--account=?*)
				_Account=${1#*=} # Delete everything up to "=" and assign the remainder.
				;;
			--account=) # Handle the case of an empty --account=
				printf 'ERROR: "%s" requires a non-empty option argument.\n' "${1}" >&2
				return ${ERROR}
				;;
			-k|--key)
				if [[ -n "${2}" && "${2:0:1}" != "--" && "${2:0:1}" != "-" ]]; then
					_DSKey="${2}"
					shift
				else
					printf 'ERROR: "%s" requires a non-empty option argument.\n' "${1}" >&2
					return ${ERROR}
				fi
				;;
			--key=?*)
				_DSKey=${1#*=} # Delete everything up to "=" and assign the remainder.
				;;
			--key=) # Handle the case of an empty --key=
				printf 'ERROR: "%s" requires a non-empty option argument.\n' "${1}" >&2
				return ${ERROR}
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

	if [ -n "${_Account}" ] && [ -n "${_DSKey}" ] && _DSValue="$(dscl . read /Users/"${_Account}" "${_DSKey}" |\
																awk -F"${_FS}" \
																	-v DSKey="${_DSKey}" \
																'BEGIN {
																	Value=""
																	KeywordFound=0
																}
																function getValuesFromPosition(StartPosition) {
																	for(FieldNr=StartPosition; FieldNr <= NF; FieldNr++) {
																		Value = (Value == "" ? "" : Value FS) $FieldNr
																	}
																}
																KeywordFound == 1 {
																	getValuesFromPosition(1)
																	KeywordFound=0
																}
																$1 == DSKey {
																	if(NF > 1) {
																		getValuesFromPosition(2)
																 	} else {
																 		KeywordFound=1
																 		next
																 	}
																}
																END {
																	# trim leading space
																	gsub(/^[[:space:]]+/, "", Value)
																	printf("%s", Value)
																}')"; then
		echo "${_DSValue}"
		return ${SUCCESS}
	else
		return ${ERROR}
	fi
}
# user name
declare -r USERNAME="$(id -p | awk -F'	' '/^uid/ { print $2 }')"
# user id
declare -ir USERID="$(readDS --account="${USERNAME}" --key="UniqueID")"
# user primary group id
declare -ir USERPRIMARYGROUPID="$(readDS --account="${USERNAME}" --key="PrimaryGroupID")"
# user home
declare -r USERHOME="$(readDS --account="${USERNAME}" --key="NFSHomeDirectory")"
# login name
LOGINNAME="$(id -p | awk -F'	' '/^login/ { print $2 }')"
if [ -z "${LOGINNAME}" ]; then
	LOGINNAME="${USERNAME}"
	# login id
	declare -i LOGINID="${USERID}"
	# login primary group id
	declare -i LOGINPRIMARYGROUPID=${USERPRIMARYGROUPID}
	# login home
	LOGINHOME="${USERHOME}"
	# launch as user
	LAUNCHASUSER=""
else
	declare -i LOGINID="$(readDS --account="${LOGINNAME}" --key="UniqueID")"
	declare -i LOGINPRIMARYGROUPID="$(readDS --account="${LOGINNAME}" --key="PrimaryGroupID")"
	LOGINHOME="$(readDS --account="${LOGINNAME}" --key="NFSHomeDirectory")"
	LAUNCHASUSER="launchctl asuser ${LOGINID} chroot -u ${LOGINID} -g ${LOGINPRIMARYGROUPID} /"
fi
declare -r LOGINNAME LOGINID LOGINPRIMARYGROUPID LOGINHOME LAUNCHASUSER
# case $(ps -o state= -p ${$}) in
if [ -t 0 ]; then
		# interactive shell (not started from launch daemon)
		declare -ri BACKGROUND=${NO}
else
		# background shell
		declare -ri BACKGROUND=${YES}
fi
# ps -a -x -ww -p ${$} -o ppid= -o pid= -o tt= -o flags= -o state= -o logname= -o command=cmd | grep "[${LOGINNAME:0:1}]${LOGINNAME:1}.*[${SCRIPT_FN:0:1}]${SCRIPT_FN:1} ${@}">>${LOG_AFN}
# parent pid
# declare -i PPID=$(ps -a -x -ww -p ${$} -o ppid= -o logname= -o command= |\
# awk -v RegexUser="[${LOGINNAME:0:1}]${LOGINNAME:1}" \
# 	-v RegexCommand="[${SCRIPT_FN:0:1}]${SCRIPT_FN:1} ${@}" \
# 	'BEGIN {
# 		Regex=sprintf("%s.*%s", RegexUser, RegexCommand)
# 	}
# 	$0 ~ Regex {
# 		print $1
# 	}
# 	')
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
declare -a LOG_LEVEL
declare -ir LOG_EMERGENCY=${#LOG_LEVEL[@]}
LOG_LEVEL[${#LOG_LEVEL[@]}]="Emergency"
declare -ir LOG_ALERT=${#LOG_LEVEL[@]}
LOG_LEVEL[${#LOG_LEVEL[@]}]="Alert"
declare -ir LOG_CRITICAL=${#LOG_LEVEL[@]}
LOG_LEVEL[${#LOG_LEVEL[@]}]="Critical"
declare -ir LOG_ERROR=${#LOG_LEVEL[@]}
LOG_LEVEL[${#LOG_LEVEL[@]}]="Error"
declare -ir LOG_WARNING=${#LOG_LEVEL[@]}
LOG_LEVEL[${#LOG_LEVEL[@]}]="Warning"
declare -ir LOG_NOTICE=${#LOG_LEVEL[@]}
LOG_LEVEL[${#LOG_LEVEL[@]}]="Notice"
declare -ir LOG_INFO=${#LOG_LEVEL[@]}
LOG_LEVEL[${#LOG_LEVEL[@]}]="Info"
declare -ir LOG_DEBUG=${#LOG_LEVEL[@]}
LOG_LEVEL[${#LOG_LEVEL[@]}]="Debug"
declare -r LOG_LEVEL
# automount plist (absolute file name)
declare -r AUTOMOUNTPLIST_AFN="${LOGINHOME}/Library/Preferences/it.niemetz.automount.plist"
# login keychain (absolute file name)
declare -r LOGINKEYCHAIN_AFN="$(${LAUNCHASUSER} security list-keychains -d user | awk -F'"' '/login/ { print $2 }')"
# max pings
declare -r MAXRETRYINSECONDS=10
# mount options
declare -r MOUNTOPTIONS="nodev,nosuid"
# map protocol to value in keychain
declare -ra PROTOCOLMAPPING=( 'afp="afp "' 'cifs="cifs"' 'ftp="ftp "' 'http="http"' 'https="htps"' 'smb="smb "' )
# ping -t timeout
declare -ir PINGTIMEOUT=1
if [[ ${OSVERSION_INTEGER} -ge 101200 && ${LOGINID} -ne 0 ]]; then
	# mountpoint absolute pathname
	MOUNTPOINT_APN="${LOGINHOME}/Volumes"
else
	MOUNTPOINT_APN="/Volumes"
fi

# Global variables
# index counter
declare -i MountlistIndex
# is ip in valid range
declare -i IsInValidRange=${TRUE}
# exit code
declare -i EC=${SUCCESS}
# array of ip addresses
declare -a IPAddresses=()
# late bound variables
CommonMaxRetryInSeconds=""
CommonValidIPRanges=""
CommonMountOptions=""
CommonAccount=""
ValidIPRanges=""
MountOptions=""
MaxRetryInSeconds=""
Protocol=""
Domain=""
Account=""
Server=""
Share=""
MountPoint=""
declare -i MountedShares=0
# Action to do
Action=""
# verbose
declare -i Verbose=0
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
							return ${ERROR}
						fi
						shift
					else
						printf 'ERROR: "%s" requires a non-empty option argument.\n' "${1}" >&2
						return ${ERROR}
					fi
					;;
				--priority=?*)
					if ! _Priority=${1#*=} 2>/dev/null; then
						printf 'ERROR: "%s" requires a numeric option argument.\n' "${1}" >&2
						return ${ERROR}
					fi
					;;
				--priority=)
					printf 'ERROR: "%s" requires a non-empty option argument.\n' "${1}" >&2
					return ${ERROR}
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
		echo "${1}" >&2
	else
		echo "${1}"
	fi
	echo "$(date +"${_DateFormat}")${_Delimiter}${$}${_Delimiter}${LOG_LEVEL[${_Priority}]}${_Delimiter}${1}" >>"${LOG_AFN}"
	return ${SUCCESS}
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
		IPAddresses=( ${_IPAddresses} )
		return ${SUCCESS}
	else
		log --priority=${LOG_ERROR} "Could not get local IP address(es)"
		return ${ERROR}
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
		return ${FOUND}
	else
		return ${MISSING}
	fi
}

function convertToHexCode {
    tr -d '\n' |\
    od -A n -t x1 |\
    sed -E 's/^ */  /;s/ *$//;s/  /\\x/g'
}

function getPasswordFromKeychain {
	local -i _RC=${TRUE}

	security find-internet-password \
		-w \
		-r "$(getKeychainProtocol)" \
		-a "${Account}" \
		-l "${Server}" \
		-j "${SCRIPTNAME}" \
		"${LOGINKEYCHAIN_AFN}"
		# xxd -p |\
		# sed -e ':a' -e 'N' -e '$!ba' -e 's/\n//g' -e 's/\(..\)/\\x\1/g'
	_RC=${?}

	if [ ${_RC} -ne ${SUCCESS} ]; then
		log --priority=${LOG_ERROR} "getPasswordFromKeychain failed (RC=${_RC})"
	fi
	return ${_RC}
}

function isPingable {
	# server to ping
	local _Server="${1}"
	# retry counter
	local -i _Try=0
	# return value
	local _RV=""
	if [ -n "${_Server}" ]; then
		while ! _RV="$(ping -c 1 -t ${PINGTIMEOUT} -o -q "${_Server}" 2>&1)" && [ ${_Try} -le ${MaxRetryInSeconds} ]; do
			((_Try++))
		done
		if [ ${_Try} -gt ${MaxRetryInSeconds} ]; then
			log --priority=${LOG_ERROR} "Could not ping ${Server} within ${MaxRetryInSeconds} (RC=${RC}, RV=${_RV})"
			return ${ERROR}
		fi
	fi
	return ${SUCCESS}
}

function initCommonValues {
	# set global common values
	CommonMaxRetryInSeconds=$(/usr/libexec/PlistBuddy -c "Print CommonMaxRetryInSeconds" "${AUTOMOUNTPLIST_AFN}" 2>/dev/null)
	CommonMaxRetryInSeconds=${CommonMaxRetryInSeconds:-${MAXRETRYINSECONDS}}
	CommonValidIPRanges="$(/usr/libexec/PlistBuddy -c "Print CommonValidIPRanges" "${AUTOMOUNTPLIST_AFN}" 2>/dev/null)"
	CommonMountOptions="$(/usr/libexec/PlistBuddy -c "Print CommonMountOptions" "${AUTOMOUNTPLIST_AFN}" 2>/dev/null)"
	CommonMountOptions="${CommonMountOptions:-${MOUNTOPTIONS}}"
	CommonAccount="$(/usr/libexec/PlistBuddy -c "Print CommonAccount" "${AUTOMOUNTPLIST_AFN}" 2>/dev/null)"
	CommonAccount="${CommonAccount:-${LOGINNAME}}"
	return ${SUCCESS}
}

function readMountlistValues {
	local -i _Index=${1}

	# first clear old values
	unset ValidIPRanges MountOptions MaxRetryInSeconds Protocol Account Server Share MountPoint

	# get values
	ValidIPRanges="$(/usr/libexec/PlistBuddy -c "Print Mountlist:${_Index}:ValidIPRanges" "${AUTOMOUNTPLIST_AFN}" 2>/dev/null)"
	ValidIPRanges="${ValidIPRanges:-${CommonValidIPRanges}}"
	MountOptions="$(/usr/libexec/PlistBuddy -c "Print Mountlist:${_Index}:MountOptions" "${AUTOMOUNTPLIST_AFN}" 2>/dev/null)"
	MountOptions="${MountOptions:-${CommonMountOptions}}"
	MaxRetryInSeconds=$(/usr/libexec/PlistBuddy -c "Print Mountlist:${_Index}:MaxRetryInSeconds" "${AUTOMOUNTPLIST_AFN}" 2>/dev/null)
	MaxRetryInSeconds=${MaxRetryInSeconds:-${CommonMaxRetryInSeconds}}
	Protocol="$(/usr/libexec/PlistBuddy -c "Print Mountlist:${_Index}:Protocol" "${AUTOMOUNTPLIST_AFN}" 2>/dev/null)"
	Domain="$(/usr/libexec/PlistBuddy -c "Print Mountlist:${_Index}:Domain" "${AUTOMOUNTPLIST_AFN}" 2>/dev/null)"
	Account="$(/usr/libexec/PlistBuddy -c "Print Mountlist:${_Index}:Account" "${AUTOMOUNTPLIST_AFN}" 2>/dev/null)"
	Account="${Account:-${CommonAccount}}"
	Server="$(/usr/libexec/PlistBuddy -c "Print Mountlist:${_Index}:Server" "${AUTOMOUNTPLIST_AFN}" 2>/dev/null)"
	Share="$(/usr/libexec/PlistBuddy -c "Print Mountlist:${_Index}:Share" "${AUTOMOUNTPLIST_AFN}" 2>/dev/null)"
	MountPoint="$(/usr/libexec/PlistBuddy -c "Print Mountlist:${_Index}:MountPoint" "${AUTOMOUNTPLIST_AFN}" 2>/dev/null)"
	MountPoint="${MountPoint:-${Share##*/}}"
	if [[ -n "${Protocol}" && -n "${Account}" && -n "${Server}" && -n "${Share}" ]]; then
		return ${SUCCESS}
	else
		log --priority=${LOG_ERROR} "Protocol \"${Protocol}\"/Account \"${Account}\"/Server \"${Server}\"/Share \"${Share}\" empty"
		return ${ERROR}
	fi
}

function isInValidIPRange {
	local _ValidIPRanges="${1}"
	local _IPAddress _IPAddressPart

	if [ -n "${_ValidIPRanges}" ]; then
		for _IPAddress in "${IPAddresses[@]}"; do
			_IPAddressPart="$(echo "${_IPAddress}" | cut -d'.' -f1-3)"
			if [[ "${_ValidIPRanges}" =~ (^|,)"${_IPAddressPart}"(,|$) ]]; then
				return ${YES}
			fi
		done
		log --priority=${LOG_WARNING} "Not allowed to mount \"${Share}\" because \"${IPAddresses[@]}\" not in range of \"${_ValidIPRanges}\""
		return ${NO}
	fi 
	return ${YES}
}

function isMounted {
	local _RV=""

	if _RV="$(mount | egrep "//.*${Server}/(${Share})? on ${MOUNTPOINT_APN}/${Share} \(.*(, mounted by ${LOGINNAME})?\)$" 2>&1)"; then
		if [ ${Verbose} -ne 0 ]; then
			log --priority=${LOG_WARNING} "Share \"${Share}\" already mounted (RV=${_RV})"
		fi
		return ${YES}
	fi
	return ${NO}
}

function createMountpoint {
	local _Share="${1}"
	local _RV=""
	local -i _RC=${TRUE}

	if [ -n "${_Share}" ]; then
		if [ ! -d "${MOUNTPOINT_APN}/${_Share}" ]; then
			_RV="$( { mkdir -p ${Verbose} "${MOUNTPOINT_APN}/${_Share}" && chown "${LOGINID}:${LOGINPRIMARYGROUPID}" "${MOUNTPOINT_APN}/${_Share}" && chmod 755 "${MOUNTPOINT_APN}/${_Share}"; } 2>&1 )"
			_RC=${?}
			if [ ${_RC} -ne ${SUCCESS} ]; then
				log --priority=${LOG_ERROR} "Could not create \"${MOUNTPOINT_APN}/${_Share}\" (RC=${_RC}, RV=${_RV})"
				rmdir "${MOUNTPOINT_APN}/${_Share}" >/dev/null 2>&1
				return ${ERROR}
			fi
		fi
	fi
	return ${SUCCESS}
}

function processMountlist {
	local _RV=""
	local -i _RC=${TRUE}
	local -i _EC=${TRUE}

	# check all files exits
	if [ ! -s "${AUTOMOUNTPLIST_AFN}" ] || [ ! -s "${LOGINKEYCHAIN_AFN}" ]; then
	# if [[ ! ( -s "${AUTOMOUNTPLIST_AFN}" && ( -s "${LOGINKEYCHAIN_AFN}" || -s "${LOGINKEYCHAIN_AFN}-db" ) ) ]]; then
		log --priority=${LOG_ERROR} "${AUTOMOUNTPLIST_AFN} and/or ${LOGINKEYCHAIN_AFN} are missing"
		return ${ERROR}
	fi		

	# get local ip address(es)
	getIPAddresses
	_RC=${?}
	if [ ${_RC} -ne ${SUCCESS} ]; then
		return ${_RC}
	fi

	# initialize common values
	initCommonValues

	# process automount plist file
	MountlistIndex=0
	while /usr/libexec/PlistBuddy -c "Print Mountlist:${MountlistIndex}" "${AUTOMOUNTPLIST_AFN}" >/dev/null 2>&1; do
		# get the values
		if ! readMountlistValues ${MountlistIndex}; then
			_EC=$((_EC||!${?}))
			((MountlistIndex++))
			continue
		fi

		# check if in valid ip range
		if ! isInValidIPRange "${ValidIPRanges}"; then
			((MountlistIndex++))
			continue
		fi

		# is share already mounted?
		if isMounted; then
			((MountlistIndex++))
			continue
		fi			

		# is server reachable?
		if ! isPingable "${Server}"; then
			_EC=$((_EC||!${?}))
			((MountlistIndex++))
			continue
		fi			
					
		# create mountpoint
		if ! createMountpoint "${MountPoint}"; then
			_EC=$((_EC||!${?}))
			((MountlistIndex++))
			continue
		fi			
					
		case ${Protocol} in
			http|https)
				_RV="$(${LAUNCHASUSER} expect -c '
					set timeout '${MaxRetryInSeconds}'
					'"${EXPECTDEBUG}"'
					spawn /sbin/mount_webdav -s -i'"${MountOptions:+ -o ${MountOptions}}"' '"${Protocol}"'://'"${Server}"' '"${MOUNTPOINT_APN}"'/'"${MountPoint}"'
					expect {
						-re ".*ser.*|.*name.*" {
							send -- "'"${Account}"'\r"
							exp_continue
						}
						-re ".*ssword.*" {
							send -- "'$(getPasswordFromKeychain | convertToHexCode)'\r"
							exp_continue
						}
						timeout {
							exit 1
						}
						eof {
							return
						}
					}
					catch wait result
					exit [lindex $result 3]
					' 2>&1)"
				_RC=${?}
				;;
			ftp)
				_RV="$(${LAUNCHASUSER} expect -c '
					set timeout '${MaxRetryInSeconds}'
					'"${EXPECTDEBUG}"'
					spawn /sbin/mount_ftp -i'"${MountOptions:+ -o ${MountOptions}}"' '"${Protocol}"'://'"${Server}"' '"${MOUNTPOINT_APN}"'/'"${MountPoint}"'
					expect {
						-re ".*ser.*|.*name.*" {
							send -- "'"${Account}"'\r"
						}
						-re ".*ssword.*" {
							send -- "'$(getPasswordFromKeychain | convertToHexCode)'\r"
							exp_continue
						}
						timeout {
							exit 1
						}
						eof {
							return
						}
					}
					catch wait result
					exit [lindex $result 3]
					' 2>&1)"
				_RC=${?}
				;;
			nfs)
				_RV="$(${LAUNCHASUSER} mount -t ${Protocol}${MountOptions:+ -o ${MountOptions}} "${Server}:/${Share}" "${MOUNTPOINT_APN}/${MountPoint}" 2>&1)"
				_RC=${?}
				;;
			afp)
				_RV="$(${LAUNCHASUSER} expect -c '
					set timeout '${MaxRetryInSeconds}'
					'"${EXPECTDEBUG}"'
					spawn /sbin/mount_afp -i -s'"${MountOptions:+ -o ${MountOptions}}"' '"${Protocol}"'://'"${Server}"'/'"${Share}"' '"${MOUNTPOINT_APN}"'/'"${MountPoint}"'
					expect {
						-re ".*ser.*" {
							if {"'"${Domain}"'" == ""} {
								send -- "'"${Account}"'\r"
							} else {
								send -- "'"${Domain}"';'"${Account}"'\r"
							}
							exp_continue
						}
						-re ".*ssword.*" {
							send -- "'"$(getPasswordFromKeychain | convertToHexCode)"'\r"
							exp_continue
						}
						timeout {
							exit 1
						}
						eof {
							return
						}
					}
					catch wait result
					exit [lindex $result 3]' 2>&1)"
				_RC=${?}
				;;
			smb)
				_RV="$(${LAUNCHASUSER} expect -c '
					set timeout '${MaxRetryInSeconds}'
					'"${EXPECTDEBUG}"'
					spawn /sbin/mount_smbfs -o soft'"${MountOptions:+,${MountOptions}}"' //'"${Domain:+${Domain};}${Account}"'@'"${Server}"'/'"${Share}"' '"${MOUNTPOINT_APN}"'/'"${MountPoint}"'
					expect {
						-re "..*ser.*|.*name.*" {
							if {"'"${Domain}"'" == ""} {
								send -- "'"${Account}"'\r"
							} else {
								send -- "'"${Domain}"';'"${Account}"'\r"
							}
							exp_continue
						}
						-re ".*ssword.*" {
							send -- "'"$(getPasswordFromKeychain | convertToHexCode)"'\r"
							exp_continue
						}
						timeout {
							exit 1
						}
						eof {
							return
						}
					}
					catch wait result
					exit [lindex $result 3]' 2>&1)"
				_RC=${?}
				;;
			cifs)
				_RV="$(${LAUNCHASUSER} expect -c '
					set timeout '${MaxRetryInSeconds}'
					'"${EXPECTDEBUG}"'
					spawn /sbin/mount -t '"${Protocol}"''"${MountOptions:+ -o ${MountOptions}}"' //'"${Account}"'@'"${Server}"'/'"${Share}"' '"${MOUNTPOINT_APN}"'/'"${MountPoint}"'
					expect {
						-re ".*ssword.*" {
							send -- "'"$(getPasswordFromKeychain | convertToHexCode)"'\r"
							exp_continue
						}
						timeout {
							exit 1
						}
						eof {
							return
						}
					}
					catch wait result
					exit [lindex $result 3]' 2>&1)"
				_RC=${?}
				;;
			*)
				log --priority=${LOG_ERROR} "Unknown protocol ${Protocol}"
				((MountlistIndex++))
				continue
				;;
		esac
		if [ ${_RC} -eq ${SUCCESS} ]; then
			log --priority=${LOG_INFO} "${Share} mounted successfully"
			((MountedShares++))
		else
			log --priority=${LOG_ERROR} "mount of ${Share} failed (RC=${_RC}, RV=${_RV})"
		fi
		_EC=$((_EC||_RC))
		((MountlistIndex++))
	done
	if [ ${_EC} -eq ${SUCCESS} ]; then
		if [ ${MountedShares} -eq ${MountlistIndex} ]; then
			log --priority=${LOG_INFO} "All shares mountd successfully."
			if [ ${BACKGROUND} -eq ${YES} ]; then
				${LAUNCHASUSER} /usr/bin/osascript -e "display notification \"All shares mounted successfully.\" with title \"automount\" subtitle \"\""
			fi
		else
			log --priority=${LOG_INFO} "Some shares mountd successfully."
		fi
	else
		log --priority=${LOG_ERROR} "automount runned with errors."
		if [ ${BACKGROUND} -eq ${YES} ]; then
			${LAUNCHASUSER} /usr/bin/osascript -e "display notification \"automount runned with errors.\" with title \"automount\" subtitle \"\""
		fi
	fi

	return ${_EC}
}

function addPassword {
	local _Account="${Account:-${LOGINNAME}}"
	local _AppAccess=""
	local _RV=""
	local -i RC=0

	if [[ "${Protocol}" =~ ^http(s)+ ]]; then
		_AppAccess="-T /System/Library/Extensions/webdav_fs.kext/Contents/Resources/webdavfs_agent"
	fi
	_RV="$(security add-internet-password \
		-a "${_Account}" \
		-l "${Server}" \
		-D "${Description:-Netzwerkpasswort}" \
		-j "${SCRIPTNAME}" \
		-r "$(getKeychainProtocol)" \
		-s "${Server}" \
		-w "$(read -r -p "Password: " -s && echo "${REPLY}"; unset REPLY)" \
		-U \
		-T /usr/bin/security \
		-T /System/Library/CoreServices/NetAuthAgent.app/Contents/MacOS/NetAuthSysAgent \
		-T /System/Library/CoreServices/NetAuthAgent.app \
		-T group://NetAuth \
		${_AppAccess} \
		"${LOGINHOME}"/Library/Keychains/login.keychain 2>&1)"
	_RC=${?}

	if [ ${_RC} -eq ${SUCCESS} ]; then
		log --priority=${LOG_INFO} "successfully added password to keychain."
	else
		log --priority=${LOG_ERROR} "error adding password to keychain. (RC=${_RC}, RV=${_RV})"
	fi
	exit ${_RC}
}

function create_lock {
	local _RV _RunningPID
	local -i _RC=${TRUE}

	_RV="$( { mkdir "${LOCK_APN}" && echo "${$}" > "${LOCK_AFN}"; } 2>&1 || false )"
	_RC=${?}
	if [ ${_RC} -ne ${SUCCESS} ]; then
		if [ -s "${LOCK_AFN}" ]; then
			_RunningPID="$(cat "${LOCK_AFN}")"
			_RV="$(pgrep -f -l -F "${LOCK_AFN}" "${SCRIPT_FN}" 2>&1)"
			_RC=${?}
		else
			_RunningPID=""
			_RV="$(pgrep -f -l "${SCRIPT_FN}" 2>&1)"
			_RC=${?}
		fi
		if [ ${_RC} -eq ${FOUND} ]; then
			log --priority=${LOG_ERROR} "${SCRIPT_FN} is already running${_RunningPID:+ with PID ${_RunningPID}}"
			exit 1
		else
			_RV="$( { rm -rf "${LOCK_APN}" && mkdir "${LOCK_APN}" && echo "${$}" > "${LOCK_AFN}"; } 2>&1 || false )"
			_RC=${?}
			if [ ${_RC} -ne ${SUCCESS} ]; then
				log --priority=${LOG_ERROR} "Could not create \"${LOCK_AFN}\", exiting (RC=${_RC}, RV=${_RV})"
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
				Action="processMountlist"
				;;
			-v|--verbose)
				((Verbose++))
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
	processMountlist)
		${Action}
		RC=${?}
		exit ${RC}
		;;
	addPassword)
		if [[ -z "${Protocol}" || -z "${Server}" ]]; then
			showUsage
			exit
		fi
		${Action}
		;;
	*)
		showUsage
		exit
		;;
esac
