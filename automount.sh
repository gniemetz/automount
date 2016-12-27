#!/usr/bin/env bash


#/Users/${UserName}/Library/LaunchAgents/it.niemetz.automount.plist
#<?xml version="1.0" encoding="UTF-8"?>
#<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
#<plist version="1.0">
#<dict>
#	<key>Label</key>
#	<string>it.niemetz.automount</string>
#	<key>ProgramArguments</key>
#	<array>
#		<string>/Users/Shared/automount.sh</string>
#	</array>
#	<key>RunAtLoad</key>
#	<true/>
#</dict>
#</plist>
#launchctl load /Users/${UserName}/Library/LaunchAgents/it.niemetz.automount.plist

#/Users/${UserName}/Library/Preferences/it.niemetz.automount.plist
#<?xml version="1.0" encoding="UTF-8"?>
#<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
#<plist version="1.0">
#<dict>
#	<key>commonacct</key>
#	<string>COMMONACCT</string>
#	<key>commonopts</key>
#	<string>COMMONOPTS (nodev,nosuid)</string>
#	<key>Mountlist</key>
#	<array>
#		<dict>
#			<key>acct</key>
#			<string>ACCOUNT</string>
#			<key>ptcl</key>
#			<string>PROTOCOL (afp/smb)</string>
#			<key>shre</key>
#			<string>SHARE</string>
#			<key>srvr</key>
#			<string>SERVER</string>
#		</dict>
#	</array>
#</dict>
#</plist>

#security add-internet-password \
#  -a ACCOUNT \
#  -l LABEL (eg. same as SERVER) \
#  -D DESCRIPTION (eg. Networkpassword) \
#  -r PROTOCOL ("afp "/"smb ") \
#  -s SERVER \
#  -w PASSWORD \
#  -T /usr/bin/security \
#  -T /System/Library/CoreServices/NetAuthAgent.app/Contents/MacOS/NetAuthSysAgent \
#  -T /System/Library/CoreServices/NetAuthAgent.app \
#  -T group://NetAuth \
#  /Users/${UserName}/Library/Keychains/login.keychain

UserName="$(logname)"
PLAutomount="/Users/${UserName}/Library/Preferences/it.niemetz.automount.plist"
KCLogin="/Users/${UserName}/Library/Keychains/login.keychain"
declare -i Idx=0
declare -i Retry
declare -i MaxRetry=30

function cleanup {
  unset KCpassword
  exit ${1}
}

trap 'cleanup' SIGHUP SIGINT SIGQUIT SIGTERM EXIT

if [[ -s "${PLAutomount}" ]] && [[ -s "${KCLogin}" ]]; then
  PLcommonacct="$(/usr/libexec/PlistBuddy -c "Print commonacct" "${PLAutomount}" 2>/dev/null)"
  PLcommonacct="${PLcommonacct:-${UserName}}"
  PLcommonopts="$(/usr/libexec/PlistBuddy -c "Print commonopts" "${PLAutomount}" 2>/dev/null)"
  while /usr/libexec/PlistBuddy -c "Print Mountlist:${Idx}" "${PLAutomount}" >/dev/null 2>&1; do
    PLptcl="$(/usr/libexec/PlistBuddy -c "Print Mountlist:${Idx}:ptcl" "${PLAutomount}" 2>/dev/null)"
    PLacct="$(/usr/libexec/PlistBuddy -c "Print Mountlist:${Idx}:acct" "${PLAutomount}" 2>/dev/null)"
    PLacct="${PLacct:-${PLcommonacct}}"
    PLsrvr="$(/usr/libexec/PlistBuddy -c "Print Mountlist:${Idx}:srvr" "${PLAutomount}" 2>/dev/null)"
    PLshre="$(/usr/libexec/PlistBuddy -c "Print Mountlist:${Idx}:shre" "${PLAutomount}" 2>/dev/null)"
    if [[ -n "${PLptcl}" && -n "${PLacct}" && -n "${PLsrvr}" && -n "${PLshre}" ]] && ! mount | egrep -s -q "^//${PLacct}@${PLsrvr}/${PLshre} on /Volumes/${PLshre} \(${PLptcl}fs,.*${UserName}\)$" 2>/dev/null; then
      Retry=0
      while ! ping -c 1 -t 1 -o -q "${PLsrvr}" >/dev/null 2>&1 && [[ ${Retry} -le ${MaxRetry} ]]; do
        if [[ ${Retry} -le ${MaxRetry} ]]; then
          sleep 1
          ((Retry++))
        fi
      done
      if [[ ${Retry} -ge ${MaxRetry} ]]; then
        ((Idx++))
        continue
      fi

      if ! eval $(
      security find-internet-password \
        -g \
        -r "$(printf "%-4s" "${PLptcl}")" \
        -a "${PLacct}" \
        -l "${PLsrvr}" \
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
    
      if [[ ! -d "/Volumes/${PLshre}" ]] && ! { mkdir -p "/Volumes/${PLshre}" && chown "${UserName}:staff" "/Volumes/${PLshre}"; } >/dev/null 2>&1;  then
        rmdir "/Volumes/${PLshre}" >/dev/null 2>&1
        ((Idx++))
        continue
      fi
    
      mount -t ${PLptcl}${PLcommonopts:+ -o ${PLcommonopts}} "${PLptcl}://${PLacct}:${KCpassword}@${PLsrvr}/${PLshre}" "/Volumes/${PLshre}" 2>/dev/null
    fi
    ((Idx++))
  done
else
  exit 1
fi
