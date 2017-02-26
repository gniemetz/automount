# automount

You want your needed network shares mounted automatically at login without the finder popping up or passwords stored in a script?

Try automount!

## Features

- Mount shares listed in `~/Library/Preferences/it.niemetz.automount.plist` at login
- Mount shares if network settings change (roaming users)
- Mount shares only if in dedicated network
- No passwords saved, keychain is used

## Installation

Drop `automount.sh` into `/usr/local/bin`, define the shares you want to mount in `~/Library/Preferences/it.niemetz.automount.plist` and set up a LaunchAgent with `~/Library/LauchAgents/it.niemetz.automount.plist`

Log in `~/Library/Logs/automount.log`


Look into the `Library` folders for further documentation



PS: Thanks to https://github.com/childrss/webdav for the implementation of WebDAV
