The script `/usr/local/bin/automount.sh --mountall` is executed at login and on any change of network settings

Prerequisites
```shell
chown ${USER}:staff ${HOME}/Library/LaunchAgents/it.niemetz.automount.plist
chmod 644 ${USER}/Library/LaunchAgents/it.niemetz.automount.plist
```

To install the LaunchAgent

`launchctl load -w ${USER}/Library/LaunchAgents/it.niemetz.automount.plist`


To uninstall the LaunchAgent

`launchctl load -w ${USER}/Library/LaunchAgents/it.niemetz.automount.plist`


