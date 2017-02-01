# Startup

The script `/usr/local/bin/automount.sh --mountall` is executed at 
* login
* any change of network settings
but only when network is up and running

## Prerequisites
```bash
chown ${USER}:staff ${HOME}/Library/LaunchAgents/it.niemetz.automount.plist
chmod 644 ${USER}/Library/LaunchAgents/it.niemetz.automount.plist
```

## To install the LaunchAgent

```bash
launchctl load -w ${USER}/Library/LaunchAgents/it.niemetz.automount.plist
```


## To uninstall the LaunchAgent

```bash
launchctl load -w ${USER}/Library/LaunchAgents/it.niemetz.automount.plist
```


