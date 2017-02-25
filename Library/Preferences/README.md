# Common options

All key beginning with `COMMON` are standard values and can be overridden in the `Mountlist` array with the corresponding key

* `COMMONMAXRETRYINSECONDS` (numeric, optional) ... How long in seconds to try to reach the server (ping)

If not set `MAXRETRYINSECONDS` defined in automount.sh is used (Standard: 10 seconds)

* `COMMONVALIDIPRANGES` (string, separated by comma, optional) ... Only try to mount when Mac is in the given network(s)

* `COMMONACCOUNT` (string, optional) ... The account to connect to the share with

If not set `LOGINUSER` is used

* `COMMONMOUNTOPTIONS` (string, separated by comma, optional) ... Mount options to use on share

If not set MOUNTOPTIONS defined in automount.sh is used (Standard: nodev,nosuid)


# Specific options

In the `Mountlist` array you define the share(s) to process

* `MAXRETRYINSECONDS` (numeric, optional) ... see `COMMONMAXRETRYINSECONDS`

If not set `COMMONMAXRETRYINSECONDS` is used

* `VALIDIPRANGES` (string, separated by comma, optional) ... see `VALIDIPRANGES`

If not set `COMMONVALIDIPRANGES` is used

* `MOUNTOPTIONS` (string, separated by comma, optional) ... see `MOUNTOPTIONS`

If not set `COMMONMOUNTOPTIONS` is used

* `PROTOCOL` (string, mandatory) ... Possible values are `afp`, `smb`, `ftp` (readonly), `nfs`, `http` or `https`

* `DOMAIN` (string, optional) ... Domain name for smbfs

* `ACCOUNT` (string, mandatory) ... see `ACCOUNT`

If not set `COMMONACCOUNT` is used

* `SERVER` (string, mandatory) ... Full qualified server name

* `SHARE` (string, mandatory) ... The name of the share to mount

* `MOUNTPOINT` (string, optional) ... The name of the mountpoint

If set /Volumes/MOUNTPOINT is used to mount the share, else /Volumes/SHARE

## Prerequesites
```bash
chown ${USER}:staff ${HOME}/Library/Preferences/it.niemetz.automount.plist
chmod 644 ${USER}/Library/Preferences/it.niemetz.automount.plist
```