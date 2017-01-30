All key beginning with `COMMON` are standard values and can be overridden on the `Mountlist` array with the corresponding key

`COMMONMAXRETRYINSECONDS` (numeric) ... How long to try to reach the server

`COMMONVALIDIPRANGES` (string, separated by comma) ... Only try to mount in the given networks

`COMMONACCOUNT` (string) ... The account to connect to the share with

`COMMONMOUNTOPTIONS` (string, separated by comma) ... Mount options to use on share



In the `Mountlist` array you define the mounts to process

`MAXRETRYINSECONDS` (numeric) ... see `COMMONMAXRETRYINSECONDS`

`VALIDIPRANGES` (string, separated by comma) ... see `VALIDIPRANGES`

`MOUNTOPTIONS` (string, separated by comma) ... see `MOUNTOPTIONS`

`PROTOCOL` (string) ... Possible values are `afp`, `smb`, `ftp` (readonly), `nfs`, `http` or `https`

`ACCOUNT` (string) ... see `ACCOUNT`

`SERVER` (string) ... Full qualified server name

`SHARE` (string) ... The name of the share to mount



Prerequesites
```bash
chown ${USER}:staff ${HOME}/Library/Preferences/it.niemetz.automount.plist
chmod 644 ${USER}/Library/Preferences/it.niemetz.automount.plist
```