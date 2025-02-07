# mfw

a static iptables-companion act as a firewall

- `iptables-save` file can be modified, organised easily, with simple cli and come with `mfw-ports` to open port (easy to comprehend). a file could be re-applied, and then it do what it is.
- doesn't mess with other programs. it will not override docker or wireguard.
- dertiminstic output, means you can just generate into a script, then make it run at boot. `apply` command will generate `iptables.rule.sh` at the same directory, so just put it run on boot, simple as that!

## get binary fast (linux x64 only)

```sh
curl -L https://github.com/LangDuaMC/mfw/releases/download/0.1.1/mfw.tar.gz -o- | sudo tar -xvzC/usr/bin
sudo chmod u+x /usr/bin/mfw*
```

## hawk to? *(lazy)*

- Must be at `/etc/mfw`: `sudo mkdir /etc/mfw && cd /etc/mfw`
- Write firewall rules
```
# /etc/mfw/iptables.rule
#include "ports.rule"
# hey, if you do docker-to-host networking, please make sure to set this to only drop the main interface.
-A INPUT -j DROP
```
- Deploy firewall rules
```sh
mfw-ports add 22/tcp
mfw-ports add 80/tcp
mfw generate # see the commands
mfw apply # deploy the rule
```
- Edit startup service `/etc/systemd/system/mfw.service`
```
[Unit]
Description=Apply mfw's iptables rules at startup
After=network.target

[Service]
Type=oneshot
ExecStart=/bin/bash /etc/mfw/iptables.rule.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```
- Activate
```sh
sudo systemctl daemon-reload
sudo systemctl enable --now mfw
```
