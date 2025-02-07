# mfw

a static iptables-companion act as a firewall

output is determinism. it manage your iptables file, and never mess it up. it play nice with docker and any friends. it has room to intergrate any external iptables rules.

## hawk to?

```
# iptable.rule
#include "ports.rule"
```

```sh
mfw-ports add 80/tcp
mfw generate # see the commands
mfw apply # deploy the rule
```