# mfw

a static iptables-companion act as a firewall

output is determinism

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