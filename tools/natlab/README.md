# NAT lab

Simulates two home networks behind different NATs on one Linux machine (network namespaces),
with local STUN servers and an MQTT broker, and runs a real host/client session between them.

```
sudo apt-get install -y mosquitto iptables
cargo build --release -p llcore --example natlab
sudo tools/natlab/lab.sh easy hard        # host NAT, client NAT: easy | hard ; optional 3rd arg: fw | nofw
```

* `easy` — Linux MASQUERADE (keeps the source port: typical home router)
* `hard` — MASQUERADE `--random-fully` (new public port per destination: carrier-grade / symmetric NAT)
* `fw` (default) — routers drop unsolicited WAN input like real home routers; `nofw` is harsher.

Results for v0.1.2: easy↔easy, easy↔hard, hard↔easy connect; hard↔hard needs a relay.
