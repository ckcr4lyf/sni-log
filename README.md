# SNI Log

SNI log is a rust application that inspect packets in realtime and prints the websites that TLS connection attempts are made to. 

It can also be used to block websites based on the SNI field, making it more powerful than a DNS solution such as pi-hole

## Purpose

The initial goal was just to highlight the shortcomings of TLS when it comes to privacy: even though the content is encrypted, anyone in the middle can determine **which** website you're connecting to.

Since I've personally also experienced what must be SNI-based blocking *(though technically I cannot be 100% sure)* from an ISP in the past, I wanted to also make a PoC so anyone can try and perform SNI-based blocking.

## Building

**NOTE: Currently sni-log ONLY supports Linux**

`sni-log` required the following libraries be present on your system: 

* [libpcap](https://github.com/the-tcpdump-group/libpcap)
* [libnetfilter_queue](https://netfilter.org/projects/libnetfilter_queue/)

**Arch Linux**

```
pacman -S libpcap libnetfilter_queue
```

**Ubuntu**

```
apt-get install libpcap-dev libnetfilter-queue-dev
```

**Building the binary**

Ensure you have the rust toolchain installed, for e.g. via [rustup](https://rustup.rs/), then run:

```
cargo build --release
```

## Usage

### Logging SNIs

If you just want to log the SNIs connection attempts are made to, you can use the `log` subcommand. 

**NOTE:** Capturing packets needs superuser permission, so you must run the program as root, or set packet capture perission on the binary: `sudo setcap cap_net_raw,cap_net_admin=eip path/to/bin`.

To sniff on all interfaces:

```
./sni-log log -a
```

To specify interfaces to sniff on:

```
./sni-log log -i eth0,eth1
```

If neither is specified, it will try and listen on the default interface.

### Blocking SNIs

Example iptables rule. The `--queue-bypass` flag will allow connections if no userspace app is connected to the queue (e.g. to make decisions)

```
# iptables -A OUTPUT -j NFQUEUE --queue-num 0 --queue-bypass
```

Run program:

```
# ./sni-log block --queue-num 0
```

Try & curl an HTTPS website!

## Shortcomings

The next steps to improve the functionality are:

- [X] Pass which interface to listen on via CLI option
- [X] Allow listening on multiple interfaces from a single instance
- [ ] Handle multiple SNI entries
- [ ] Support QUIC ClientHello
