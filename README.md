# SNI Log

SNI log is a rust application that inspect packets in realtime and prints the websites that TLS connection attempts are made to.

## Purpose

The main goal is to highlight (in my opinion) the biggest privacy shortcoming of TLS: [Server Name Indication](https://www.rfc-editor.org/rfc/rfc6066#section-3). This sends, in plaintext, the domain you are trying to connect to. The reason is that there may be multiple websites on a single IP address, so the server handling the initial connection needs to know which certificate to present.

The consequence of this is that anyone in between your PC and the server knows which website you're trying to connect to _by domain name_. This is often used to block websites by ISPs (since they sit between you and the internet, and every packet passes through them).

Encrypted DNS (such as DNS-over-HTTPS or DNS-over-TLS) **WONT** help you, since the information is lost during the TLS connection attempt, not the DNS lookup.

## TLS is still safe!

TLS will still protect all your data, so no one can see _what_ you're doing, it's just the domain that is "leaked". But depending on your threat model, this alone may be compromising.

## Building

`sni-log` uses [rust-pacp](https://github.com/rust-pcap/pcap), which in turn depends on libpcap (or Npcap on Windows). You should get the dependencies [as instructed here](https://github.com/rust-pcap/pcap/#installing-dependencies).

Then, with the rust toolchain installed, simply run 

```
cargo build --release
```

## Usage

Capturing packets needs superuser permission, so you must run the program as root, or set packet capture perission on the binary: `sudo setcap cap_net_raw,cap_net_admin=eip path/to/bin`.

To sniff on all interfaces:

```
sudo ./sni-log -a
```

To specify interfaces to sniff on:

```
sudo ./sni-log -i eth0,eth1
```

If neither is specified, it will try and listen on the default interface.

## Shorcomings

The next steps to improve the functionality are:

- [X] Pass which interface to listen on via CLI option
- [X] Allow listening on multiple interfaces from a single instance
- [ ] Handle multiple SNI entries
- [ ] Support QUIC ClientHello
