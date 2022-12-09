# SNI Log

SNI log is a rust application that inspect packets in realtime and prints the websites that connection attempts are made to.

## Purpose

The main goal is to highlight (in my opinion) the biggest weakness in TLS: [Server Name Indication](https://www.rfc-editor.org/rfc/rfc6066#section-3). This sends, in plaintext, the domain you are trying to connect to. The reason is that there may be multiple websites on a single IP address, so the server handling the initial connection needs to know which certificate to present.

The consequence of this is that anyone in between your PC and the server knows which website you're trying to connect to _by domain name_. This is often used to block websites by ISPs (since they sit between you and the internet, and every packet passes through them).

## TLS is still safe!

TLS will still protect all your data, so no one can see _what_ you're doing, it's just the domain that is "leaked". But as noted above, this alone can be revealing.

## Building

`sni-log` uses [rust-pacp](https://github.com/rust-pcap/pcap), which in turn depends on libpcap (or Npcap on Windows). You should get the dependencies [as instructed here](https://github.com/rust-pcap/pcap/#installing-dependencies).

Then, with the rust toolchain installed, simply run 

```
cargo build
```

## Usage

Capturing packets needs superuser permission, so you must run the program as root

```
sudo ./sni-log [interface]
```

`[interface]` is optional. If not provided, it will listen on the default interface.

## Shorcomings

The current version is a quick & dirty PoC to see if I could do this in Rust. The next steps to improve and make this actually usable are:

- [X] Pass which interface to listen on via CLI option
- [ ] Handle multiple SNI entries
- [ ] Support QUIC ClientHello
