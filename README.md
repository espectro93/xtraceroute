# xtraceroute

Extended traceroute program that shows geo information besides the server ip, if available.

## Description

xtraceroute implements the regular traceroute logic and thus is sending ICMP EchoRequests to a destination ip while increasing the time to live (ttl) value. Due to increasing the ttl and thus terminating at each hop we get information about the hop our paket travels through before reaching the destination (data is in the ICMP EchoReply). We strip of the ip of that hop from that ICMP EchoReply and try a reverse geo ip lookup to get the address in a readable format. Sadly the used api is not really precise.

## Getting Started

### Dependencies

* Install rust (https://doc.rust-lang.org/book/ch01-01-installation.html)

### Installing

* Checkout repository and build project

### Executing program

This was only tested on a linux distribution, where we need root privileges as we oparte on layer 3 to send icmp EchoRequests.

```
sudo -E cargo run www.google.de
```


### Further improvements
* we could use a more precise api
