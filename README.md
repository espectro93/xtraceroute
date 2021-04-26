# XTRACEROUTE

Extended traceroute program that shows geo information besides the server ip, if available.
As we operate on layer 3 and send ICMP EchoRequest and receive replies, we need root privileges 
to filter ICMP packets (at least on linux): e.g. sudo -E cargo run www.google.de