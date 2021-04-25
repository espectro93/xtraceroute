use std::iter::Iterator;
use std::{env, process};
use xtraceroute::dns::dns_resolve_ip;
use xtraceroute::traceroute::trace_route;
use xtraceroute::config::Config;

fn main() {
    let dns_addr = env::args().nth(1).unwrap_or_else(|| {
        eprintln!("[!] Usage: traceroute <domain>");
        process::exit(1);
    });

    println!("traceroute to {}", dns_addr);

    let ip_destination = dns_resolve_ip(dns_addr.as_str());
    trace_route(Config { destination: ip_destination, tries_per_hop: 5, timeout: 1 });
}


