use std::net::{Ipv4Addr, IpAddr};
use dns_lookup::lookup_host;

pub fn dns_resolve_ip(target: &str) -> Ipv4Addr {
    let ips: Vec<std::net::IpAddr> = lookup_host(target).unwrap().into_iter().filter(|addr| addr.is_ipv4()).collect();
    match ips.last() {
        Some(ip) => {
            if let IpAddr::V4(ipv4) = ip {
                return ipv4.to_owned();
            } else { panic!("Could not resolve ip address for: {}", target) }
        }
        None => panic!("Could not find corresponding ipv4 addr")
    }
}