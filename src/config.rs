use std::net::Ipv4Addr;

#[derive(Clone, Copy)]
pub struct Config {
    pub destination: Ipv4Addr,
    pub tries_per_hop: usize,
    pub timeout: u64,
}