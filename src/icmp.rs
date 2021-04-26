use pnet::packet::{
    icmp::{
        echo_request::{MutableEchoRequestPacket},
        IcmpTypes,
    },
    ip::IpNextHeaderProtocols,
    ipv4::MutableIpv4Packet,
    MutablePacket,
};
use std::net::Ipv4Addr;
use pnet::packet::util::checksum;
use crate::config::Config;
use pnet::transport::{TransportSender};

static IPV4_HEADER_LEN: u32 = 21;
static ICMP_HEADER_LEN: u32 = 8;
static ICMP_PAYLOAD_LEN: u32 = 32;

pub fn create_icmp_packet<'a>(
    buf_ip: &'a mut [u8],
    buf_icmp: &'a mut [u8],
    dest: Ipv4Addr,
    ttl: u8,
    sequence_number: u16,
) -> MutableIpv4Packet<'a> {
    let mut ipv4_packet = MutableIpv4Packet::new(buf_ip)
        .expect("Failed to create ipv4 packet");

    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length(IPV4_HEADER_LEN as u8);
    ipv4_packet.set_total_length((IPV4_HEADER_LEN + ICMP_HEADER_LEN + ICMP_PAYLOAD_LEN) as u16);
    ipv4_packet.set_ttl(ttl);
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    ipv4_packet.set_destination(dest);

    let mut icmp_packet = MutableEchoRequestPacket::new(buf_icmp)
        .expect("Failed to create icmp packet");

    icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
    icmp_packet.set_sequence_number(sequence_number);

    let checksum = checksum(&icmp_packet.packet_mut(), 1);

    icmp_packet.set_checksum(checksum);
    ipv4_packet.set_payload(icmp_packet.packet_mut());

    ipv4_packet
}

pub fn send_requests(config: &Config, tx: &mut TransportSender, ttl: usize, mut buf_ip: &mut [u8], mut buf_icmp: &mut [u8]) {
    for i in 0..config.tries_per_hop {
        let icmp_packet = create_icmp_packet(
            &mut buf_ip,
            &mut buf_icmp,
            config.destination,
            ttl as u8,
            ((ttl - 1) * config.tries_per_hop + i) as u16);

        tx.send_to(icmp_packet, std::net::IpAddr::V4(config.destination))
            .expect("Sending packet failed!");
    }
}