use std::net::{IpAddr};
use std::time::{Duration, Instant};

use pnet::packet::{
    icmp::{
        echo_reply::EchoReplyPacket,
        echo_request::{EchoRequestPacket},
        IcmpPacket,
        IcmpType,
        IcmpTypes,
    },
    ip::IpNextHeaderProtocols,
    Packet,
};
use crate::icmp::create_icmp_packet;
use crate::config::Config;
use pnet::transport::{icmp_packet_iter, transport_channel, TransportSender};
use pnet::transport::TransportChannelType::Layer3;
use std::panic::Location;
use crate::location::get_location_for;

static MAX_TTL: usize = 64;

#[derive(Clone, Debug)]
pub struct TraceHop {
    hop_addr: IpAddr,
    reply_time: Duration,
    reply_type: IcmpType,
    sequence_number: u16,
}

#[derive(Clone, Debug)]
pub struct TraceHopResult {
    ttl: usize,
    hop_addr: IpAddr,
    answer_time: String,
}

pub fn trace_route(config: Config) -> ()
{
    let (mut tx, mut rx) = transport_channel(
        1024,
        Layer3(IpNextHeaderProtocols::Icmp))
        .expect("Creating transport channel failed!");

    let mut rx = icmp_packet_iter(&mut rx);

    let mut ttl: usize = 1;
    let timeout_in_sec = Duration::from_secs(config.timeout);

    let mut buf_ip = [0u8; 64];
    let mut buf_icmp = [0u8; 40];

    println!("{:>4}   {:<20} {:<15} {:<15}", "Hop", "Host IP address", "Location", "Answer time");

    let mut hop_results: Vec<TraceHopResult> = Vec::new();

    'outer: while ttl <= MAX_TTL {
        let mut replies: Vec<TraceHop> = Vec::with_capacity(config.tries_per_hop);

        let timer_start = Instant::now();
        send_requests(&config, &mut tx, ttl, &mut buf_ip, &mut buf_icmp);

        loop {
            if timer_start.elapsed() > timeout_in_sec { break; }
            match rx.next_with_timeout(timeout_in_sec) {
                Ok(Some((reply, host))) => {
                    let icmp_header = IcmpPacket::new(&reply.packet()[20..])
                        .expect("Parsing icmp reply failed!");

                    if let Some(hop) = process_reply(icmp_header, host, timer_start.elapsed()) {
                        replies.push(hop);
                    }
                }
                Ok(None) => break, // time expired
                Err(err) => panic!("Receiving packet error:\n{:?}", err),
            }
        }

        let replies = filter_out_unhandled_packets(&config, ttl, replies);

        let destination_reached = replies.iter().any(|reply| reply.reply_type == IcmpTypes::EchoReply);
        if destination_reached {
            break 'outer;
        }

        if replies.is_empty() {
            /* 0 received packets */
            //println!("{:>3}.   {:^20} {:^15}", ttl, "*", "*");
        } else if replies.len() < config.tries_per_hop {
            /* Received less packets than were sent. */
            //println!("{:>3}.   {:<20} {:<15} {:^15}", ttl, replies[0].hop_addr.to_string(), "Location", "*");
            hop_results.push(TraceHopResult {
                hop_addr: replies[0].hop_addr,
                answer_time: String::from("*"),
                ttl,
            });
        } else if replies.len() == config.tries_per_hop {
            /* Received all packets */
            let avrg_time = replies.iter()
                .fold(Duration::from_secs(0), |acc, reply| acc + reply.reply_time) / config.tries_per_hop as u32;

            hop_results.push(TraceHopResult {
                hop_addr: replies[0].hop_addr,
                answer_time: duration_to_string(&avrg_time),
                ttl,
            });
            //println!("{:>3}.   {:<20} {:^15?}", ttl, replies[0].hop_addr.to_string(), avrg_time);
        }

        ttl += 1;
    }

    if ttl > MAX_TTL {
        println!("TTL value exceeded! Traceroute exits.", );
    }

    print_results_with_location(hop_results);
}

fn print_results_with_location(results: Vec<TraceHopResult>) {
    for result in results.iter() {
        println!("{:>3}.   {:<20} {:<20} {:^15?}", result.ttl, result.hop_addr.to_string(), get_location_for(result.hop_addr).unwrap_or("N.a.".to_string()), result.answer_time);
    }
}

fn process_reply(reply: IcmpPacket, host: IpAddr, duration: Duration) -> Option<TraceHop> {
    match reply.get_icmp_type() {
        IcmpTypes::TimeExceeded => {
            let request_packet = EchoRequestPacket::new(&reply.packet()[28..])
                .expect("Parsing echo request packet failed!");

            Some(TraceHop {
                hop_addr: host,
                reply_time: duration,
                reply_type: IcmpTypes::TimeExceeded,
                sequence_number: request_packet.get_sequence_number(),
            })
        }
        IcmpTypes::EchoReply => {
            let reply_packet = EchoReplyPacket::new(&reply.packet())
                .expect("Parsing echo reply packet failed!");

            Some(TraceHop {
                hop_addr: host,
                reply_time: duration,
                reply_type: IcmpTypes::EchoReply,
                sequence_number: reply_packet.get_sequence_number(),
            })
        }
        _ => None,
    }
}

fn duration_to_string(duration: &Duration) -> String {
    let seconds = duration.as_secs() % 60;
    let minutes = (duration.as_secs() / 60) % 60;
    let hours = (duration.as_secs() / 60) / 60;
    format!("{}:{}:{}", hours, minutes, seconds)
}

fn filter_out_unhandled_packets(config: &Config, ttl: usize, replies: Vec<TraceHop>) -> Vec<TraceHop> {
    replies.into_iter().filter(|reply| {
        let sequence_number = reply.sequence_number as usize;
        (ttl - 1) * config.tries_per_hop <= sequence_number && sequence_number < ttl * config.tries_per_hop
    }).collect()
}

fn send_requests(config: &Config, tx: &mut TransportSender, ttl: usize, mut buf_ip: &mut [u8], mut buf_icmp: &mut [u8]) {
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