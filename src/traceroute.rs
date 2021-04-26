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
use crate::icmp::{send_requests};
use crate::config::Config;
use pnet::transport::{icmp_packet_iter, transport_channel};
use pnet::transport::TransportChannelType::Layer3;
use crate::location::get_location_for;
use std::thread;

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
    let mut ttl: usize = 1;

    let (mut tx, mut rx) = transport_channel(
        1024,
        Layer3(IpNextHeaderProtocols::Icmp))
        .expect("Creating transport channel failed!");

    let mut rx = icmp_packet_iter(&mut rx);


    let mut buf_ip = [0u8; 64];
    let mut buf_icmp = [0u8; 40];

    let timeout_in_sec = Duration::from_secs(config.timeout);

    println!("{:>4}   {:<20} {:<15} {:<15}", "Hop", "Host IP address", "Location", "Answer time");

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

        //EchoReply means we have reached destination, TimeLimitExceeded is the response of hap where it terminates because the ttl was not high enough
        //e.g. we start with ttl 1, so it terminates at hop 1 and sends timelimit exceeded, but we still have 10 or more hops to go so we increment and try again
        let destination_reached = replies.iter().any(|reply| reply.reply_type == IcmpTypes::EchoReply);
        if destination_reached {
            break 'outer;
        }

        if replies.is_empty() {
            println!("{:>3}.   {:^20} {:<15} {:^15}", ttl, "*", "N.a.", "*");
        } else if replies.len() < config.tries_per_hop {
            thread::spawn(move || {
                println!("{:>3}.   {:<20} {:<15} {:^15}", ttl.clone(), replies[0].hop_addr.to_string().clone(), get_location_for(replies[0].hop_addr.clone()).unwrap_or("N.a.".to_string()), "*");
            });
        } else if replies.len() == config.tries_per_hop {
            let avg_time = replies.iter()
                .fold(Duration::from_secs(0), |acc, reply| acc + reply.reply_time) / config.tries_per_hop as u32;

            let ip_clone = replies[0].hop_addr.clone();
            thread::spawn(move || {
                println!("{:>3}.   {:<20} {:<15} {:^15}", ttl.clone(), ip_clone.to_string(), get_location_for(ip_clone).unwrap_or("N.a.".to_string()), avg_time.as_millis());
            });
        }
        ttl += 1;
    }

    if ttl > MAX_TTL {
        println!("TTL value exceeded! Traceroute exits.", );
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

fn filter_out_unhandled_packets(config: &Config, ttl: usize, replies: Vec<TraceHop>) -> Vec<TraceHop> {
    replies.into_iter().filter(|reply| {
        let sequence_number = reply.sequence_number as usize;
        (ttl - 1) * config.tries_per_hop <= sequence_number && sequence_number < ttl * config.tries_per_hop
    }).collect()
}