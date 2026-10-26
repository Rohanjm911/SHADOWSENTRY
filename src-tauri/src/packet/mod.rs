// Safe, zero-panic packet parser for SHADOWSENTRY
// Extracts metadata without storing raw payloads. Handles malformed frames gracefully.

use crate::models::{
    DnsSummary, PacketMetadata, ProtocolType, TcpFlags, TrafficDirection,
};
use chrono::Utc;
use uuid::Uuid;

pub struct ParsedPacket {
    pub metadata: PacketMetadata,
    pub is_arp: bool,
    pub arp_sender_ip: Option<String>,
    pub arp_sender_mac: Option<String>,
    pub arp_target_ip: Option<String>,
    pub arp_target_mac: Option<String>,
    pub arp_opcode: Option<u16>,
}

pub struct PacketParser;

impl PacketParser {
    /// Parse an Ethernet frame (Npcap / pcap layer 2 format)
    pub fn parse_ethernet_frame(data: &[u8], interface_name: &str) -> Option<ParsedPacket> {
        if data.len() < 14 {
            return None;
        }

        let dest_mac = format_mac(&data[0..6]);
        let src_mac = format_mac(&data[6..12]);
        let ether_type = u16::from_be_bytes([data[12], data[13]]);

        let payload = &data[14..];

        match ether_type {
            // IPv4
            0x0800 => Self::parse_ipv4_payload(payload, interface_name, Some(src_mac), Some(dest_mac)),
            // IPv6
            0x86DD => Self::parse_ipv6_payload(payload, interface_name, Some(src_mac), Some(dest_mac)),
            // ARP
            0x0806 => Self::parse_arp_payload(payload, interface_name, src_mac, dest_mac),
            _ => None,
        }
    }

    /// Parse raw IP packet (Windows Raw Socket format, starts at IPv4 header)
    pub fn parse_raw_ip_packet(data: &[u8], interface_name: &str) -> Option<ParsedPacket> {
        if data.is_empty() {
            return None;
        }
        let version = (data[0] >> 4) & 0x0F;
        if version == 4 {
            Self::parse_ipv4_payload(data, interface_name, None, None)
        } else if version == 6 {
            Self::parse_ipv6_payload(data, interface_name, None, None)
        } else {
            None
        }
    }

    fn parse_ipv4_payload(
        data: &[u8],
        interface_name: &str,
        src_mac: Option<String>,
        dest_mac: Option<String>,
    ) -> Option<ParsedPacket> {
        if data.len() < 20 {
            return None;
        }

        let ihl = (data[0] & 0x0F) as usize * 4;
        if data.len() < ihl || ihl < 20 {
            return None;
        }

        let total_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        let actual_packet_size = if total_len > 0 && total_len <= data.len() {
            total_len
        } else {
            data.len()
        };

        let protocol_num = data[9];
        let src_ip = format!("{}.{}.{}.{}", data[12], data[13], data[14], data[15]);
        let dst_ip = format!("{}.{}.{}.{}", data[16], data[17], data[18], data[19]);

        let l4_payload = &data[ihl..actual_packet_size.min(data.len())];

        let mut src_port = None;
        let mut dst_port = None;
        let mut tcp_flags = None;
        let mut dns_data = None;
        let mut protocol = ProtocolType::OTHER;
        let mut summary = String::new();

        match protocol_num {
            // TCP
            6 => {
                protocol = ProtocolType::TCP;
                if l4_payload.len() >= 20 {
                    let sp = u16::from_be_bytes([l4_payload[0], l4_payload[1]]);
                    let dp = u16::from_be_bytes([l4_payload[2], l4_payload[3]]);
                    src_port = Some(sp);
                    dst_port = Some(dp);

                    let flags_byte = l4_payload[13];
                    let flags = TcpFlags {
                        fin: (flags_byte & 0x01) != 0,
                        syn: (flags_byte & 0x02) != 0,
                        rst: (flags_byte & 0x04) != 0,
                        psh: (flags_byte & 0x08) != 0,
                        ack: (flags_byte & 0x10) != 0,
                        urg: (flags_byte & 0x20) != 0,
                    };
                    tcp_flags = Some(flags.clone());

                    let mut flag_strs = Vec::new();
                    if flags.syn { flag_strs.push("SYN"); }
                    if flags.ack { flag_strs.push("ACK"); }
                    if flags.fin { flag_strs.push("FIN"); }
                    if flags.rst { flag_strs.push("RST"); }
                    if flags.psh { flag_strs.push("PSH"); }

                    summary = format!("TCP {}:{} -> {}:{} [{}]", src_ip, sp, dst_ip, dp, flag_strs.join(","));

                    // Check for DNS over TCP (port 53)
                    if sp == 53 || dp == 53 {
                        protocol = ProtocolType::DNS;
                        let data_offset = ((l4_payload[12] >> 4) as usize) * 4;
                        if l4_payload.len() > data_offset + 2 {
                            let tcp_dns_payload = &l4_payload[data_offset + 2..];
                            dns_data = Self::parse_dns_payload(tcp_dns_payload);
                            if let Some(ref d) = dns_data {
                                summary = format!("DNS (TCP) {} {}", if d.is_response { "RESP" } else { "QUERY" }, d.query_name);
                            }
                        }
                    }
                }
            }
            // UDP
            17 => {
                protocol = ProtocolType::UDP;
                if l4_payload.len() >= 8 {
                    let sp = u16::from_be_bytes([l4_payload[0], l4_payload[1]]);
                    let dp = u16::from_be_bytes([l4_payload[2], l4_payload[3]]);
                    src_port = Some(sp);
                    dst_port = Some(dp);

                    summary = format!("UDP {}:{} -> {}:{}", src_ip, sp, dst_ip, dp);

                    // DNS over UDP
                    if sp == 53 || dp == 53 {
                        protocol = ProtocolType::DNS;
                        let udp_payload = &l4_payload[8..];
                        dns_data = Self::parse_dns_payload(udp_payload);
                        if let Some(ref d) = dns_data {
                            summary = format!("DNS {} {}", if d.is_response { "RESP" } else { "QUERY" }, d.query_name);
                        }
                    }
                }
            }
            // ICMP
            1 => {
                protocol = ProtocolType::ICMP;
                let icmp_type = l4_payload.first().copied().unwrap_or(0);
                let icmp_code = l4_payload.get(1).copied().unwrap_or(0);
                summary = format!("ICMP type {} code {} from {} to {}", icmp_type, icmp_code, src_ip, dst_ip);
            }
            _ => {
                summary = format!("IP proto {} from {} to {}", protocol_num, src_ip, dst_ip);
            }
        }

        let direction = infer_direction(&src_ip, &dst_ip);

        let metadata = PacketMetadata {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            interface_name: interface_name.to_string(),
            source_ip: src_ip,
            source_port: src_port,
            dest_ip: dst_ip,
            dest_port: dst_port,
            source_mac: src_mac,
            dest_mac: dest_mac,
            protocol,
            ip_version: Some(4),
            packet_size: actual_packet_size,
            direction,
            tcp_flags,
            dns_data,
            has_security_event: false,
            associated_event_id: None,
            summary,
        };

        Some(ParsedPacket {
            metadata,
            is_arp: false,
            arp_sender_ip: None,
            arp_sender_mac: None,
            arp_target_ip: None,
            arp_target_mac: None,
            arp_opcode: None,
        })
    }

    fn parse_ipv6_payload(
        data: &[u8],
        interface_name: &str,
        src_mac: Option<String>,
        dest_mac: Option<String>,
    ) -> Option<ParsedPacket> {
        if data.len() < 40 {
            return None;
        }

        let payload_len = u16::from_be_bytes([data[4], data[5]]) as usize;
        let mut next_header = data[6];
        let src_ip = format_ipv6(&data[8..24]);
        let dst_ip = format_ipv6(&data[24..40]);

        let mut offset = 40;
        // Skip common IPv6 extension headers safely
        while offset < data.len() {
            match next_header {
                0 | 43 | 60 => { // Hop-by-hop, Routing, Destination options
                    if offset + 2 > data.len() { break; }
                    next_header = data[offset];
                    let ext_len = ((data[offset + 1] as usize) + 1) * 8;
                    offset += ext_len;
                }
                _ => break,
            }
        }

        let l4_payload = if offset <= data.len() { &data[offset..] } else { &[] };
        let mut src_port = None;
        let mut dst_port = None;
        let mut protocol = ProtocolType::OTHER;
        let mut tcp_flags = None;
        let mut dns_data = None;
        let mut summary = String::new();

        match next_header {
            6 => {
                protocol = ProtocolType::TCP;
                if l4_payload.len() >= 20 {
                    let sp = u16::from_be_bytes([l4_payload[0], l4_payload[1]]);
                    let dp = u16::from_be_bytes([l4_payload[2], l4_payload[3]]);
                    src_port = Some(sp);
                    dst_port = Some(dp);

                    let flags_byte = l4_payload[13];
                    tcp_flags = Some(TcpFlags {
                        fin: (flags_byte & 0x01) != 0,
                        syn: (flags_byte & 0x02) != 0,
                        rst: (flags_byte & 0x04) != 0,
                        psh: (flags_byte & 0x08) != 0,
                        ack: (flags_byte & 0x10) != 0,
                        urg: (flags_byte & 0x20) != 0,
                    });
                    summary = format!("TCP [IPv6] {}:{} -> {}:{}", src_ip, sp, dst_ip, dp);

                    if sp == 53 || dp == 53 {
                        protocol = ProtocolType::DNS;
                    }
                }
            }
            17 => {
                protocol = ProtocolType::UDP;
                if l4_payload.len() >= 8 {
                    let sp = u16::from_be_bytes([l4_payload[0], l4_payload[1]]);
                    let dp = u16::from_be_bytes([l4_payload[2], l4_payload[3]]);
                    src_port = Some(sp);
                    dst_port = Some(dp);
                    summary = format!("UDP [IPv6] {}:{} -> {}:{}", src_ip, sp, dst_ip, dp);

                    if sp == 53 || dp == 53 {
                        protocol = ProtocolType::DNS;
                        dns_data = Self::parse_dns_payload(&l4_payload[8..]);
                    }
                }
            }
            58 => {
                protocol = ProtocolType::IPv6Icmp;
                summary = format!("ICMPv6 from {} to {}", src_ip, dst_ip);
            }
            _ => {
                summary = format!("IPv6 next_header {} from {} to {}", next_header, src_ip, dst_ip);
            }
        }

        let direction = infer_direction(&src_ip, &dst_ip);

        let metadata = PacketMetadata {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            interface_name: interface_name.to_string(),
            source_ip: src_ip,
            source_port: src_port,
            dest_ip: dst_ip,
            dest_port: dst_port,
            source_mac: src_mac,
            dest_mac: dest_mac,
            protocol,
            ip_version: Some(6),
            packet_size: 40 + payload_len,
            direction,
            tcp_flags,
            dns_data,
            has_security_event: false,
            associated_event_id: None,
            summary,
        };

        Some(ParsedPacket {
            metadata,
            is_arp: false,
            arp_sender_ip: None,
            arp_sender_mac: None,
            arp_target_ip: None,
            arp_target_mac: None,
            arp_opcode: None,
        })
    }

    fn parse_arp_payload(
        data: &[u8],
        interface_name: &str,
        _src_mac: String,
        dest_mac: String,
    ) -> Option<ParsedPacket> {
        if data.len() < 28 {
            return None;
        }

        let hw_type = u16::from_be_bytes([data[0], data[1]]);
        let proto_type = u16::from_be_bytes([data[2], data[3]]);
        let opcode = u16::from_be_bytes([data[6], data[7]]);

        if hw_type != 1 || proto_type != 0x0800 {
            return None;
        }

        let sender_mac = format_mac(&data[8..14]);
        let sender_ip = format!("{}.{}.{}.{}", data[14], data[15], data[16], data[17]);
        let target_mac = format_mac(&data[18..24]);
        let target_ip = format!("{}.{}.{}.{}", data[24], data[25], data[26], data[27]);

        let _op_name = match opcode {
            1 => "Request",
            2 => "Reply",
            _ => "Unknown",
        };

        let summary = match opcode {
            1 => format!("ARP Who has {}? Tell {}", target_ip, sender_ip),
            2 => format!("ARP {} is at {}", sender_ip, sender_mac),
            _ => format!("ARP opcode {}", opcode),
        };

        let metadata = PacketMetadata {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            interface_name: interface_name.to_string(),
            source_ip: sender_ip.clone(),
            source_port: None,
            dest_ip: target_ip.clone(),
            dest_port: None,
            source_mac: Some(sender_mac.clone()),
            dest_mac: Some(dest_mac),
            protocol: ProtocolType::ARP,
            ip_version: None,
            packet_size: 42,
            direction: TrafficDirection::Local,
            tcp_flags: None,
            dns_data: None,
            has_security_event: false,
            associated_event_id: None,
            summary,
        };

        Some(ParsedPacket {
            metadata,
            is_arp: true,
            arp_sender_ip: Some(sender_ip),
            arp_sender_mac: Some(sender_mac),
            arp_target_ip: Some(target_ip),
            arp_target_mac: Some(target_mac),
            arp_opcode: Some(opcode),
        })
    }

    /// Safe DNS message decoder
    pub fn parse_dns_payload(data: &[u8]) -> Option<DnsSummary> {
        if data.len() < 12 {
            return None;
        }

        let query_id = u16::from_be_bytes([data[0], data[1]]);
        let flags = u16::from_be_bytes([data[2], data[3]]);
        let is_response = (flags & 0x8000) != 0;
        let rcode = flags & 0x000F;
        let qdcount = u16::from_be_bytes([data[4], data[5]]);
        let ancount = u16::from_be_bytes([data[6], data[7]]);

        let response_code = if is_response {
            Some(match rcode {
                0 => "NOERROR".to_string(),
                1 => "FORMERR".to_string(),
                2 => "SERVFAIL".to_string(),
                3 => "NXDOMAIN".to_string(),
                4 => "NOTIMP".to_string(),
                5 => "REFUSED".to_string(),
                _ => format!("RCODE_{}", rcode),
            })
        } else {
            None
        };

        let mut offset = 12;
        let mut query_name = String::new();
        let mut query_type = "A".to_string();

        if qdcount > 0 && offset < data.len() {
            if let Some((name, new_offset)) = read_dns_name(data, offset) {
                query_name = name;
                offset = new_offset;

                if offset + 4 <= data.len() {
                    let qtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
                    query_type = match qtype {
                        1 => "A".to_string(),
                        28 => "AAAA".to_string(),
                        5 => "CNAME".to_string(),
                        15 => "MX".to_string(),
                        16 => "TXT".to_string(),
                        12 => "PTR".to_string(),
                        255 => "ANY".to_string(),
                        _ => format!("TYPE_{}", qtype),
                    };
                    offset += 4;
                }
            }
        }

        let mut resolved_ips = Vec::new();
        if is_response && ancount > 0 && offset < data.len() {
            for _ in 0..ancount {
                if offset >= data.len() { break; }
                if let Some((_, new_offset)) = read_dns_name(data, offset) {
                    offset = new_offset;
                    if offset + 10 > data.len() { break; }

                    let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
                    let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
                    offset += 10;

                    if offset + rdlength <= data.len() {
                        if rtype == 1 && rdlength == 4 {
                            let ip = format!("{}.{}.{}.{}", data[offset], data[offset + 1], data[offset + 2], data[offset + 3]);
                            resolved_ips.push(ip);
                        } else if rtype == 28 && rdlength == 16 {
                            let ip = format_ipv6(&data[offset..offset + 16]);
                            resolved_ips.push(ip);
                        }
                        offset += rdlength;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
        }

        // Entropy and Suspicious Pattern Checks
        let entropy = calculate_shannon_entropy(&query_name);
        let mut is_suspicious = false;
        let mut reasons = Vec::new();

        if query_name.len() > 55 {
            is_suspicious = true;
            reasons.push(format!("Excessively long query name ({} characters)", query_name.len()));
        }

        if entropy > 3.8 && query_name.len() > 14 {
            is_suspicious = true;
            reasons.push(format!("High entropy name (DGA indicator, score: {:.2})", entropy));
        }

        if query_name.ends_with(".top") || query_name.ends_with(".xyz") || query_name.ends_with(".buzz") {
            reasons.push("Frequently abused top-level domain".to_string());
        }

        Some(DnsSummary {
            query_id,
            is_response,
            query_name,
            query_type,
            response_code,
            resolved_ips,
            latency_ms: None,
            is_suspicious,
            suspicious_reasons: reasons,
        })
    }
}

fn read_dns_name(data: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut return_offset = offset;
    let mut jumps_count = 0;

    while offset < data.len() {
        let len = data[offset] as usize;
        if len == 0 {
            if !jumped {
                return_offset = offset + 1;
            }
            break;
        }

        // Pointer compression
        if (len & 0xC0) == 0xC0 {
            if offset + 2 > data.len() { return None; }
            let ptr_offset = (((len & 0x3F) as usize) << 8) | (data[offset + 1] as usize);
            if !jumped {
                return_offset = offset + 2;
                jumped = true;
            }
            offset = ptr_offset;
            jumps_count += 1;
            if jumps_count > 10 { // loop prevention
                return None;
            }
            continue;
        }

        offset += 1;
        if offset + len > data.len() { return None; }
        let label = String::from_utf8_lossy(&data[offset..offset + len]).to_string();
        labels.push(label);
        offset += len;

        if !jumped {
            return_offset = offset;
        }
    }

    if labels.is_empty() {
        Some((".".to_string(), return_offset))
    } else {
        Some((labels.join("."), return_offset))
    }
}

pub fn calculate_shannon_entropy(s: &str) -> f64 {
    if s.is_empty() { return 0.0; }
    let mut counts = std::collections::HashMap::new();
    let chars: Vec<char> = s.chars().filter(|c| *c != '.').collect();
    let total = chars.len() as f64;
    if total == 0.0 { return 0.0; }

    for c in chars {
        *counts.entry(c).or_insert(0) += 1;
    }

    let mut entropy = 0.0;
    for count in counts.values() {
        let p = (*count as f64) / total;
        entropy -= p * p.log2();
    }
    entropy
}

fn format_mac(b: &[u8]) -> String {
    if b.len() == 6 {
        format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", b[0], b[1], b[2], b[3], b[4], b[5])
    } else {
        "00:00:00:00:00:00".to_string()
    }
}

fn format_ipv6(b: &[u8]) -> String {
    if b.len() == 16 {
        let mut parts = Vec::new();
        for i in 0..8 {
            let seg = u16::from_be_bytes([b[i * 2], b[i * 2 + 1]]);
            parts.push(format!("{:x}", seg));
        }
        parts.join(":")
    } else {
        "::".to_string()
    }
}

fn infer_direction(src: &str, dst: &str) -> TrafficDirection {
    let is_src_local = is_private_or_loopback(src);
    let is_dst_local = is_private_or_loopback(dst);

    if is_src_local && is_dst_local {
        TrafficDirection::Local
    } else if is_src_local && !is_dst_local {
        TrafficDirection::Outbound
    } else if !is_src_local && is_dst_local {
        TrafficDirection::Inbound
    } else {
        TrafficDirection::Unknown
    }
}

fn is_private_or_loopback(ip: &str) -> bool {
    if ip == "127.0.0.1" || ip == "::1" || ip.starts_with("127.") {
        return true;
    }
    if ip.starts_with("10.") || ip.starts_with("192.168.") {
        return true;
    }
    if ip.starts_with("172.") {
        if let Some(second_octet) = ip.split('.').nth(1).and_then(|s| s.parse::<u8>().ok()) {
            if (16..=31).contains(&second_octet) {
                return true;
            }
        }
    }
    if ip.starts_with("fe80:") || ip.starts_with("fc") || ip.starts_with("fd") {
        return true;
    }
    false
}
