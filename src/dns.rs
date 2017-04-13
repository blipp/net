use {TxPacket, WriteOut};
use ethernet::{EthernetAddress, EthernetPacket};
use ipv4::{Ipv4Address, Ipv4Packet};
use udp::UdpPacket;
use parse::{Parse, ParseError};
use byteorder::{ByteOrder, NetworkEndian};
use bit_field::BitField;
use collections::string::String;
use collections::str;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsHeader {
    pub id: u16,
    pub query_response: bool,
    pub opcode: DnsOpcode,
    /*
     *pub authoritative_answer: bool,
     *pub truncation: bool,
     *pub recursion_desired: bool,
     *pub recursion_available: bool,
     *pub rcode: u8,
     *pub qd_count: u16,
     *pub an_count: u16,
     *pub ns_count: u16,
     *pub ar_count: u16
     */
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsOpcode {
    Query,
    Inverse_Query,
    Status,
    Reserved,
    Notify,
    Update,
    Other(u16)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub hostname: String,
}

impl<'a> Parse<'a> for DnsPacket {
    fn parse(data: &'a [u8]) -> Result<Self, ParseError> {
        let id = NetworkEndian::read_u16(&data[0..2]);
        let flags = NetworkEndian::read_u16(&data[2..4]);
        // first flag bit is the query_response bit
        let query_response = flags.get_bit(15);
        let opcode: DnsOpcode = match flags.get_bits(11..15) {
            0 => DnsOpcode::Query,
            1 => DnsOpcode::Inverse_Query,
            2 => DnsOpcode::Status,
            3 => DnsOpcode::Reserved,
            4 => DnsOpcode::Notify,
            5 => DnsOpcode::Update,
            other => DnsOpcode::Other(other),
        };
        let mut hostname = String::from("");
        if opcode == DnsOpcode::Query {
            // Parse the first query.
            //
            // Read the first byte
            let mut label_length = data[12] as usize;
            let mut label_pointer = 13 as usize;
            let mut next_label_length_pointer = (label_pointer + label_length) as usize;

            while label_length != 0 && next_label_length_pointer < data.len() {
                // read the label
                if let Ok(label) = str::from_utf8(&data[label_pointer..next_label_length_pointer]) {
                    // TODO: add "."
                    hostname += label;
                    //println!("parsed label: '{}'", label);
                }

                // read one byte, this is the length of the next label
                label_length = data[next_label_length_pointer] as usize;
                label_pointer = (next_label_length_pointer + 1) as usize;
                next_label_length_pointer = (label_pointer + label_length) as usize;
            }
            println!("DNS query for: {}", hostname);
        }
        Ok(DnsPacket {header: DnsHeader {id: id, query_response: query_response, opcode: opcode}, hostname: hostname})
    }
}
