use pcap::{PacketHeader, PacketCodec, Packet, Device, Capture};

mod tls_packet;

/// Represents a owned packet
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketOwned {
    pub header: PacketHeader,
    pub data: Box<[u8]>,
}

/// Simple codec that tranform [`pcap::Packet`] into [`PacketOwned`]
pub struct Codec;

impl PacketCodec for Codec {
    type Item = PacketOwned;

    fn decode(&mut self, packet: Packet) -> Self::Item {
        PacketOwned {
            header: *packet.header,
            data: packet.data.into(),
        }
    }
}

fn main() {
    let mut cap: Capture<pcap::Active> = match std::env::args().len() {
        2 => {
            let if_name = std::env::args().nth(1).expect("failed to get arg");
            println!("listening on {:?}", if_name);
            Capture::from_device(if_name.as_str()).expect("no such device").immediate_mode(true).open().expect("failed to open device")
        },
        _ => {
            let device = Device::lookup().expect("device lookup failed").expect("no device found");
            println!("no interface specified, using device {}", device.name);
            Capture::from_device(device).expect("no such device").immediate_mode(true).open().expect("failed to open device")
        },
    };

    cap.filter("tcp port 443 and (tcp[((tcp[12] & 0xf0) >>2)] = 0x16) && (tcp[((tcp[12] & 0xf0) >>2)+5] = 0x01)", true).unwrap();

    for packet in cap.iter(Codec) {
        let packet = packet.expect("Failed to read packet");
        let hostname = tls_packet::get_sni(&packet.data);
        
        if let Some(x) = hostname {
            println!("Captured SNI: {:?}", x);
        }
    }
}