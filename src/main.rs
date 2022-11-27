use std::error;
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

fn main() -> Result<(), Box<dyn error::Error>> {
    let device = Device::lookup()?.ok_or("no device available")?;

    // get the default Device
    println!("Using device {}", device.name);

    let mut cap = Capture::from_device(device)?.immediate_mode(true).open()?;

    cap.filter("tcp port 443 and (tcp[((tcp[12] & 0xf0) >>2)] = 0x16) && (tcp[((tcp[12] & 0xf0) >>2)+5] = 0x01)", true).unwrap();

    for packet in cap.iter(Codec) {
        let packet = packet?;
        let hostname = tls_packet::get_sni(&packet.data);
        
        if let Some(x) = hostname {
            println!("Captured SNI: {:?}", x);
        }
    }

    Ok(())
}