use std::thread;
use pcap::{PacketHeader, PacketCodec, Packet, Device, Capture};
use clap::Parser;

mod tls_packet;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
   /// Flag to enable all interfaces
   #[arg(short, long)]
   all: bool,

   /// Flag to pass which interfaces to sniff on, comma separated
   #[arg(short, long)]
   interfaces: Option<String>,
}

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

    let args = Args::parse();
    let mut handled: Vec<thread::JoinHandle<()>> = vec![];

    if args.all {
        // Listen on all devices. Get device names
        let devices = Device::list().expect("Failed to list devices");

        for device in devices {
            if device.flags.is_up() {
                println!("Found device that is up: {:?}. Will listen on it", device.name);
                let t_handle = thread::spawn(move || {
                    cap_and_log(&device.name);
                });
                handled.push(t_handle);              
            }
        }
    } else if let Some(interfaces_arg) = args.interfaces {
        let interfaces = interfaces_arg.split(",");

        for interface in interfaces {
            println!("Going to listen on {}", interface);
            let i_owned = interface.to_owned();
            let t_handle = thread::spawn(move || {
                cap_and_log(&i_owned);
            });
            handled.push(t_handle);              
        }
    } else {
        println!("No interface / all flag specified. Going to attempt to listen on default interface");
        let device = Device::lookup().unwrap().ok_or("no device available").unwrap();
        println!("Using device {}", device.name);
        let t_handle = thread::spawn(move || {
            cap_and_log(&device.name);
        });
        handled.push(t_handle);
    }

    // We started the listener on all, now join all
    for t_handle in handled {
        t_handle.join().unwrap();
    }
}

fn cap_and_log(if_name: &str) {
    let mut cap = Capture::from_device(if_name).expect("no such device").immediate_mode(true).open().expect("failed to open device");
    // thanks to https://www.baeldung.com/linux/tcpdump-capture-ssl-handshake
    cap.filter("tcp port 443 and (tcp[((tcp[12] & 0xf0) >>2)] = 0x16) && (tcp[((tcp[12] & 0xf0) >>2)+5] = 0x01)", true).unwrap();

    for packet in cap.iter(Codec) {
        let packet = packet.expect("Failed to read packet");
        let hostname = tls_packet::get_sni(&packet.data);
        
        if let Some(x) = hostname {
            println!("[{}] Captured SNI: {:?}", &if_name, x);
        }
    }
}
