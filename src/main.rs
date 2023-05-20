use std::thread;
use pcap::{PacketHeader, PacketCodec, Packet, Device, Capture};
use clap::{Parser, Subcommand};

mod tls_packet;

#[cfg(target_os = "linux")]
use libc;

#[cfg(target_os = "linux")]
use nfqueue;

#[cfg(target_os = "linux")]
struct State<'a>{
    blacklist: Vec<&'a str>
}

#[cfg(target_os = "linux")]
impl State<'_> {
    pub fn new(blacklist: Vec<&str>) -> State {
        State { blacklist: blacklist }
    }
}

#[cfg(target_os = "linux")]
fn queue_callback(msg: &nfqueue::Message, state: &mut State) {
    if let Some(hostname) = tls_packet::get_sni(msg.get_payload()) {
        println!("[NFQUEUE] Captured SNI: {:?}", hostname);

        if state.blacklist.contains(&hostname) {
            println!("[NFQUEUE] {} IS BLOCKED!", hostname);
            msg.set_verdict(nfqueue::Verdict::Drop);
            return;
        }
    }

    msg.set_verdict(nfqueue::Verdict::Accept);
}

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
#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Just logging
    Log {
        /// Flag to enable all interfaces
        #[arg(short, long)]
        all: bool,

        /// Flag to pass which interfaces to sniff on, comma separated
        #[arg(short, long)]
        interfaces: Option<String>,
    },
    #[cfg(target_os = "linux")]
    /// Block TLS connections to a domain via iptables & nfqueue
    /// 
    /// As an example, to pass all TLS connections to queue number 0, you can add the rule:
    /// iptables -A OUTPUT -p tcp --dport 443 -j NFQUEUE --queue-num 0
    Block {
        /// netfilter queue number
        #[arg(short, long)]
        queue_num: u16,

        /// domains to block, comma separated.
        /// Wildcards NOT supported (yet...)
        #[arg(short, long)]
        block: Option<String>
    }
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
    let args_0 = Cli::parse();

    match args_0.command {
        #[cfg(target_os = "linux")]
        Commands::Block { queue_num, block } => {
            let blacklist: Vec<&str> = if let Some(ref csv_block) = block {
                csv_block.split(",").collect()
            } else {
                vec![]
            };

            let mut q = nfqueue::Queue::new(State::new(blacklist));
            q.open();

            q.unbind(libc::AF_INET); // ignore result, failure is not critical here

            let rc = q.bind(libc::AF_INET);
            assert!(rc == 0);

            q.create_queue(queue_num, queue_callback);
            q.set_mode(nfqueue::CopyMode::CopyPacket, 0xffff);
            q.run_loop();
        }
        Commands::Log { all, interfaces } => {
            println!("Logging SNIs");

            let mut handled: Vec<thread::JoinHandle<()>> = vec![];

            if all {
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
            } else if let Some(interfaces_arg) = interfaces {
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
