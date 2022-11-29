use etherparse::SlicedPacket;

pub fn get_sni(packet: &[u8]) -> Option<&str> {

    let ethernet_packet = match SlicedPacket::from_ethernet(packet) {
        Err(_) => {
            println!("Failed to parse packet");
            return None;
        },
        Ok(value) => value,
    };

    match ethernet_packet.transport {
        None => {
            println!("No transport!");
            return None;
        },
        Some(value) => match value {
            etherparse::TransportSlice::Tcp(header) => header,
            _ => return None,
        },
    };

    // println!("payload: {:x?}", ethernet_packet.payload);

    let mut pos = 0;

    // Fantastic reference: https://tls12.xargs.org/#client-hello

    // 5 + 4 + 2 + 32 + 1 = 43 bytes of data we can always skip.
    pos += 43;

    // next byte is length of existing session (if any)
    let session_length = u8::from_be_bytes(ethernet_packet.payload.get(pos .. pos + 1)?.try_into().expect("Fucked up"));
    pos += 1;
    // println!("session length is {:?}, data is {:x?}", session_length, &ethernet_packet.payload[pos .. pos + session_length as usize]);
    pos += session_length as usize;

    // next two bytes give use length of Cipher Suite data
    let cs_length = u16::from_be_bytes(ethernet_packet.payload.get(pos .. pos + 2)?.try_into().expect("Fucked up"));
    pos += 2;
    // println!("Cipher Suite length is {:?}, data is {:x?}", cs_length, &ethernet_packet.payload[pos .. pos + cs_length as usize]);
    pos += cs_length as usize;

    // next byte is length of compression data
    let cd_length = u8::from_be_bytes(ethernet_packet.payload.get(pos .. pos + 1)?.try_into().expect("Fucked up"));
    pos += 1;
    // println!("compression data length is {:?}, data is {:x?}", cd_length, &ethernet_packet.payload[pos .. pos + cd_length as usize]);
    pos += cd_length as usize;

    // next two bytes are length of extensions
    let extension_length = u16::from_be_bytes(ethernet_packet.payload.get(pos .. pos + 2)?.try_into().expect("Fucked up"));
    pos += 2;
    // println!("extension length is {:?}, data is {:x?}", extension_length, &ethernet_packet.payload[pos .. pos + extension_length as usize]);
    // println!("extension length is {:?}", extension_length);

    let mut ext_pos: usize = 0;

    while ext_pos < extension_length as usize {
        let ext_type = u16::from_be_bytes(ethernet_packet.payload.get(pos + ext_pos .. pos + ext_pos + 2)?.try_into().expect("Fucked up"));
        ext_pos += 2;
        let ext_length = u16::from_be_bytes(ethernet_packet.payload.get(pos + ext_pos .. pos + ext_pos + 2)?.try_into().expect("Fucked up"));
        ext_pos += 2;

        if ext_type != 0 {
            // println!("Got non SNI entry. Type: {:x?}", ext_type);
        } else {
            // println!("got SNI entry!");
            let mut sni_pos = 0;
            let _sni_data_len = u16::from_be_bytes(ethernet_packet.payload.get(pos + ext_pos .. pos + ext_pos + 2)?.try_into().expect("Fucked up"));
            sni_pos += 2;

            if ethernet_packet.payload[pos + ext_pos + sni_pos] == 0x00 {
                sni_pos += 1;
                // DNS hostname
                let hostname_len = u16::from_be_bytes(ethernet_packet.payload.get(pos + ext_pos + sni_pos .. pos + ext_pos + sni_pos + 2)?.try_into().expect("Fucked up"));
                sni_pos += 2;
                match std::str::from_utf8(&ethernet_packet.payload.get(pos + ext_pos + sni_pos .. pos + ext_pos+ sni_pos + hostname_len as usize)?) {
                    Err(_) => return None,
                    Ok(hostname) => return Some(hostname),
                }
            }

            sni_pos += 1;
            // TODO: loop over SNI entries
        }

        ext_pos += ext_length as usize;
    }
    // pos += cs_length as usize;

    return None;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn when_invalid_packet(){
        let packet: [u8; 10] = [0; 10];
        let parsed_packet = get_sni(&packet);

        assert_eq!(parsed_packet.is_none(), true);
    }

    #[test]
    fn is_legit(){
        // A TLS Client Hello Manually Captured at Ethernet Frame
        let packet: [u8; 583] = [196, 104, 208, 137, 87, 251, 0, 40, 248, 158, 117, 85, 8, 0, 69, 0, 2, 57, 131, 16, 64, 0, 64, 6, 255, 57, 192, 168, 128, 128, 172, 64, 201, 11, 191, 16, 1, 187, 213, 80, 4, 147, 80, 223, 65, 122, 128, 24, 1, 246, 158, 137, 0, 0, 1, 1, 8, 10, 20, 131, 119, 49, 168, 185, 238, 224, 22, 3, 1, 2, 0, 1, 0, 1, 252, 3, 3, 46, 100, 91, 225, 60, 242, 109, 71, 168, 84, 54, 64, 29, 170, 54, 107, 134, 248, 37, 15, 15, 82, 60, 255, 134, 245, 138, 76, 18, 135, 154, 175, 32, 137, 0, 107, 73, 39, 15, 183, 40, 171, 225, 156, 24, 116, 146, 204, 33, 95, 162, 210, 50, 105, 3, 57, 254, 180, 23, 202, 190, 235, 103, 65, 123, 0, 62, 19, 2, 19, 3, 19, 1, 192, 44, 192, 48, 0, 159, 204, 169, 204, 168, 204, 170, 192, 43, 192, 47, 0, 158, 192, 36, 192, 40, 0, 107, 192, 35, 192, 39, 0, 103, 192, 10, 192, 20, 0, 57, 192, 9, 192, 19, 0, 51, 0, 157, 0, 156, 0, 61, 0, 60, 0, 53, 0, 47, 0, 255, 1, 0, 1, 117, 0, 0, 0, 16, 0, 14, 0, 0, 11, 105, 102, 99, 111, 110, 102, 105, 103, 46, 99, 111, 0, 11, 0, 4, 3, 0, 1, 2, 0, 10, 0, 22, 0, 20, 0, 29, 0, 23, 0, 30, 0, 25, 0, 24, 1, 0, 1, 1, 1, 2, 1, 3, 1, 4, 0, 16, 0, 14, 0, 12, 2, 104, 50, 8, 104, 116, 116, 112, 47, 49, 46, 49, 0, 22, 0, 0, 0, 23, 0, 0, 0, 49, 0, 0, 0, 13, 0, 42, 0, 40, 4, 3, 5, 3, 6, 3, 8, 7, 8, 8, 8, 9, 8, 10, 8, 11, 8, 4, 8, 5, 8, 6, 4, 1, 5, 1, 6, 1, 3, 3, 3, 1, 3, 2, 4, 2, 5, 2, 6, 2, 0, 43, 0, 9, 8, 3, 4, 3, 3, 3, 2, 3, 1, 0, 45, 0, 2, 1, 1, 0, 51, 0, 38, 0, 36, 0, 29, 0, 32, 253, 145, 47, 236, 113, 48, 41, 240, 119, 11, 202, 50, 66, 164, 227, 193, 101, 112, 36, 165, 41, 178, 170, 60, 180, 183, 209, 90, 174, 9, 90, 14, 0, 21, 0, 178, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let parsed_sni = get_sni(&packet);
        assert_eq!(parsed_sni.is_some(), true);
        assert_eq!(parsed_sni, Some("ifconfig.co"));
    }

    #[test]
    fn invalid_packet(){
        // We manually change cipher suite length to 0xFFFF (65535) , so that it should trigger index out of bounds after adding
        // it on, and then trying to read compression data, resulting in the return value being "none'"
        let packet: [u8; 583] = [196, 104, 208, 137, 87, 251, 0, 40, 248, 158, 117, 85, 8, 0, 69, 0, 2, 57, 131, 16, 64, 0, 64, 6, 255, 57, 192, 168, 128, 128, 172, 64, 201, 11, 191, 16, 1, 187, 213, 80, 4, 147, 80, 223, 65, 122, 128, 24, 1, 246, 158, 137, 0, 0, 1, 1, 8, 10, 20, 131, 119, 49, 168, 185, 238, 224, 22, 3, 1, 2, 0, 1, 0, 1, 252, 3, 3, 46, 100, 91, 225, 60, 242, 109, 71, 168, 84, 54, 64, 29, 170, 54, 107, 134, 248, 37, 15, 15, 82, 60, 255, 134, 245, 138, 76, 18, 135, 154, 175, 32, 137, 0, 107, 73, 39, 15, 183, 40, 171, 225, 156, 24, 116, 146, 204, 33, 95, 162, 210, 50, 105, 3, 57, 254, 180, 23, 202, 190, 235, 103, 65, 123, 255, 255, 19, 2, 19, 3, 19, 1, 192, 44, 192, 48, 0, 159, 204, 169, 204, 168, 204, 170, 192, 43, 192, 47, 0, 158, 192, 36, 192, 40, 0, 107, 192, 35, 192, 39, 0, 103, 192, 10, 192, 20, 0, 57, 192, 9, 192, 19, 0, 51, 0, 157, 0, 156, 0, 61, 0, 60, 0, 53, 0, 47, 0, 255, 1, 0, 255, 255, 0, 0, 0, 16, 0, 14, 0, 0, 11, 105, 102, 99, 111, 110, 102, 105, 103, 46, 99, 111, 0, 11, 0, 4, 3, 0, 1, 2, 0, 10, 0, 22, 0, 20, 0, 29, 0, 23, 0, 30, 0, 25, 0, 24, 1, 0, 1, 1, 1, 2, 1, 3, 1, 4, 0, 16, 0, 14, 0, 12, 2, 104, 50, 8, 104, 116, 116, 112, 47, 49, 46, 49, 0, 22, 0, 0, 0, 23, 0, 0, 0, 49, 0, 0, 0, 13, 0, 42, 0, 40, 4, 3, 5, 3, 6, 3, 8, 7, 8, 8, 8, 9, 8, 10, 8, 11, 8, 4, 8, 5, 8, 6, 4, 1, 5, 1, 6, 1, 3, 3, 3, 1, 3, 2, 4, 2, 5, 2, 6, 2, 0, 43, 0, 9, 8, 3, 4, 3, 3, 3, 2, 3, 1, 0, 45, 0, 2, 1, 1, 0, 51, 0, 38, 0, 36, 0, 29, 0, 255, 253, 145, 47, 236, 113, 48, 41, 240, 119, 11, 202, 50, 66, 164, 227, 193, 101, 112, 36, 165, 41, 178, 170, 60, 180, 183, 209, 90, 174, 9, 90, 14, 0, 21, 0, 178, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let parsed_sni = get_sni(&packet);
        assert_eq!(parsed_sni.is_none(), true);

    }
}