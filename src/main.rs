mod dns;
use std::net::UdpSocket;

use bytes::BytesMut;

use crate::dns::{header::DNSHeader, byte_order::ByteOrder, question::DNSQuestion};

fn main() {
	// You can use print statements as follows for debugging, they'll be visible when running tests.
	println!("Logs from your program will appear here!");

	let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
	let mut buf = [0; 512];
	
	loop {
		match udp_socket.recv_from(&mut buf) {
			Ok((size, source)) => {
				println!("Received {} bytes from {}", size, source);
				let mut filled_buf: BytesMut = BytesMut::from(&buf[..size]);
				println!("Buffer {:?}", filled_buf);

				let header = DNSHeader::from(&mut filled_buf);
				let question = DNSQuestion::from(&mut filled_buf);

				println!("Header: {:?}", header);
				println!("Question: {:?}", question);

				let res_buf = &mut [0u8; 512];

				header.write_be_bytes(&mut res_buf[..12]);
				question.write_be_bytes(&mut res_buf[12..]);

				println!("response: {:?}", res_buf);
				
				udp_socket
					.send_to(res_buf, source)
					.expect("Failed to send response");
			}
			Err(e) => {
				eprintln!("Error receiving data: {}", e);
				break;
			}
		}
	}
}
