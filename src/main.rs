mod dns;
use std::net::UdpSocket;

use bytes::BytesMut;

use crate::dns::{header::DNSHeader, byte_order::ByteOrder};

fn main() {
	// You can use print statements as follows for debugging, they'll be visible when running tests.
	println!("Logs from your program will appear here!");

	let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
	let mut buf = [0; 512];
	
	loop {
		match udp_socket.recv_from(&mut buf) {
			Ok((size, source)) => {
				println!("Received {} bytes from {}", size, source);
				let mut filled_buf = BytesMut::from(&buf[..size]);
				let header = DNSHeader::from(&mut filled_buf);

				let response = header.to_be_bytes();
				udp_socket
					.send_to(&response, source)
					.expect("Failed to send response");
			}
			Err(e) => {
				eprintln!("Error receiving data: {}", e);
				break;
			}
		}
	}
}
