mod dns;
use std::net::UdpSocket;

use bytes::{BytesMut, Buf};

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
				let mut filled_buf = BytesMut::from(&buf[..size]);
				println!("Buffer {:?}", filled_buf);

				let header = DNSHeader::default();
				filled_buf.advance(12);
				let question = DNSQuestion::from(&mut filled_buf);

				println!("Header: {:?}", header);
				println!("Question: {:?}", question);

				let h_response = header.to_be_bytes();
				let q_response = question.to_be_bytes();

				println!("header response: {:?}", h_response);
				println!("question respoinse: {:?}", q_response);
				
				udp_socket
					.send_to(&h_response, source)
					.expect("Failed to send response");
			}
			Err(e) => {
				eprintln!("Error receiving data: {}", e);
				break;
			}
		}
	}
}
