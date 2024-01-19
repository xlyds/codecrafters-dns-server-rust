use bytes::{BytesMut, Buf};
use super::field::{Field, Fields, FieldIter};

/// Represents a DNS Header Section
/// 
/// #### Fields
/// *id* _packet identifier_: A random id assigned to query packets. Response replies with same id.
/// 
/// *qr* _Query/Response indicator_: 1 for reply, 0 for question.
/// 
/// *opcode* _Operation Code_: specifies the kind of query in a message.
/// 
/// *aa* _Authoritative Answer_: 1 if the responding servers "owns" the domain queried.
/// 
/// *tc* _Truncation_: 1 if the message is larger than 512 bytes. Always 0 in UDP responses.
/// 
/// *rd* _Recursion Desired_: Sender sets this to 1 if the server should recursively resolve this query.
/// 
/// *ra* _Recursion Available: Server sets this to 1 to indicate the recursion is availible.
/// 
/// *z* _Reserved_: Used by DNSSEC queries. At inception it was reserved for future use.
/// 
/// *rcode* _Response Code_: Response code indication the status of the response.
/// 
/// *qdcount* _Question Count_: Number of questions in the Question section.
/// 
/// *ancount* _Answer Count_: Number of answers in the Answer section.
/// 
/// *nscount* _Authority Record Count_: Number of records in the Authority section.
/// 
/// *arcount* _Additional Record Count_: Number of records int the Additional section.

#[derive(Debug, PartialEq)]
pub struct DNSHeader {
	
	/// *id* _packet identifier_: (16 bit)
	/// A random id assigned to query packets. Response replies with same id. 
	pub id: Field, 

	/// *qr* _Query/Response indicator_: (1 bit)
	/// 1 for reply, 0 for question.
	pub qr: Field,

	/// *opcode* _Operation Code_: (4 bit)
	/// specifies the kind of query in a message.
	pub opcode: Field,

	/// *aa* _Authoritative Answer_: (1 bit)
	/// 1 if the responding servers "owns" the domain queried.
	pub aa: Field,

	/// *tc* _Truncation_: (1 bit)
	/// 1 if the message is larger than 512 bytes. Always 0 in UDP responses.
	pub tc: Field,

	/// *rd* _Recursion Desired_: (1 bit)
	/// Sender sets this
	///  to 1 if the server should recursively resolve this query.
	pub rd: Field,
	
	/// *ra* _Recursion Available: (1 bit)
	/// Server sets this to 1 to indicate the recursion is availible.
	pub ra: Field,

	/// *z* _Reserved_: (3 bit)
	/// Used by DNSSEC queries. At inception it was reserved for future use.
	pub z: Field,
	
	/// *rcode* _Response Code_: (4 bits)
	/// Response code indication the status of the response.
	pub rcode: Field,

	/// *qdcount* _Question Count_: (16 bits)
	/// Number of questions in the Question section.
	pub qdcount: Field,

	/// *ancount* _Answer Count_: (16 bits)
	/// Number of answers in the Answer section.
	pub ancount: Field,
	
	/// *nscount* _Authority Record Count_: (16 bits)
	/// Number of records in the Authority section.
	pub nscount: Field,
	
	/// *arcount* _Additional Record Count_: (16 bits)
	/// Number of records int the Additional section.
	pub arcount: Field
}

impl Fields for DNSHeader {
	fn fields(&self) -> FieldIter {
			vec![
				&self.id,
				&self.qr,
				&self.opcode,
				&self.aa,
				&self.tc,
				&self.rd,
				&self.ra,
				&self.z,
				&self.rcode,
				&self.qdcount,
				&self.ancount,
				&self.nscount,
				&self.arcount
			].into()
	}
}

impl Default for DNSHeader {
	fn default() -> Self {
		DNSHeader {
			id: Field::Word(1234),
			qr: Field::Byte(1, 1),
			opcode: Field::Byte(0, 4),
			aa: Field::Byte(0, 1),
			tc: Field::Byte(0, 1),
			rd: Field::Byte(0, 1),
			ra: Field::Byte(0, 1),
			z: Field::Byte(0, 3),
			rcode: Field::Byte(0, 4),
			qdcount: Field::Word(1),
			ancount: Field::Word(0),
			nscount: Field::Word(0),
			arcount: Field::Word(0),
		}
	}
}


impl From<&mut BytesMut> for DNSHeader {
	fn from(buf: &mut BytesMut) -> Self {
		let id = buf.get_u16();
		let qr = buf.get_u8();
		let opcode = buf.get_u8();
		let aa = buf.get_u8();
		let tc = buf.get_u8();
		let rd = buf.get_u8();
		let ra = buf.get_u8();
		let z = buf.get_u8();
		let rcode = buf.get_u8();
		let qdcount = buf.get_u16();
		let ancount = 0x00;
		let nscount = 0x00;
		let arcount = 0x00;

		DNSHeader {
			id: Field::Word(id),
			qr: Field::Byte(qr, 1),
			opcode: Field::Byte(opcode, 4),
			aa: Field::Byte(aa, 1),
			tc: Field::Byte(tc, 1),
			rd: Field::Byte(rd, 1),
			ra: Field::Byte(ra, 1),
			z: Field::Byte(z, 3),
			rcode: Field::Byte(rcode, 4),
			qdcount: Field::Word(qdcount),
			ancount: Field::Word(ancount),
			nscount: Field::Word(nscount),
			arcount: Field::Word(arcount),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn from_bytes_mut_works() {
		let buf = b"\xc7B\x01 \0\x01\0\0\0\0\0\0";
		let bytes = &mut BytesMut::from( &buf[..]);

		let expect = DNSHeader {
			id: Field::Word(51010),
			qr: Field::Byte(1, 1),
			opcode: Field::Byte(32, 4),
			aa: Field::Byte(0, 1),
			tc: Field::Byte(1, 1),
			rd: Field::Byte(0, 1),
			ra: Field::Byte(0, 1),
			z: Field::Byte(0, 3),
			rcode: Field::Byte(0, 4),
			qdcount: Field::Word(0),
			ancount: Field::Word(0),
			nscount: Field::Word(0),
			arcount: Field::Word(0)
		};

		let actual = DNSHeader::from( bytes );

		assert_eq!(expect, actual);

	}
}
