
use bytes::{Bytes, BytesMut, BufMut, Buf};
use crate::dns::byte_order::ByteOrder;


#[derive(Copy, Clone, Debug)]
pub enum Field {
	_16Bit(u16, usize),
	_8Bit(u8, usize)
}

pub struct FieldIter {
	fields: Vec<Field>,
	idx: usize
}

impl Iterator for FieldIter {
	type Item = Field;

	fn next(&mut self) -> Option<Self::Item> {
		let idx = self.idx;
		self.idx += 1;

		self.fields.get(idx).map(|f| *f )
	}
}

impl From<Vec<Field>> for FieldIter {
	fn from(value: Vec<Field>) -> Self {
		FieldIter { fields: value, idx: 0 }
	}
}

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
#[derive(Debug)]
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

trait Fields {
	fn fields(&self) -> FieldIter;
}

impl Fields for DNSHeader {
	fn fields(&self) -> FieldIter {
			vec![
				self.id,
				self.qr,
				self.opcode,
				self.aa,
				self.tc,
				self.rd,
				self.ra,
				self.z,
				self.rcode,
				self.qdcount,
				self.ancount,
				self.nscount,
				self.arcount
			].into()
	}
}

struct BufFrame {
	frame: u8,
	remaining_capacity: usize
}


impl BufFrame {
	fn new() -> Self {
		BufFrame {
			frame: 0,
			remaining_capacity: 8
		}
	}

	fn clear(&mut self) {
		self.remaining_capacity = 8;
		self.frame = 0;
	}

	fn flush(&mut self, dst: &mut BytesMut) {
		dst.put_u8(self.frame);
		self.clear();
	}

	fn append(&mut self, val: u8, size: usize) {
		let shift_val = self.remaining_capacity - size;

		let next_frame_val = val << shift_val; 
		self.frame |= next_frame_val;
		self.remaining_capacity -= size;
	}
	
	fn append_then_flush(&mut self, val: u8, size: usize, dst: &mut BytesMut) {
		self.append(val, size);

		if self.remaining_capacity == 0 {
			self.flush(dst);
		}
	}
}

impl ByteOrder for DNSHeader {
	fn to_be_bytes(&self) -> Bytes {
		let mut buf = BytesMut::with_capacity(12);

		let mut buf_frame = BufFrame::new();
		for field in self.fields() {
			match field {
				Field::_16Bit(val, _) => {
					buf.extend_from_slice(&val.to_be_bytes());
				},
				Field::_8Bit(val, size) => {
					buf_frame.append_then_flush(val, size, &mut buf);
				}
			}
		}

		buf.into()
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
		let ancount = buf.get_u16();
		let nscount = buf.get_u16();
		let arcount = buf.get_u16();
		
		DNSHeader {
			id: Field::_16Bit(id, 16),
			qr: Field::_8Bit(qr, 1),
			opcode: Field::_8Bit(opcode, 4),
			aa: Field::_8Bit(aa, 1),
			tc: Field::_8Bit(tc, 1),
			rd: Field::_8Bit(rd, 1),
			ra: Field::_8Bit(ra, 1),
			z: Field::_8Bit(z, 3),
			rcode: Field::_8Bit(rcode, 4),
			qdcount: Field::_16Bit(qdcount, 16),
			ancount: Field::_16Bit(ancount, 16),
			nscount: Field::_16Bit(nscount, 16),
			arcount: Field::_16Bit(arcount, 16),
		}
	}
}
