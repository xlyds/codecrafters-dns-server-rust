use bytes::{Bytes, BytesMut, BufMut};
use super::field::{Field, Fields};

/// convert to Big-Endian byte order
pub trait ByteOrder {
	fn to_be_bytes(&self) -> Bytes; 
}

pub struct BufFrame {
	frame: u8,
	remaining_capacity: usize
}


impl BufFrame {
	pub fn new() -> Self {
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

	fn append(&mut self, val: &u8, size: &usize) {
		let shift_val = self.remaining_capacity - size;

		let next_frame_val = val << shift_val; 
		self.frame |= next_frame_val;
		self.remaining_capacity -= size;
	}
	
	pub fn append_then_flush(&mut self, val: &u8, size: &usize, dst: &mut BytesMut) {
		self.append(val, size);

		if self.remaining_capacity == 0 {
			self.flush(dst);
		}
	}
}

impl<V> ByteOrder for V
where V: Fields {
	fn to_be_bytes(&self) -> Bytes {
		let mut buf = BytesMut::new();

		let mut buf_frame = BufFrame::new();
		for field in self.fields() {
			match field {
				Field::Word(val) => {
					buf_frame.flush(&mut buf);
					buf.extend_from_slice(&val.to_be_bytes());
				},
				Field::Byte(val, size) => {
					buf_frame.append_then_flush(val, size, &mut buf);
				},
				Field::Label(val) => {
					val.iter().for_each(|l| {
						buf.put_u8(l.len() as u8);
						buf.extend_from_slice(l.as_bytes())
					});
					buf.put_u8(0x00); //escape
				}
			}
		}

		buf.into()
	}
}

#[cfg(test)]
mod tests {
	use nom::AsBytes;
	use super::*;

	struct MockFields {
		byte1: Field,
		byte2: Field,
		word: Field,
		label: Field
	}

	impl Fields for MockFields {
		fn fields(&self) -> crate::dns::field::FieldIter {
			vec![
				&self.byte1,
				&self.byte2,
				&self.word,
				&self.label
			].into()
		}
	}


	#[test]
	fn byte_order_works() {
		let mock = MockFields {
			byte1: Field::Byte(7, 5),
			byte2: Field::Byte(4, 3),
			word: Field::Word(512),
			label: Field::Label(vec![String::from("google"), String::from("lol")])
		};

		let d_gram = b"\x3c\0\x02\0\x06google\x03lol\0";
		let expect = Bytes::from(&d_gram[..]);

		let actual = mock.to_be_bytes();
		
		println!("expecteed: {:?}", d_gram.as_bytes());
		println!("actual: {:?}", actual.as_bytes());

		assert_eq!(expect, actual);
	}
}
