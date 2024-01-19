use bytes::BufMut;
use super::field::{Field, Fields};

/// convert to Big-Endian byte order
pub trait ByteOrder<'a> {
	fn write_be_bytes(&self, dst: &'a mut [u8]) -> &'a [u8]; 
}

pub struct BufFrame<'a> {
	dst: &'a mut [u8],
	frame: u8,
	frame_capacity: &'a usize,
	remaining_capacity: usize
}


impl <'a> BufFrame<'a> {
	pub fn new(dst: &'a mut [u8], frame_cap: &'a usize) -> Self {
		BufFrame {
			dst: dst,
			frame: 0,
			frame_capacity: frame_cap,
			remaining_capacity: *frame_cap
		}
	}

	fn clear(&mut self) {
		self.remaining_capacity = 8;
		self.frame = 0;
	}

	/// flushes the content of the frame to the underlying buffer and clears the frame.
	fn flush(&mut self) {
		self.dst.put_u8(self.frame);
		self.clear();
	}

	pub fn append(&mut self, vals: &[u8]) {
		vals.iter().for_each(|b| self.push_be(b, self.frame_capacity));
	}

	pub fn push_be(&mut self, val: &u8, size: &usize) {
		let shift_val = self.remaining_capacity - size;

		let next_frame_val = val << shift_val; 
		self.frame |= next_frame_val;
		self.remaining_capacity -= size;

		self.flush_full_frame();
	}

	pub fn flush_full_frame(&mut self) {
		if self.remaining_capacity == 0 {
			self.flush();
		}
	}
	
}

impl <'a, V> ByteOrder<'a> for V
where V: Fields {
	fn write_be_bytes(&self, dst: &'a mut [u8]) -> &'a [u8] {

		let mut buf_frame = BufFrame::new(dst, &8usize);
		for field in self.fields() {
			match field {
				Field::Word(val) => {
					buf_frame.append(&val.to_be_bytes());
				},
				Field::Byte(val, size) => {
					buf_frame.push_be(val, size);
				},
				Field::Label(val) => {
					val.iter().for_each(|l| {
						buf_frame.push_be(&(l.len() as u8), &8usize);
						buf_frame.append(l.as_bytes())
					});
					buf_frame.push_be(&0x00, &8usize); //escape
				}
			}
		}

		dst
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	struct MockFields {
		byte1: Field,
		byte2: Field,
		nil: Field,
		word: Field,
		label: Field
	}

	impl Fields for MockFields {
		fn fields(&self) -> crate::dns::field::FieldIter {
			vec![
				&self.byte1,
				&self.byte2,
				&self.nil,
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
			nil: Field::Byte(0, 8),
			word: Field::Word(512),
			label: Field::Label(vec![String::from("google"), String::from("lol")])
		};

		let expect = b"\x3c\0\x02\0\x06google\x03lol\0";
		
		let actual = &mut [0; 16];
		mock.write_be_bytes(actual);
		
		println!("expected: {:?}", expect);
		println!("actual: {:?}", actual);

		assert_eq!(expect, actual);
	}
}
