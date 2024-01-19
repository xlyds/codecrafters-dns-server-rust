use bytes::{BytesMut, Buf};
use super::field::{Field, Fields, FieldIter};

#[derive(Debug, PartialEq)]
pub struct DNSQuestion {
	pub name: Field,
	pub q_type: Field,
	pub q_class: Field
}

impl Fields for DNSQuestion {
	fn fields(&self) -> FieldIter {
		vec![
			&self.name,
			&self.q_type,
			&self.q_class
		].into()
	}
}

fn to_labels(source: &mut BytesMut) -> Vec<String> {
	let mut label_length = source.get_u8() as usize;
	let mut labels: Vec<String> = vec![];

	while label_length > 0 {
		let label_vec = source.iter().take(label_length).map( |x| *x).collect::<Vec<u8>>();

		let label = match String::from_utf8(label_vec) {
			Ok(l) => l,
			Err(e) => panic!( "couldn't read question name. {}", e )
		};
		
		labels.push(label);
		source.advance(label_length);
		label_length = source.get_u8() as usize;
	}

	labels
}

impl From<&mut BytesMut> for DNSQuestion {
	fn from(value: &mut BytesMut) -> Self {
		let label: Vec<String> = to_labels(value);
		
		DNSQuestion {
			name: Field::Label(label),
			q_type: Field::Word(value.get_u16()),
			q_class: Field::Word(value.get_u16())
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn from_bytes_mut_works() {
		let buf = b"\x0ccodecrafters\x02io\0\0\x01\0\x01";
		let bytes = &mut BytesMut::from(&buf[..]);

		let expect = DNSQuestion {
			name: Field::Label(vec![String::from("codecrafters"), String::from("io")]),
			q_type: Field::Word(1),
			q_class: Field::Word(1)
		};

		let actual = DNSQuestion::from(bytes);

		assert_eq!(expect, actual);
	}
}