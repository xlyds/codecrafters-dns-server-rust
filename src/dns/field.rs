#[derive(Clone, Debug, PartialEq)]
pub enum Field {
	Label(Vec<String>),
	Word(u16),
	Byte(u8, usize)
}

pub trait Fields {
	fn fields(&self) -> FieldIter;
}

pub struct FieldIter<'a> {
	fields: Vec<&'a Field>,
	idx: usize
}

impl <'a> Iterator for FieldIter <'a> {
	type Item = &'a Field;

	fn next(&mut self) -> Option<Self::Item> {
		let idx = self.idx;
		self.idx += 1;

		self.fields.get(idx).map(|x| *x)
	}
}

impl <'a> From<Vec<&'a Field>> for FieldIter<'a> {
	fn from(value: Vec<&'a Field>) -> Self {
		FieldIter { fields: value, idx: 0 }
	}
}
