use bytes::Bytes;

/// convert to Big-Endian byte order
pub trait ByteOrder {
	fn to_be_bytes(&self) -> Bytes; 
}