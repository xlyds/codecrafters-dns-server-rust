
pub mod additional;
pub mod answer;
pub mod authority;
pub mod header;
pub mod question;
pub mod byte_order;

#[allow(dead_code)]
pub struct DNSMessage {
	header: header::DNSHeader,
	question: Option<question::DNSQuestion>,
	answer: Option<answer::DNSAnswer>,
	authority: authority::DNSAuthority,
	additional: additional::DNSAdditional,
}
