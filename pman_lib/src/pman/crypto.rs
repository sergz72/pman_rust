pub trait CryptoProcessor {
    fn encode(&self, data: [u8;64]) -> [u8;64];
    fn decode(&self, data: &[u8;64]) -> [u8;64];
}

pub struct AesProcessor {

}

impl CryptoProcessor for AesProcessor {

}