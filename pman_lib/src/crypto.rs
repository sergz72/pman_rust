use aes::Aes256;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::cipher::generic_array::GenericArray;

pub trait CryptoProcessor {
    fn encode(&self, data: [u8;64]) -> [u8;64];
    fn decode(&self, data: &[u8;64]) -> [u8;64];
}

pub struct AesProcessor {
    cipher: Aes256,
    iv: [u8;16]
}

impl CryptoProcessor for AesProcessor {
    fn encode(&self, data: [u8; 64]) -> [u8; 64] {
        let mut out_data = [0u8;64];
        for i in (0..64).step_by(16) {
            let end = i + 16;
            let mut in_data = [0u8; 16];
            in_data.copy_from_slice(&data[i..end]);
            let mut block = GenericArray::from(in_data);
            self.cipher.encrypt_block(&mut block);
            out_data[i..end].copy_from_slice(block.as_slice());
        }
        out_data
    }

    fn decode(&self, data: &[u8; 64]) -> [u8; 64] {
        let mut out_data = [0u8;64];
        for i in (0..64).step_by(16) {
            let end = i + 16;
            let mut in_data = [0u8; 16];
            in_data.copy_from_slice(&data[i..end]);
            let mut block = GenericArray::from(in_data);
            self.cipher.decrypt_block(&mut block);
            out_data[i..end].copy_from_slice(block.as_slice());
        }
        out_data
    }
}

impl AesProcessor {
    pub fn new(key: [u8;32], iv: [u8;16]) -> Box<dyn CryptoProcessor> {
        let k = GenericArray::from(key);
        Box::new(AesProcessor{ cipher: Aes256::new(&k), iv })
    }
}

#[cfg(test)]
mod tests {
    use rand::RngCore;
    use rand::rngs::OsRng;
    use crate::crypto::{AesProcessor, CryptoProcessor};

    #[test]
    fn test_crypto_processors() {
        let mut key = [0u8;32];
        OsRng.fill_bytes(&mut key);
        let mut iv = [0u8;16];
        OsRng.fill_bytes(&mut iv);
        test_crypto_processor(AesProcessor::new(key, iv))
    }

    fn test_crypto_processor(processor: Box<dyn CryptoProcessor>) {
        let mut data = [0u8;64];
        OsRng.fill_bytes(&mut data);
        let encoded = processor.encode(data);
        let decoded = processor.decode(&encoded);
        assert_eq!(decoded, data);
    }
}