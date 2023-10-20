use std::cmp::min;
use std::io::Error;
use std::sync::Arc;
use aes::Aes256;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::cipher::generic_array::GenericArray;
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use rand::RngCore;
use rand::rngs::OsRng;
use crate::error_builders::{build_corrupted_data_error, build_unsupported_error};

pub trait CryptoProcessor {
    fn encode(&self, data: Vec<u8>) -> Result<Vec<u8>, Error>;
    fn decode(&self, data: &Vec<u8>) -> Result<Vec<u8>, Error>;
    fn encode_bytes(&self, data: &mut [u8]) -> Result<(), Error>;
    fn decode_bytes(&self, data: &mut [u8]) -> Result<(), Error>;
}

pub struct AesProcessor {
    cipher: Aes256
}

impl CryptoProcessor for AesProcessor {
    fn encode(&self, data: Vec<u8>) -> Result<Vec<u8>, Error> {
        let mut out_data = Vec::new();
        let mut l = data.len();
        let mut idx = 0;
        while idx < data.len() {
            let mut in_data = [0u8; 16];
            OsRng.fill_bytes(&mut in_data);
            if idx == 0 {
                let bytes = (l as u32).to_le_bytes();
                in_data[7..11].copy_from_slice(&bytes);
                let size = min(l, 5);
                in_data[11..11+size].copy_from_slice(&data[0..size]);
                idx = size;
                l -= size;
            } else {
                let size = min(l, 9);
                in_data[7..7+size].copy_from_slice(&data[idx..idx+size]);
                idx += size;
                l -= size;
            }
            let mut block = GenericArray::from(in_data);
            self.cipher.encrypt_block(&mut block);
            out_data.extend_from_slice(block.as_slice())
        }
        Ok(out_data)
    }

    fn decode(&self, data: &Vec<u8>) -> Result<Vec<u8>, Error> {
        let mut out_data = Vec::new();
        let mut out_length = 0;
        for i in (0..data.len()).step_by(16) {
            let end = i + 16;
            let mut in_data = [0u8; 16];
            in_data.copy_from_slice(&data[i..end]);
            let mut block = GenericArray::from(in_data);
            self.cipher.decrypt_block(&mut block);
            let sl = block.as_slice();
            if i == 0 {
                let mut buffer32 = [0u8; 4];
                buffer32.copy_from_slice(&sl[7..11]);
                out_length = u32::from_le_bytes(buffer32) as usize;
                let size = min(out_length, 5);
                out_data.extend_from_slice(&sl[11..11+size]);
                out_length -= size;
            } else {
                if out_length == 0 {
                    return Err(build_corrupted_data_error())
                }
                let size = min(out_length, 9);
                out_data.extend_from_slice(&sl[7..7+size]);
                out_length -= size;
            }
        }
        if out_length != 0 {
            return Err(build_corrupted_data_error())
        }
        Ok(out_data)
    }

    fn encode_bytes(&self, _data: &mut [u8]) -> Result<(), Error> {
        Err(build_unsupported_error())
    }

    fn decode_bytes(&self, _data: &mut [u8]) -> Result<(), Error> {
        Err(build_unsupported_error())
    }
}

impl AesProcessor {
    pub fn new(key: [u8;32]) -> Arc<dyn CryptoProcessor> {
        let k = GenericArray::from(key);
        Arc::new(AesProcessor{ cipher: Aes256::new(&k) })
    }
}

pub struct NoEncryptionProcessor {
}

impl CryptoProcessor for NoEncryptionProcessor {
    fn encode(&self, data: Vec<u8>) -> Result<Vec<u8>, Error> {
        Ok(data)
    }

    fn decode(&self, data: &Vec<u8>) -> Result<Vec<u8>, Error> {
        Ok(data.clone())
    }

    fn encode_bytes(&self, _data: &mut [u8]) -> Result<(), Error> {
        Ok(())
    }

    fn decode_bytes(&self, _data: &mut [u8]) -> Result<(), Error> {
        Ok(())
    }
}

impl NoEncryptionProcessor {
    pub fn new() -> Arc<dyn CryptoProcessor> {
        Arc::new(NoEncryptionProcessor{})
    }
}

pub struct ChachaProcessor {
    key: [u8; 32],
    iv: [u8; 12]
}

impl CryptoProcessor for ChachaProcessor {
    fn encode(&self, _data: Vec<u8>) -> Result<Vec<u8>, Error> {
        Err(build_unsupported_error())
    }

    fn decode(&self, _data: &Vec<u8>) -> Result<Vec<u8>, Error> {
        Err(build_unsupported_error())
    }

    fn encode_bytes(&self, data: &mut [u8]) -> Result<(), Error> {
        let mut cipher = ChaCha20::new((&self.key).into(), (&self.iv).into());
        cipher.apply_keystream(data);
        Ok(())
    }

    fn decode_bytes(&self, data: &mut [u8]) -> Result<(), Error> {
        let mut cipher = ChaCha20::new((&self.key).into(), (&self.iv).into());
        cipher.apply_keystream(data);
        Ok(())
    }
}

impl ChachaProcessor {
    pub fn new(key: [u8; 32], iv: [u8; 12]) -> Arc<dyn CryptoProcessor> {
        Arc::new(ChachaProcessor{key, iv})
    }
}

#[cfg(test)]
mod tests {
    use std::io::Error;
    use std::sync::Arc;
    use rand::RngCore;
    use rand::rngs::OsRng;
    use crate::crypto::{AesProcessor, ChachaProcessor, CryptoProcessor};

    #[test]
    fn test_crypto_processors() -> Result<(), Error> {
        let mut key = [0u8;32];
        OsRng.fill_bytes(&mut key);
        let mut iv = [0u8;12];
        OsRng.fill_bytes(&mut iv);
        test_crypto_processor(AesProcessor::new(key.clone()))?;
        test_crypto_processor2(ChachaProcessor::new(key, iv))
    }

    fn test_crypto_processor(processor: Arc<dyn CryptoProcessor>) -> Result<(), Error> {
        let mut data = [0u8;64];
        OsRng.fill_bytes(&mut data);
        let encoded = processor.encode(data.to_vec())?;
        let decoded = processor.decode(&encoded)?;
        assert_eq!(decoded, data.to_vec());

        let mut data2 = [0u8;5];
        OsRng.fill_bytes(&mut data2);
        let encoded2 = processor.encode(data2.to_vec())?;
        let decoded2 = processor.decode(&encoded2)?;
        assert_eq!(decoded2, data2.to_vec());
        Ok(())
    }

    fn test_crypto_processor2(processor: Arc<dyn CryptoProcessor>) -> Result<(), Error> {
        let mut data = [0u8;64];
        OsRng.fill_bytes(&mut data);
        let copy = data.clone();
        processor.encode_bytes(&mut data)?;
        processor.decode_bytes(&mut data)?;
        assert_eq!(copy, data);

        let mut data2 = [0u8;5];
        OsRng.fill_bytes(&mut data2);
        let copy2 = data2.clone();
        processor.encode_bytes(&mut data2)?;
        processor.decode_bytes(&mut data2)?;
        assert_eq!(copy2, data2);
        Ok(())
    }
}