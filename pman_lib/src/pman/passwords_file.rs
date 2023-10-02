use std::sync::Arc;
use crate::crypto::CryptoProcessor;
use crate::pman::id_value_map::IdValueMap;

pub struct PasswordsFile {
    processor: Arc<dyn CryptoProcessor>,
    passwords: IdValueMap<String>
}
