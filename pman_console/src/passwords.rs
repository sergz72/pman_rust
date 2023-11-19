use std::fs::File;
use std::io::{Error, ErrorKind, Write};
use sha2::{Sha256, Digest};
use aes::Aes256;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::cipher::generic_array::GenericArray;
use pman_lib::structs_interfaces::PasswordDatabaseType;
use crate::{get_password, Parameters};
use crate::entity_actions::get_entity_password;
use crate::utils::load_file;

fn build_cipher(password: String) -> Result<Aes256, Error> {
    let key = get_password("key", password)?;
    let key_hash = create_hash(key);
    let mut k = [0u8; 32];
    k.copy_from_slice(key_hash.as_slice());
    let key = GenericArray::from(k);
    let cipher = Aes256::new(&key);
    Ok(cipher)
}

fn create_encrypted_hash(password: String, cipher: &Aes256) -> Vec<u8> {
    let h = create_hash(password);
    let password_hash = h.as_slice();
    let mut ph = [0u8; 16];
    ph.copy_from_slice(&password_hash[0..16]);
    let mut block1 = GenericArray::from(ph);
    cipher.encrypt_block(&mut block1);
    ph.copy_from_slice(&password_hash[16..32]);
    let mut block2 = GenericArray::from(ph);
    cipher.encrypt_block(&mut block2);
    let mut v = block1.to_vec();
    v.extend_from_slice(&block2.as_slice());
    v
}

fn create_key_file_data(key: String, password: String, password2: String) -> Result<Vec<u8>, Error> {
    let cipher = build_cipher(key)?;
    let mut password_hash = create_encrypted_hash(password, &cipher);
    let password2_hash = create_encrypted_hash(password2, &cipher);
    password_hash.extend_from_slice(&password2_hash);
    Ok(password_hash)
}

pub fn create_key_file(parameters: Parameters) -> Result<(), Error> {
    let file_name = parameters.key_file_parameter.get_value();
    if file_name == "" {
        println!("key file name expected");
        return Ok(());
    }
    let password = get_password("password", parameters.password_parameter.get_value())?;
    let password2 = get_password("password2", parameters.password2_parameter.get_value())?;
    let data = create_key_file_data("".to_string(), password, password2)?;
    let mut f = File::create(file_name)?;
    f.write_all(&data)
}

pub fn generate_password_command(rules: String) -> Result<bool, Error> {
    if rules.is_empty() {
        return Ok(false);
    }
    let _ = get_entity_password(rules, 0)?;
    return Ok(true);
}

pub fn build_password_hashes(database_type: &PasswordDatabaseType, parameters: &Parameters)
                         -> Result<(Vec<u8>, Option<Vec<u8>>), Error> {
    let password = get_password("password", parameters.password_parameter.get_value())?;
    let password2 = if database_type.requires_second_password() {
        Some(get_password("password2", parameters.password2_parameter.get_value())?)
    } else { None };
    let password_hash = create_hash(password);
    let password2_hash = password2.map(|p|create_hash(p));
    Ok((password_hash, password2_hash))
}

pub fn build_password_hashes_from_key_file(file_name: String) -> Result<(Vec<u8>, Option<Vec<u8>>), Error> {
    let data = load_file(file_name)?;
    build_password_hashes_from_data(data, "".to_string())
}

fn build_password_hashes_from_data(data: Vec<u8>, key: String) -> Result<(Vec<u8>, Option<Vec<u8>>), Error> {
    if data.len() != 64 {
        return Err(Error::new(ErrorKind::InvalidData, "wrong key file length"));
    }
    let cipher = build_cipher(key)?;
    let d = data.as_slice();
    let mut ph = [0u8; 16];

    ph.copy_from_slice(&d[0..16]);
    let mut block1 = GenericArray::from(ph);
    cipher.decrypt_block(&mut block1);

    ph.copy_from_slice(&d[16..32]);
    let mut block2 = GenericArray::from(ph);
    cipher.decrypt_block(&mut block2);

    ph.copy_from_slice(&d[32..48]);
    let mut block3 = GenericArray::from(ph);
    cipher.decrypt_block(&mut block3);

    ph.copy_from_slice(&d[48..64]);
    let mut block4 = GenericArray::from(ph);
    cipher.decrypt_block(&mut block4);

    let mut v1 = block1.to_vec();
    v1.extend_from_slice(block2.as_slice());

    let mut v2 = block3.to_vec();
    v2.extend_from_slice(block4.as_slice());

    Ok((v1, Some(v2)))
}

fn create_hash(password: String) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(password);
    let hash = hasher.finalize();
    Vec::from(hash.as_slice())
}

#[cfg(test)]
mod tests {
    use std::io::Error;
    use crate::passwords::{build_password_hashes_from_data, create_hash, create_key_file_data};

    #[test]
    fn test_key_file() -> Result<(), Error> {
        let key = "12345".to_string();
        let password = "2131415".to_string();
        let password_hash = create_hash(password.clone());
        let password2 = "9876543".to_string();
        let password2_hash = create_hash(password2.clone());
        let data =
            create_key_file_data(key.clone(), password, password2)?;
        let (h1, h2) = build_password_hashes_from_data(data, key)?;
        assert!(h2.is_some());
        assert_eq!(password_hash, h1);
        assert_eq!(password2_hash, h2.unwrap());
        Ok(())
    }
}