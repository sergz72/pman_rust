use std::collections::HashMap;
use std::io::{Error, ErrorKind, Read, stdin};
use std::env::args;
use std::fs::File;
use std::time::Instant;
use arguments_parser::{Arguments, IntParameter, BoolParameter, Switch, StringParameter, EnumParameter};
use pman_lib::{build_argon2_hash, create, get_database_type, open, pre_open, prepare};
use pman_lib::crypto::AesProcessor;
use pman_lib::pman::id_value_map::id_value_map::IdValueMap;
use pman_lib::pman::id_value_map::id_value_map_s3_handler::IdValueMapS3Handler;
use pman_lib::pman::pman_database_file::ENCRYPTION_ALGORITHM_CHACHA20;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};

const TIME_DEFAULT: isize = 1000;
const PARALLELISM_DEFAULT: isize = 6;
const MEMORY_DEFAULT: isize = 128;

fn main() -> Result<(), Error> {
    let location_values = HashMap::from([(0, "local".to_string())]);
    let locations: Vec<String> = location_values.values().map(|v|v.clone()).collect();
    let names_file_parameter = EnumParameter::new(locations.clone(), "local");
    let passwords_file_parameter = EnumParameter::new(locations, "local");
    let password_parameter = StringParameter::new("");
    let password2_parameter = StringParameter::new("");
    let file_name_parameter = StringParameter::new("");
    let salt_parameter = StringParameter::new("");
    let hash_values = vec!["argon2".to_string()];
    let hash_parameter = EnumParameter::new(hash_values.clone(), "argon2");
    let hash2_parameter = EnumParameter::new(hash_values, "argon2");
    let encryption_values = vec!["aes".to_string()];
    let encryption_parameter = EnumParameter::new(encryption_values.clone(), "aes");
    let encryption2_parameter = EnumParameter::new(encryption_values, "aes");
    let verbose_parameter = BoolParameter::new();
    let create_parameter = BoolParameter::new();
    let argon2_test_parameter = BoolParameter::new();
    let time_parameter = IntParameter::new(TIME_DEFAULT, |v|v>0);
    let parallelism_parameter = IntParameter::new(PARALLELISM_DEFAULT, |v|v>0&&v<256);
    let time2_parameter = IntParameter::new(TIME_DEFAULT, |v|v>0);
    let parallelism2_parameter = IntParameter::new(PARALLELISM_DEFAULT, |v|v>0&&v<256);
    let memory_parameter = IntParameter::new(MEMORY_DEFAULT, |v|v>0);
    let memory2_parameter = IntParameter::new(MEMORY_DEFAULT, |v|v>0);
    let iterations_parameter = IntParameter::new(0, |v|v>=0);
    let iterations2_parameter = IntParameter::new(0, |v|v>=0);
    let s3_path_parameter = StringParameter::new("");
    let s3_key_parameter = StringParameter::new("");
    let switches = [
        Switch::new("first password", None, Some("pw"),
                    &password_parameter),
        Switch::new("second password", None, Some("pw2"),
                    &password2_parameter),
        Switch::new("password hash algorithm", Some('h'), None,
                    &hash_parameter),
        Switch::new("second password hash algorithm", None, Some("h2"),
                    &hash2_parameter),
        Switch::new("verbose", Some('v'), None, &verbose_parameter),
        Switch::new("create mode", Some('c'), None, &create_parameter),
        Switch::new("argon2 test mode", None, Some("argon2-test"), &argon2_test_parameter),
        Switch::new("s3 path for s3 test", None, Some("s3-path"), &s3_path_parameter),
        Switch::new("s3 key file for s3 test", None, Some("s3-key"), &s3_key_parameter),
        Switch::new("encryption algorithm for names file", Some('e'), None,
                    &encryption_parameter),
        Switch::new("encryption algorithm for passwords file", None, Some("e2"),
                    &encryption2_parameter),
        Switch::new("hash build time in ms for first hash algorithm", Some('t'),
                    None, &time_parameter),
        Switch::new("hash build time in ms of iterations for second hash algorithm", None,
                    Some("t2"), &time2_parameter),
        Switch::new("parallelism for first hash algorithm", Some('p'),
                    None, &parallelism_parameter),
        Switch::new("parallelism for second hash algorithm", None,
                    Some("p2"), &parallelism2_parameter),
        Switch::new("iterations for first hash algorithm", Some('i'),
                    None, &iterations_parameter),
        Switch::new("iterations for second hash algorithm", None,
                    Some("i2"), &iterations2_parameter),
        Switch::new("memory size in Mb for first hash algorithm", Some('m'),
                    None, &memory_parameter),
        Switch::new("memory size in Mb for second hash algorithm", None,
                    Some("m2"), &memory2_parameter),
        Switch::new("names file location", None, Some("nf"),
                    &names_file_parameter),
        Switch::new("passwords_file_location", None, Some("pf"),
                    &passwords_file_parameter),
        Switch::new("file name", Some('f'), None,
                    &file_name_parameter),
        Switch::new("salt for hash algorithm test", None, Some("salt"),
                    &salt_parameter),
    ];
    let mut arguments = Arguments::new("pman_console", &switches, None);
    if let Err(e) = arguments.build(args().skip(1).collect()) {
        println!("{}", e);
        arguments.usage();
        return Ok(());
    }
    if argon2_test_parameter.get_value() {
        let password = get_password("password", &password_parameter)?;
        let salt_string = salt_parameter.get_value();
        let salt = salt_string.as_bytes();
        if salt.len() != 16 {
            println!("salt should have 16 bytes length");
            return Ok(());
        }
        test_argon2(password, iterations_parameter.get_value(), parallelism_parameter.get_value(),
                    memory_parameter.get_value(), salt)
    } else if s3_test(s3_path_parameter.get_value(), s3_key_parameter.get_value())? {
        Ok(())
    } else {
        let password = get_password("password", &password_parameter)?;
        let file_name = file_name_parameter.get_value();
        if file_name == "" {
            println!("file name expected");
            return Ok(());
        }
        let database_type = get_database_type(&file_name)?;
        let password2 = if database_type.requires_second_password() {
            Some(get_password("password2", &password2_parameter)?)
        } else { None };
        let verbose = verbose_parameter.get_value();
        let password_hash = create_hash(password);
        let password2_hash = password2.map(|p|create_hash(p));
        let database = if create_parameter.get_value() {
            create(database_type, password_hash, password2_hash, None)
                .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?
        } else {
            let mut f = File::open(file_name.clone())?;
            let mut data = Vec::new();
            f.read_to_end(&mut data)?;
            let id = prepare(data, file_name)
                .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
            let files =
                pre_open(id, password_hash, password2_hash, None)
                    .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
            let data = load_files(files)?;
            open(id, data)
                .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
            id
        };
        Ok(())
    }
}

fn s3_test(s3_path: String, s3_key: String) -> Result<bool, Error> {
    if s3_path.is_empty() && s3_key.is_empty() {
        return Ok(false);
    }
    if s3_path.is_empty() || s3_key.is_empty() {
        return Err(Error::new(ErrorKind::InvalidInput, "s3-path & s3-key must be provided"));
    }
    let location_data = build_location_data(s3_path, s3_key)?;
    let handler = IdValueMapS3Handler::new(location_data.clone())?;
    let mut key = [0u8;32];
    OsRng.fill_bytes(&mut key);
    let mut map = IdValueMap::new(AesProcessor::new(key), vec![Box::new(handler)])?;
    let v = "12345".to_string();
    let k = map.add(v.clone())?;
    let mut key2 = [0u8;32];
    OsRng.fill_bytes(&mut key2);
    map.save(None, Some(ENCRYPTION_ALGORITHM_CHACHA20), Some(key2))?;
    let handler2 = IdValueMapS3Handler::load(location_data, key2, ENCRYPTION_ALGORITHM_CHACHA20)?;
    let mut map2 = IdValueMap::new(AesProcessor::new(key), vec![Box::new(handler2)])?;
    let v2: String = map2.get(k)?;
    println!("{} {}", v, v2);
    Ok(true)
}

fn build_location_data(s3_path: String, s3_key: String) -> Result<Vec<u8>, Error> {
    let data = load_file(s3_key)?;
    let mut result = Vec::new();
    let bytes = s3_path.as_bytes();
    result.push(bytes.len() as u8);
    result.extend_from_slice(bytes);
    result.push(data.len() as u8);
    result.extend_from_slice(&data);
    Ok(result)
}

fn load_file(file_name: String) -> Result<Vec<u8>, Error> {
    let mut f = File::open(file_name)?;
    let mut data = Vec::new();
    f.read_to_end(&mut data)?;
    Ok(data)
}

fn load_files(file_names: Vec<String>) -> Result<Vec<Vec<u8>>, Error> {
    let mut result = Vec::new();
    for file_name in file_names {
        result.push(load_file(file_name)?);
    }
    Ok(result)
}

fn test_argon2(password: String, iterations: isize, parallelism: isize, memory: isize, salt: &[u8]) -> Result<(), Error> {
    let mut s = [0u8; 16];
    s.copy_from_slice(salt);
    let start = Instant::now();
    let hash = build_argon2_hash((password+"\n").into_bytes(), iterations, parallelism, memory, s)?;
    let duration = start.elapsed();
    println!("Iterations: {}\nParallelism: {}\nMemory: {}Mb\nSalt: {:x?}\nHash: {:x?}\nTime: {}ms", iterations,
             parallelism, memory, s, hash, duration.as_millis());
    Ok(())
}

fn get_password(prompt: &str, password_parameter: &StringParameter) -> Result<String, Error> {
    let password = password_parameter.get_value();
    if !password.is_empty() {
        return Ok(password);
    }
    let mut buffer = String::new();
    print!("{}: ", prompt);
    stdin().read_line(&mut buffer)?;
    if buffer.is_empty() {
        return Err(Error::new(ErrorKind::InvalidInput, "empty password"));
    }
    Ok(buffer)
}

fn create_hash(password: String) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(password);
    let hash = hasher.finalize();
    Vec::from(hash.as_slice())
}
