use std::io::{Error, ErrorKind, Read, stdin, stdout, Write};
use std::env::args;
use std::fs::File;
use std::sync::Arc;
use std::time::Instant;
use arguments_parser::{Arguments, IntParameter, BoolParameter, Switch, StringParameter, EnumParameter};
use pman_lib::{add_group, add_user, build_argon2_hash, create, get_database_type, get_groups, get_users, lib_init, open, pre_open, prepare, save};
use pman_lib::crypto::AesProcessor;
use pman_lib::pman::id_value_map::id_value_map::IdValueMap;
use pman_lib::pman::id_value_map::id_value_map_s3_handler::IdValueMapS3Handler;
use pman_lib::pman::pman_database_file::ENCRYPTION_ALGORITHM_CHACHA20;
use pman_lib::structs_interfaces::FileAction;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};

const TIME_DEFAULT: isize = 1000;
const PARALLELISM_DEFAULT: isize = 6;
const MEMORY_DEFAULT: isize = 128;

struct Parameters {
    names_file_parameter: StringParameter,
    passwords_file_parameter: StringParameter,
    password_parameter: StringParameter,
    password2_parameter: StringParameter,
    file_name_parameter: StringParameter,
    salt_parameter: StringParameter,
    hash_parameter: EnumParameter,
    hash2_parameter: EnumParameter,
    encryption_parameter: EnumParameter,
    encryption2_parameter: EnumParameter,
    verbose_parameter: BoolParameter,
    create_parameter: BoolParameter,
    argon2_test_parameter: BoolParameter,
    time_parameter: IntParameter,
    parallelism_parameter: IntParameter,
    time2_parameter: IntParameter,
    parallelism2_parameter: IntParameter,
    memory_parameter: IntParameter,
    memory2_parameter: IntParameter,
    iterations_parameter: IntParameter,
    iterations2_parameter: IntParameter,
    s3_path_parameter: StringParameter,
    s3_key_parameter: StringParameter,
    s3_path_parameter1: StringParameter,
    s3_key_parameter1: StringParameter,
    s3_path_parameter2: StringParameter,
    s3_key_parameter2: StringParameter,
    actions_parameter: StringParameter,
    group_names_parameter: StringParameter,
    user_names_parameter: StringParameter,
    entity_names_parameter: StringParameter,
    entity_passwords_parameter: StringParameter,
    entity_groups_parameter: StringParameter,
    entity_users_parameter: StringParameter,
    entity_urls_parameter: StringParameter
}

fn main() -> Result<(), Error> {
    let names_file_parameter = StringParameter::new("local");
    let passwords_file_parameter = StringParameter::new("local");
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
    let s3_path_parameter1 = StringParameter::new("");
    let s3_key_parameter1 = StringParameter::new("");
    let s3_path_parameter2 = StringParameter::new("");
    let s3_key_parameter2 = StringParameter::new("");
    let actions_parameter = StringParameter::new("none");
    let group_names_parameter = StringParameter::new("");
    let user_names_parameter = StringParameter::new("");
    let entity_names_parameter = StringParameter::new("");
    let entity_passwords_parameter = StringParameter::new("");
    let entity_groups_parameter = StringParameter::new("");
    let entity_users_parameter = StringParameter::new("");
    let entity_urls_parameter = StringParameter::new("");
    let parameters = Parameters{
        names_file_parameter,
        passwords_file_parameter,
        password_parameter,
        password2_parameter,
        file_name_parameter,
        salt_parameter,
        hash_parameter,
        hash2_parameter,
        encryption_parameter,
        encryption2_parameter,
        verbose_parameter,
        create_parameter,
        argon2_test_parameter,
        time_parameter,
        parallelism_parameter,
        time2_parameter,
        parallelism2_parameter,
        memory_parameter,
        memory2_parameter,
        iterations_parameter,
        iterations2_parameter,
        s3_path_parameter,
        s3_key_parameter,
        s3_path_parameter1,
        s3_key_parameter1,
        s3_path_parameter2,
        s3_key_parameter2,
        actions_parameter,
        group_names_parameter,
        user_names_parameter,
        entity_names_parameter,
        entity_passwords_parameter,
        entity_groups_parameter,
        entity_users_parameter,
        entity_urls_parameter
    };
    let switches = [
        Switch::new("action", None, Some("actions"),
                    &parameters.actions_parameter),
        Switch::new("first password", None, Some("pw"),
                    &parameters.password_parameter),
        Switch::new("second password", None, Some("pw2"),
                    &parameters.password2_parameter),
        Switch::new("password hash algorithm", Some('h'), None,
                    &parameters.hash_parameter),
        Switch::new("second password hash algorithm", None, Some("h2"),
                    &parameters.hash2_parameter),
        Switch::new("verbose", Some('v'), None, &parameters.verbose_parameter),
        Switch::new("create mode", Some('c'), None, &parameters.create_parameter),
        Switch::new("argon2 test mode", None, Some("argon2-test"), &parameters.argon2_test_parameter),
        Switch::new("s3 path for s3 test", None, Some("s3-path"), &parameters.s3_path_parameter),
        Switch::new("s3 key file for s3 test", None, Some("s3-key"), &parameters.s3_key_parameter),
        Switch::new("s3 path for names file", None, Some("s3-path1"), &parameters.s3_path_parameter1),
        Switch::new("s3 key file for names file", None, Some("s3-key1"), &parameters.s3_key_parameter1),
        Switch::new("s3 path for passwords file", None, Some("s3-path1"), &parameters.s3_path_parameter2),
        Switch::new("s3 key file for passwords file", None, Some("s3-key1"), &parameters.s3_key_parameter2),
        Switch::new("encryption algorithm for names file", Some('e'), None,
                    &parameters.encryption_parameter),
        Switch::new("encryption algorithm for passwords file", None, Some("e2"),
                    &parameters.encryption2_parameter),
        Switch::new("hash build time in ms for first hash algorithm", Some('t'),
                    None, &parameters.time_parameter),
        Switch::new("hash build time in ms of iterations for second hash algorithm", None,
                    Some("t2"), &parameters.time2_parameter),
        Switch::new("parallelism for first hash algorithm", Some('p'),
                    None, &parameters.parallelism_parameter),
        Switch::new("parallelism for second hash algorithm", None,
                    Some("p2"), &parameters.parallelism2_parameter),
        Switch::new("iterations for first hash algorithm", Some('i'),
                    None, &parameters.iterations_parameter),
        Switch::new("iterations for second hash algorithm", None,
                    Some("i2"), &parameters.iterations2_parameter),
        Switch::new("memory size in Mb for first hash algorithm", Some('m'),
                    None, &parameters.memory_parameter),
        Switch::new("memory size in Mb for second hash algorithm", None,
                    Some("m2"), &parameters.memory2_parameter),
        Switch::new("names file location", None, Some("nf"),
                    &parameters.names_file_parameter),
        Switch::new("passwords_file_location", None, Some("pf"),
                    &parameters.passwords_file_parameter),
        Switch::new("file name", Some('f'), None,
                    &parameters.file_name_parameter),
        Switch::new("salt for hash algorithm test", None, Some("salt"),
                    &parameters.salt_parameter),
        Switch::new("group names", None, Some("group-names"),
                    &parameters.group_names_parameter),
        Switch::new("user names", None, Some("user-names"),
                    &parameters.user_names_parameter),
        Switch::new("entity names", None, Some("entity-names"),
                    &parameters.entity_names_parameter),
        Switch::new("entity passwords", None, Some("entity-passwords"),
                    &parameters.entity_passwords_parameter),
        Switch::new("entity groups", None, Some("entity-groups"),
                    &parameters.entity_groups_parameter),
        Switch::new("entity users", None, Some("entity-users"),
                    &parameters.entity_users_parameter),
        Switch::new("entity urls", None, Some("entity-urls"),
                    &parameters.entity_urls_parameter)
    ];
    let mut arguments = Arguments::new("pman_console", &switches, None);
    if let Err(e) = arguments.build(args().skip(1).collect()) {
        println!("{}", e);
        arguments.usage();
        return Ok(());
    }
    if parameters.argon2_test_parameter.get_value() {
        let password = get_password("password", &parameters.password_parameter)?;
        let salt_string = parameters.salt_parameter.get_value();
        let salt = salt_string.as_bytes();
        if salt.len() != 16 {
            println!("salt should have 16 bytes length");
            return Ok(());
        }
        test_argon2(password, parameters.iterations_parameter.get_value(),
                    parameters.parallelism_parameter.get_value(),
                    parameters.memory_parameter.get_value(), salt)
    } else if s3_test(parameters.s3_path_parameter.get_value(),
                      parameters.s3_key_parameter.get_value())? {
        Ok(())
    } else {
        execute_database_operations(parameters)
    }
}

fn execute_database_operations(parameters: Parameters) -> Result<(), Error> {
    let file_name = parameters.file_name_parameter.get_value();
    if file_name == "" {
        println!("file name expected");
        return Ok(());
    }
    let password = get_password("password", &parameters.password_parameter)?;
    let database_type = get_database_type(&file_name)?;
    let password2 = if database_type.requires_second_password() {
        Some(get_password("password2", &parameters.password2_parameter)?)
    } else { None };
    let verbose = parameters.verbose_parameter.get_value();
    let password_hash = create_hash(password);
    let password2_hash = password2.map(|p|create_hash(p));
    lib_init();
    let database = if parameters.create_parameter.get_value() {
        create(database_type, password_hash, password2_hash, None, file_name)
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
    let mut save_database = false;
    for action in parameters.actions_parameter.get_value().split(',') {
        if execute_action(database, action, &parameters, verbose)? {
            save_database = true;
        }
    }
    if save_database {
        for action in save(database)
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))? {
            create_file(action)?;
        }
    }
    Ok(())
}

fn create_file(action: Arc<FileAction>) -> Result<(), Error> {
    let mut f = File::create(&action.file_name)?;
    f.write_all(action.data.as_slice())
}

fn execute_action(database: u64, action: &str, parameters: &Parameters, verbose: bool) -> Result<bool, Error> {
    match action {
        "none" => Ok(false),
        "save" => Ok(true),
        "add_groups" => add_groups(database, parameters.group_names_parameter.get_value()),
        "get_groups" => select_groups(database),
        "get_users" => select_users(database),
        "add_users" => add_users(database, parameters.user_names_parameter.get_value()),
        _ => Err(Error::new(ErrorKind::Unsupported, "unknown action"))
    }
}

fn select_users(database: u64) -> Result<bool, Error> {
    for (_, name) in get_users(database)
        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))? {
        println!("{}", name);
    }
    Ok(false)
}

fn select_groups(database: u64) -> Result<bool, Error> {
    for group in get_groups(database)
        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))? {
        println!("{} {}", group.name, group.entities_count);
    }
    Ok(false)
}

fn add_groups(database: u64, group_names: String) -> Result<bool, Error> {
    for name in parse_string_array(group_names, "group names expected")? {
        add_group(database, name)
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
    }
    Ok(true)
}

fn add_users(database: u64, user_names: String) -> Result<bool, Error> {
    for name in parse_string_array(user_names, "user names expected")? {
        add_user(database, name)
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
    }
    Ok(true)
}

fn parse_string_array(array: String, error_message: &str) -> Result<Vec<String>, Error> {
    if array.is_empty() {
        return Err(Error::new(ErrorKind::InvalidInput, error_message));
    }
    Ok(array.split(',').map(|v|v.to_string()).collect())
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
    stdout().flush()?;
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
