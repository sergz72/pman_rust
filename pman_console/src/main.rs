use std::collections::{HashMap, HashSet};
use std::io::{Error, ErrorKind, Read, stdin, stdout, Write};
use std::env::args;
use std::fs::File;
use std::sync::Arc;
use std::time::Instant;
use arguments_parser::{Arguments, IntParameter, BoolParameter, Switch, StringParameter, EnumParameter};
use pman_lib::{add_entity, add_group, add_user, build_argon2_hash, create, DatabaseEntity, get_database_type, get_entities, get_groups, get_users, lib_init, modify_entity, open, pre_open, prepare, remove_entity, save, search, set_argon2};
use pman_lib::crypto::AesProcessor;
use pman_lib::pman::data_file::build_s3_location_data;
use pman_lib::pman::database_entity::ENTITY_VERSION_LATEST;
use pman_lib::pman::id_value_map::id_value_map::IdValueMap;
use pman_lib::pman::id_value_map::id_value_map_s3_handler::IdValueMapS3Handler;
use pman_lib::pman::pman_database_file::ENCRYPTION_ALGORITHM_CHACHA20;
use pman_lib::structs_interfaces::{DatabaseGroup, FileAction, PasswordDatabaseType};
use rand::{Rng, RngCore};
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};
use aes::Aes256;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};

const TIME_DEFAULT: isize = 1000;
const PARALLELISM_DEFAULT: isize = 6;
const MEMORY_DEFAULT: isize = 128;

const LETTER_TABLE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const NUMBER_TABLE: &str = "0123456789";
const SYMBOL_TABLE: &str = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

struct Parameters {
    names_file_parameter: StringParameter,
    passwords_file_parameter: StringParameter,
    password_parameter: StringParameter,
    password2_parameter: StringParameter,
    file_name_parameter: StringParameter,
    hash_parameter: EnumParameter,
    hash2_parameter: EnumParameter,
    encryption_parameter: EnumParameter,
    encryption2_parameter: EnumParameter,
    verbose_parameter: BoolParameter,
    create_parameter: BoolParameter,
    time_parameter: IntParameter,
    parallelism_parameter: IntParameter,
    time2_parameter: IntParameter,
    parallelism2_parameter: IntParameter,
    memory_parameter: IntParameter,
    memory2_parameter: IntParameter,
    iterations_parameter: IntParameter,
    iterations2_parameter: IntParameter,
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
    entity_urls_parameter: StringParameter,
    entity_properties_parameter: StringParameter,
    key_file_parameter: StringParameter
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
    let key_create_parameter = BoolParameter::new();
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
    let entity_properties_parameter = StringParameter::new("");
    let generate_password_parameter = StringParameter::new("");
    let key_file_parameter = StringParameter::new("");
    let parameters = Parameters{
        names_file_parameter,
        passwords_file_parameter,
        password_parameter,
        password2_parameter,
        file_name_parameter,
        hash_parameter,
        hash2_parameter,
        encryption_parameter,
        encryption2_parameter,
        verbose_parameter,
        create_parameter,
        time_parameter,
        parallelism_parameter,
        time2_parameter,
        parallelism2_parameter,
        memory_parameter,
        memory2_parameter,
        iterations_parameter,
        iterations2_parameter,
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
        entity_urls_parameter,
        entity_properties_parameter,
        key_file_parameter
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
        Switch::new("argon2 test mode", None, Some("argon2-test"), &argon2_test_parameter),
        Switch::new("key file create", None, Some("key-create"), &key_create_parameter),
        Switch::new("s3 path for s3 test", None, Some("s3-path"), &s3_path_parameter),
        Switch::new("s3 key file for s3 test", None, Some("s3-key"), &s3_key_parameter),
        Switch::new("s3 path for names file", None, Some("s3-path1"), &parameters.s3_path_parameter1),
        Switch::new("s3 key file for names file", None, Some("s3-key1"), &parameters.s3_key_parameter1),
        Switch::new("s3 path for passwords file", None, Some("s3-path2"), &parameters.s3_path_parameter2),
        Switch::new("s3 key file for passwords file", None, Some("s3-key2"), &parameters.s3_key_parameter2),
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
                    &salt_parameter),
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
                    &parameters.entity_urls_parameter),
        Switch::new("entity parameters", None, Some("entity-properties"),
                    &parameters.entity_properties_parameter),
        Switch::new("password generator", None, Some("generate-password"),
                    &generate_password_parameter),
        Switch::new("key file name", None, Some("key-file"),
                    &parameters.key_file_parameter)
    ];
    let mut arguments = Arguments::new("pman_console", &switches, None);
    if let Err(e) = arguments.build(args().skip(1).collect()) {
        println!("{}", e);
        arguments.usage();
        return Ok(());
    }
    if argon2_test_parameter.get_value() {
        let password = get_password("password", parameters.password_parameter.get_value())?;
        let salt_string = salt_parameter.get_value();
        let salt = salt_string.as_bytes();
        if salt.len() != 16 {
            println!("salt should have 16 bytes length");
            return Ok(());
        }
        test_argon2(password, parameters.iterations_parameter.get_value(),
                    parameters.parallelism_parameter.get_value(),
                    parameters.memory_parameter.get_value(), salt)
    } else if key_create_parameter.get_value() {
        create_key_file(parameters)
    } else if s3_test(s3_path_parameter.get_value(),
                      s3_key_parameter.get_value())? ||
        generate_password_command(generate_password_parameter.get_value())? {
        Ok(())
    } else {
        execute_database_operations(parameters)
    }
}

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

fn create_key_file(parameters: Parameters) -> Result<(), Error> {
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

fn generate_password_command(rules: String) -> Result<bool, Error> {
    if rules.is_empty() {
        return Ok(false);
    }
    let _ = get_entity_password(rules, 0)?;
    return Ok(true);
}

fn build_password_hashes(database_type: &PasswordDatabaseType, file_name: &String, parameters: &Parameters)
    -> Result<(Vec<u8>, Option<Vec<u8>>), Error> {
    let password = get_password("password", parameters.password_parameter.get_value())?;
    let password2 = if database_type.requires_second_password() {
        Some(get_password("password2", parameters.password2_parameter.get_value())?)
    } else { None };
    let password_hash = create_hash(password);
    let password2_hash = password2.map(|p|create_hash(p));
    Ok((password_hash, password2_hash))
}

fn build_password_hashes_from_key_file(file_name: String) -> Result<(Vec<u8>, Option<Vec<u8>>), Error> {
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

fn execute_database_operations(parameters: Parameters) -> Result<(), Error> {
    let file_name = parameters.file_name_parameter.get_value();
    if file_name == "" {
        println!("file name expected");
        return Ok(());
    }
    let database_type = get_database_type(&file_name)?;
    let verbose = parameters.verbose_parameter.get_value();
    let (password_hash, password2_hash) =
        if parameters.key_file_parameter.get_value().is_empty() {
        build_password_hashes(&database_type, &file_name, &parameters)?
    } else {
        build_password_hashes_from_key_file(parameters.key_file_parameter.get_value())?
    };
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
        "add_entities" => add_entities(database, parameters),
        "get_entities" => select_entities(database, parameters.group_names_parameter.get_value()),
        "remove_entities" => remove_entities(database, parameters),
        "modify_entities" => modify_entities(database, parameters),
        "set_hash1" => set_hash1(database, parameters),
        "set_hash2" => set_hash2(database, parameters),
        "names_location" => set_names_file_location(database, parameters),
        "passwords_location" => set_passwords_file_location(database, parameters),
        "search" => search_entities(database, parameters),
        "show" => show_entities(database, parameters),
        _ => Err(Error::new(ErrorKind::Unsupported, "unknown action"))
    }
}

fn show_entities(database: u64, parameters: &Parameters) -> Result<bool, Error> {
    let entity_names = get_entity_names(parameters)?;
    let users = get_users(database)
        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
    let (entities, groups) = get_entities_from_names(database, entity_names)?;
    for (_, entity) in entities {
        show_entity(&groups, &users, entity)?;
    }
    Ok(false)
}

fn search_entities(database: u64, parameters: &Parameters) -> Result<bool, Error> {
    let entity_names = get_entity_names(parameters)?;
    let groups: HashMap<u32, String> = get_groups(database)
        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?
        .into_iter()
        .map(|g|(g.id, g.name.clone()))
        .collect();
    for name in entity_names {
        let result = search(database, name)
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
        for (group_id, entities) in result {
            println!("{}:", groups.get(&group_id).unwrap());
            for (_, entity) in entities {
                println!("  {}",
                         entity.get_name()
                             .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?)
            }
        }
    }
    Ok(false)
}

fn set_passwords_file_location(database: u64, parameters: &Parameters) -> Result<bool, Error> {
    match parameters.passwords_file_parameter.get_value().as_str() {
        "local" => pman_lib::set_passwords_file_location_local(database)
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string())),
        "s3" => {
            let s3_path = parameters.s3_path_parameter2.get_value();
            let s3_key = parameters.s3_key_parameter2.get_value();
            if s3_path.is_empty() || s3_key.is_empty() {
                return Err(Error::new(ErrorKind::InvalidInput, "s3-path2 & s3-key2 must be provided"));
            }
            pman_lib::set_passwords_file_location_s3(database, s3_path, load_file(s3_key)?)
                .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))
        },
        _ => Err(Error::new(ErrorKind::InvalidInput, "invalid passwords file location"))
    }
}

fn set_names_file_location(database: u64, parameters: &Parameters) -> Result<bool, Error> {
    match parameters.names_file_parameter.get_value().as_str() {
        "local" => pman_lib::set_names_file_location_local(database)
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string())),
        "s3" => {
            let s3_path = parameters.s3_path_parameter1.get_value();
            let s3_key = parameters.s3_key_parameter1.get_value();
            if s3_path.is_empty() || s3_key.is_empty() {
                return Err(Error::new(ErrorKind::InvalidInput, "s3-path1 & s3-key1 must be provided"));
            }
            pman_lib::set_names_file_location_s3(database, s3_path, load_file(s3_key)?)
                .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))
        },
        _ => Err(Error::new(ErrorKind::InvalidInput, "invalid names file location"))
    }
}

fn set_hash2(database: u64, parameters: &Parameters) -> Result<bool, Error> {
    set_hash(database, 1, parameters.hash2_parameter.get_value(),
    parameters.iterations2_parameter.get_value(),
             parameters.memory2_parameter.get_value(),
             parameters.parallelism2_parameter.get_value())?;
    Ok(true)
}

fn set_hash1(database: u64, parameters: &Parameters) -> Result<bool, Error> {
    set_hash(database, 0, parameters.hash_parameter.get_value(),
             parameters.iterations_parameter.get_value(),
             parameters.memory_parameter.get_value(),
             parameters.parallelism_parameter.get_value())?;
    Ok(true)
}

fn set_hash(database: u64, hash_id: u64, hash_type: String, iterations: isize, memory: isize,
            parallelism: isize) -> Result<(), Error> {
    match hash_type.as_str() {
        "argon2" => set_argon2(database, hash_id, iterations as u64,
                               parallelism as u64, memory as u64)
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string())),
        _ => Err(Error::new(ErrorKind::InvalidInput, "unknown hash type"))
    }
}

fn modify_entities(database: u64, parameters: &Parameters) -> Result<bool, Error> {
    let entity_names = get_entity_names(parameters)?;
    let (entities, _) = get_entities_from_names(database, entity_names)?;
    let l = entities.len();
    let passwords = if !parameters.entity_passwords_parameter.get_value().is_empty() {
        Some(get_entity_passwords(parameters, Some(l))?)
    } else {None};
    let urls = if !parameters.entity_urls_parameter.get_value().is_empty() {
        Some(get_entity_urls(parameters, Some(l))?)
    } else {None};
    let params = if !parameters.entity_properties_parameter.get_value().is_empty() {
        Some(get_entity_parameters(parameters, Some(l))?)
    } else {None};
    for i in 0..l {
        let password = if let Some(pwds) = &passwords {
            Some(get_entity_password(pwds[i].clone(), i)?)
        } else {None};
        let (url, change_url) = if let Some(u) = &urls {
            (u[i].clone(), true)
        } else {(None, false)};
        let (new_properties, modified_properties) =
            if let Some(p) = &params {
            build_property_maps(entities[i].1.clone(), p[i].clone())?
        } else {(HashMap::new(), HashMap::new())};
        modify_entity(database, entities[i].0, None, None,
                      password, url, change_url, new_properties,
                      modified_properties)
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
    }
    Ok(true)
}

fn build_property_maps(entity: Arc<DatabaseEntity>, parameters: HashMap<String, String>)
    -> Result<(HashMap<String, String>, HashMap<u32, Option<String>>), Error> {
    let property_names = entity.get_property_names(ENTITY_VERSION_LATEST)
        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
    let mut new_properties = HashMap::new();
    let mut modified_properties = HashMap::new();
    for (name, value) in parameters {
        if let Some(id) = property_names.get(&name) {
            let v = if value == "None" { None } else { Some(value) };
            modified_properties.insert(*id, v);
        } else {
            new_properties.insert(name, value);
        }
    }
    Ok((new_properties, modified_properties))
}

fn remove_entities(database: u64, parameters: &Parameters) -> Result<bool, Error> {
    let entity_names = get_entity_names(parameters)?;
    let (entities, _) = get_entities_from_names(database, entity_names)?;
    for (entity_id, _) in entities {
        remove_entity(database, entity_id)
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
    }
    Ok(true)
}

fn get_entities_from_names(database: u64, entity_names: Vec<String>)
    -> Result<(Vec<(u32, Arc<DatabaseEntity>)>, Vec<Arc<DatabaseGroup>>), Error> {
    let names_set: HashSet<String> = entity_names.into_iter().collect();
    let groups = get_groups(database)
        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
    let mut entities = Vec::new();
    for group in &groups {
        for (id, entity) in get_entities(database, group.id)
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?{
            if names_set.contains(&entity.get_name().map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?) {
                entities.push((id, entity));
            }
        }
    }
    Ok((entities, groups))
}

fn get_entity_names(parameters: &Parameters) -> Result<Vec<String>, Error> {
    parse_string_array(parameters.entity_names_parameter.get_value(),
                       "entity names expected", None)
}

fn get_entity_passwords(parameters: &Parameters, l: Option<usize>) -> Result<Vec<String>, Error> {
    parse_string_array(parameters.entity_passwords_parameter.get_value(),
                       "entity passwords expected", l)
}

fn get_entity_urls(parameters: &Parameters, l: Option<usize>) -> Result<Vec<Option<String>>, Error> {
    let urls = parse_string_array(parameters.entity_urls_parameter.get_value(),
                                  "entity urls expected", l)?;
    Ok(urls.into_iter().map(|u|if u == "None" {None} else {Some(u)}).collect())
}

fn get_entity_parameters(parameters: &Parameters, l: Option<usize>) -> Result<Vec<HashMap<String, String>>, Error> {
    let params = parse_string_array(parameters.entity_properties_parameter.get_value(),
                                  "entity parameters expected", l)?;
    let mut result = Vec::new();
    for p in params {
        let mut entity_parameters = HashMap::new();
        if p != "None" {
            for part in p.split(';') {
                let namevalue: Vec<String> = part.split(':').map(|e| e.to_string()).collect();
                if namevalue.len() != 2 {
                    return Err(Error::new(ErrorKind::InvalidInput, "invalid parameters"));
                }
                let value = if namevalue[1] == "Ask" {
                    get_password(format!("value for parameter {}", namevalue[0]).as_str(), "".to_string())?
                } else {namevalue[1].clone()};
                entity_parameters.insert(namevalue[0].clone(), value);
            }
        }
        result.push(entity_parameters);
    }
    Ok(result)
}

fn get_entity_password(password: String, i: usize) -> Result<String, Error> {
    if password == "Ask" {
        get_password(format!("password for entity {}", i).as_str(), "".to_string())
    } else if password.starts_with("gen") && password.len() > 5 {
        Ok(generate_password(password))
    } else {Ok(password)}
}

fn generate_password(rules: String) -> String {
    let l = rules.len();
    if let Ok(length) = rules[l-2..l].parse::<usize>() {
        let mut table = String::new();
        for c in rules[3..l-2].chars() {
            match c {
                'a' => table += LETTER_TABLE,
                '1' => table += NUMBER_TABLE,
                '@' => table += SYMBOL_TABLE,
                _ => return rules
            }
        }
        let chars: Vec<char> = table.chars().collect();
        let mut result = String::new();
        let mut rng = rand::thread_rng();
        for _ in 0..length {
            let idx = rng.gen_range(0..chars.len());
            result.push(chars[idx]);
        }
        println!("Generated password: {}", result);
        return result;
    }
    rules
}

fn add_entities(database: u64, parameters: &Parameters) -> Result<bool, Error> {
    let entity_names = get_entity_names(parameters)?;
    let l = Some(entity_names.len());
    let entity_groups =
        parse_string_array(parameters.entity_groups_parameter.get_value(), "entity groups expected", l)?;
    let entity_users =
        parse_string_array(parameters.entity_users_parameter.get_value(), "entity users expected", l)?;
    let entity_passwords = get_entity_passwords(parameters, l)?;
    let entity_urls = get_entity_urls(parameters, l)?;
    let params = if !parameters.entity_properties_parameter.get_value().is_empty() {
        Some(get_entity_parameters(parameters, l)?)
    } else {None};
    let groups: HashMap<String, u32> = get_groups(database)
        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?
        .into_iter()
        .map(|g|(g.name.clone(), g.id))
        .collect();
    let users: HashMap<String, u32> = get_users(database)
        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?
        .into_iter()
        .map(|(k, v)|(v, k))
        .collect();
    let mut entity_group_ids = Vec::new();
    let mut entity_user_ids = Vec::new();
    for i in 0..l.unwrap() {
        let group_id = *groups.get(&entity_groups[i]).ok_or(Error::new(ErrorKind::NotFound, "group not found"))?;
        let user_id = *users.get(&entity_users[i]).ok_or(Error::new(ErrorKind::NotFound, "user not found"))?;
        entity_group_ids.push(group_id);
        entity_user_ids.push(user_id);
    }
    for i in 0..l.unwrap() {
        let password = get_entity_password(entity_passwords[i].clone(), i)?;
        let properties = if let Some(p) = &params {
            p[i].clone()
        } else { HashMap::new() };
        add_entity(database, entity_names[i].clone(), entity_group_ids[i],
                   entity_user_ids[i], password, entity_urls[i].clone(), properties)
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
    }
    Ok(true)
}

fn show_entity(groups: &Vec<Arc<DatabaseGroup>>, users: &HashMap<u32, String>,
               entity: Arc<DatabaseEntity>) -> Result<(), Error> {
    println!("Name: {}", entity.get_name()
        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?);
    let group_id = entity.get_group_id(ENTITY_VERSION_LATEST)
        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
    let group = groups.iter()
        .find(|g|g.id == group_id).unwrap().name.clone();
    println!("Group: {}", group);
    let user_id = entity.get_user_id(ENTITY_VERSION_LATEST)
        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
    println!("User: {}", users.get(&user_id).unwrap().clone());
    let url = entity.get_url(ENTITY_VERSION_LATEST)
        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?
        .unwrap_or("None".to_string());
    println!("Url: {}", url);
    println!("Password: {}", entity.get_password(ENTITY_VERSION_LATEST)
        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?);
    println!("Properties:");
    for (name, id) in entity.get_property_names(ENTITY_VERSION_LATEST)
        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))? {
        let value = entity.get_property_value(ENTITY_VERSION_LATEST, id)
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
        println!("{}:{}", name, value);
    }
    println!("-------------------------------------");
    Ok(())
}

fn select_entities(database: u64, group_names: String) -> Result<bool, Error> {
    let groups = get_groups(database)
        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
    let users = get_users(database)
        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
    for name in parse_string_array(group_names, "group names expected", None)? {
        let group = groups.iter()
            .find(|g|g.name == name)
            .ok_or(Error::new(ErrorKind::NotFound, "group not found"))?;
        for (_, entity) in get_entities(database, group.id)
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))? {
            show_entity(&groups, &users, entity)?;
        }
    }
    Ok(false)
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
    for name in parse_string_array(group_names, "group names expected", None)? {
        add_group(database, name)
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
    }
    Ok(true)
}

fn add_users(database: u64, user_names: String) -> Result<bool, Error> {
    for name in parse_string_array(user_names, "user names expected", None)? {
        add_user(database, name)
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
    }
    Ok(true)
}

fn parse_string_array(array: String, error_message: &str, expected_count: Option<usize>) -> Result<Vec<String>, Error> {
    if array.is_empty() {
        return Err(Error::new(ErrorKind::InvalidInput, error_message));
    }
    let result: Vec<String> = array.split(',').map(|v|v.to_string()).collect();
    if let Some(count) = expected_count {
        if result.len() != count {
            return Err(Error::new(ErrorKind::InvalidInput,
                                  format!("{} items in {}", count, error_message)));
        }
    }
    Ok(result)
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
    build_s3_location_data(&mut result, s3_path, data);
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

fn get_password(prompt: &str, password: String) -> Result<String, Error> {
    if !password.is_empty() {
        return Ok(password);
    }
    let mut buffer = String::new();
    print!("{}: ", prompt);
    stdout().flush()?;
    stdin().read_line(&mut buffer)?;
    buffer = buffer.trim().to_string();
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

#[cfg(test)]
mod tests {
    use std::io::Error;
    use crate::{build_password_hashes_from_data, create_hash, create_key_file_data};

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