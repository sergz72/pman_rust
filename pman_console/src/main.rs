mod entity_actions;
mod groups_users_actions;
mod passwords;
mod db_properties;
mod utils;

use std::collections::HashMap;
use std::io::{Error, ErrorKind, Read};
use std::env::args;
use std::fs::File;
use std::time::Instant;
use arguments_parser::{Arguments, IntParameter, BoolParameter, Switch, StringParameter, EnumParameter};
use pman_lib::{build_argon2_hash, create, get_database_type, lib_init, open, pre_open, prepare, save};
use pman_lib::crypto::AesProcessor;
use pman_lib::pman::data_file::build_qs3_location_data;
use pman_lib::pman::id_value_map::id_value_map::IdValueMap;
use pman_lib::pman::pman_database_file::ENCRYPTION_ALGORITHM_CHACHA20;
use rand::RngCore;
use rand::rngs::OsRng;
use crate::db_properties::{set_hash1, set_hash2, set_names_file_location, set_passwords_file_location};
use crate::entity_actions::{add_entities, modify_entities, remove_entities, search_entities, select_entities, show_entities, show_entity_properties};
use crate::groups_users_actions::{add_groups, add_users, select_groups, select_users};
use crate::passwords::{build_password_hashes, build_password_hashes_from_key_file, create_key_file, generate_password_command};
use crate::utils::{create_file, get_password, load_file, load_files};

const TIME_DEFAULT: isize = 1000;
const PARALLELISM_DEFAULT: isize = 6;
const MEMORY_DEFAULT: isize = 128;

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

struct DatabaseAction {
    description: &'static str,
    dependencies: Vec<&'static str>,
    handler: fn(database: u64, parameters: &Parameters) -> Result<bool, Error>
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
        build_password_hashes(&database_type, &parameters)?
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
    let database_actions = build_database_actions();
    for action in parameters.actions_parameter.get_value().split(',') {
        if let Some(action) = database_actions.get(action) {
            if (action.handler)(database, &parameters)? {
                save_database = true;
            }
        } else {
            show_actions_help(&database_actions);
            return Ok(());
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

fn show_actions_help(actions: &HashMap<&str, DatabaseAction>) {
    println!("Database actions:");
    let mut sorted: Vec<(&str, &DatabaseAction)> = actions.into_iter().map(|(k, v)|(*k, v)).collect();
    sorted.sort_by_key(|a|a.0);
    for (k, v) in sorted {
        println!(" {} - {}{}", k, v.description, build_action_requirements_text(&v.dependencies))
    }
}

fn build_action_requirements_text(dependencies: &Vec<&str>) -> String {
    if !dependencies.is_empty() {
        return format!(", requires {}", dependencies.join(","));
    }
    return "".to_string()
}

fn build_database_actions() -> HashMap<&'static str, DatabaseAction> {
    let database_actions = HashMap::from([
        ("none", DatabaseAction{description: "no action", dependencies: Vec::new(),
            handler: |_database, _parameters|Ok(false)}),
        ("save", DatabaseAction{description: "save action", dependencies: Vec::new(),
            handler: |_database, _parameters|Ok(true)}),
        ("add_groups", DatabaseAction{description: "add database group", dependencies: vec!["group_names"],
            handler: |database, parameters|add_groups(database, parameters.group_names_parameter.get_value())}),
        ("get_groups", DatabaseAction{description: "get database groups", dependencies: Vec::new(),
            handler: |database, _parameters|select_groups(database)}),
        ("get_users", DatabaseAction{description: "get database users", dependencies: Vec::new(),
            handler: |database, _parameters|select_users(database)}),
        ("add_users", DatabaseAction{description: "add database users", dependencies: vec!["user_names"],
            handler: |database, parameters|add_users(database, parameters.user_names_parameter.get_value())}),
        ("add_entities", DatabaseAction{description: "add database entities",
            dependencies: vec!["entity_names", "entity_groups", "entity_users", "entity_passwords", "entity_urls", "entity_properties"],
            handler: |database, parameters|add_entities(database, parameters)}),
        ("get_entities", DatabaseAction{description: "get database entities", dependencies: vec!["group_names"],
            handler: |database, parameters|select_entities(database, parameters.group_names_parameter.get_value())}),
        ("remove_entities", DatabaseAction{description: "remove database entities", dependencies: vec!["entity_names"],
            handler: |database, parameters|remove_entities(database, parameters)}),
        ("modify_entities", DatabaseAction{description: "modify database entities",
            dependencies: vec!["entity_names", "entity_passwords", "entity_urls", "entity_properties"],
            handler: |database, parameters|modify_entities(database, parameters)}),
        ("set_hash1", DatabaseAction{description: "set first password hashing algorithm",
            dependencies: vec!["iterations", "memory", "parallelism"],
            handler: |database, parameters|set_hash1(database, parameters)}),
        ("set_hash2", DatabaseAction{description: "set second password hashing algorithm",
            dependencies: vec!["iterations2", "memory2", "parallelism2"],
            handler: |database, parameters|set_hash2(database, parameters)}),
        ("names_location", DatabaseAction{description: "set names file location",
            dependencies: vec!["s3_path1", "s3_key1"],
            handler: |database, parameters|set_names_file_location(database, parameters)}),
        ("passwords_location", DatabaseAction{description: "set passwords file location",
            dependencies: vec!["s3_path2", "s3_key2"],
            handler: |database, parameters|set_passwords_file_location(database, parameters)}),
        ("search", DatabaseAction{description: "search by entity partial name",
            dependencies: vec!["entity_names"],
            handler: |database, parameters|search_entities(database, parameters)}),
        ("show", DatabaseAction{description: "show database entities",
            dependencies: vec!["entity_names"],
            handler: |database, parameters|show_entities(database, parameters)}),
        ("show_properties", DatabaseAction{description: "show database properties values",
            dependencies: vec!["entity_names in format name@property_name"],
            handler: |database, parameters|show_entity_properties(database, parameters)}),
    ]);
    database_actions
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
