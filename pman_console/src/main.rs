use std::collections::HashMap;
use std::io::{Error, ErrorKind, Read};
use std::env::args;
use std::fs::File;
use arguments_parser::{Arguments, IntParameter, BoolParameter, Switch, StringParameter, EnumParameter};
use pman_lib::{create, get_database_type, prepare};

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
    let hash_values = vec!["argon2".to_string()];
    let hash_parameter = EnumParameter::new(hash_values.clone(), "argon2");
    let hash2_parameter = EnumParameter::new(hash_values, "argon2");
    let encryption_values = vec!["aes".to_string()];
    let encryption_parameter = EnumParameter::new(encryption_values.clone(), "aes");
    let encryption2_parameter = EnumParameter::new(encryption_values, "aes");
    let verbose_parameter = BoolParameter::new();
    let create_parameter = BoolParameter::new();
    let time_parameter = IntParameter::new(TIME_DEFAULT, |v|v>0);
    let parallelism_parameter = IntParameter::new(PARALLELISM_DEFAULT, |v|v>0);
    let time2_parameter = IntParameter::new(TIME_DEFAULT, |v|v>0);
    let parallelism2_parameter = IntParameter::new(PARALLELISM_DEFAULT, |v|v>0);
    let memory_parameter = IntParameter::new(MEMORY_DEFAULT, |v|v>0);
    let memory2_parameter = IntParameter::new(MEMORY_DEFAULT, |v|v>0);
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
        Switch::new("encryption algorithm for names file", Some('e'), None,
                    &encryption_parameter),
        Switch::new("encryption algorithm for passwords file", None, Some("e2"),
                    &encryption_parameter),
        Switch::new("hash build time in ms for first hash algorithm", Some('t'),
                    None, &time_parameter),
        Switch::new("hash build time in ms of iterations for second hash algorithm", None,
                    Some("t2"), &time2_parameter),
        Switch::new("parallelism for first hash algorithm", Some('p'),
                    None, &parallelism_parameter),
        Switch::new("parallelism for second hash algorithm", None,
                    Some("p2"), &parallelism2_parameter),
        Switch::new("memory size in Mb for first hash algorithm", Some('m'),
                    None, &memory_parameter),
        Switch::new("memory size in Mb for second hash algorithm", None,
                    Some("m2"), &memory2_parameter),
        Switch::new("names file location", None, Some("nf"),
                    &names_file_parameter),
        Switch::new("passwords_file_location", None, Some("pf"),
                    &passwords_file_parameter),
    ];
    let mut arguments = Arguments::new("pman_console", &switches,
                                       Some(vec!["file_name".to_string()]));
    if let Err(e) = arguments.build(args().skip(1).collect()) {
        println!("{}", e);
        arguments.usage();
        return Ok(());
    }
    let file_name = &arguments.get_other_arguments()[0];
    let database_type = get_database_type(file_name)?;
    let password = get_password("password", &password_parameter);
    let passsword2 = if database_type.requires_second_password() {
        Some(get_password("password2", &password2_parameter))
    } else { None };
    let verbose = verbose_parameter.get_value();
    let database = if create_parameter.get_value() {
        create(database_type, password, passsword2, None)
            .map_err(|e|Error::new(ErrorKind::Other, e.to_string()))?
    } else {
        let mut f = File::open(file_name)?;
        let mut data = Vec::new();
        f.read_to_end(&mut data)?;
        prepare(&data, file_name.clone())
            .map_err(|e|Error::new(ErrorKind::Other, e.to_string()))?
    };
    Ok(())
}

fn get_password(prompt: &str, password_parameter: &StringParameter) -> String {
    todo!()
}
