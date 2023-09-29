/*

database file structure
    header -> id_value_map
        database version
        names_file_hash_algorithm properties
        names_file_encryption_algorithm properties
        names_file_location
    names_file_properties -> id_value_map
        for local names file -> file contents
    sha512 for file data

names file structure -> id_value_map
    header -> id_name_map
        passwords_file_hash_algorithm properties
        passwords_file_encryption_algorithm properties
        passwords_file_location

*/