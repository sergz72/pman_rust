use std::process::Command;

fn main() {
    let udl_file = "src/pman_lib.udl";
    let out_dir = "bindings";
    uniffi_build::generate_scaffolding(udl_file).unwrap();
    uniffi_bindgen::generate_bindings(udl_file.into(),
                      None,
                      vec![uniffi_bindgen::bindings::TargetLanguage::Swift,
                           uniffi_bindgen::bindings::TargetLanguage::Kotlin],
                      Some(out_dir.into()),
                      None,
                                      None,
                      true).unwrap();

    Command::new("uniffi-bindgen-cs").arg("--out-dir").arg(out_dir).arg(udl_file).output()
        .expect("Failed when generating C# bindings");
}