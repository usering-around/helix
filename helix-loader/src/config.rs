use std::{io::ErrorKind, str::from_utf8};

use crate::{trust_db, workspace_languages_file};

/// Default built-in languages.toml.
pub fn default_lang_config() -> toml::Value {
    let default_config = include_bytes!("../../languages.toml");
    toml::from_str(from_utf8(default_config).unwrap())
        .expect("Could not parse built-in languages.toml to valid toml")
}

pub fn is_local_lang_config_trusted() -> std::io::Result<bool> {
    let path = workspace_languages_file();
    let contents = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => {
            if e.kind() == ErrorKind::NotFound {
                return Ok(false);
            } else {
                return Err(e);
            }
        }
    };
    trust_db::is_file_trusted(&path, contents.as_bytes())
}

/// User configured languages.toml file, merged with the default config.
pub fn user_lang_config(use_local: bool) -> Result<toml::Value, toml::de::Error> {
    let mut dirs = vec![crate::config_dir()];
    if use_local {
        dirs.push(crate::find_workspace().0.join(".helix"));
    }

    let config = dirs
        .into_iter()
        .map(|path| path.join("languages.toml"))
        .filter_map(|file| {
            std::fs::read_to_string(file)
                .map(|config| toml::from_str(&config))
                .ok()
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .fold(default_lang_config(), |a, b| {
            crate::merge_toml_values(a, b, 3)
        });

    Ok(config)
}
