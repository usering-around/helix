use std::{
    collections::HashMap,
    fs::File,
    io::ErrorKind,
    path::{Path, PathBuf},
};

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::{data_dir, ensure_parent_dir, find_workspace_in};

#[derive(Serialize, Deserialize, Default)]
struct TrustDb {
    trust: Option<HashMap<PathBuf, Trust>>,
}

#[derive(Serialize, Deserialize, PartialEq)]
pub enum Trust {
    Workspace { completely: bool },
    File { hash: Vec<u8> },
    Untrusted,
}

impl TrustDb {
    fn is_file_in_completely_trusted(&self, path: impl AsRef<Path>) -> bool {
        self.trust.as_ref().is_some_and(|t| {
            t.get(&find_workspace_in(path).0)
                .is_some_and(|trust| match trust {
                    Trust::Workspace { completely } => *completely,
                    _ => false,
                })
        })
    }
    fn is_file_trusted(&self, path: impl AsRef<Path>, file_hash: &[u8]) -> bool {
        self.trust.as_ref().is_some_and(|t| {
            t.get(path.as_ref()).is_some_and(|h| match h {
                Trust::File { hash } => hash == file_hash,
                _ => false,
            })
        }) || self.is_file_in_completely_trusted(path)
    }

    fn is_workspace_trusted(&self, path: impl AsRef<Path>) -> Option<bool> {
        self.trust.as_ref().and_then(|t| {
            path.as_ref().ancestors().find_map(|p| {
                t.get(p)
                    .map(|trust| matches!(trust, Trust::Workspace { .. }))
            })
        })
    }

    fn lock() -> std::io::Result<File> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(trust_db_lock_file())?;
        file.lock_exclusive()?;
        Ok(file)
    }

    fn inspect<F, R>(f: F) -> std::io::Result<R>
    where
        F: FnOnce(TrustDb) -> R,
    {
        let lock = TrustDb::lock()?;
        let contents = match std::fs::read_to_string(trust_db_file()) {
            Ok(s) => s,
            Err(e) => {
                if e.kind() == ErrorKind::NotFound {
                    toml::to_string(&TrustDb::default()).unwrap()
                } else {
                    return Err(e);
                }
            }
        };
        let toml: TrustDb = toml::from_str(&contents).unwrap_or_else(|_| {
            panic!(
                "Trust database is corrupted. Try to fix {} or delete it",
                trust_db_file().display()
            )
        });
        let r = f(toml);
        drop(lock);
        Ok(r)
    }

    fn modify<F, R>(f: F) -> std::io::Result<R>
    where
        F: FnOnce(&mut TrustDb) -> R,
    {
        let lock = TrustDb::lock()?;
        let contents = match std::fs::read_to_string(trust_db_file()) {
            Ok(s) => s,
            Err(e) => {
                if e.kind() == ErrorKind::NotFound {
                    toml::to_string(&TrustDb::default()).unwrap()
                } else {
                    return Err(e);
                }
            }
        };
        let mut toml: TrustDb = toml::from_str(&contents).unwrap_or_else(|_| {
            panic!(
                "Trust database is corrupted. Try to fix {} or delete it",
                trust_db_file().display()
            )
        });
        let r = f(&mut toml);
        let toml_updated =
            toml::to_string(&toml).expect("toml serialization of trust database failed?");
        std::fs::write(trust_db_file(), toml_updated)?;
        drop(lock);
        Ok(r)
    }

    fn hash_file(path: impl AsRef<Path>, contents: &[u8]) -> Vec<u8> {
        let mut hasher = sha2::Sha256::new();
        hasher.update(path.as_ref().as_os_str().as_encoded_bytes());
        hasher.update(contents);
        hasher.finalize().iter().copied().collect()
    }
}

fn trust_db_file() -> PathBuf {
    data_dir().join("trust_db.toml")
}

fn trust_db_lock_file() -> PathBuf {
    trust_db_file().with_extension("lock")
}

pub fn trust_workspace(path: impl AsRef<Path>, completely: bool) -> std::io::Result<Option<Trust>> {
    let Ok(path) = path.as_ref().canonicalize() else {
        return Ok(None);
    };
    TrustDb::modify(|db| {
        db.trust
            .get_or_insert(HashMap::new())
            .insert(path, Trust::Workspace { completely })
    })
}

pub fn untrust_workspace(path: impl AsRef<Path>) -> std::io::Result<Option<Trust>> {
    let Ok(path) = path.as_ref().canonicalize() else {
        return Ok(None);
    };
    TrustDb::modify(|db| {
        db.trust
            .get_or_insert(HashMap::new())
            .insert(path, Trust::Untrusted)
    })
}

pub fn is_workspace_trusted(path: impl AsRef<Path>) -> std::io::Result<Option<bool>> {
    let Ok(path) = path.as_ref().canonicalize() else {
        return Ok(Some(false));
    };
    TrustDb::inspect(|db| db.is_workspace_trusted(path))
}

pub fn trust_file(path: impl AsRef<Path>, contents: &[u8]) -> std::io::Result<bool> {
    let Ok(path) = path.as_ref().canonicalize() else {
        return Ok(false);
    };
    let hash = TrustDb::hash_file(&path, contents);
    TrustDb::modify(|db| {
        db.trust
            .get_or_insert(HashMap::new())
            .insert(path, Trust::File { hash })
            .is_none()
    })
}

pub fn untrust_file(path: impl AsRef<Path>) -> std::io::Result<bool> {
    let Ok(path) = path.as_ref().canonicalize() else {
        return Ok(false);
    };
    TrustDb::modify(|db| {
        db.trust
            .get_or_insert(HashMap::new())
            .remove(&path)
            .is_some()
    })
}

pub fn is_file_trusted(path: impl AsRef<Path>, contents: &[u8]) -> std::io::Result<bool> {
    let Ok(path) = path.as_ref().canonicalize() else {
        return Ok(false);
    };
    let hash = TrustDb::hash_file(&path, contents);
    TrustDb::inspect(|db| db.is_file_trusted(path, &hash))
}

pub fn initialize_trust_db() {
    ensure_parent_dir(&trust_db_file());
}
