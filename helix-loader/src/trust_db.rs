use std::{
    collections::HashSet,
    fs::File,
    hash::Hash,
    io::ErrorKind,
    path::{Path, PathBuf},
};

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::{data_dir, ensure_parent_dir, find_workspace_in};

#[derive(Serialize, Deserialize, Default)]
struct TrustDb {
    workspace: Option<HashSet<PathBuf>>,
    files: Option<HashSet<Vec<u8>>>,
    completely: Option<HashSet<PathBuf>>,
}

fn insert_or_create<T: Eq + Hash>(maybe_set: &mut Option<HashSet<T>>, t: T) -> bool {
    if let Some(set) = maybe_set {
        HashSet::insert(set, t)
    } else {
        let mut set = HashSet::new();
        set.insert(t);
        *maybe_set = Some(set);
        true
    }
}

fn remove_if_exists<T: Eq + Hash>(maybe_set: &mut Option<HashSet<T>>, val: &T) -> bool {
    if let Some(set) = maybe_set {
        set.remove(val)
    } else {
        false
    }
}

impl TrustDb {
    fn is_file_in_completely_trusted(&self, path: impl AsRef<Path>) -> bool {
        self.completely
            .as_ref()
            .is_some_and(|c| c.contains(&find_workspace_in(path).0))
    }
    fn is_file_trusted(&self, path: impl AsRef<Path>, hash: &[u8]) -> bool {
        self.files.as_ref().is_some_and(|f| f.contains(hash))
            || self.is_file_in_completely_trusted(path)
    }

    fn is_workspace_trusted(&self, path: impl AsRef<Path>) -> bool {
        self.workspace
            .as_ref()
            .is_some_and(|w| w.contains(path.as_ref()))
            || self
                .completely
                .as_ref()
                .is_some_and(|c| c.contains(path.as_ref()))
    }

    fn lock() -> std::io::Result<File> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
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
        let toml: TrustDb = toml::from_str(&contents).expect(&format!(
            "Trust database is corrupted. Try to fix {} or delete it",
            trust_db_file().display()
        ));
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
        let mut toml: TrustDb = toml::from_str(&contents).expect(&format!(
            "Trust database is corrupted. Try to fix {} or delete it",
            trust_db_file().display()
        ));
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

pub fn trust_workspace_completely(path: impl AsRef<Path>) -> std::io::Result<bool> {
    let path = path.as_ref().canonicalize()?;
    TrustDb::modify(|db| insert_or_create(&mut db.completely, path))
}

pub fn untrust_workspace_completely(path: impl AsRef<Path>) -> std::io::Result<bool> {
    let path = path.as_ref().canonicalize()?;
    TrustDb::modify(|db| {
        remove_if_exists(&mut db.workspace, &path);
        remove_if_exists(&mut db.completely, &path)
    })
}

pub fn trust_workspace(path: impl AsRef<Path>) -> std::io::Result<bool> {
    let path = path.as_ref().canonicalize()?;
    TrustDb::modify(|db| insert_or_create(&mut db.workspace, path))
}

pub fn untrust_workspace(path: impl AsRef<Path>) -> std::io::Result<bool> {
    let path = path.as_ref().canonicalize()?;
    TrustDb::modify(|db| remove_if_exists(&mut db.workspace, &path))
}

pub fn is_workspace_trusted(path: impl AsRef<Path>) -> std::io::Result<bool> {
    let path = path.as_ref().canonicalize()?;
    TrustDb::inspect(|db| db.is_workspace_trusted(path))
}

pub fn trust_file(path: impl AsRef<Path>, contents: &[u8]) -> std::io::Result<bool> {
    let path = path.as_ref().canonicalize()?;
    let hash = TrustDb::hash_file(path, contents);
    TrustDb::modify(|db| insert_or_create(&mut db.files, hash))
}

pub fn untrust_file(path: impl AsRef<Path>, contents: &[u8]) -> std::io::Result<bool> {
    let path = path.as_ref().canonicalize()?;
    let hash = TrustDb::hash_file(path, contents);
    TrustDb::modify(|db| remove_if_exists(&mut db.files, &hash))
}

pub fn is_file_trusted(path: impl AsRef<Path>, contents: &[u8]) -> std::io::Result<bool> {
    let path = path.as_ref().canonicalize()?;
    let hash = TrustDb::hash_file(&path, contents);
    TrustDb::inspect(|db| db.is_file_trusted(path, &hash))
}

pub fn initialize_trust_db() {
    ensure_parent_dir(&trust_db_file());
}
