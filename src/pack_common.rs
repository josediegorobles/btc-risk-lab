use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};

pub fn validate_input_dir(input_dir: &Path, pack_label: &str) -> Result<()> {
    if !input_dir.is_dir() {
        bail!(
            "{pack_label} input must be a directory: {}",
            input_dir.display()
        );
    }

    Ok(())
}

pub fn optional_file(input_dir: &Path, file: &str) -> Option<PathBuf> {
    let path = input_dir.join(file);
    path.exists().then_some(path)
}

pub fn has_file(input_dir: &Path, file: &str) -> bool {
    input_dir.join(file).exists()
}

pub fn read_to_string(path: &Path, context: impl FnOnce() -> String) -> Result<String> {
    fs::read_to_string(path).with_context(context)
}

pub fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| PathBuf::from(name).display().to_string())
        .unwrap_or_else(|| path.display().to_string())
}

pub fn is_metadata_artifact(artifact: &str) -> bool {
    artifact == "metadata"
}
