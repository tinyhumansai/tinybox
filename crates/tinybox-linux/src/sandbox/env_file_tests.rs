//! The private environment file: contents, permissions and cleanup.

use super::*;
use std::os::unix::fs::PermissionsExt as _;

fn env(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect()
}

#[test]
fn the_file_holds_nul_separated_setenv_triples() -> io::Result<()> {
    let file = EnvArgsFile::create(&env(&[("A", "1"), ("TOKEN", "s3cret value")]), &[])?;

    let contents = std::fs::read(file.path())?;

    assert_eq!(
        contents,
        b"--setenv\0A\x001\0--setenv\0TOKEN\0s3cret value\0".to_vec()
    );
    Ok(())
}

#[test]
fn the_file_and_its_directory_are_private_and_removed_on_drop() -> io::Result<()> {
    let file = EnvArgsFile::create(&env(&[("K", "v")]), &[])?;
    let path = file.path().to_path_buf();
    let dir = path
        .parent()
        .map(Path::to_path_buf)
        .ok_or(io::ErrorKind::NotFound)?;

    assert_eq!(
        std::fs::metadata(&path)?.permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(std::fs::metadata(&dir)?.permissions().mode() & 0o777, 0o700);

    drop(file);
    assert!(!path.exists());
    assert!(!dir.exists());
    Ok(())
}

#[test]
fn a_nul_in_an_entry_is_refused() {
    for pairs in [[("K\0", "v")], [("K", "v\0")]] {
        let kind = EnvArgsFile::create(&env(&pairs), &[])
            .err()
            .map(|e| e.kind());
        assert_eq!(kind, Some(io::ErrorKind::InvalidInput));
    }
}

#[test]
fn a_directory_inside_a_grant_is_never_used() {
    // Every candidate (the runtime dir and the temp dir) lies under `/`.
    let root = Path::new("/");
    let kind = EnvArgsFile::create(&env(&[("K", "v")]), &[root])
        .err()
        .map(|e| e.kind());
    assert_eq!(kind, Some(io::ErrorKind::PermissionDenied));
}
