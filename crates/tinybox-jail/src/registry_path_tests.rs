//! Resolution pins missing components and the symlink/traversal boundary.
use super::*;

#[test]
fn existing_and_missing_paths_share_the_same_canonical_base() -> io::Result<()> {
    let root = tempfile::tempdir()?;
    assert_eq!(
        canonicalize_missing(root.path())?,
        root.path().canonicalize()?
    );
    assert_eq!(
        canonicalize_missing(&root.path().join("missing/nested"))?,
        root.path().canonicalize()?.join("missing/nested")
    );
    let relative = Path::new("tinybox-missing-relative-child/nested");
    assert_eq!(
        canonicalize_missing(relative)?,
        std::env::current_dir()?.canonicalize()?.join(relative)
    );
    Ok(())
}

#[test]
fn parent_traversal_is_rejected_even_inside_the_base() -> io::Result<()> {
    let root = tempfile::tempdir()?;
    assert_eq!(
        canonicalize_missing(&root.path().join("child/../missing"))
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::PermissionDenied)
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn missing_children_follow_existing_symlinks_but_not_dangling_symlinks() -> io::Result<()> {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir()?;
    let outside = tempfile::tempdir()?;
    let link = root.path().join("outside");
    symlink(outside.path(), &link)?;
    assert_eq!(
        canonicalize_missing(&link.join("missing"))?,
        outside.path().canonicalize()?.join("missing")
    );
    let dangling = root.path().join("dangling");
    symlink(root.path().join("absent"), &dangling)?;
    assert_eq!(
        canonicalize_missing(&dangling.join("missing"))
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::NotFound)
    );
    Ok(())
}

#[test]
fn non_directory_ancestors_propagate_the_os_error() -> io::Result<()> {
    let root = tempfile::tempdir()?;
    let file = root.path().join("file");
    std::fs::write(&file, b"file")?;
    let child = file.join("child");
    assert!(canonicalize_missing(&child).is_err());
    // Windows may report an intermediate missing child as NotFound. Even if
    // canonicalization reaches its existing file ancestor, no children fit.
    assert_eq!(
        append_missing(file.canonicalize()?, &["child".into()])
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::NotADirectory)
    );
    Ok(())
}
