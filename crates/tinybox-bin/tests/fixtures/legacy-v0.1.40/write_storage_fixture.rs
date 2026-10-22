use std::path::PathBuf;
use tinybox_cli::{FileStore, FileTemplates};
use tinybox_core::{
    BoxId, BoxInfo, BoxSpec, BoxState, HostRef, Placement, SandboxRef, SnapshotId, Store,
    TemplateName, Templates, WorkspaceSource,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(std::env::args_os().nth(1).ok_or("fixture output path required")?);
    std::fs::create_dir_all(&root)?;
    let spec = BoxSpec::new(
        Placement::new(HostRef::new("local")?, SandboxRef::new("passthrough")?),
        WorkspaceSource::LocalDir("/srv/legacy-project".into()),
    )
    .with_env("FIXTURE", "released-writer");
    let info = BoxInfo::new(BoxId::new("box-released")?, BoxState::Ready, spec);
    FileStore::new(root.join("boxes.json")).insert(&info)?;
    FileTemplates::new(root.join("templates.json")).save(
        &TemplateName::new("released-template")?,
        &SnapshotId::new("snapshot-released")?,
    )?;
    Ok(())
}
