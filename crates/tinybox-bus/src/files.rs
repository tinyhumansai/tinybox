//! Bounded workspace file-transfer requests and responses.

use serde::{Deserialize, Serialize};

use crate::ResourceId;

/// Begin a read from a resource's mounted workspace using a relative path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeginFileReadRequest {
    /// Resource that owns the mounted workspace.
    pub resource: ResourceId,
    /// Caller-known reservation returned by Reserve(FileRead(resource)).
    pub transfer: ResourceId,
    /// Normalized path relative to that workspace.
    pub path: String,
}

/// Opaque read handle and the size observed when it was opened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileReadInfo {
    /// Resource that owns the read handle.
    pub resource: ResourceId,
    /// Module-minted opaque transfer handle.
    pub transfer: ResourceId,
    /// File length in bytes at open time.
    pub size: u64,
}

/// Read one bounded range from an open workspace file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadFileChunkRequest {
    /// Resource that owns the read handle.
    pub resource: ResourceId,
    /// Opaque handle returned by `BeginFileRead`.
    pub transfer: ResourceId,
    /// Byte offset from the start of the file.
    pub offset: u64,
    /// Requested bytes, bounded by [`crate::MAX_FILE_CHUNK_BYTES`].
    pub max_bytes: usize,
}

/// A bounded file range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileChunk {
    /// Byte offset represented by `bytes`.
    pub offset: u64,
    /// Unmodified file bytes.
    pub bytes: Vec<u8>,
    /// File length captured when the reader opened.
    pub total_bytes: u64,
}

/// Close an open workspace file reader.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinishFileReadRequest {
    /// Resource that owns the read handle.
    pub resource: ResourceId,
    /// Opaque handle returned by `BeginFileRead`.
    pub transfer: ResourceId,
}

/// Begin an atomic write to a resource's mounted workspace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeginFileWriteRequest {
    /// Resource that owns the mounted workspace.
    pub resource: ResourceId,
    /// Caller-known reservation returned by Reserve(FileWrite(resource)).
    pub transfer: ResourceId,
    /// Normalized path relative to that workspace.
    pub path: String,
}

/// Opaque write handle and its initial offset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileWriteInfo {
    /// Resource that owns the writer.
    pub resource: ResourceId,
    /// Module-minted opaque transfer handle.
    pub transfer: ResourceId,
    /// Next accepted byte offset; initially zero.
    pub next_offset: u64,
}

/// Append one bounded chunk at the writer's next offset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteFileChunkRequest {
    /// Resource that owns the writer.
    pub resource: ResourceId,
    /// Opaque handle returned by `BeginFileWrite`.
    pub transfer: ResourceId,
    /// Byte offset; chunks are sequential and exact retries are idempotent.
    pub offset: u64,
    /// Unmodified file bytes.
    pub bytes: Vec<u8>,
}

/// The writer's current acknowledged position.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileWriteProgress {
    /// Next accepted byte offset.
    pub next_offset: u64,
}

/// Atomically publish all bytes written so far at the requested path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinishFileWriteRequest {
    /// Resource that owns the writer.
    pub resource: ResourceId,
    /// Opaque handle returned by `BeginFileWrite`.
    pub transfer: ResourceId,
}

/// Abort a staged file write without changing its destination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbortFileWriteRequest {
    /// Resource that owns the writer.
    pub resource: ResourceId,
    /// Opaque handle returned by `BeginFileWrite`.
    pub transfer: ResourceId,
}
