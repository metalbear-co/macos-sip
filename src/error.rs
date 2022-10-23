use thiserror::Error;

pub type Result<T> = std::result::Result<T, SipError>;

#[derive(Debug, Error)]
pub enum SipError {
    #[error("IO failed with `{0}`")]
    IO(#[from] std::io::Error),

    #[error("Signing failed statuscode: `{0}`, output: `{1}`")]
    Sign(i32, String),

    #[error("Can't patch file format `{0}`")]
    UnsupportedFileFormat(String),

    #[error("No x64 architecture in file")]
    NoX64Arch(String),

    #[error("ObjectParse failed with `{0}`")]
    ObjectParse(#[from] object::Error),
}
