
use thiserror::Error;

pub type Result<T> = std::result::Result<T, SipError>;

#[derive(Debug, Error)]
pub enum SipError {
    #[error("IO failed with `{0}`!")]
    IO(#[from] std::io::Error),
    
    #[error("Signing failed statuscode: `{0}`, output: `{1}`!")]
    Sign(Option<i32>, String)
}
