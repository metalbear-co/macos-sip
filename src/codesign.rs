use std::process::Command;
use crate::error::{Result, SipError};

pub(crate) fn sign(path: &str) -> Result<()> {
    let output = Command::new("codesign")
        .arg("-s") // sign with identity
        .arg("-") // adhoc identity
        .arg("-f") // force (might have a signature already)
        .arg(path)
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(SipError::Sign(output.status.code(), String::from_utf8_lossy(&output.stderr).to_string()))
    }
}
