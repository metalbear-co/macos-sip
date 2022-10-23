use crate::error::{Result, SipError};
use std::process::Command;

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
        let code = output.status.code().unwrap(); // shuoldn't happen
        Err(SipError::Sign(
            code,
            String::from_utf8_lossy(&output.stderr).to_string(),
        ))
    }
}
