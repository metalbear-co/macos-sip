mod codesign;
mod error;

use std::{
    fs::Permissions,
    os::{macos::fs::MetadataExt, unix::prelude::PermissionsExt},
};

use object::{
    macho::{FatHeader, MachHeader32, MachHeader64, CPU_TYPE_X86_64},
    read::macho::{FatArch, MachHeader},
    Architecture, Endianness, FileKind,
};

use crate::error::{Result, SipError};

fn is_fat_x64_arch(arch: &&impl FatArch) -> bool {
    matches!(arch.architecture(), Architecture::X86_64)
}

struct BinaryInfo {
    offset: usize,
    size: usize,
}

impl BinaryInfo {
    fn new(offset: usize, size: usize) -> Self {
        Self { offset, size }
    }

    /// Gets x64 binary offset from a Mach-O fat binary or returns 0 if is x64 macho binary.
    fn from_object_bytes(bytes: &[u8]) -> Result<Self> {
        match FileKind::parse(bytes)? {
            FileKind::MachO32 => {
                let header: &MachHeader32<Endianness> =
                    MachHeader::parse(bytes, 0).map_err(|_| {
                        SipError::UnsupportedFileFormat("MachO 32 file parsing failed".to_string())
                    })?;
                if header.cputype(Endianness::default()) == CPU_TYPE_X86_64 {
                    Ok(Self::new(0, bytes.len()))
                } else {
                    Err(SipError::NoX64Arch("MachO file is not x64".to_string()))
                }
            }
            FileKind::MachO64 => {
                let header: &MachHeader64<Endianness> =
                    MachHeader::parse(bytes, 0).map_err(|_| {
                        SipError::UnsupportedFileFormat("MachO 64 file parsing failed".to_string())
                    })?;
                if header.cputype(Endianness::default()) == CPU_TYPE_X86_64 {
                    Ok(Self::new(0, bytes.len()))
                } else {
                    Err(SipError::NoX64Arch("MachO file is not x64".to_string()))
                }
            }
            FileKind::MachOFat32 => FatHeader::parse_arch32(bytes)
                .map_err(|_| SipError::UnsupportedFileFormat("FatMach-O 32-bit".to_string()))?
                .iter()
                .find(is_fat_x64_arch)
                .map(|arch| Self::new(arch.offset() as usize, arch.size() as usize))
                .ok_or_else(|| {
                    SipError::NoX64Arch("Couldn't find x64 arch in fat file".to_string())
                }),
            FileKind::MachOFat64 => FatHeader::parse_arch64(bytes)
                .map_err(|_| SipError::UnsupportedFileFormat("Mach-O 32-bit".to_string()))?
                .iter()
                .find(is_fat_x64_arch)
                .map(|arch| Self::new(arch.offset() as usize, arch.size() as usize))
                .ok_or_else(|| {
                    SipError::NoX64Arch("Couldn't find x64 arch in fat file".to_string())
                }),
            other => Err(SipError::UnsupportedFileFormat(format!("{:?}", other))),
        }
    }
}

/// Patches a binary to disable SIP.
/// Right now it extracts x64 binary from fat/MachO binary and patches it.
pub fn patch_binary(path: &str, output: &str) -> Result<()> {
    let data = std::fs::read(path)?;
    let binary_info = BinaryInfo::from_object_bytes(&data)?;

    let x64_binary = &data[binary_info.offset..binary_info.offset + binary_info.size];
    std::fs::write(output, x64_binary)?;
    std::fs::set_permissions(output, Permissions::from_mode(0o755))?;
    codesign::sign(output)
}

const SF_RESTRICTED: u32 = 0x00080000; // entitlement required for writing, from stat.h (macos)

/// Checks the SF_RESTRICTED flags on a file (there might be a better check, feel free to suggest)
pub fn is_sip(path: &str) -> Result<bool> {
    let metadata = std::fs::metadata(path)?;
    Ok((metadata.st_flags() & SF_RESTRICTED) > 0)
}

#[cfg(test)]
mod tests {

    use std::io::Write;

    use super::*;

    #[test]
    fn is_sip_true() {
        assert!(is_sip("/bin/ls").unwrap());
    }

    #[test]
    fn is_sip_false() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        let data = std::fs::read("/bin/ls").unwrap();
        f.write(&data).unwrap();
        f.flush().unwrap();
        assert!(!is_sip(f.path().to_str().unwrap()).unwrap());
    }

    #[test]
    fn is_sip_notfound() {
        let err = is_sip("/donald/duck/was/a/duck/not/a/quack/a/duck").unwrap_err();
        assert!(err.to_string().contains("No such file or directory"));
    }

    #[test]
    fn patch_binary_fat() {
        let path = "/bin/ls";
        let output = "/tmp/ls_mirrord_test";
        patch_binary(path, output).unwrap();
        assert!(!is_sip(output).unwrap());
        // Check DYLD_* features work on it:
        let output = std::process::Command::new(output)
            .env("DYLD_PRINT_LIBRARIES", "1")
            .output()
            .unwrap();
        assert!(String::from_utf8_lossy(&output.stderr).contains("libsystem_kernel.dylib"));
    }
}
