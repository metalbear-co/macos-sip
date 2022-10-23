mod codesign;
mod error;

use std::ops::Range;
use std::os::macos::fs::MetadataExt;

use object::{
    macho::{FatHeader, MachHeader32, MachHeader64, CPU_TYPE_X86_64},
    read::macho::{FatArch, MachHeader},
    Architecture, Endianness, FileKind,
};

use crate::error::{Result, SipError};

struct BinaryInfo {
    offset: usize,
    size: usize,
}

fn is_fat_x64_arch(arch: &&impl FatArch) -> bool {
    matches!(arch.architecture(), Architecture::X86_64)
}

/// Gets x64 binary offset from a Mach-O fat binary or returns 0 if is x64 macho binary.
fn get_x64_binary_offset(file: &[u8]) -> Result<usize> {
    match FileKind::parse(file)? {
        FileKind::MachO32 => {
            let header: &MachHeader32<Endianness> = MachHeader::parse(file, 0).map_err(|_| {
                SipError::UnsupportedFileFormat("MachO 32 file parsing failed".to_string())
            })?;
            if header.cputype(Endianness::default()) == CPU_TYPE_X86_64 {
                Ok(0)
            } else {
                Err(SipError::NoX64Arch("MachO file is not x64".to_string()))
            }
        }
        FileKind::MachO64 => {
            let header: &MachHeader64<Endianness> = MachHeader::parse(file, 0).map_err(|_| {
                SipError::UnsupportedFileFormat("MachO 64 file parsing failed".to_string())
            })?;
            if header.cputype(Endianness::default()) == CPU_TYPE_X86_64 {
                Ok(0)
            } else {
                Err(SipError::NoX64Arch("MachO file is not x64".to_string()))
            }
        }
        FileKind::MachOFat32 => FatHeader::parse_arch32(file)
            .map_err(|_| SipError::UnsupportedFileFormat("FatMach-O 32-bit".to_string()))?
            .iter()
            .find(is_fat_x64_arch)
            .map(|arch| arch.offset() as usize)
            .ok_or_else(|| SipError::NoX64Arch("Couldn't find x64 arch in fat file".to_string())),
        FileKind::MachOFat64 => FatHeader::parse_arch64(file)
            .map_err(|_| SipError::UnsupportedFileFormat("Mach-O 32-bit".to_string()))?
            .iter()
            .find(is_fat_x64_arch)
            .map(|arch| arch.offset() as usize)
            .ok_or_else(|| SipError::NoX64Arch("Couldn't find x64 arch in fat file".to_string())),
        other => Err(SipError::UnsupportedFileFormat(
            format!("{:?}", other).to_string(),
        )),
    }
}

/// Patches a binary to disable SIP.
/// Right now it extracts
pub fn patch_binary(path: &str, output: &str) -> Result<()> {
    let mut data = std::fs::read(path)?;
    let (header, _): (&FatHeader, _) =
        object::from_bytes(&data[..std::mem::size_of::<FatHeader>()]).unwrap();
    let magic = header.magic.get(BigEndian);
    if magic != FAT_MAGIC {
        return Err(anyhow!("invalid magic {magic:?}"));
    }
    let arch_count = header.nfat_arch.get(BigEndian) as usize;
    let archs_range = Range {
        start: std::mem::size_of::<FatHeader>(),
        end: std::mem::size_of::<FatHeader>() + arch_count * std::mem::size_of::<FatArch32>(),
    };
    let (archs, _): (&[FatArch32], _) =
        object::slice_from_bytes(&data[archs_range], arch_count).unwrap();
    // let mut arch_offset = 0;
    // let mut arch_size = 0;
    let range = Range {
        start: archs[0].offset.get(BigEndian) as usize,
        end: archs[0].offset.get(BigEndian) as usize + archs[0].size.get(BigEndian) as usize,
    };
    let x64 = &data[range];

    // for arch in archs {
    //     let cpu_type = arch.cputype.get(BigEndian);
    //     let cpu_subtype = arch.cpusubtype.get(BigEndian);
    //     println!("test: {:?}", cpu_type & CPU_TYPE_ARM64);
    //     if cpu_type == CPU_TYPE_ARM64 && (cpu_subtype & CPU_SUBTYPE_ARM64E) > 0 {
    //         let val = CPU_SUBTYPE_ARM64_ALL; // CPU_SUBTYPE_ARM64_ALL; // (cpu_subtype ^ CPU_SUBTYPE_ARM64E) ^ ;
    //         arch.cpusubtype.set(BigEndian, val);
    //         arch_offset = arch.offset.get(BigEndian) as usize;
    //         arch_size = arch.size.get(BigEndian) as usize;
    //         println!("patch1 {val:?}");
    //     } else {
    //         println!("{cpu_type:?} {cpu_subtype:?}");

    //     }

    // }
    // {
    //     let hash = md5::compute(&data);
    //     println!("second: {:x}", hash);
    // }
    // let range = Range {
    //     start: arch_offset,
    //     end: arch_offset + arch_size,
    // };
    // let (arch_header, _): (&mut MachHeader64<LittleEndian>, _) = object::from_bytes_mut(&mut data[range]).unwrap();
    // let cpu_type = arch_header.cputype.get(LittleEndian);
    // let cpu_subtype = arch_header.cpusubtype.get(LittleEndian);
    // println!("magic {:?}", arch_header.magic.get(BigEndian));
    // if cpu_type == CPU_TYPE_ARM64 && (cpu_subtype & CPU_SUBTYPE_ARM64E) > 0 {
    //     println!("patch2");
    //     let val = CPU_SUBTYPE_ARM64_ALL; // (cpu_subtype ^ CPU_SUBTYPE_ARM64E) ^ CPU_SUBTYPE_PTRAUTH_ABI;
    //     arch_header.cpusubtype.set(LittleEndian, val);
    // } else {
    //     println!("{cpu_type:?} {cpu_subtype:?}");
    // }
    // {
    //     let hash = md5::compute(&data);
    //     println!("last: {:x}", hash);
    // }
    std::fs::write(output, x64).unwrap();
    codesign::sign(output).unwrap();
    Ok(())
}

const SF_RESTRICTED: u32 = 0x00080000; // entitlement required for writing, from stat.h (macos)

/// Checks the SF_RESTRICTED flags on a file (there might be a better check, feel free to suggest)
pub fn is_sip(path: &str) -> Result<bool> {
    let metadata = std::fs::metadata(path)?;
    Ok((metadata.st_flags() & SF_RESTRICTED) > 0)
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn is_sip_true() {
        assert!(is_sip("/bin/ls").unwrap());
    }

    #[test]
    fn is_sip_false() {
        std::fs::copy("/bin/ls", "/tmp/ls_mirrord_test").unwrap();
        assert!(!is_sip("/tmp/ls_mirrord_test").unwrap());
    }

    #[test]
    fn is_sip_notfound() {
        let err = is_sip("/donald/duck/was/a/duck/not/a/quack/a/duck").unwrap_err();
        assert!(err.to_string().contains("No such file or directory"));
    }
}
