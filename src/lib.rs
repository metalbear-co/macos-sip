mod codesign;
mod error;

use error::Result;

use std::ops::Range;
use std::os::macos::fs::MetadataExt;
// /// To know if binary is SIP protected for sure, it's in either cases (based on dyld-852.2 code):
// /// 1. has __RESTRICT segment -- skipped, didn't see it in the wild
// /// 2. has setuid/setgid bit set - skipped for now
// /// 3. code is signed with entitlements.
// pub(crate) fn is_sip(path: &str) -> Result<bool> {
//     let mut f = File::open(path)?;
//     let mut buf = Vec::new();
//     let size = f.read_to_end(&mut buf).unwrap();
//     let mut cur = Cursor::new(&buf[..size]);
//     match OFile::parse(&mut cur) {
//         Ok(OFile::MachFile { header, commands }) => is_sip_macho(&header, &commands),
//         Ok(OFile::FatFile { magic: _, files }) => Ok(files.iter().any(|(_, in_file)| match in_file {
//             OFile::MachFile { header, commands } => {
//                 is_sip_macho(&header, &commands).unwrap_or(false)
//             }
//             _ => false,
//         })),
//         _ => Ok(false),
//     }
// }
// use object::{File, read::macho::FatArch, macho::{FatHeader, CPU_TYPE_ARM64, CPU_SUBTYPE_PTRAUTH_ABI, FatArch64}, BigEndian};
// use anyhow::{anyhow, Result};
// use object::{BigEndian, macho::{FatHeader, FAT_MAGIC, FatArch64, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E, CPU_TYPE_ARM64_32, FatArch32, CPU_SUBTYPE_PTRAUTH_ABI, MachHeader64, CPU_SUBTYPE_ARM64_ALL}, LittleEndian};

// /// Patches a binary to disable SIP.
// /// Right now it extracts 
// pub fn patch_binary(path: &str, output: &str) -> Result<()> {
//     let mut data = std::fs::read(path)?;
//     let (header, _): (&FatHeader,_) = object::from_bytes(&data[..std::mem::size_of::<FatHeader>()]).unwrap();
//     let magic = header.magic.get(BigEndian);
//     if magic != FAT_MAGIC {
//         return Err(anyhow!("invalid magic {magic:?}"));
//     }
//     let arch_count = header.nfat_arch.get(BigEndian) as usize;
//     let archs_range = Range {
//         start: std::mem::size_of::<FatHeader>(),
//         end: std::mem::size_of::<FatHeader>() + arch_count * std::mem::size_of::<FatArch32>(),
//     };
//     let (archs, _) : (&[FatArch32], _) = object::slice_from_bytes(&data[archs_range], arch_count).unwrap();
//     // let mut arch_offset = 0;
//     // let mut arch_size = 0;
//     let range = Range {
//         start: archs[0].offset.get(BigEndian) as usize,
//         end: archs[0].offset.get(BigEndian) as usize + archs[0].size.get(BigEndian) as usize,
//     };
//     let x64 = &data[range];
    
//     // for arch in archs {
//     //     let cpu_type = arch.cputype.get(BigEndian);
//     //     let cpu_subtype = arch.cpusubtype.get(BigEndian);
//     //     println!("test: {:?}", cpu_type & CPU_TYPE_ARM64);
//     //     if cpu_type == CPU_TYPE_ARM64 && (cpu_subtype & CPU_SUBTYPE_ARM64E) > 0 {
//     //         let val = CPU_SUBTYPE_ARM64_ALL; // CPU_SUBTYPE_ARM64_ALL; // (cpu_subtype ^ CPU_SUBTYPE_ARM64E) ^ ;
//     //         arch.cpusubtype.set(BigEndian, val);
//     //         arch_offset = arch.offset.get(BigEndian) as usize;
//     //         arch_size = arch.size.get(BigEndian) as usize;
//     //         println!("patch1 {val:?}");
//     //     } else {
//     //         println!("{cpu_type:?} {cpu_subtype:?}");

//     //     }

//     // }
//     // {
//     //     let hash = md5::compute(&data);
//     //     println!("second: {:x}", hash);
//     // }
//     // let range = Range {
//     //     start: arch_offset,
//     //     end: arch_offset + arch_size,
//     // };
//     // let (arch_header, _): (&mut MachHeader64<LittleEndian>, _) = object::from_bytes_mut(&mut data[range]).unwrap();
//     // let cpu_type = arch_header.cputype.get(LittleEndian);
//     // let cpu_subtype = arch_header.cpusubtype.get(LittleEndian);
//     // println!("magic {:?}", arch_header.magic.get(BigEndian));
//     // if cpu_type == CPU_TYPE_ARM64 && (cpu_subtype & CPU_SUBTYPE_ARM64E) > 0 {
//     //     println!("patch2");
//     //     let val = CPU_SUBTYPE_ARM64_ALL; // (cpu_subtype ^ CPU_SUBTYPE_ARM64E) ^ CPU_SUBTYPE_PTRAUTH_ABI;
//     //     arch_header.cpusubtype.set(LittleEndian, val);
//     // } else {
//     //     println!("{cpu_type:?} {cpu_subtype:?}");
//     // }
//     // {
//     //     let hash = md5::compute(&data);
//     //     println!("last: {:x}", hash);
//     // }
//     std::fs::write(output, x64).unwrap();
//     codesign::sign(output).unwrap();
//     Ok(())
// }

// pub fn patch_binary(path: &str, _output: &str) -> Result<()> {
//     let data = std::fs::read(path)?;
//     let arch = object::macho::FatHeader::parse_arch32(&*data).unwrap();

//     Ok(())
// }



const SF_RESTRICTED: u32 = 0x00080000;      // entitlement required for writing, from stat.h (macos)

/// Checks the SF_RESTRICTED flags on a file (there might be a better check, feel free to suggest)
pub fn is_sip(path: &str) -> Result<bool> {
    let metadata = std::fs::metadata(path)?;
    Ok((metadata.st_flags() &SF_RESTRICTED) > 0)
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