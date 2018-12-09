use failure::{bail, err_msg, Error};
use goblin::container::Endian;
use goblin::pe::data_directories::DataDirectory;
use goblin::pe::section_table::SectionTable;
use goblin::pe::PE;
use scroll::ctx::TryFromCtx;
use scroll::{self, Pread, Pwrite, SizeWith};
use std::cmp;

#[repr(C)]
#[derive(Debug, Pread, Pwrite, SizeWith)]
pub struct CliHeader {
    pub cb: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub metadata: DataDirectory,
    pub flags: u32,
    pub entry_point_token: u32,
}

#[repr(C)]
#[derive(Debug)]
struct MetadataRoot<'a> {
    pub signature: u32,
    pub major_version: u16,
    pub minor_version: u16,
    _reserved: u32,
    pub length: u32,
    pub version: &'a str,
}

impl<'a> TryFromCtx<'a, Endian> for MetadataRoot<'a> {
    type Error = scroll::Error;
    type Size = usize;
    // and the lifetime annotation on `&'a [u8]` here
    fn try_from_ctx(src: &'a [u8], endian: Endian) -> Result<(Self, Self::Size), Self::Error> {
        let offset = &mut 0;
        let signature = src.gread_with(offset, endian)?;
        let major_version = src.gread_with(offset, endian)?;
        let minor_version = src.gread_with(offset, endian)?;
        let reserved = src.gread_with(offset, endian)?;
        let length = src.gread_with(offset, endian)?;
        let version = src.gread(offset)?;
        Ok((
            Self {
                signature,
                major_version,
                minor_version,
                _reserved: reserved,
                length,
                version,
            },
            *offset,
        ))
    }
}

fn main() -> Result<(), Error> {
    let path = std::env::args()
        .skip(1)
        .next()
        .ok_or_else(|| err_msg("Path to executable was not specified"))?;
    let file = std::fs::read(path)?;
    let pe = PE::parse(&file)?;
    if pe.header.coff_header.machine != 0x14c {
        bail!("Is not a .Net executable");
    }
    let optional_header = pe.header.optional_header.ok_or_else(|| err_msg("No optional header"))?;
    let file_alignment = optional_header.windows_fields.file_alignment;
    let cli_header = optional_header
        .data_directories
        .get_clr_runtime_header()
        .ok_or_else(|| err_msg("No CLI header"))?;
    let sections = &pe.sections;

    let rva = cli_header.virtual_address as usize;
    let offset = find_offset(rva, sections, file_alignment).ok_or(err_msg("Cannot map rva into offset"))?;
    let cli_header_value: CliHeader = file.pread_with(offset, scroll::LE)?;

    println!("{:#?}", cli_header_value);
    let rva = cli_header_value.metadata.virtual_address as usize;
    let offset = find_offset(rva, sections, file_alignment).ok_or(err_msg("Cannot map rva into offset"))?;
    let root: MetadataRoot = file.pread_with(offset, scroll::LE)?;
    println!("{:#?}", root);

    Ok(())
}

fn find_offset(rva: usize, sections: &[SectionTable], file_alignment: u32) -> Option<usize> {
    for (i, section) in sections.iter().enumerate() {
        if is_in_section(rva, &section, file_alignment) {
            let offset = rva2offset(rva, &section);
            return Some(offset);
        }
    }
    None
}

fn rva2offset(rva: usize, section: &SectionTable) -> usize {
    (rva - section.virtual_address as usize) + aligned_pointer_to_raw_data(section.pointer_to_raw_data as usize)
}

fn is_in_section(rva: usize, section: &SectionTable, file_alignment: u32) -> bool {
    let section_rva = section.virtual_address as usize;
    is_in_range(
        rva,
        section_rva,
        section_rva + section_read_size(section, file_alignment),
    )
}

#[inline]
fn aligned_pointer_to_raw_data(pointer_to_raw_data: usize) -> usize {
    const PHYSICAL_ALIGN: usize = 0x1ff;
    pointer_to_raw_data & !PHYSICAL_ALIGN
}

fn is_in_range(rva: usize, r1: usize, r2: usize) -> bool {
    r1 <= rva && rva < r2
}

#[inline]
fn section_read_size(section: &SectionTable, file_alignment: u32) -> usize {
    fn round_size(size: usize) -> usize {
        const PAGE_MASK: usize = 0xfff;
        (size + PAGE_MASK) & !PAGE_MASK
    }

    let file_alignment = file_alignment as usize;
    let size_of_raw_data = section.size_of_raw_data as usize;
    let virtual_size = section.virtual_size as usize;
    let read_size = {
        let read_size =
            (section.pointer_to_raw_data as usize + size_of_raw_data + file_alignment - 1) & !(file_alignment - 1);
        cmp::min(read_size, round_size(size_of_raw_data))
    };

    if virtual_size == 0 {
        read_size
    } else {
        cmp::min(read_size, round_size(virtual_size))
    }
}
