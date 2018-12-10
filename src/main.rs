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
    pub flags: u16,
    pub streams: u16,
    pub stream_headers: Vec<StreamHeader<'a>>,
}

#[repr(C)]
#[derive(Debug)]
struct StreamHeader<'a> {
    pub offset: u32,
    pub size: u32,
    pub name: &'a str,
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
        let padding = 4 - *offset % 4;
        if padding < 4 {
            *offset += padding;
        }
        let flags = src.gread_with(offset, endian)?;
        let streams: u16 = src.gread_with(offset, endian)?;
        let mut stream_headers = Vec::with_capacity(streams as usize);
        for _ in 0..streams {
            stream_headers.push(src.gread(offset)?);
            let padding = 4 - *offset % 4;
            if padding < 4 {
                *offset += padding;
            }
        }

        Ok((
            Self {
                signature,
                major_version,
                minor_version,
                _reserved: reserved,
                length,
                version,
                flags,
                streams,
                stream_headers,
            },
            *offset,
        ))
    }
}

impl<'a> TryFromCtx<'a, Endian> for StreamHeader<'a> {
    type Error = scroll::Error;
    type Size = usize;
    // and the lifetime annotation on `&'a [u8]` here
    fn try_from_ctx(src: &'a [u8], endian: Endian) -> Result<(Self, Self::Size), Self::Error> {
        let offset = &mut 0;
        let offset_field = src.gread_with(offset, endian)?;
        let size = src.gread_with(offset, endian)?;
        let name = src.gread(offset)?;
        Ok((
            Self {
                offset: offset_field,
                size,
                name,
            },
            *offset,
        ))
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct TildaStream {
    _reserved: u32,
    pub major_version: u8,
    pub minor_version: u8,
    pub heap_sizes: u8,
    _reserved2: u8,
    pub valid: u64,
    pub sorted: u64,
    pub rows: Vec<(u32, u32)>,
    pub methods: Vec<MethodDef>,
}

impl<'a> TryFromCtx<'a, Endian> for TildaStream {
    type Error = scroll::Error;
    type Size = usize;
    // and the lifetime annotation on `&'a [u8]` here
    fn try_from_ctx(src: &'a [u8], endian: Endian) -> Result<(Self, Self::Size), Self::Error> {
        let offset = &mut 0;
        let _reserved = src.gread_with(offset, endian)?;
        let major_version = src.gread_with(offset, endian)?;
        let minor_version = src.gread_with(offset, endian)?;
        let heap_sizes = src.gread_with(offset, endian)?;
        let _reserved2 = src.gread_with(offset, endian)?;
        let valid = src.gread_with(offset, endian)?;
        let sorted = src.gread_with(offset, endian)?;
        let mut rows = Vec::new();

        let mut j = 1;
        for i in 0..64_u32 {
            if valid & j == j {
                let count = src.gread_with(offset, endian)?;
                rows.push((i, count));
            }
            j <<= 1;
        }

        let table_sizes = [
            10_u32, 6, 14, 0, 6, 0, 14, 0, // 0x00 - 0x07
            6, 0, 6, 0, 6, 0, 0, 0,    // 0x08 - 0x0f
            0, 2, 0, 0, 0, 0, 0, 0,    // 0x10 - 0x17
            0, 0, 0, 0, 0, 0, 0, 0,    // 0x18 - 0x1f
            22, 0, 0, 20               // 0x20 - 0x23
        ];

        let mut methods = Vec::new();

        for (i, count) in rows.iter().cloned() {
            if i == 6 {
                for _ in 0..count {
                    methods.push(src.gread(offset)?);
                }
            } else {
                *offset += (table_sizes[i as usize] * count) as usize;
            }
        }

        Ok((
            Self {
                _reserved,
                major_version,
                minor_version,
                heap_sizes,
                _reserved2,
                valid,
                sorted,
                rows,
                methods
            },
            *offset,
        ))
    }
}

#[repr(C, packed)]
#[derive(Debug, Pread, Pwrite, SizeWith)]
pub struct MethodDef {
    pub rva: u32,
    pub impl_flags: u16,
    pub flags: u16,
    pub name: u16,
    pub signature: u16,
    pub param_list: u16
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

    let offset = offset + root.stream_headers.iter().find(|x| x.name == "#~").unwrap().offset as usize;
    let tilda_stream: TildaStream = file.pread_with(offset, scroll::LE)?;
    println!("{:#?}", tilda_stream);

    let offset = offset + root.stream_headers.iter().find(|x| x.name == "#Strings").unwrap().offset as usize;
    let name: &str = file.pread(offset - 4)?;
    println!("{}", name);
    Ok(())
}

fn find_offset(rva: usize, sections: &[SectionTable], file_alignment: u32) -> Option<usize> {
    for section in sections {
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
