use failure::{bail, Error, err_msg};
use goblin::pe::PE;
use goblin::pe::data_directories::DataDirectory;
use goblin::pe::section_table::SectionTable;

fn main() -> Result<(), Error> {
    let path = std::env::args()
        .skip(1)
        .next()
        .expect("Path to executable was not specified");
    let file = std::fs::read(path)?;
    let pe = PE::parse(&file)?;
    if pe.header.coff_header.machine != 0x14c {
        bail!("Is not a .Net executable");
    }
    let optional_header = pe.header.optional_header.ok_or_else(|| err_msg("No optional header"))?;
    let cli_header = optional_header.data_directories.data_directories[14].ok_or_else(|| err_msg("No CLI header"))?;
    let section = get_section(&pe, &cli_header)?;
    println!("{:#?}", pe);
    println!("{:?}", cli_header.virtual_address);
    Ok(())
}

fn get_section<'a>(pe: &'a PE, header: &DataDirectory) -> Result<&'a SectionTable, Error> {
    for section in pe.sections.iter() {
        if header.virtual_address >= section.virtual_address && header.virtual_address < section.virtual_address + header.size {
            return Ok(&section);
        }
    }
    bail!("Section for address {} was not found", header.virtual_address)
}