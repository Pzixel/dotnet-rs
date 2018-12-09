use failure::{bail, Error, err_msg};
use goblin::pe::PE;

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
    println!("{:#?}", pe);
    println!("{:?}", cli_header.virtual_address);
    Ok(())
}
