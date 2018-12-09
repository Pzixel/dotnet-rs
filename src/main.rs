use failure::{bail, Error};
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
    println!("Hello, world! {:?}", pe.header);
    Ok(())
}
