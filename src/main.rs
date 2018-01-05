mod coff;

use coff::*;
use std::io::*;
use std::fs::File;

fn main() {
    println!("helo");
    let mut f = File::open("test/some_module.win.o").unwrap();
    let mut buf: Vec<u8> = Vec::new();
    f.read_to_end(&mut buf);
    let coff = Coff::parse(buf).unwrap();
    println!("{}", coff);
}
