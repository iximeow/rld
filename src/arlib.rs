use coff::*;
use ::ObjectFile;

use std::fs::File;
use std::io::Read;

use std::str;

use ar::Archive;

/*
 *  For a .lib (or .lib-like files)
 *  eg an `ar` archive of object files
 */
pub struct ArLib {
    archive: Archive<File>
}

impl ArLib {
    pub fn new(f: File) -> ArLib {
        let archive = Archive::new(f);
        ArLib {
            archive: archive
        }
    }
    pub fn objects(&mut self) -> Vec<Box<ObjectFile>> {
        let mut result = vec![];
        while let Some(entry_result) = self.archive.next_entry() {
            let mut entry = entry_result.unwrap();
            let mut body: Vec<u8> = vec![];
            entry.read_to_end(&mut body);
            let name = str::from_utf8(entry.header().identifier().clone()).unwrap();
            println!("Looking at {}", name);
            if name.ends_with(".o") || name.ends_with(".obj") {
                result.push(Box::new(Coff::parse(body).unwrap()) as Box<ObjectFile>);
            }
        }
        return result;
    }
}
