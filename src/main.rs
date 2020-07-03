mod ar;
// mod coff;
mod arlib;

// use coff::*;
use std::collections::HashSet;
use std::env;
use std::io::*;
use std::path::Path;
use std::fs::File;

use object::read::Object;
use object::read::ObjectSection;
use object::read::ObjectSegment;
use object::read::RelocationTarget;

use yaxpeax_arch::{LengthedInstruction, AddressBase, Arch, Decoder, Instruction};

pub trait ObjectFile {
    fn provides_symbol(&self, name: &str) -> bool;
    fn dependencies(&self) -> HashSet<String>;
    fn provides(&self) -> HashSet<String>;
}

fn main() {
    let mut log = File::create("/tmp/link.exe.log").unwrap();

    writeln!(log, "helo");
//    let mut config = Config::new();
    let mut inputs = vec![];
    let mut rlibs = vec![];

    for (i, arg) in env::args().enumerate() {
        if i == 0 { continue; }
        writeln!(log, "arg: {}", arg);
        if (arg.starts_with("/NOLOGO")) {
//            config.show_logo(false);
        } else if (arg.starts_with("/NXCOMPAT")) {
//            config.nxcompat(true);
        } else if (arg.starts_with("/LIBPATH")) {
            writeln!(log, "Extra libpath dir: {}", arg);
        } else if (arg.starts_with("/OUT:")) {
//            config.outpath(arg);
        } else if (arg.starts_with("/OPT")) {
            writeln!(log, "OPT");
        } else if (arg.starts_with("/DEBUG")) {
//            config.debug(true);
        } else if (arg.ends_with(".o")) {
            writeln!(log, "Input! {}", arg);
            if Path::new(&arg).is_file() {
                inputs.push(arg);
            } else {
                println!("File not found: {}", arg);
            }
        } else if arg.ends_with(".rlib") || arg.ends_with(".lib") {
            if Path::new(&arg).is_file() {
                rlibs.push(arg);
            } else {
                println!("File not found: {}", arg);
            }
        }
    }

    rlibs.push("kernel32.lib".to_string());

    let mut unresolved_syms: Vec<String> = vec![];
    let mut present_syms: Vec<String> = vec![];

    for elem in inputs {
        writeln!(log, "\nobj: {}", elem);
//        let mut f = File::open("test/some_module.win.o").unwrap();
        let mut f = File::open(&elem).unwrap();
        let mut buf: Vec<u8> = Vec::new();
        f.read_to_end(&mut buf);
        let coff = object::read::coff::CoffFile::parse(&buf).unwrap();
        eprintln!("input {} is a COFF for architecture {:?}", elem, coff.architecture());
        eprintln!("bitness? {}", coff.is_64());
        for seg in coff.segments() {
            eprintln!("section {:?}, {:#x} @ {:#x}, data: {:x?}", seg.name(), seg.address(), seg.size(), seg.data());
        }
        for sec in coff.sections() {
            if sec.name() == Ok(".text") {
                // special-case text to show disassembly with relocations
                eprintln!("section .text, {:#x} @ {:#x}, kind: {:?}, flags: {:?}", sec.size(), sec.address(), sec.kind(), sec.flags());
                let bytes = sec.data().expect("text has data");
                let mut offset = 0u64;
                let decoder = <yaxpeax_x86::long_mode::Arch as yaxpeax_arch::Arch>::Decoder::default();
                while offset < bytes.len() as u64 {
                    let inst = decoder.decode(bytes[offset as usize..].iter().cloned()).expect("can decode");
                    eprintln!("  {:#x}: {}", offset, inst);
                    for (addr, reloc) in sec.relocations() {
                        if addr >= offset as u64 && addr < (offset + inst.len()) as u64 {
                            let (name, sym_offset) = match reloc.target() {
                                RelocationTarget::Symbol(sym_idx) => {
                                    let sym = coff.symbol_by_index(sym_idx).expect("valid symbol index");
                                    (sym.name().expect("name").to_owned(), sym.address())
                                },
                                RelocationTarget::Section(sec_idx) => {
                                    let sec = coff.section_by_index(sec_idx).expect("valid section index");
                                    (sec.name().expect("name").to_owned(), sec.address())
                                },
                            };
                            eprintln!("    reloc +{}: {}(+{:#x})",
                                addr - offset as u64,
                                name,
                                sym_offset,
                            );
                        }
                    }
                    offset += inst.len();
                }
            } else {
                eprintln!("section {:?}, {:#x} @ {:#x}, data: {:x?}. kind: {:?}, flags: {:?}", sec.name(), sec.size(), sec.address(), sec.data(), sec.kind(), sec.flags());
                for (addr, reloc) in sec.relocations() {
                    eprint!("  reloc: {:#x}: ", addr);
                    eprint!("{:?}, {:?}, {}, target:", reloc.kind(), reloc.encoding(), reloc.size());
                    match reloc.target() {
                        RelocationTarget::Symbol(sym_idx) => {
                            let sym = coff.symbol_by_index(sym_idx).expect("valid symbol index");
                            eprintln!("{} @ {:#x}(+{:#x}), global? {}, local? {}", sym.name().expect("name"), sym.address(), sym.size(), sym.is_global(), sym.is_local());
                        },
                        RelocationTarget::Section(sec_idx) => {
                            let sec = coff.section_by_index(sec_idx).expect("valid section index");
                            eprintln!("section {}", sec.name().expect("name"));
                        },
                    };
                }
            }
        }
    }
    /*

    let mut needed_syms = unresolved_syms.iter().filter(|n| !present_syms.contains(n)).collect::<Vec<&String>>();
    needed_syms.sort();
    needed_syms.dedup();

    writeln!(log, "\n\nEnd-of-day unresolved symbols:");
    for n in needed_syms {
        writeln!(log, "{}", n);
    }

    let mut global_provided: HashSet<String> = HashSet::new();
    let mut global_needed: HashSet<String> = HashSet::new();
    let mut duplicates: HashSet<String> = HashSet::new();

    for rlib in rlibs {
        writeln!(log, "lib: {}", rlib);
        let mut archive = arlib::ArLib::new(File::open(rlib).unwrap());
        let mut provided: HashSet<String> = HashSet::new();
        let mut needed: HashSet<String> = HashSet::new();
        for obj in archive.objects() {
            for p in obj.provides() {
                provided.insert(p.to_owned());
                if global_provided.contains(&p) {
                    duplicates.insert(p.to_owned());
                } else {
                    global_provided.insert(p.to_owned());
                }
            }
            for d in obj.dependencies() {
                needed.insert(d.to_owned());
                global_needed.insert(d.to_owned());
            }
        }

        println!("provides: {:?}", provided);
        println!("needs: {:?}", needed.difference(&provided));
    }

    println!("provides: {:?}", global_provided);
    writeln!(log, "provides: {:?}", global_provided);
    println!("needs: {:?}", global_needed.difference(&global_provided));
    writeln!(log, "needs: {:?}", global_needed.difference(&global_provided));
    println!("duplicates: {:?}", duplicates);
    writeln!(log, "duplicates: {:?}", duplicates);
    */
}
