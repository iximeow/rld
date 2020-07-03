mod ar;
mod coff;
mod arlib;

use coff::*;
use std::collections::HashSet;
use std::env;
use std::io::*;
use std::path::Path;
use std::fs::File;

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

    let mut unresolved_syms = vec![];
    let mut present_syms = vec![];

    for elem in inputs {
        writeln!(log, "\nobj: {}", elem);
//        let mut f = File::open("test/some_module.win.o").unwrap();
        let mut f = File::open(elem).unwrap();
        let mut buf: Vec<u8> = Vec::new();
        f.read_to_end(&mut buf);
        let coff = Coff::parse(buf).unwrap();
        writeln!(log, "{}", coff);
        writeln!(log, "\nUnresolved symbols:");
        for name in coff.needed_symbols_by_name() {
            writeln!(log, "{}", name);
            unresolved_syms.push(name);
        }
        writeln!(log, "\nProvided symbols:");
        for name in coff.provided_symbols_by_name() {
            writeln!(log, "{}", name);
            present_syms.push(name);
        }
    }

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
}
