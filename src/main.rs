mod ar;
// mod coff;
mod arlib;

// use coff::*;
use std::collections::HashSet;
use std::env;
use std::fmt;
//use std::io::*;
use std::io::Cursor;
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::fs::File;

use std::rc::Rc;
use std::cell::RefCell;
use std::collections::HashMap;

use object::Relocation;
use object::RelocationEncoding;
use object::RelocationKind;
use object::SectionIndex;
use object::SymbolFlags;
use object::SymbolIndex;
use object::SectionKind;
use object::{read, write};
use object::read::Object;
use object::read::ObjectSection;
use object::read::ObjectSegment;
use object::read::RelocationTarget;
use object::read::SymbolSection;
use object::{Architecture, BinaryFormat, Endianness};

use yaxpeax_arch::{LengthedInstruction, Decoder};

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
        eprintln!("arg {}: {}", i, arg);
        if i == 0 { continue; }
        writeln!(log, "arg: {}", arg);
        if arg.starts_with("/NOLOGO") {
//            config.show_logo(false);
        } else if arg.starts_with("/NXCOMPAT") {
//            config.nxcompat(true);
        } else if arg.starts_with("/LIBPATH") {
            writeln!(log, "Extra libpath dir: {}", arg);
        } else if arg.starts_with("/OUT:") {
//            config.outpath(arg);
        } else if arg.starts_with("/OPT") {
            writeln!(log, "OPT");
        } else if arg.starts_with("/DEBUG") {
//            config.debug(true);
        } else if arg.ends_with(".o") {
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

    // rlibs.push("kernel32.lib".to_string());

    #[derive(Debug, Clone, Copy)]
    struct SegmentObservation {
        input_index: usize,
        segment_size: u64,
    }

    struct SegmentRecords {
        total_size: u64,
        definitions: Vec<SegmentObservation>,
    }

    impl SegmentRecords {
        fn add_observation(&mut self, observation: SegmentObservation) {
            self.total_size += observation.segment_size;
            self.definitions.push(observation);
        }
    }

    impl Default for SegmentRecords {
        fn default() -> Self {
            SegmentRecords {
                total_size: 0,
                definitions: Vec::new(),
            }
        }
    }

    #[derive(Debug, Clone, Copy)]
    struct SectionObservation {
        input_index: usize,
        section_size: u64,
    }

    struct SectionRecords {
        total_size: u64,
        definitions: Vec<SectionObservation>,
    }

    impl SectionRecords {
        fn add_observation(&mut self, observation: SectionObservation) {
            self.total_size += observation.section_size;
            self.definitions.push(observation);
        }
    }

    impl Default for SectionRecords {
        fn default() -> Self {
            SectionRecords {
                total_size: 0,
                definitions: Vec::new(),
            }
        }
    }

    #[derive(Debug, Eq, Hash, PartialEq)]
    enum SectionDesc {
        ByKind(u8, String),
        ByName(String),
    }

    #[derive(Debug, Eq, Hash, PartialEq)]
    struct SegmentDesc {
        name: Vec<u8>,
        kind: u8,
    }

    impl fmt::Display for SegmentDesc {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{}", unsafe { std::str::from_utf8_unchecked(&self.name) })?;
            write!(f, ": {:?}", unsafe { std::mem::transmute::<u8, SectionKind>(self.kind) })
        }
    }

    // sections observed among inputs, and their sizes. primarily useful to reserve enough space
    // when performing final linking.
    // let internal_sections: Rc<RefCell<HashMap<String, SectionRecords>>> = Rc::new(RefCell::new(HashMap::new()));
    let internal_segments: Rc<RefCell<HashMap<SegmentDesc, SegmentRecords>>> = Rc::new(RefCell::new(HashMap::new()));
    let internal_sections: Rc<RefCell<HashMap<SectionDesc, SectionRecords>>> = Rc::new(RefCell::new(HashMap::new()));
    // 
    let internal_symbols: Rc<RefCell<Vec<(usize, usize)>>> = Rc::new(RefCell::new(Vec::new()));

    // we're going to collapse like-kinded sections together, so figure out the appropriate segment for a given section.
    fn segment_for_desc(obj: &object::write::Object, desc: &SectionDesc) -> SegmentDesc {
        use object::write::StandardSegment;
        match desc {
            SectionDesc::ByName(name) => {
                SegmentDesc {
                    name: name.as_bytes().to_vec(),
                    kind: SectionKind::Unknown as u8
                }
            },
            SectionDesc::ByKind(kind, name) => {
                match unsafe { std::mem::transmute::<u8, SectionKind>(*kind) } {
                    SectionKind::Text => {
                        SegmentDesc {
                            name: b".text".to_vec(), //obj.segment_name(StandardSegment::Text).to_vec(),
                            kind: SectionKind::Text as u8
                        }
                    }
                    SectionKind::Data => {
                        SegmentDesc {
                            name: b".data".to_vec(), //obj.segment_name(StandardSegment::Data).to_vec(),
                            kind: SectionKind::Data as u8
                        }
                    }
                    SectionKind::ReadOnlyData => {
                        SegmentDesc {
                            name: b".rodata".to_vec(),
                            kind: SectionKind::ReadOnlyData as u8
                        }
                    }
                    SectionKind::Metadata => {
                        SegmentDesc {
                            name: name.as_bytes().to_vec(),
                            kind: SectionKind::Metadata as u8
                        }
                    }
                    other => {
                        SegmentDesc {
                            name: name.as_bytes().to_vec(),
                            kind: other as u8
                        }
                    }
                }
            }
        }
    }

    use object::write::Object as WriteObject;
    let mut result = WriteObject::new(
        BinaryFormat::Elf,
        Architecture::X86_64,
        Endianness::Little
    );

    for (idx, elem) in inputs.iter().enumerate() {
        let mut f = File::open(&elem).unwrap();
        writeln!(log, "linking {}", elem);
        let mut buf: Vec<u8> = Vec::new();
        f.read_to_end(&mut buf);
        // let obj = object::read::coff::CoffFile::parse(&buf).unwrap();
        let obj = object::read::File::parse(&buf).unwrap();
        // summarize_coff(&obj, &elem);
        // summarize_obj(&obj, &elem);
        for sec in obj.sections() {
            let section_name = sec.name().expect("section name is accessible");
            let desc = if sec.kind() != SectionKind::Unknown {
                SectionDesc::ByKind(sec.kind() as u8, section_name.to_string())
            } else {
                SectionDesc::ByName(section_name.to_string())
            };
            // relocations are handled in the linker, we won't know what makes it through until
            // we're pretty much done linking.
            if section_name.starts_with(".rela.") || section_name.starts_with(".rel.") {
                continue;
            }
            // add or grow a segment for this section
            internal_segments
                .borrow_mut()
                .entry(segment_for_desc(&result, &desc))
                .or_default()
                .add_observation(
                    SegmentObservation {
                        input_index: idx,
                        segment_size: sec.size()
                    }
                );
            // and keep tabs on what sections we've seen where
            internal_sections
                .borrow_mut()
                .entry(desc)
                .or_default()
                .add_observation(
                    SectionObservation {
                        input_index: idx,
                        section_size: sec.size(),
                    }
                );
        }
    }

    // as we're building up the object, maintain a table to know where we've placed internal
    // symbols.
    let mut symbolmap: HashMap<SymbolIndex, (SectionIndex, u64)> = HashMap::new();
    let mut sections: HashMap<u8, Vec<u8>> = HashMap::new();
    let mut section_ids: HashMap<u8, write::SectionId> = HashMap::new();

    // when we find a home for a global symbol in the result, record that so we can fix
    // inter-object references later.
    let mut global_symbols: HashMap<String, (SectionIndex, u64)> = HashMap::new();

    for (desc, records) in &*internal_segments.borrow() {
        writeln!(log, "segment {} needs at least {} bytes", desc, records.total_size);
        let section_id = result.add_section(
            Vec::new(), // we'll build data for sections elsewhere and set it later
            desc.name.clone(),
            unsafe { std::mem::transmute::<u8, SectionKind>(desc.kind) }
        );
        section_ids.insert(desc.kind, section_id);
        // todo: handle wrapping of usize
        sections.insert(desc.kind, Vec::with_capacity(records.total_size as usize));
    }

    // as objects are appended, locations are solidified relative to their containing segment, but
    // inter-segment offsets are undetermined until segment addresses themselves are decided.
    //
    // this tracks what addresses in a given segment are relative to which other segments, and the
    // offsets of that relative fixup
    let mut global_section_relocations: HashMap<write::SectionId, Vec<(write::SectionId, u64)>> = HashMap::new();

    // weak symbols need to be tracked, but are fallbacks for when no global symbol has already
    // been added. we don't know which weak symbols are necessary until we've found a reference to
    // them that also has not been satisfied by a strong symbol, so instead track where we've seen
    // weak symbols in imputs we've processed.
    let mut weak_symbols: HashMap<String, usize> = HashMap::new();

    let mut intra_object_unresolved: Vec<String> = Vec::new();
    let mut input_provided_symbols: HashSet<String> = HashSet::new();

    let mut writers: HashMap<u8, Cursor<&mut Vec<u8>>> = HashMap::new();
    for (k, v) in &mut sections {
        writers.insert(*k, Cursor::new(v));
    }
    eprintln!("building .data...");
    // ok, try to build .data
    for (idx, elem) in inputs.iter().enumerate() {
        let mut f = File::open(&elem).unwrap();
        let mut buf: Vec<u8> = Vec::new();
        f.read_to_end(&mut buf);

        let obj = object::read::File::parse(&buf).unwrap();
        let mut symbols_by_section: HashMap<Option<SectionIndex>, Vec<(SymbolIndex, read::Symbol)>> = HashMap::new();
        for (sym_idx, sym) in obj.symbols() {
            symbols_by_section
                .entry(sym.section_index())
                .or_default()
                .push((sym_idx, sym)); // todo: index by address so this doesn't accidentally quadradic
        }

        // and as we figure out homes for local symbols, we know where data intra-segment is, but
        // don't have a stable address to line up inter-segment references. so record inter-segment
        // references explicitly and fix them up once we know all segment sizes and can compute a
        // total layout. this is a map of segment -> Vec<(segment, reloc)> indicating all
        // relocations (from) -> targeting (to, reloc).
        let mut local_section_refs: HashMap<write::SectionId, Vec<(read::SectionIndex, write::Relocation)>> = HashMap::new();

        // track what symbols this object references, and where those references are made, so we
        // can clean up intra-object references and know when to add dynamic references later
        let mut local_symbol_refs: HashMap<read::SymbolIndex, Vec<(write::SectionId, u64)>> = HashMap::new();

        // one more table to track where symbols _exported_ by this object have been moved to. this
        // is the other end of cleaning up intra-object links. this maps a local symbol to the
        // section/offset it now lives at.
        let mut local_moved_symbols: HashMap<read::SymbolIndex, (write::SectionId, u64)> = HashMap::new();

        // one more table to track where sections in this object have been moved to. this
        // is the other end of cleaning up intra-object links. this maps a local symbol to the
        // section/offset it now lives at.
        let mut local_moved_sections: HashMap<read::SectionIndex, (write::SectionId, u64)> = HashMap::new();

        // offsets of 
        let mut inner_section_offsets: HashMap<SectionIndex, u64> = HashMap::new();
        let data_section_id = *section_ids.get(&(SectionKind::Data as u8)).expect("data section is defined");
        let rodata_section_id = *section_ids.get(&(SectionKind::ReadOnlyData as u8)).expect("rodata section is defined");

        for sec in obj.sections() {
            if SectionKind::Text == sec.kind() || SectionKind::Data == sec.kind() || SectionKind::ReadOnlyData == sec.kind() {
                let data_section_kind = sec.kind() as u8;
                let data_section_id = *section_ids.get(&data_section_kind).expect("section kind has been seen and a matching output segment has been declared");
                let mut data_writer = writers.get_mut(&data_section_kind).unwrap_or_else(|| {
                    panic!("writer for section {:?} exists", sec.kind())
                });
                let position = data_writer.position();
                writeln!(log, "found data section: {:?}. copying {} bytes to section for {:?} at {}", sec.name(), sec.data().unwrap().len(), sec.kind(), position);
                data_writer.write(sec.data().unwrap());
                local_moved_sections.insert(sec.index(), (*section_ids.get(&data_section_kind).unwrap(), sec.address() + position));
                if let Some(symbols) = symbols_by_section.get(&Some(sec.index())) {
                    for (sym_idx, sym) in symbols {
                        local_moved_symbols.insert(*sym_idx, (data_section_id, sym.address() + position));
                        // make a new symbol for the output
                        let new_sym = write::Symbol {
                            name: sym.name().map(|x| x.as_bytes().to_vec()).unwrap_or_else(|| Vec::new()),
                            // todo: check overflow
                            value: sym.address() + position,
                            size: sym.size(),
                            kind: sym.kind(),
                            scope: sym.scope(),
                            weak: sym.is_weak(),
                            section: write::SymbolSection::Section(data_section_id),
                            flags: match sym.flags() {
                                SymbolFlags::Elf { st_info, st_other } => {
                                    SymbolFlags::Elf {
                                        st_info, st_other
                                    }
                                }
                                o => { panic!("bad flags type: {:?}", o); }
                            }
                        };
                        if sym.is_weak() {
                            weak_symbols.insert(sym.name().expect("weak symbols have names").to_string(), idx);
                        } else {
                            // add a symbol for the data we just copied..
                            result.add_symbol(new_sym);
                            if sym.is_global() {
                                writeln!(log, "adding global symbol {} from {}", sym.name().expect("has name"), elem);
                                if !input_provided_symbols.insert(sym.name().expect("symbol has a name").to_string()) {
                                    writeln!(log, "duplicate symbol {:?}", sym);
                                    panic!("duplicate symbol {}", sym.name().expect("symbol has a name"));
                                }
                            }
                        }
                    }
                }

                for (addr, reloc) in sec.relocations() {
 //                   eprintln!("retaining relocation {:?}", reloc);
                    match reloc.target() {
                        RelocationTarget::Symbol(sym_idx) => {
//                            eprintln!("  oh and that target is the symbol {:?}", obj.symbol_by_index(sym_idx).expect("valid index"));
                            let sym = obj.symbol_by_index(sym_idx).expect("valid symbol index");
//                            eprintln!("<sym {:?}>", sym);
                            if sym.name() != Some("") || sym.address() != 0 {
//                                eprintln!("  oh and that target is {}", sym.name().expect("name").to_owned());
                                local_symbol_refs
                                    .entry(sym_idx)
                                    .or_default()
                                    .push((data_section_id, addr + position));
                            } else {
                                // reloc target might be named by the start of a section in
                                // this object
                                eprintln!("section referent of reloc: {:?}", reloc);
                                assert!(sym.address() == 0, "can't handle section relocations with nonzero addend ...yet");
                                if let SymbolSection::Section(idx) = sym.section() {
                                    let retained_reloc = write::Relocation {
                                        offset: addr + position, // todo: check for overflow
                                        size: reloc.size(),
                                        kind: reloc.kind(),
                                        encoding: reloc.encoding(),
                                        addend: reloc.addend(),
                                        symbol: result.section_symbol(data_section_id),
                                    };
                                    local_section_refs
                                        .entry(data_section_id)
                                        .or_default()
                                        .push((idx, retained_reloc));
//                                    eprintln!("  oh and that target is {}", obj.section_by_index(idx).unwrap().name().unwrap());
                                } else {
                                    panic!("reloc target is not a section, also doesn't have a name? {:?}", reloc);
                                }
                            }
                        }
                        RelocationTarget::Section(sec_idx) => {
                            eprintln!("  oh and that target is the section {:?}", obj.section_by_index(sec_idx).expect("valid index").name());
                        }
                    }
                }
            }
        }

        for (result_section_id, source_section_refs) in &local_section_refs {
            for (source_section, reloc) in source_section_refs {
                let (moved_section_dest_id, moved_section_dest_offset) =
                    local_moved_sections.get(&source_section).expect("moved section has a source");

                if moved_section_dest_id == result_section_id {
                    writeln!(log, "inter-section ref has become intra-section ref for reloc {:?}", reloc);
                } else {
                    writeln!(log, "inter-section ref is still inter-section ref for reloc {:?}", reloc);
                }
            }
        }

        for (sym, local_sym_refs) in local_symbol_refs {
            match local_moved_symbols.get(&sym) {
                Some((section, offset)) => {
                    // walk through references to this symbol to see if any cohabit in the symbol's
                    // new home
                    for (sym_ref_section, sym_ref_offset) in local_sym_refs {
                        // if it's a local symbol reference, we can do one of two things:
                        // * if it's a local reference across segments that have now been joined, apply the
                        // relocation on the WIP section body and discard the relocation
                        // * if it's a local reference across segments that have not been joined together
                        // (for example, data.rel.ro reference to rodata), we can incorporate the current
                        // offset of the referent in the destination segment, and note that we must
                        // additionally adjust those bytes by whatever final offset the referent has
                        let is_coresident_with_referent = sym_ref_section == *section;
                        if is_coresident_with_referent {
                            writeln!(log, "can remove reference {:?},{} to {:?}", sym_ref_section, sym_ref_offset, sym);
                        } else {
                            writeln!(log, "remote reference {:?},{} to {:?}", sym_ref_section, sym_ref_offset, sym);
                        }
                    }
                }
                None => {
                    let sym = obj.symbol_by_index(sym).expect("valid index");
                    let name = sym.name().expect("intra-object symbol references should have a name");
                    if name == "_Unwind_Resume" {
                        writeln!(log, "FOUND _UNWIND_RESUME: {:?}", sym);
                    }
                    writeln!(log, "unsatisfied symbol: {:?}", name);
                    intra_object_unresolved.push(name.to_string());
                }
            }
        }

        writeln!(log, "linked object unresolved section refs: {:?}", local_section_refs);
    }

    eprintln!("unresolved symbols must be found in the following libraries: {:?}", rlibs);

    fn resolve_symbol(log: &mut File, rlibs: &[String], name: &str) -> Result<Vec<u8>, String> {
        for path in rlibs {
            writeln!(log, "looking at rlib {}", path);
            let mut f = File::open(&path).unwrap();
            let mut buf: Vec<u8> = Vec::new();
            f.read_to_end(&mut buf);

            let mut archive = ar::Archive::new(Cursor::new(&buf));

            while let Some(entry) = archive.next_entry() {
                match entry {
                    Ok(mut entry) => {
                        if !entry.header().identifier().ends_with(b".o") {
                            continue;
                        }
                        writeln!(log, "looking at object {}", unsafe { std::str::from_utf8_unchecked(entry.header().identifier()) });
                        let mut objbuf: Vec<u8> = Vec::new();
                        entry.read_to_end(&mut objbuf);
                        let obj = read::File::parse(&objbuf).unwrap();
                        for sym in obj.symbols() {
                            if sym.1.is_undefined() {
                                continue;
                            }
                            if sym.1.name() == Some(name) {
                                writeln!(log, "found object containing {}", name);
                                return Ok(objbuf);
                            }
                        }
                    }
                    Err(err) => {
                        writeln!(log, "err reading archive entry in {}, {}", path, err);
                    }
                }
            }
        }

        Err("no thank you".to_string())
    }

    let mut unresolved_dynamic: HashSet<String> = HashSet::new();

    for name in &intra_object_unresolved {
        if input_provided_symbols.contains(name) {
            writeln!(log, "symbol {} is provided by an input object", name);
            continue;
        }
        let result = resolve_symbol(&mut log, &rlibs, name);
        writeln!(log, "resolved to? {}", result.is_ok());
        if result.is_err() {
            writeln!(log, "unresolved symbol {}", name);
            unresolved_dynamic.insert(name.to_string());
        }
    }

    writeln!(log, "end-of-day unresolved symbols: {:?}", unresolved_dynamic);

    panic!("hello");
}

fn summarize_obj(obj: &object::read::File, path: &str) {
    eprintln!("input {} is a COFF for architecture {:?}", path, obj.architecture());
    eprintln!("bitness? {}", obj.is_64());
    for seg in obj.segments() {
        eprintln!("section {:?}, {:#x} @ {:#x}, data: {:x?}", seg.name(), seg.address(), seg.size(), seg.data());
    }
    for sec in obj.sections() {
        if sec.relocations().next().is_some() {
            eprintln!("!!! HAS RELOCATIONS:");
            for reloc in sec.relocations() {
                eprintln!("  {:?}", reloc);
            }
        }
        if sec.name().map(|name| name.starts_with(".text")) == Ok(true) {
            // special-case text to show disassembly with relocations
            eprintln!("section .text, {:#x} @ {:#x}, kind: {:?}, flags: {:?}", sec.size(), sec.address(), sec.kind(), sec.flags());
            let bytes = sec.data().expect("text has data");
            let mut offset = 0u64;
            let decoder = <yaxpeax_x86::long_mode::Arch as yaxpeax_arch::Arch>::Decoder::default();
            while offset < bytes.len() as u64 {
                let inst = decoder.decode(bytes[offset as usize..].iter().cloned()).expect("can decode");
                for (_, sym) in obj.symbols() {
                    if sym.section_index() == Some(sec.index()) && sym.address() == offset {
                        eprintln!("{} (+{})", sym.name().expect("has a name"), sym.size());
                    }
                }
                eprintln!("  {:#x}: {}", offset, inst);
                for (addr, reloc) in sec.relocations() {
                    if addr >= offset as u64 && addr < (offset + inst.len()) as u64 {
                        let (name, sym_offset) = match reloc.target() {
                            RelocationTarget::Symbol(sym_idx) => {
                                let sym = obj.symbol_by_index(sym_idx).expect("valid symbol index");
                                eprintln!("<sym {:?}>", sym);
                                if sym.name() != Some("") || sym.address() != 0 {
                                    (sym.name().expect("name").to_owned(), sym.address())
                                } else {
                                    // reloc target might be named by the start of a section in
                                    // this object
                                    if let SymbolSection::Section(idx) = sym.section() {
                                        (obj.section_by_index(idx).expect("valid section index").name().expect("name").to_owned(), sec.address())
                                    } else {
                                        panic!("reloc target is not a section, also doesn't have a name? {:?}", reloc);
                                    }
                                }
                            },
                            RelocationTarget::Section(sec_idx) => {
                                let sec = obj.section_by_index(sec_idx).expect("valid section index");
                                (sec.name().expect("name").to_owned(), sec.address())
                            },
                        };
                        eprintln!("    reloc ({:?}) +{}: {}(+{:#x})",
                            reloc.target(),
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
                        let sym = obj.symbol_by_index(sym_idx).expect("valid symbol index");
                        eprintln!("{} @ {:#x}(+{:#x}), global? {}, local? {}", sym.name().expect("name"), sym.address(), sym.size(), sym.is_global(), sym.is_local());
                    },
                    RelocationTarget::Section(sec_idx) => {
                        let sec = obj.section_by_index(sec_idx).expect("valid section index");
                        eprintln!("section {}", sec.name().expect("name"));
                    },
                };
            }
        }
    }
}

fn summarize_coff(coff: &object::coff::CoffFile, path: &str) {
    eprintln!("input {} is a COFF for architecture {:?}", path, coff.architecture());
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
                for (_, sym) in coff.symbols() {
                    if sym.section_index() == Some(sec.index()) && sym.address() == offset {
                        eprintln!("{} (+{})", sym.name().expect("has a name"), sym.size());
                    }
                }
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
