use std;
use std::collections::HashSet;
use std::fmt;
use std::fmt::Display;

/// The Microsoft PE format is largely an extension to the COFF format, which is why PE is also
/// sometimes written as PE/COFF. These structures, then, often have two names, or at least two
/// names for a given field - the COFF name, and the Microsoft name.
///
/// The Microsoft information comes from MSDN documentation, here:
/// https://msdn.microsoft.com/en-us/library/windows/desktop/ms680547(v=vs.85).aspx#optional_header__image_only_

/// This is the base struct describing a COFF image, very much as the spec would describe one.
#[derive(Debug)]
pub struct Coff {
    f: FileHeader,
    opt: Option<OptionalHeader>,
    sect: Vec<SectionHeader>,
    pub sym: SymbolTable,
    pub strings: StringTable
}

impl Display for Coff {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Header: {:?}", self.f)?;
        writeln!(f, "OptionalHeader: {:?}", self.opt)?;
        for hdr in self.sect.iter() {
            writeln!(f, "Section: {}", hdr)?;

            if let &Some(ref relocs) = &hdr.relo_table {
                writeln!(f, "Relocations:");
                for reloc in relocs.entries.iter() {
                    writeln!(f, "  {:>#8x}: RELOC {:#x} ({}) {:?}",
                        reloc.vaddr,
                        reloc.sym_idx,
                        self.sym.lookup(reloc.sym_idx).unwrap().n_name.to_string(&self.strings).unwrap_or("<Invalid name>".to_owned()).to_owned(),
                        reloc.reloc_type
                    );
                }
            }

            if let &Some(ref linenos) = &hdr.lineno_table {
                write!(f, "Line numbers:");
            }
        }
        writeln!(f, "{:^68} | n_value    | scnum | type  | sclass|numaux", "Symbols:");
        for elem in &self.sym.entries {
            let name = elem.n_name.to_string(&self.strings).unwrap_or("<Invalid name>".to_owned());
            writeln!(f, "Symbol: {:<60} | {:>#10x} | {:>5} | {:>5} | {:>5} | {:>5}",
                name, elem.n_value, elem.n_scnum,
                elem.n_type, elem.n_sclass, elem.n_numaux
            );
            if let &Some(ref entries) = &elem.n_auxentries {
                for aux in entries {
                    writeln!(f, "  Aux entry: {}", aux);
                }
            }
        }
        Ok(())
    }
}

impl ::ObjectFile for Coff {
    fn provides_symbol(&self, name: &str) -> bool {
        self.provided_symbols_by_name().contains(&name.to_string())
    }
    fn dependencies(&self) -> HashSet<String> {
        self.needed_symbols_by_name().into_iter().collect::<HashSet<String>>()
    }
    fn provides(&self) -> HashSet<String> {
        self.provided_symbols_by_name().into_iter().collect::<HashSet<String>>()
    }
}

impl Coff {
    pub fn needed_symbols_by_name(&self) -> Vec<String> {
        self.sym.entries.iter()
            .filter(|sym| sym.n_sclass == 2 && sym.n_scnum == 0)
            .map(|sym| sym.n_name.to_string(&self.strings).unwrap())
            .collect()
    }

    pub fn provided_symbols_by_name(&self) -> Vec<String> {
        self.sym.entries.iter()
            .filter(|sym| !(sym.n_sclass == 2 && sym.n_scnum == 0))
            .map(|sym| sym.n_name.to_string(&self.strings).unwrap())
            .collect()
    }

    pub fn parse(bytes: Vec<u8>) -> Result<Coff, ParseErr> {
        let (file_header, next) = FileHeader::parse(&bytes, 0).unwrap();
        let (opthdr, offset_after_opt) = if file_header.f_opthdr != 0 {
            (Some(OptionalHeader::parse(&bytes, next, file_header.f_opthdr).unwrap()), next + file_header.f_opthdr as usize)
        } else {
            (None, next)
        };
        let mut section_headers: Vec<SectionHeader> = Vec::new();
        let mut scn_hdr_offset = offset_after_opt;
        for i in 0..file_header.f_nscns {
            let hdr = SectionHeader::parse(&bytes, scn_hdr_offset).unwrap();
            scn_hdr_offset += SectionHeader::size();
            section_headers.push(hdr);
        }
        let (symtab, strtab_offset) = SymbolTable::parse(&bytes, file_header.f_symptr as usize, file_header.f_nsyms as usize).unwrap();
        let str_data = &bytes[strtab_offset..];
        Ok(Coff {
            f: file_header,
            opt: opthdr,
            sect: section_headers,
            sym: symtab,
            strings: StringTable {
                data: str_data.to_vec()
            }
        })
    }
}

#[derive(Debug)]
pub enum ParseErr {
    Unknown(String)
}

#[derive(Debug)]
pub struct SymbolTable {
    pub entries: Vec<SymbolEntry>
}

impl SymbolTable {
    fn parse(buf: &[u8], offset: usize, records: usize) -> Result<(SymbolTable, usize), ParseErr> {
        let mut entries: Vec<SymbolEntry> = Vec::new();

        let mut start = offset;
        let mut entries_read = 0;
        while entries_read < records {
            let (mut entry, next) = SymbolEntry::parse(buf, start).unwrap();
            entries_read += 1 + entry.n_numaux as usize;
            start = next;
            entries.push(entry);
        }

        Ok((SymbolTable { entries: entries }, start))
    }
    fn lookup(&self, idx: u32) -> Option<&SymbolEntry> {
        let mut curr = 0;
        for entry in &self.entries {
            if curr == idx as usize {
                return Some(entry);
            } else {
                curr += 1 + entry.n_numaux as usize;
            }
        }
        None
    }
}

#[derive(Debug)]
pub struct SymbolEntry {
    pub n_name: StringEntry,
    pub n_value: u32,
    pub n_scnum: u16,
    pub n_type: u16,
    pub n_sclass: u8,
    pub n_numaux: u8,
    pub n_auxentries: Option<Vec<AuxEntry>>
}

#[derive(Debug)]
pub enum AuxEntry {
    // TagIndex, TotalSize, PointerToLinenumber, PointerToNextFunction
    FunctionDef(u32, u32, u32, u32, u16),
    // Length, NumReloc, NumLineno, Checksum (applicable for comdat), Number, Selection (COMDAT
    // selection number
    SectionDef(u32, u16, u16, u32, u16, u8, u8, u8, u8),
    Unknown(Vec<u8>)
}

impl Display for AuxEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &AuxEntry::FunctionDef(tag, size, ptr_lno, ptr_nextfn, unused) => {
                write!(f, "FnDef: tag:{:>#8x}, size:{:>#8x}, ptr_lno:{:>#8x}, ptr_nextfn:{:>#8x}", tag, size, ptr_lno, ptr_nextfn)
            },
            &AuxEntry::SectionDef(length, nreloc, nlineno, checksum, number, selection, _, _, _) => {
                write!(f, "SectionDef: length:{:>#8x}, nreloc:{:>#8x}, nlineno:{:>#8x}", length, nreloc, nlineno);
                // if this is symbol has comdat bits set, assume those were verified at parse-time
                if selection == 5 {
                    write!(f, ", comdat_section:{}, checksum:{:8x}", number, checksum)
                } else {
                    write!(f, ", selection:{}, comdat params not applicable ({}, {:8x})", selection, number, checksum)
                }
            },
            &AuxEntry::Unknown(ref bytes) => {
                write!(f, "Unknown: {}", bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>())
            }
        }
    }
}

impl Display for SymbolEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl SymbolEntry {
    fn size() -> usize {
        8 + 4 + 2 + 2 + 1 + 1
    }
    fn parse(buf: &[u8], offset: usize) -> Result<(SymbolEntry, usize), ParseErr> {
        let mut curr_ofs = offset;
        let as_vec = buf.to_vec();
        let mut entry = SymbolEntry::parse_non_recursive(&as_vec, curr_ofs);
        curr_ofs += SymbolEntry::size();

        match entry {
            Ok(mut symbol) => {
                if symbol.n_numaux > 0 {
                    let mut aux_entries: Vec<AuxEntry> = Vec::new();

                    for i in 0..symbol.n_numaux {
                        let next = if curr_ofs + SymbolEntry::size() > buf.len() {
                            Err(ParseErr::Unknown("Not enough data for aux entry".to_owned()))
                        } else {
                            let bytes = as_vec[curr_ofs..(curr_ofs + SymbolEntry::size())].to_vec();
                            let aux = if symbol.n_sclass == 2 && symbol.n_type == 0x20 && symbol.n_scnum > 0 {
                                AuxEntry::FunctionDef(
                                    bytes.read_u32(0).unwrap(),
                                    bytes.read_u32(4).unwrap(),
                                    bytes.read_u32(8).unwrap(),
                                    bytes.read_u32(12).unwrap(),
                                    bytes.read_u16(16).unwrap()
                                )
                                // read a FunctionDef
                            } else if symbol.n_sclass == 3 && true /* is section */ {
                                AuxEntry::SectionDef(
                                    bytes.read_u32(0).unwrap(),
                                    bytes.read_u16(4).unwrap(),
                                    bytes.read_u16(6).unwrap(),
                                    bytes.read_u32(8).unwrap(),
                                    bytes.read_u16(12).unwrap(),
                                    bytes.read_u8(14).unwrap(),
                                    bytes.read_u8(15).unwrap(),
                                    bytes.read_u8(16).unwrap(),
                                    bytes.read_u8(17).unwrap()
                                )
                            } else {
                                AuxEntry::Unknown(bytes)
                            };
                            Ok(aux)
                        };
                        match next {
                            Ok(sym) => {
                                aux_entries.push(sym);
                            },
                            Err(e) => {
                                return Err(e);
                            }
                        }
                        curr_ofs += SymbolEntry::size();
                    }
                    symbol.n_auxentries = Some(aux_entries);
                }
                Ok((symbol, curr_ofs))
            },
            Err(e) => Err(e)
        }
    }

    fn parse_non_recursive(buf: &Vec<u8>, offset: usize) -> Result<SymbolEntry, ParseErr> {
        if offset + SymbolEntry::size() > buf.len() {
            return Err(ParseErr::Unknown("Symbol extends past end of file".to_owned()));
        }
        Ok(SymbolEntry {
            n_name: StringEntry::parse(&buf, offset + 0).unwrap(),
            n_value: buf.read_u32(offset + 8).unwrap(),
            n_scnum: buf.read_u16(offset + 12).unwrap(),
            n_type: buf.read_u16(offset + 14).unwrap(),
            n_sclass: buf.read_u8(offset + 16).unwrap(),
            n_numaux: buf.read_u8(offset + 17).unwrap(),
            n_auxentries: None
        })
    }
}

#[derive(Debug)]
pub struct StringTable {
    data: Vec<u8>
}

#[derive(Debug)]
pub enum StringEntry {
    Literal([u8; 8]),
    Offset(u32)
}

impl StringEntry {
    pub fn to_string(&self, strtab: &StringTable) -> Option<String> {
        match self {
            &StringEntry::Literal(ref slice) => {
                let mut name = String::new();
                for c in slice.iter().rev() {
                    // skip trailing 0's
                    if *c == 0 { continue; }

                    for escaped in std::ascii::escape_default(*c).rev() {
                        name.insert(0, escaped as char);
                    }
                }
                Some(name)
            },
            &StringEntry::Offset(ref offset) => {
                let start: usize = *offset as usize;
                if start >= strtab.data.len() {
                    return None;
                }
                let mut end = start;
                while end < strtab.data.len() && strtab.data[end] != 0 {
                    end += 1;
                }
                std::str::from_utf8(&strtab.data[start..end]).ok().map(|x| x.to_owned())
            }
        }
    }
}

impl StringEntry {
    fn parse(buf: &[u8], offset: usize) -> Result<StringEntry, ParseErr> {
        if offset + 8 > buf.len() {
            return Err(ParseErr::Unknown("Not enough space for string entry".to_owned()));
        }

        let slice = buf[offset..(offset + 8)].to_vec();

        if slice[0] == 0 && slice[1] == 0 && slice[2] == 0 && slice[3] == 0 {
            Ok(StringEntry::Offset(slice.read_u32(4).unwrap()))
        } else {
            Ok(StringEntry::Literal([
                slice[0], slice[1], slice[2], slice[3],
                slice[4], slice[5], slice[6], slice[7]
            ]))
        }
    }
}

#[derive(Debug)]
enum RelocationType {
    /// The relocation is ignored.
    IMAGE_REL_AMD64_ABSOLUTE,
    /// The 64-bit VA of the relocation target.
    IMAGE_REL_AMD64_ADDR64,
    /// The 32-bit VA of the relocation target.
    IMAGE_REL_AMD64_ADDR32,
    /// The 32-bit address without an image base (RVA).
    IMAGE_REL_AMD64_ADDR32NB,
    /// The 32-bit relative address from the byte following the relocation.
    IMAGE_REL_AMD64_REL32,
    /// The 32-bit address relative to byte distance 1 from the relocation.
    IMAGE_REL_AMD64_REL32_1,
    /// The 32-bit address relative to byte distance 2 from the relocation.
    IMAGE_REL_AMD64_REL32_2,
    /// The 32-bit address relative to byte distance 3 from the relocation.
    IMAGE_REL_AMD64_REL32_3,
    /// The 32-bit address relative to byte distance 4 from the relocation.
    IMAGE_REL_AMD64_REL32_4,
    /// The 32-bit address relative to byte distance 5 from the relocation.
    IMAGE_REL_AMD64_REL32_5,
    /// The 16-bit section index of the section that contains the target. This is used to support debugging information.
    IMAGE_REL_AMD64_SECTION,
    /// The 32-bit offset of the target from the beginning of its section. This is used to support debugging information and static thread local storage.
    IMAGE_REL_AMD64_SECREL,
    /// A 7-bit unsigned offset from the base of the section that contains the target.
    IMAGE_REL_AMD64_SECREL7,
    /// CLR tokens.
    IMAGE_REL_AMD64_TOKEN,
    /// A 32-bit signed span-dependent value emitted into the object.
    IMAGE_REL_AMD64_SREL32,
    /// A pair that must immediately follow every span-dependent value.
    IMAGE_REL_AMD64_PAIR,
    /// A 32-bit signed span-dependent value that is applied at link time.
    IMAGE_REL_AMD64_SSPAN32,
    Unknown(u16)
}

impl RelocationType {
    pub fn from_u16(num: u16) -> RelocationType {
        match num {
            0x0000 => RelocationType::IMAGE_REL_AMD64_ABSOLUTE,
            0x0001 => RelocationType::IMAGE_REL_AMD64_ADDR64,
            0x0002 => RelocationType::IMAGE_REL_AMD64_ADDR32,
            0x0003 => RelocationType::IMAGE_REL_AMD64_ADDR32NB,
            0x0004 => RelocationType::IMAGE_REL_AMD64_REL32,
            0x0005 => RelocationType::IMAGE_REL_AMD64_REL32_1,
            0x0006 => RelocationType::IMAGE_REL_AMD64_REL32_2,
            0x0007 => RelocationType::IMAGE_REL_AMD64_REL32_3,
            0x0008 => RelocationType::IMAGE_REL_AMD64_REL32_4,
            0x0009 => RelocationType::IMAGE_REL_AMD64_REL32_5,
            0x000A => RelocationType::IMAGE_REL_AMD64_SECTION,
            0x000B => RelocationType::IMAGE_REL_AMD64_SECREL,
            0x000C => RelocationType::IMAGE_REL_AMD64_SECREL7,
            0x000D => RelocationType::IMAGE_REL_AMD64_TOKEN,
            0x000E => RelocationType::IMAGE_REL_AMD64_SREL32,
            0x000F => RelocationType::IMAGE_REL_AMD64_PAIR,
            0x0010 => RelocationType::IMAGE_REL_AMD64_SSPAN32,
            x => RelocationType::Unknown(x)
        }
    }
}

#[derive(Debug)]
pub struct RelocationEntry {
    vaddr: u32,
    sym_idx: u32,
    reloc_type: RelocationType
}

impl RelocationEntry {
    pub fn parse(buf: &[u8], idx: usize) -> Result<RelocationEntry, ParseErr> {
        if idx + RelocationEntry::size() > buf.len() {
            Err(ParseErr::Unknown("Relocation goes past end of file".to_string()))
        } else {
            let vec = buf.to_vec();
            Ok(RelocationEntry {
                vaddr: vec.read_u32(idx).unwrap(),
                sym_idx: vec.read_u32(idx + 4).unwrap(),
                reloc_type: RelocationType::from_u16(vec.read_u16(idx + 6).unwrap())
            })
        }
    }

    pub fn size() -> usize {
        4 + 4 + 2
    }
}

#[derive(Debug)]
pub struct SectionRelocationTable {
    entries: Vec<RelocationEntry>
}
//    file_offset: u32,
//    size: u16

#[derive(Debug)]
pub struct SectionLineNumberTable {
    file_offset: u32,
    size: u16
}

/// The first pieces of a COFF image in any given file
#[derive(Debug)]
pub struct FileHeader {
    /// This is also known as `Machine` in MSDN docs.
    ///
    /// Typical values you may expect are:
    ///     IMAGE_FILE_MACHINE_AMD64, for x86_64, aka 0x8664
    ///     IMAGE_FILE_MACHINE_I386, for i386, aka 0x014c
    ///
    /// Additionally, ANY (aka 0) here indicates compatibility with any machine type
    /// (think pure data blobs)
    f_magic: CoffMagic,
    f_nscns: u16,
    f_timdat: u32,
    f_symptr: u32,
    f_nsyms: u32,
    f_opthdr: u16,
    f_flags: u16
}

impl FileHeader {
    pub fn parse(buf: &[u8], offset: usize) -> Result<(FileHeader, usize), ParseErr> {
        let magic: u16 = ((buf[offset + 1] as u16) << 8) | buf[offset] as u16;
        let nscns: u16 = ((buf[offset + 3] as u16) << 8) | buf[offset + 2] as u16;
        let timdat: u32 = ((buf[offset + 7] as u32) << 24) | ((buf[offset + 6] as u32) << 16) | ((buf[offset + 5] as u32) << 8) | buf[offset + 4] as u32;
        let symptr: u32 = ((buf[offset + 11] as u32) << 24) | ((buf[offset + 10] as u32) << 16) | ((buf[offset + 9] as u32) << 8) | buf[offset + 8] as u32;
        let nsyms: u32 = ((buf[offset + 15] as u32) << 24) | ((buf[offset + 14] as u32) << 16) | ((buf[offset + 13] as u32) << 8) | buf[offset + 12] as u32;
        let opthdr: u16 = ((buf[offset + 17] as u16) << 8) | buf[offset + 16] as u16;
        let flags: u16 = ((buf[offset + 19] as u16) << 8) | buf[offset + 18] as u16;
        Ok((FileHeader {
            f_magic: CoffMagic::from(magic),
            f_nscns: nscns,
            f_timdat: timdat,
            f_symptr: symptr,
            f_nsyms: nsyms,
            f_opthdr: opthdr,
            f_flags: flags
        }, offset + 20))
    }
}

/// This "Optional" header is pretty much always present in modern COFF images,
/// but not object files.
#[derive(Debug)]
pub struct OptionalHeader {
    /// Known as `Magic`
    magic: u16,
    /// MSDN: `MajorLinkerVersion`
    /// also MSDN: `MajorLinkerVersion`
    /// this is, specifically: (MajorLinkerVersion << 8) | MinorLinkerVersion
    vstamp: u16,
    /// MSDN: `SizeOfCode`
    tsize: u32,
    /// MSDN: `SizeOfInitializedData`
    dsize: u32,
    /// MSDN: `SizeOfUninitializedData`
    bsize: u32,
    /// MSDN: `AddressOfEntryPoint`
    entry: u32,
    /// MSDN: `BaseOfCode`
    text_start: u32,
    /// MSDN: `BaseOfData`
    /// Notably, this field is absent for PE32+ (which makes them divergent from COFF...)
    /// This is set to 0xffffffff
    data_start: u32,
    /// This extension to the COFF header only exists for images on Windows.
    windows_fields: Option<WindowsSpecificOptionalHeader>
}

trait ReadAdapter {
    fn read_u8(&self, offset: usize) -> Option<u8>;
    fn read_u16(&self, offset: usize) -> Option<u16>;
    fn read_u32(&self, offset: usize) -> Option<u32>;
}

impl ReadAdapter for Vec<u8> {
    fn read_u8(&self, offset: usize) -> Option<u8> {
        if offset < self.len() {
            Some(self[offset])
        } else {
            None
        }
    }
    fn read_u16(&self, offset: usize) -> Option<u16> {
        if offset < self.len() - 1 {
            Some(self[offset] as u16 | (self[offset + 1] as u16) << 8)
        } else {
            None
        }
    }
    fn read_u32(&self, offset: usize) -> Option<u32> {
        if offset < self.len() - 3 {
            Some(
                self[offset] as u32 |
                ((self[offset + 1] as u32) << 8) |
                ((self[offset + 2] as u32) << 16) |
                ((self[offset + 3] as u32) << 24)
            )
        } else {
            None
        }
    }
}

impl OptionalHeader {
    pub fn parse(buf: &[u8], offset: usize, size: u16) -> Result<OptionalHeader, ParseErr> {
        let region: Vec<u8> = buf[offset..(offset + size as usize)].to_vec();
        let mut i: usize = 0;
        let header_err = "optional header too small".to_owned();
        if offset + (size as usize) > buf.len() {
            return Err(ParseErr::Unknown(header_err))
        }

        let magic = region.read_u16(0).unwrap();
        let vstamp = region.read_u16(2).unwrap();
        let tsize = region.read_u32(4).unwrap();
        let dsize = region.read_u32(8).unwrap();
        let bsize = region.read_u32(12).unwrap();
        let entry = region.read_u32(16).unwrap();
        let text_start = region.read_u32(20).unwrap();
        let data_start = region.read_u32(24).unwrap();
        // if the header size continues, try reading windows fields
        // windows_fields: Option<WindowsSpecificOptionalHeader>
        Ok(OptionalHeader {
            magic: magic,
            vstamp: vstamp,
            tsize: tsize,
            dsize: dsize,
            bsize: bsize,
            entry: entry,
            text_start: text_start,
            data_start: data_start,
            windows_fields: None
        })
    }
}

/// These fields come after the standard COFF Optional header, and are only present in PE images,
/// not object files.
#[derive(Debug)]
pub struct WindowsSpecificOptionalHeader {
}

impl Display for SectionHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut name = String::new();
        for c in self.s_name.iter().rev() {
            // skip trailing 0's
            if *c == 0 { continue; }

            for escaped in std::ascii::escape_default(*c).rev() {
                name.insert(0, escaped as char);
            }
        }

        write!(f, "{:>8} | {:>#8x}, {:>#8x} | {:>#8x}, {:>#8x} | {}",
            name,
            self.s_scnptr, self.s_size,
            self.s_vaddr, self.s_vsize,
            self.s_flags
        )?;

        Ok(())
    }
}

/// This header describes a section of the file, which may be code, data, or both.
/// There are `f_nscns` many of these headers.
#[derive(Debug)]
pub struct SectionHeader {
    /// MSDN: `Name`
    s_name: [u8; 8],
    /// MSDN: `VirtualSize`
    s_vsize: u32,
    /// MSDN: `VirtualAddress`
    s_vaddr: u32,
    /// MSDN: `SizeOfRawData`
    s_size: u32,
    /// MSDN: `PointerToRawData`
    s_scnptr: u32,
    /// The following tables record the information that is expressed through the
    /// fields `PointerToRelocations`, `PointerToLinenumbers`,
    /// `NumberOfRelocations`, and `NumberOfLinenumbers`, as documented in MSDN
    /// A relocation table *may* exist!
    relo_table: Option<SectionRelocationTable>,
    /// A line number table *may* exist!
    lineno_table: Option<SectionLineNumberTable>,
    /*
    /// MSDN: `PointerToRelocations`
    s_relptr: u32,
    /// MSDN: `PointerToLinenumbers`
    s_lnnoptr: u32,
    /// MSDN: `NumberOfRelocations`
    s_nreloc: u16,
    /// MSDN: `NumberOfLinenumbers`
    s_nlnno: u16,
    */
    /// MSDN: `Characteristics`
    s_flags: Characteristics
}

impl SectionHeader {
    fn size() -> usize {
        8 + 4 + 4 + 4 + 4 + (2 + 4) + (2 + 4) + 4
    }

    fn parse(buf: &[u8], offset: usize) -> Result<SectionHeader, ParseErr> {
        if offset + SectionHeader::size() > buf.len() {
            return Err(ParseErr::Unknown("Insufficient data for section header".to_owned()))
        }

        let hdrbytes = buf[offset..(offset + SectionHeader::size())].to_vec();
        let name = [
            hdrbytes[0], hdrbytes[1], hdrbytes[2], hdrbytes[3],
            hdrbytes[4], hdrbytes[5], hdrbytes[6], hdrbytes[7]
        ];
        let vsize = hdrbytes.read_u32(8).unwrap();
        let vaddr = hdrbytes.read_u32(12).unwrap();
        let size = hdrbytes.read_u32(16).unwrap();
        let scnptr = hdrbytes.read_u32(20).unwrap();
        let relptr = hdrbytes.read_u32(24).unwrap();
        let lnoptr = hdrbytes.read_u32(28).unwrap();
        let nreloc = hdrbytes.read_u16(32).unwrap();
        let nlnno = hdrbytes.read_u16(34).unwrap();
        let characteristics = Characteristics { value: hdrbytes.read_u32(36).unwrap() };
        let relotab = match (relptr, nreloc) {
            (0, 0) => None,
            (_, 0) => { println!("Reloc ptr non-zero but zero reloc entries"); None },
            (0, _) => { println!("Reloc ptr zero but non-zero reloc entries"); None },
            (ptr, count) => {
                let mut idx = ptr as usize;
                let mut entries: Vec<RelocationEntry> = Vec::new();
                for i in 0..count {
                    entries.push(RelocationEntry::parse(buf, idx).unwrap());
                    idx += RelocationEntry::size();
                }
                Some(SectionRelocationTable {
                    entries: entries
                })
            }
        };
        let linenotab = match (lnoptr, nlnno) {
            (0, 0) => None,
            (_, 0) => { println!("Reloc ptr non-zero but zero lineno entries"); None },
            (0, _) => { println!("Reloc ptr zero but non-zero lineno entries"); None },
            (ptr, count) => {
                Some(SectionLineNumberTable {
                    file_offset: ptr,
                    size: count
                })
            }
        };
        Ok(SectionHeader {
            s_name: name,
            s_vsize: vsize,
            s_vaddr: vaddr,
            s_size: size,
            s_scnptr: scnptr,
            relo_table: relotab,
            lineno_table: linenotab,
            s_flags: characteristics
        })
    }
}

/// A struct for the flags of a section to provide nicer accessors for each bit
#[derive(Debug)]
pub struct Characteristics {
    value: u32
}

impl Characteristics {
    fn from_value(value: u32) -> Characteristics {
        Characteristics {
            value: value
        }
    }
}

impl Display for Characteristics {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:8x},", self.value);
        write!(f, "ALIGN:{}", self.IMAGE_SCN_ALIGN());
        let mut flags: Vec<&str> = vec![""];
        if self.IMAGE_SCN_TYPE_NO_PAD() { flags.push("NO_PAD"); }
        if self.IMAGE_SCN_CNT_CODE() { flags.push("CODE"); }
        if self.IMAGE_SCN_CNT_INITIALIZED_DATA() { flags.push("INITIALIZED_DATA"); }
        if self.IMAGE_SCN_CNT_UNINITIALIZED_DATA() { flags.push("UNINITIALIZED_DATA"); }
        if self.IMAGE_SCN_LNK_OTHER() { flags.push("OTHER"); }
        if self.IMAGE_SCN_LNK_INFO() { flags.push("INFO"); }
        if self.IMAGE_SCN_LNK_REMOVE() { flags.push("REMOVE"); }
        if self.IMAGE_SCN_LNK_COMDAT() { flags.push("COMDAT"); }
        if self.IMAGE_SCN_GPREL() { flags.push("GPREL"); }
        if self.IMAGE_SCN_MEM_PURGEABLE() { flags.push("PURGEABLE"); }
        if self.IMAGE_SCN_MEM_16BIT() { flags.push("16BIT"); }
        if self.IMAGE_SCN_MEM_LOCKED() { flags.push("LOCKED"); }
        if self.IMAGE_SCN_MEM_PRELOAD() { flags.push("PRELOAD"); }
        if self.IMAGE_SCN_LNK_NRELOC_OVFL() { flags.push("NRELOC_OVFL"); }
        if self.IMAGE_SCN_MEM_DISCARDABLE() { flags.push("DISCARDABLE"); }
        if self.IMAGE_SCN_MEM_NOT_CACHED() { flags.push("NOT_CACHED"); }
        if self.IMAGE_SCN_MEM_NOT_PAGED() { flags.push("NOT_PAGED"); }
        if self.IMAGE_SCN_MEM_SHARED() { flags.push("SHARED"); }
        if self.IMAGE_SCN_MEM_EXECUTE() { flags.push("EXECUTE"); }
        if self.IMAGE_SCN_MEM_READ() { flags.push("READ"); }
        if self.IMAGE_SCN_MEM_WRITE() { flags.push("WRITE"); }
        write!(f, "{}", flags.join(","))
    }
}

// TODO: implement setters for all of these.
/// I Honestly don't know which of these values are Microsoft-specific.
impl Characteristics {
    fn IMAGE_SCN_TYPE_NO_PAD(&self) -> bool { (self.value & 0x00000008) != 0 }
    /// The section contains executable code.
    fn IMAGE_SCN_CNT_CODE(&self) -> bool { (self.value & 0x00000020) != 0 }
    /// The section contains initialized data.
    fn IMAGE_SCN_CNT_INITIALIZED_DATA(&self) -> bool { (self.value & 0x00000040) != 0 }
    /// The section contains uninitialized data.
    fn IMAGE_SCN_CNT_UNINITIALIZED_DATA(&self) -> bool { (self.value & 0x00000080) != 0 }
    /// Reserved for future use.
    fn IMAGE_SCN_LNK_OTHER(&self) -> bool { (self.value & 0x00000100) != 0 }
    /// The section contains comments or other information. The .drectve section has this type. This is valid for object files only.
    fn IMAGE_SCN_LNK_INFO(&self) -> bool { (self.value & 0x00000200) != 0 }
    /// The section will not become part of the image. This is valid only for object files.
    fn IMAGE_SCN_LNK_REMOVE(&self) -> bool { (self.value & 0x00000800) != 0 }
    /// The section contains COMDAT data. For more information, see COMDAT Sections (Object Only). This is valid only for object files.
    fn IMAGE_SCN_LNK_COMDAT(&self) -> bool { (self.value & 0x00001000) != 0 }
    /// The section contains data referenced through the global pointer (GP).
    fn IMAGE_SCN_GPREL(&self) -> bool { (self.value & 0x00008000) != 0 }
    /// Reserved for future use.
    fn IMAGE_SCN_MEM_PURGEABLE(&self) -> bool { (self.value & 0x00020000) != 0 }
    /// Reserved for future use.
    fn IMAGE_SCN_MEM_16BIT(&self) -> bool { (self.value & 0x00020000) != 0 }
    /// Reserved for future use.
    fn IMAGE_SCN_MEM_LOCKED(&self) -> bool { (self.value & 0x00040000) != 0 }
    /// Reserved for future use.
    fn IMAGE_SCN_MEM_PRELOAD(&self) -> bool { (self.value & 0x00080000) != 0 }
    /// Alignment is stored as log2(ALIGNMENT), indicating powers of 2 from 1 to 8192.
    /// This provides that exponential factor directly, instead of querying each pattern.
    fn IMAGE_SCN_ALIGN_EXP(&self) -> u8 { ((self.value >> 20) as u8) & 0x0f }
    /// This provides the numeric value of expected alignment, which is one of the powers of two
    /// between 1 and 8192 (inclusive)
    fn IMAGE_SCN_ALIGN(&self) -> u16 { 1 << (self.IMAGE_SCN_ALIGN_EXP() - 1) }
    /// Align data on a 1-byte boundary. Valid only for object files.
    fn IMAGE_SCN_ALIGN_1BYTES(&self) -> bool { (self.value & 0x00100000) != 0 }
    /// Align data on a 2-byte boundary. Valid only for object files.
    fn IMAGE_SCN_ALIGN_2BYTES(&self) -> bool { (self.value & 0x00200000) != 0 }
    /// Align data on a 4-byte boundary. Valid only for object files.
    fn IMAGE_SCN_ALIGN_4BYTES(&self) -> bool { (self.value & 0x00300000) != 0 }
    /// Align data on an 8-byte boundary. Valid only for object files.
    fn IMAGE_SCN_ALIGN_8BYTES(&self) -> bool { (self.value & 0x00400000) != 0 }
    /// Align data on a 16-byte boundary. Valid only for object files.
    fn IMAGE_SCN_ALIGN_16BYTES(&self) -> bool { (self.value & 0x00500000) != 0 }
    /// Align data on a 32-byte boundary. Valid only for object files.
    fn IMAGE_SCN_ALIGN_32BYTES(&self) -> bool { (self.value & 0x00600000) != 0 }
    /// Align data on a 64-byte boundary. Valid only for object files.
    fn IMAGE_SCN_ALIGN_64BYTES(&self) -> bool { (self.value & 0x00700000) != 0 }
    /// Align data on a 128-byte boundary. Valid only for object files.
    fn IMAGE_SCN_ALIGN_128BYTES(&self) -> bool { (self.value & 0x00800000) != 0 }
    /// Align data on a 256-byte boundary. Valid only for object files.
    fn IMAGE_SCN_ALIGN_256BYTES(&self) -> bool { (self.value & 0x00900000) != 0 }
    /// Align data on a 512-byte boundary. Valid only for object files.
    fn IMAGE_SCN_ALIGN_512BYTES(&self) -> bool { (self.value & 0x00A00000) != 0 }
    /// Align data on a 1024-byte boundary. Valid only for object files.
    fn IMAGE_SCN_ALIGN_1024BYTES(&self) -> bool { (self.value & 0x00B00000) != 0 }
    /// Align data on a 2048-byte boundary. Valid only for object files.
    fn IMAGE_SCN_ALIGN_2048BYTES(&self) -> bool { (self.value & 0x00C00000) != 0 }
    /// Align data on a 4096-byte boundary. Valid only for object files.
    fn IMAGE_SCN_ALIGN_4096BYTES(&self) -> bool { (self.value & 0x00D00000) != 0 }
    /// Align data on an 8192-byte boundary. Valid only for object files.
    fn IMAGE_SCN_ALIGN_8192BYTES(&self) -> bool { (self.value & 0x00E00000) != 0 }
    /// The section contains extended relocations.
    fn IMAGE_SCN_LNK_NRELOC_OVFL(&self) -> bool { (self.value & 0x01000000) != 0 }
    /// The section can be discarded as needed.
    fn IMAGE_SCN_MEM_DISCARDABLE(&self) -> bool { (self.value & 0x02000000) != 0 }
    /// The section cannot be cached.
    fn IMAGE_SCN_MEM_NOT_CACHED(&self) -> bool { (self.value & 0x04000000) != 0 }
    /// The section is not pageable.
    fn IMAGE_SCN_MEM_NOT_PAGED(&self) -> bool { (self.value & 0x08000000) != 0 }
    /// The section can be shared in memory.
    fn IMAGE_SCN_MEM_SHARED(&self) -> bool { (self.value & 0x10000000) != 0 }
    /// The section can be executed as code.
    fn IMAGE_SCN_MEM_EXECUTE(&self) -> bool { (self.value & 0x20000000) != 0 }
    /// The section can be read.
    fn IMAGE_SCN_MEM_READ(&self) -> bool { (self.value & 0x40000000) != 0 }
    /// The section can be written to.
    fn IMAGE_SCN_MEM_WRITE(&self) -> bool { (self.value & 0x80000000) != 0 }
}

impl From<u16> for CoffMagic {
    fn from(x: u16) -> Self {
        match x {
            0x0 => CoffMagic::IMAGE_FILE_MACHINE_UNKNOWN,
            0x1d3 => CoffMagic::IMAGE_FILE_MACHINE_AM33,
            0x8664 => CoffMagic::IMAGE_FILE_MACHINE_AMD64,
            0x1c0 => CoffMagic::IMAGE_FILE_MACHINE_ARM,
            0xaa64 => CoffMagic::IMAGE_FILE_MACHINE_ARM64,
            0x1c4 => CoffMagic::IMAGE_FILE_MACHINE_ARMNT,
            0xebc => CoffMagic::IMAGE_FILE_MACHINE_EBC,
            0x14c => CoffMagic::IMAGE_FILE_MACHINE_I386,
            0x200 => CoffMagic::IMAGE_FILE_MACHINE_IA64,
            0x9041 => CoffMagic::IMAGE_FILE_MACHINE_M32R,
            0x266 => CoffMagic::IMAGE_FILE_MACHINE_MIPS16,
            0x366 => CoffMagic::IMAGE_FILE_MACHINE_MIPSFPU,
            0x466 => CoffMagic::IMAGE_FILE_MACHINE_MIPSFPU16,
            0x1f0 => CoffMagic::IMAGE_FILE_MACHINE_POWERPC,
            0x1f1 => CoffMagic::IMAGE_FILE_MACHINE_POWERPCFP,
            0x166 => CoffMagic::IMAGE_FILE_MACHINE_R4000,
            0x5032 => CoffMagic::IMAGE_FILE_MACHINE_RISCV32,
            0x5064 => CoffMagic::IMAGE_FILE_MACHINE_RISCV64,
            0x5128 => CoffMagic::IMAGE_FILE_MACHINE_RISCV128,
            0x1a2 => CoffMagic::IMAGE_FILE_MACHINE_SH3,
            0x1a3 => CoffMagic::IMAGE_FILE_MACHINE_SH3DSP,
            0x1a6 => CoffMagic::IMAGE_FILE_MACHINE_SH4,
            0x1a8 => CoffMagic::IMAGE_FILE_MACHINE_SH5,
            0x1c2 => CoffMagic::IMAGE_FILE_MACHINE_THUMB,
            0x169 => CoffMagic::IMAGE_FILE_MACHINE_WCEMIPSV2,
            v => CoffMagic::Unknown(v)
        }
    }
}

impl CoffMagic {
    fn to_u16(&self) -> u16 {
        match *self {
            CoffMagic::IMAGE_FILE_MACHINE_UNKNOWN => 0x0,
            CoffMagic::IMAGE_FILE_MACHINE_AM33 => 0x1d3,
            CoffMagic::IMAGE_FILE_MACHINE_AMD64 => 0x8664,
            CoffMagic::IMAGE_FILE_MACHINE_ARM => 0x1c0,
            CoffMagic::IMAGE_FILE_MACHINE_ARM64 => 0xaa64,
            CoffMagic::IMAGE_FILE_MACHINE_ARMNT => 0x1c4,
            CoffMagic::IMAGE_FILE_MACHINE_EBC => 0xebc,
            CoffMagic::IMAGE_FILE_MACHINE_I386 => 0x14c,
            CoffMagic::IMAGE_FILE_MACHINE_IA64 => 0x200,
            CoffMagic::IMAGE_FILE_MACHINE_M32R => 0x9041,
            CoffMagic::IMAGE_FILE_MACHINE_MIPS16 => 0x266,
            CoffMagic::IMAGE_FILE_MACHINE_MIPSFPU => 0x366,
            CoffMagic::IMAGE_FILE_MACHINE_MIPSFPU16 => 0x466,
            CoffMagic::IMAGE_FILE_MACHINE_POWERPC => 0x1f0,
            CoffMagic::IMAGE_FILE_MACHINE_POWERPCFP => 0x1f1,
            CoffMagic::IMAGE_FILE_MACHINE_R4000 => 0x166,
            CoffMagic::IMAGE_FILE_MACHINE_RISCV32 => 0x5032,
            CoffMagic::IMAGE_FILE_MACHINE_RISCV64 => 0x5064,
            CoffMagic::IMAGE_FILE_MACHINE_RISCV128 => 0x5128,
            CoffMagic::IMAGE_FILE_MACHINE_SH3 => 0x1a2,
            CoffMagic::IMAGE_FILE_MACHINE_SH3DSP => 0x1a3,
            CoffMagic::IMAGE_FILE_MACHINE_SH4 => 0x1a6,
            CoffMagic::IMAGE_FILE_MACHINE_SH5 => 0x1a8,
            CoffMagic::IMAGE_FILE_MACHINE_THUMB => 0x1c2,
            CoffMagic::IMAGE_FILE_MACHINE_WCEMIPSV2 => 0x169,
            CoffMagic::Unknown(v) => v
        }
    }
}

#[derive(Debug)]
enum CoffMagic {
    /// The contents of this field are assumed to be applicable to any machine type
    IMAGE_FILE_MACHINE_UNKNOWN,
    /// Matsushita AM33
    IMAGE_FILE_MACHINE_AM33,
    /// x64
    IMAGE_FILE_MACHINE_AMD64,
    /// ARM little endian
    IMAGE_FILE_MACHINE_ARM,
    /// ARM64 little endian
    IMAGE_FILE_MACHINE_ARM64,
    /// ARM Thumb-2 little endian
    IMAGE_FILE_MACHINE_ARMNT,
    /// EFI byte code
    IMAGE_FILE_MACHINE_EBC,
    /// Intel 386 or later processors and compatible processors
    IMAGE_FILE_MACHINE_I386,
    /// Intel Itanium processor family
    IMAGE_FILE_MACHINE_IA64,
    /// Mitsubishi M32R little endian
    IMAGE_FILE_MACHINE_M32R,
    /// MIPS16
    IMAGE_FILE_MACHINE_MIPS16,
    /// MIPS with FPU
    IMAGE_FILE_MACHINE_MIPSFPU,
    /// MIPS16 with FPU
    IMAGE_FILE_MACHINE_MIPSFPU16,
    /// Power PC little endian
    IMAGE_FILE_MACHINE_POWERPC,
    /// Power PC with floating point support
    IMAGE_FILE_MACHINE_POWERPCFP,
    /// MIPS little endian
    IMAGE_FILE_MACHINE_R4000,
    /// RISC-V 32-bit address space
    IMAGE_FILE_MACHINE_RISCV32,
    /// RISC-V 64-bit address space
    IMAGE_FILE_MACHINE_RISCV64,
    /// RISC-V 128-bit address space
    IMAGE_FILE_MACHINE_RISCV128,
    /// Hitachi SH3
    IMAGE_FILE_MACHINE_SH3,
    /// Hitachi SH3 DSP
    IMAGE_FILE_MACHINE_SH3DSP,
    /// Hitachi SH4
    IMAGE_FILE_MACHINE_SH4,
    /// Hitachi SH5
    IMAGE_FILE_MACHINE_SH5,
    /// Thumb
    IMAGE_FILE_MACHINE_THUMB,
    /// MIPS little-endian WCE v2
    IMAGE_FILE_MACHINE_WCEMIPSV2,
    /// Some undocumented value. THIS IS DIFFERENT FROM IMAGE_FILE_MACHINE_UNKNOWN.
    Unknown(u16)
}
