use goblin::elf::section_header::{SHT_DYNSYM, SHT_PROGBITS, SHT_SYMTAB};
use goblin::elf::{self};
use goblin::Object;
use std::env;
use std::fs;
use std::path::Path;

#[derive(Debug)]
struct FnName {
    address: usize,
    name: String,
}

fn parse_elf(elf: &elf::Elf) -> Vec<FnName> {
    let mut names = Vec::new();

    for shdr in &elf.section_headers {
        match shdr.sh_type {
            SHT_PROGBITS => {
                // TODO:
            }
            SHT_DYNSYM => {
                println!("dynsym not implemented yet")
            }
            SHT_SYMTAB => {
                /*  let dyn_start = shdr.sh_offset;
                let dyn_end = dyn_start + shdr.sh_size; */
                for sym in elf.syms.iter() {
                    if sym.st_name != 0 {
                        let sym_val = elf.strtab.get_at(sym.st_name).expect("Malformed symname");
                        names.push(FnName {
                            address: sym.st_value as usize,
                            name: sym_val.into(),
                        })
                    }
                }
            }

            _ => continue,
        }
    }

    names
}

fn main() {
    let args = env::args().collect::<Vec<String>>();
    let path = Path::new(args[1].as_str());
    let buffer = fs::read(path).unwrap();
    let elf = if let Object::Elf(elf) = Object::parse(&buffer).unwrap() {
        elf
    } else {
        panic!("Only elf files supported");
    };

    let names = parse_elf(&elf);
    println!("{names:#?}");
}
