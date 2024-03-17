use byteorder::{LittleEndian, WriteBytesExt};
use goblin::elf::section_header::{SHT_DYNSYM, SHT_PROGBITS, SHT_SYMTAB};
use goblin::elf::{self};
use goblin::Object;
use libc::{c_long, c_void};
use linux_personality::personality;
use nix::sys::ptrace::{self, AddressType};
use nix::sys::wait::wait;
use nix::unistd::{fork, ForkResult, Pid};
use std::env;
use std::fs;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{exit, Command};

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

// TODO: get length argument from registers
fn read_string(pid: Pid, address: AddressType) -> String {
    let mut string = String::new();
    // Move 8 bytes up each time for next read.
    let mut count = 0;
    let word_size = 8;

    'done: loop {
        let mut bytes: Vec<u8> = vec![];
        let address = unsafe { address.offset(count) };

        let res: c_long = ptrace::read(pid, address).unwrap_or_else(|err| {
            panic!("Failed to read data for pid {}: {}", pid, err);
        });
        bytes.write_i64::<LittleEndian>(res).unwrap_or_else(|err| {
            panic!("Failed to write {} as i64 LittleEndian: {}", res, err);
        });

        for b in bytes {
            if b != 0 {
                string.push(b as char);
            } else {
                break 'done;
            }
        }
        count += word_size;
    }

    string
}

fn run_tracer(child: Pid, names: &[FnName]) -> Result<(), nix::errno::Errno> {
    // Handle the initial execve
    wait().unwrap();

    loop {
        // Syscall will error out when the program finnishes
        // TODO: better error handling
        if ptrace::step(child, None).is_err() {
            return Ok(());
        }

        wait()?;

        let regs = ptrace::getregs(child)?;
        let opcode = ptrace::read(child, regs.rip as *mut c_void)?;

        if let Some(fun) = names.iter().find(|n| n.address as u64 == regs.rip) {
            println!("{:016x} <{}>", regs.rip, fun.name);
        }
        // decompile_instr(regs.rip, opcode);
        // Check if syscall
        if opcode & 0xffff == 0x050f {
            // regx.rax == 1 is syscall write
            // rdi == 1 or 2 is stdout or std err. we don't care about writing to files
            if regs.rax == 1 && (regs.rdi == 1 || regs.rdi == 2) {
                let output = read_string(child, regs.rsi as *mut c_void);
                if output == "Hello, World!2\n" {
                    println!("[tracer]: Hello, World!2 found!, stopping execution");
                    return Ok(());
                }
            } else if regs.rax == 60 {
                return Ok(());
            }
        }
    }
}

fn run_tracee(command: &str) {
    ptrace::traceme().unwrap();
    personality(linux_personality::ADDR_NO_RANDOMIZE).unwrap();

    Command::new(command).exec();

    exit(0)
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

    match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            run_tracee(&args[1]);
        }

        Ok(ForkResult::Parent { child }) => {
            if let Err(e) = run_tracer(child, &names) {
                println!("Tracer failed: '{:?}'", e);
            }
        }

        Err(err) => {
            panic!("[main] fork() failed: {}", err);
        }
    }
}
