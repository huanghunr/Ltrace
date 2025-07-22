from libdebug import debugger
from libdebug import libcontext
from ctypes import * 
import os
import signal
from capstone import *
from capstone.x86 import *
from tqdm import tqdm
import psutil
from pwn import ELF,context
import argparse
from elftools.elf.elffile import ELFFile

context.log_level ="error"
# libcontext.sym_lvl = 4

args_regs = [
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "rip",
]

x64_regs = [
    # 64-bit
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "rip",
    
    # 32-bit
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
    "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",

    # 16-bit
    "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
    "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w",

    # 8-bit
    "al", "bl", "cl", "dl", "sil", "dil", "bpl", "spl",
    "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
    "ah", "bh", "ch", "dh"
]


def dump_registers_to_file(d, f):
    regs = d.regs
    general_regs = [
        'rax', 'rbx', 'rcx', 'rdx', 'rdi', 'rsi',
        'r8',  'r9',  'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
        'rbp', 'rsp', 'rip', 'eflags',
        'cs', 'ss', 'ds', 'es', 'fs', 'gs',
        'fs_base', 'gs_base'
    ]

    # general
    for i in range(0, len(general_regs), 3):
        line = ""
        for reg in general_regs[i:i+3]:
            val = getattr(regs, reg)
            line += f"{reg:<8} 0x{val:016x}    "
        f.write(line.rstrip() + "\n")

    # MMX/ST 
    for i in range(8):
        mm = getattr(regs, f"mm{i}")
        st = getattr(regs, f"st{i}")
        f.write(f"mm{i}=0x{mm:x}    ")
        f.write(f"st{i}={st}    ")

    # XMM/YMM 
    for i in range(16):
        xmm = getattr(regs, f"xmm{i}")
        ymm = getattr(regs, f"ymm{i}")
        f.write(f"xmm{i}=0x{xmm:x}    ")
        f.write(f"ymm{i}=0x{ymm:x}    ")
    f.write("\n-----------\n")

def get_binary_name(filepath):
    path = filepath.split("/")
    return path[-1]

def find_pid_by_name(name):
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        if name in proc.info['cmdline']:
            return proc.info['pid']
    return None

def get_libs_info(d,binary_file_name):
    libs_info = {}
    binary_info ={}
    maps = d.maps
    for m in maps:
        path = m.backing_file
        if not path or not path.startswith("/"):
            continue
        if binary_file_name in path:
            if len(binary_info) == 0:
                binary_info = {"name": binary_file_name, "base": m.start, "end": m.end}
            else:
                binary_info["base"] = min(binary_info["base"], m.start)
                binary_info["end"] = max(binary_info["end"], m.end)
            continue
        elif "ld-linux-x86-64.so.2" in path:
            continue
        if path not in libs_info:
            lib_name = path.split("/")[-1]
            libs_info[path] = {"name": lib_name, "base": m.start, "end": m.end, "symbol":{}}
        else:
            libs_info[path]["base"] = min(libs_info[path]["base"], m.start)
            libs_info[path]["end"] = max(libs_info[path]["end"], m.end)
    
    for i in libs_info:
        lib = ELF(i)
        libs_info[i]["symbol"] = {libs_info[i]["base"] + addr: name for name, addr in lib.symbols.items()}

    return binary_info,libs_info

def get_entrypoint(filepath):
    try:
        with open(filepath, "rb") as f:
            elf = ELFFile(f)
        return elf.header.e_entry
    except Exception as e:
        print("error:Can't find binary entrypoint. ELF maybe is breaken. plase use \"attach trace\"")
        print(e)
        exit(0)

handle_lib_func_enable  = True
def handle_lib_func(d,ripaddr,f,lib_info,ret_addr,binary_info):
    if handle_lib_func_enable:
        for lib_path in lib_info:
            libc_base = lib_info[lib_path]["base"]
            libc_end = lib_info[lib_path]["end"]
            if ripaddr >= libc_base and ripaddr <= libc_end:
                if ripaddr in lib_info[lib_path]["symbol"]:
                    func_name = lib_info[lib_path]["symbol"][ripaddr]
                else:
                    func_name = f"unknown_lib_function({lib_info[lib_path]["name"]})"
                f.write(f"{hex(ripaddr)}\tlibc+{hex(ripaddr-libc_base)}\t{func_name}\n")
                # print(func_name,ret_addr)
                while(1):
                    d.step()
                    rip = d.regs.rip
                    if rip >= binary_info["base"] and rip <= binary_info["end"]:
                        return 1
        return 0

def trace_file(filepath:str, args: str, startaddr:int, maxlen:int, output:str, env:dict, inputdata:list):

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    
    binary_file_name = get_binary_name(filepath)
    # print(filepath)
    print([filepath] + args)
    if args: 
        d = debugger(argv= [filepath] + args,
                     auto_interrupt_on_command=True,continue_to_binary_entrypoint=False,escape_antidebug=True,env=env)
    else: 
        d = debugger(filepath,
                     auto_interrupt_on_command=True, continue_to_binary_entrypoint=False,escape_antidebug=True,env=env)
    p = d.run()
    pid = d.pid

    rip  = lambda:                        d.regs.rip

    global count
    count = 0
    def handle_read(inputdata):
        global count
        p.sendline(inputdata[count].encode())
        count += 1

    if startaddr != 0:
        d.breakpoint(startaddr, hardware=True, file = binary_file_name)
        d.cont()
        d.wait()
        d.breakpoints[rip()].disable()
        base_addr = rip() - startaddr
    else:
        entrypoint = get_entrypoint(filepath)
        d.breakpoint(entrypoint, hardware=True, file = binary_file_name)
        d.cont()
        d.wait()
        d.breakpoints[rip()].disable()
        base_addr = rip() - entrypoint

    try:
        binary_info,lib_info = get_libs_info(d,binary_file_name)
    except Exception as e:
        d.print_maps()
        d.kill()
        print(e)
        print("error: Can't find the libc. Please kill all of the process about this binary and try again.")
        exit(0)

    if len(inputdata) > 0: d.handle_syscall("read",on_enter=handle_read(inputdata))

    f = open(output, "w")

    dump_registers_to_file(d, f)
    ret_addr = None
    
    for i in tqdm(range(maxlen)):

        ripaddr = rip()
        CODE = d.memory[ripaddr,16]
        address, size, mnemonic, op_str = next( md.disasm_lite(CODE, 0x1))
        registers = [reg.strip() for reg in op_str.split(',')]
        # print(mnemonic,op_str)

        lib_func_handler=handle_lib_func(d,ripaddr,f,lib_info,ret_addr,binary_info)
        if lib_func_handler: continue

        reg_str = ""
        reg_name = registers[0]
        if reg_name in x64_regs:
            d.step()
            reg_str = ''.join(f"{reg_name:<3}={getattr(d.regs,reg_name):#018x}")
            rsp = d.regs.rsp
            ret_addr = int.from_bytes(d.memory[rsp : rsp + 8], "little")
        elif mnemonic == "call":
            d.step()
            reg_str = " ".join(f"{r:<3}={getattr(d.regs,r):#018x}" for r in args_regs)
        elif "["in reg_name:
            # print(reg_name)
            insn = next(md.disasm(CODE,100))
            op = insn.operands[0]
            if op.type == X86_OP_MEM:
                base = insn.reg_name(op.mem.base)
                index = insn.reg_name(op.mem.index)
                seg = insn.reg_name(op.mem.segment)
                scale = op.mem.scale
                disp = op.mem.disp
                if not seg is None:
                    d.step()
                elif index is None or index == "riz":
                    mem_addr = getattr(d.regs, base) + disp
                else:
                    mem_addr = getattr(d.regs, base) + getattr(d.regs, index) * scale + disp
                try:
                    d.step()
                    mem_data_qword = int.from_bytes(d.memory[mem_addr&0xffffffffffffffff,8], "little")
                except Exception as e:
                    print(f"Error reading memory at {hex(mem_addr)}: {e},rip={hex(rip()-base_addr)}")
                    print(f"[{base} + {index}*{scale} + {hex(disp)}]")
                    d.pprint_regs()
                    d.print_maps()
                    exit(1)
                reg_str = f"mem={mem_data_qword:#018x}"
        else:
            d.step()
        f.write(f"{hex(ripaddr)}\toff: {hex(ripaddr-base_addr)}\t{mnemonic:<6}\t{op_str:<30}\t{reg_str}\n")
    f.close()
    d.kill()

def parse_args():
    parser = argparse.ArgumentParser(description="Linux trace tool")

    # Mutually exclusive group: either --file or --pid must be provided
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--file', type=str, help='Path to the executable file to be traced')
    group.add_argument('-p', '--pid', type=int, help='PID of the process to attach to')

    # Optional: program arguments (only relevant when using --file)
    parser.add_argument('-a', '--args', nargs=argparse.REMAINDER,
                    help='Arguments for the target program (use "--" to separate them)(only valid with --file)')


    # Optional: start address (hex or decimal), default 0
    parser.add_argument('-s', '--start', type=lambda x: int(x, 0), default=0,
                        help='Trace start address (default: 0; accepts hex like 0x400000)')

    # Optional: max trace count
    parser.add_argument('-m', '--max-trace', type=int, default=100000,
                        help='Maximum number of instructions to trace (default: 100000)')

    # Optional: environment variables (format KEY=VALUE)
    parser.add_argument('-e', '--env', nargs='*',default=None,
                        help='Environment variables for the process, e.g., KEY1=VAL1 KEY2=VAL2')

    # Optional: output trace file
    parser.add_argument('-o', '--output', type=str, default='Ltrace.asm',
                        help='Output trace file name (default: Ltrace.asm)')
    
    # Optional: deal input data (interact)
    parser.add_argument('-i', '--input', nargs='*',
                        help='Inputs to be passed to the program via stdin (multiple inputs separated by space)')

    return parser.parse_args()

def main():

    args = parse_args()
    env = (dict(item.split("=", 1) for item in args.env)) if args.env else {}
    inputs = args.input or []
    if args.file:
        print(f"Tracing file: {args.file}")
        # try:
        trace_file(args.file,args.args,args.start,args.max_trace,args.output,env,inputs)
        # except Exception as e:
        #     print("main")
        #     print(e) 
    else:
        print(f"Attaching to PID: {args.pid}")
    # trace_file("./AWayOut2","",0x1249,1000,"Ltrace.asm",{},["lllllllllllllllllllllllll"])
    # print(f"Start address: {hex(args.start)}")
    # print(f"Max trace count: {args.max_trace}")
    # print(f"Output file: {args.output}")

    # if args.env:
    #     env_dict = dict(item.split("=", 1) for item in args.env)
    #     print(f"Environment variables: {env_dict}")
    # else:
    #     print("No environment variables set")


    

if __name__ == '__main__':
    main()
