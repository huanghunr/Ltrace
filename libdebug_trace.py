from libdebug import debugger
from libdebug import libcontext
from ctypes import * 
import os
import signal
import threading
import time
import io
from capstone import *
from capstone.x86 import *
from tqdm import tqdm
import psutil
from pwn import ELF,context
import argparse
from elftools.elf.elffile import ELFFile

context.log_level ="error"
# libcontext.sym_lvl = 4
TIMEOUT = 5

def exit_program(d:object):
    """
    当计时器超时时执行的函数，用于退出程序。
    """
    print(f"error 开始地址不正确，程序可能运行不到这个开始地址，请重新设置")
    os.kill(d.pid,signal.SIGKILL)
    exit(1)

args_regs = [
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "rip",
]

x64_regs = [
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "rip",
    
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
    "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",

    "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
    "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w",

    "al", "bl", "cl", "dl", "sil", "dil", "bpl", "spl",
    "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
    "ah", "bh", "ch", "dh"
]

def dump_registers_to_file(d:object, f:io.TextIOBase):
    """
    打印寄存器的初始值
    """
    regs = d.regs
    general_regs = [
        'rax', 'rbx', 'rcx', 'rdx', 'rdi', 'rsi',
        'r8',  'r9',  'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
        'rbp', 'rsp', 'rip', 'eflags',
        'cs', 'ss', 'ds', 'es', 'fs', 'gs',
        'fs_base', 'gs_base'
    ]

    # 通用寄存器
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

def format_rflags_string(rflags_value):
    """
    解析 RFLAGS 寄存器值，并以字符串形式返回关键标志位的状态。

    Args:
        rflags_value (int): RFLAGS 寄存器的整数值。

    Returns:
        str: 包含 ZF, SF, CF, OF 状态的格式化字符串，例如 "ZF=1 SF=0 CF=0 OF=0"。
    """
    # 提取各个标志位
    zf = (rflags_value >> 6) & 1  # Zero Flag (位 6)
    sf = (rflags_value >> 7) & 1  # Sign Flag (位 7)
    cf = (rflags_value >> 0) & 1  # Carry Flag (位 0)
    of = (rflags_value >> 11) & 1 # Overflow Flag (位 11)

    # 格式化为字符串
    flags_str = f"ZF={hex(zf)} SF={hex(sf)} CF={hex(cf)} OF={hex(of)}"
    
    return flags_str

def get_binary_name(filepath):
    """
    获取程序的名称
    """
    path = filepath.split("/")
    return path[-1]

def get_libs_info(d,binary_file_name):
    """
    获取程序以及标准库的数据，包括名称、路径、起止地址、导出符号
    """
    try:
        libs_info = {}
        maps = d.maps
        for m in maps:
            path = m.backing_file
            if not path or not path.startswith("/"):
                continue
            if binary_file_name in path:
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

        return libs_info
    except Exception as e:
        d.print_maps()
        d.kill()
        print(e)
        print("error: 无法读取标准库，请在结束所有与追踪程序相关进程后再继续")
        exit(0)

def get_binary_info(d, binary_file_name):
    """
    获取程序以及标准库的数据，包括名称、路径、起止地址、导出符号
    """
    try:
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
        return binary_info
    except Exception as e:
        d.print_maps()
        d.kill()
        print(e)
        print("error: 无法读取程序信息，请在结束所有与追踪程序相关进程后再继续")
        exit(0)

def get_entrypoint(filepath):
    """
    获取程序的入口点
    """
    try:
        with open(filepath, "rb") as f:
            elf = ELFFile(f)
        return elf.header.e_entry
    except Exception as e:
        print("error:无法获取程序的入口点，elf 文件可能已经损坏，请手动指定开始地址或者使用 pid 进行附加")
        print(e)
        exit(0)

def handle_lib_func(d,ripaddr, f, lib_info, binary_info):
    """
    处理标准库函数
    """
    for lib_path in lib_info:
        libc_base = lib_info[lib_path]["base"]
        libc_end = lib_info[lib_path]["end"]
        if ripaddr >= libc_base and ripaddr <= libc_end:
            if ripaddr in lib_info[lib_path]["symbol"]:
                func_name = lib_info[lib_path]["symbol"][ripaddr]
            else:
                func_name = f"unknown_lib_function({lib_info[lib_path]["name"]})"
            f.write(f"{hex(ripaddr)}\t{lib_info[lib_path]["name"]}!{hex(ripaddr-libc_base)}\t{func_name:<6}\n")

            # print(func_name,ret_addr)
            try:
                while(1):
                    d.step()
                    rip = d.regs.rip
                    # f.write(f"{hex(rip)}\n")
                    if "ld-linux-x86-64.so.2" in lib_path:
                        if rip < lib_info[lib_path]["base"] or rip > lib_info[lib_path]["end"]:
                            return 1
                    if rip >= binary_info["base"] and rip <= binary_info["end"]:
                        return 1
                    # handle_lib_func(d,rip, f, lib_info, binary_info)
                    
            except RuntimeError as e:
                if str(e) =="All threads are dead." or str(e) == "The thread is dead.":
                    print(f"追踪程序已运行结束。退出代码：{d.exit_code}; 退出信号：{d.exit_signal}")
                    f.close()
                    exit(0)
                else:
                    print("运行错误",e)
                    exit(1)
    return 0

def trace_file(filepath:str, args: list, startaddr:int, maxlen:int, output:str, env:dict, inputdata:list):
    """
    通过二进制文件启动追踪
    """
    
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    
    binary_file_name = get_binary_name(filepath)

    # 判断追踪程序是否需要输入参数
    if args: 
        d = debugger(argv= [filepath] + args,
                     auto_interrupt_on_command=True,continue_to_binary_entrypoint=False,escape_antidebug=True,env=env)
    else: 
        d = debugger(filepath,
                     auto_interrupt_on_command=True, continue_to_binary_entrypoint=False,escape_antidebug=True,env=env)
    p = d.run()
    pid = d.pid
    
    # d.pprint_maps()

    global count
    count = 0
    # read系统调用的回调函数，处理程序标准输入
    def handle_read(inputdata):
        global count
        p.sendline(inputdata[count].encode())
        count += 1

    # hook read的系统调用
    if len(inputdata) > 0: d.handle_syscall("read",on_enter=handle_read(inputdata))

    rip  = lambda: d.regs.rip
    
    # 获取二进制文件的信息，包括起止地址
    binary_info = get_binary_info(d,binary_file_name)

    # 计数器用于检查初始位置是否合法
    timer = threading.Timer(TIMEOUT, exit_program,args=(d))
    timer.daemon = True
    timer.start()
    f = open(output, "w")

    # 运行到指定的开始地址，没有指定默认从入口点开始
    base_addr = binary_info["base"]
    if startaddr != 0:
        bp1 = d.breakpoint(startaddr, hardware=True, file = binary_file_name)
        while 1:
            d.cont()
            d.wait()
            if bp1.hit_on(d):
                d.breakpoints[base_addr+startaddr].disable()
                # print(hex(base_addr+startaddr),hex(rip()))
                break
    else:
        entrypoint = get_entrypoint(filepath)
        bp2 = d.breakpoint(entrypoint, hardware=True, file = binary_file_name)
        while 1:
            d.cont()
            d.wait()
            if bp2.hit_on(d):
                d.breakpoints[base_addr+entrypoint].disable()
                # print(hex(base_addr+startaddr),hex(rip()))
                break

    # 如果初始位置正确，取消计时器
    timer.cancel()

    # 获取程序以及标准库的数据，包括名称、路径、起止地址、导出符号(不能在太前面运行，用于确保所有库已经加载进去)
    lib_info = get_libs_info(d,binary_file_name)
    dump_registers_to_file(d, f)
    
    binary_nick_name = f"\'{binary_file_name}\'" if len(binary_file_name) < 12 else f"\'{binary_file_name[0:10:] + ".."}\'"
    for i in tqdm(range(maxlen)):
        ripaddr = rip()

        try:
            CODE = d.memory[ripaddr,16]
        except RuntimeError as e:
            if str(e) =="All threads are dead.":
                print(f"追踪程序已运行结束。退出代码：{d.exit_code}; 退出信号：{d.exit_signal}")
                f.close()
                exit(0)
            else:
                print("解析错误",e)
                exit(1)
        address, size, mnemonic, op_str = next(md.disasm_lite(CODE, 0x1))
        registers = [reg.strip() for reg in op_str.split(',')]
        # print(mnemonic,op_str)
        # print(binary_info)
        lib_func_handler=handle_lib_func(d,ripaddr,f,lib_info,binary_info)
        if lib_func_handler: continue

        # 右侧打印寄存器和内存
        reg_str = ""
        reg_name = registers[0]
        # 直接打印寄存器
        if reg_name in x64_regs:
            d.step()
            reg_str = ''.join(f"{reg_name:<3}={getattr(d.regs,reg_name):#018x}")

        # 处理指针，内存访问
        elif "["in reg_name:
            # print(reg_name)
            insn = next(md.disasm(CODE,1))
            op = insn.operands[0]
            if op.type == X86_OP_MEM:
                base = insn.reg_name(op.mem.base)
                index = insn.reg_name(op.mem.index)
                seg = insn.reg_name(op.mem.segment)
                scale = op.mem.scale
                disp = op.mem.disp
                if not seg is None or mnemonic == "nop":
                    d.step()
                elif index is None or index == "riz":
                    mem_addr = getattr(d.regs, base) + disp
                else:
                    mem_addr = getattr(d.regs, base) + getattr(d.regs, index) * scale + disp
                try:
                    d.step()
                    # print(hex(mem_addr),mnemonic,op_str,ripaddr)
                    mem_data_qword = int.from_bytes(d.memory[(mem_addr&0xffffffffffffffff),8], "little")
                    reg_str = f"mem={mem_data_qword:#018x}"
                except Exception as e:
                    # print(f"Error reading memory at {hex(mem_addr)}: {e},rip={hex(rip())}")
                    # print(f"[{base} + {index}*{scale} + {hex(disp)}]")
                    # d.pprint_regs()
                    # d.print_maps()
                    # exit(1)
                    reg_str = f"mem=[get error]"
                    d.step()
        else:
            d.step()

                # 遇到call时打印参数寄存器
        if mnemonic == "call":
            d.step()
            reg_str = " ".join(f"{r:<3}={getattr(d.regs,r):#018x}" for r in args_regs)

        # 遇到cmp时输出标志位
        elif mnemonic == "cmp" or mnemonic == "":
            d.step()
            reg_str += " " + format_rflags_string(d.regs.eflags)


        if ripaddr >= binary_info["base"] and ripaddr <= binary_info["end"]:
            f.write(f"{hex(ripaddr)}\t{binary_nick_name}!{hex(ripaddr-base_addr)}\t{mnemonic:<6}\t{op_str:<30}\t{reg_str}\n")
        else:
            f.write(f"{hex(ripaddr)}\t!unkonwn_file\t{mnemonic:<6}\t{op_str:<30}\t{reg_str}\n")
    f.close()
    d.kill()

def parse_args():
    parser = argparse.ArgumentParser(description="Linux trace tool")

    # 选择文件启动还是通过pid附加启动，两者之间必选一个
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--file', type=str, help='Path to the executable file to be traced')
    group.add_argument('-p', '--pid', type=int, help='PID of the process to attach to')

    # 可选参数，添加程序的启动参数，只有再选择通过文件启动才有效
    parser.add_argument('-a', '--args', nargs=argparse.REMAINDER,
                    help='Arguments for the target program (use "--" to separate them)(only valid with --file)')

    # 可选参数，指定开始trace的地址(十六进制的相对地址)，默认从程序的入口点开始。例如：0x1231
    parser.add_argument('-s', '--start', type=lambda x: int(x, 0), default=0,
                        help='Trace start address (default: 0; accepts hex like 0x400000)')

    # 可选参数，指定最大的追踪数量，默认100000条
    parser.add_argument('-m', '--max-trace', type=int, default=100000,
                        help='Maximum number of instructions to trace (default: 100000)')

    # 可选参数，运行程序的环境变量，仅在通过文件启动时有效。输入格式 key=value1 key2=value2
    parser.add_argument('-e', '--env', nargs='*',default=None,
                        help='Environment variables for the process, e.g., KEY1=VAL1 KEY2=VAL2')

    # 可选参数，指定输出的追踪文件名称
    parser.add_argument('-o', '--output', type=str, default='Ltrace.asm',
                        help='Output trace file name (default: Ltrace.asm)')
    
    # 可选参数，程序标准输入流需要输入的数据，如果中途有多次输入，用空格分隔
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
        print(args.file,args.args,args.start,args.max_trace,args.output,env,inputs)
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
