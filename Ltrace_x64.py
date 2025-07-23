from libdebug import debugger
import os,sys,time
import signal
import threading
from capstone import *
from capstone.x86 import *
from pwn import ELF,context
import argparse
from elftools.elf.elffile import ELFFile

context.log_level ="error"
# libcontext.sym_lvl = 4
TIMEOUT = 10

def timer_thread():
    start = time.perf_counter()
    while True:
        elapsed = time.perf_counter() - start
        sys.stdout.write(f"\rTime: {elapsed:.2f} 秒> ")
        sys.stdout.flush()
        time.sleep(0.1)

def exit_program(d):
    """
    当计时器超时时执行的函数，用于退出程序。
    """
    print(f"error 开始地址不正确，程序可能运行不到这个开始地址，请重新设置")
    os.kill(d.pid,signal.SIGKILL)
    

def exit_program_pid_attach():
    """
    当计时器超时时执行的函数，用于退出程序。
    """
    print(f"没有找到pid，请检查pid是否正确，或者程序是否已经退出")
    os._exit(1)

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

def format_rflags_string(rflags_value):
    """
    解析 RFLAGS 寄存器值，并以字符串形式返回关键标志位的状态。
    """
    # 提取各个标志位
    zf = (rflags_value >> 6) & 1
    sf = (rflags_value >> 7) & 1
    cf = (rflags_value >> 0) & 1
    of = (rflags_value >> 11) & 1
    pf = (rflags_value >> 2) & 1
    af = (rflags_value >> 4) & 1

    # 格式化为字符串
    flags_str = f"ZF={hex(zf)} SF={hex(sf)} CF={hex(cf)} OF={hex(of) } PF={hex(pf)} AF={hex(af)}"
    
    return flags_str

def dump_registers_to_file(d, f):
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

    f.write(format_rflags_string(regs.eflags) + "\n")

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

def pass_ptrace(d):
    def ptrace_handler(d):
        d.regs.rax = 0
        print("hit")
        return
    d.handle_syscall("ptrace",on_exit=ptrace_handler(d))

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
            f.write(f"{hex(ripaddr)}\t\'{lib_info[lib_path]["name"]}\'!{hex(ripaddr-libc_base)}\t{func_name:<6}\n")
            try:
                while(1):
                    if d.dead or d.zombie:
                        print(f"追踪程序已退出。退出代码：{d.exit_code}; 退出信号：{d.exit_signal}")
                        f.close()
                        exit(0)
                    d.step()
                    rip = d.regs.rip

                    if "ld-linux-x86-64.so.2" in lib_path:
                        if rip < lib_info[lib_path]["base"] or rip > lib_info[lib_path]["end"]:
                            return 1
                    if rip >= binary_info["base"] and rip <= binary_info["end"]:
                        return 1
            except RuntimeError as e:
                    print(f"追踪程序意外结束。退出代码：{d.exit_code}; 退出信号：{d.exit_signal}",e)
                    f.close()
                    exit(0)
    return 0

def trace_file(filepath:str, args: list, startaddr:int, maxlen:int, output:str, env:dict, inputdata:list):
    """
    通过二进制文件启动追踪
    """
    
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    # 取程序名称
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
    # pass_ptrace(d)

    # 获取寄存器的值
    rip  = lambda: d.regs.rip
    zf = lambda: (d.regs.eflags & 0x40) >> 6
    sf = lambda: (d.regs.eflags & 0x80) >> 7
    pf = lambda: (d.regs.eflags & 0x4) >> 2
    cf = lambda: (d.regs.eflags & 0x1) >> 0
    of = lambda: (d.regs.eflags & 0x800) >> 11
    af = lambda: (d.regs.eflags & 0x10) >> 4
    
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
                break
    else:
        entrypoint = get_entrypoint(filepath)
        bp2 = d.breakpoint(entrypoint, hardware=True, file = binary_file_name)
        while 1:
            d.cont()
            d.wait()
            if bp2.hit_on(d):
                d.breakpoints[base_addr+entrypoint].disable()
                break

    # 如果初始位置正确，取消计时器
    timer.cancel()

    # 获取程序以及标准库的数据，包括名称、路径、起止地址、导出符号(不能在太前面运行，用于确保所有库已经加载进去)
    lib_info = get_libs_info(d,binary_file_name)
    dump_registers_to_file(d, f)
    
    binary_nick_name = f"\'{binary_file_name}\'" if len(binary_file_name) < 12 else f"\'{binary_file_name[0:10:] + ".."}\'"
    for i in range(maxlen):
        # 检查最终是否已到最大值
        if d.dead or d.zombie:
            print(f"追踪程序已退出。退出代码：{d.exit_code}; 退出信号：{d.exit_signal}")
            f.close()
            exit(0)

        rip_addr = rip()
        try:
            # 读取当前指令
            CODE = d.memory[rip_addr,16]
        except RuntimeError as e:
                print(f"追踪程序意外结束。退出代码：{d.exit_code}; 退出信号：{d.exit_signal}",e)
                f.close()
                exit(0)
        # 解析当前指令
        address, size, mnemonic, op_str = next(md.disasm_lite(CODE, 0x1))
        # 获取标志位，用于跟踪指令执行前后的变化
        flag_regs_before = {"OF": of(), "SF": sf(), "ZF": zf(), "CF": cf(), "PF": pf(), "AF": af()}
        # 获取左右两边的操作数
        registers = [reg.strip() for reg in op_str.split(',')]
        # 处理标准库函数
        lib_func_handler=handle_lib_func(d,rip_addr,f,lib_info,binary_info)
        if lib_func_handler: continue

        # 右侧打印寄存器和内存
        reg_str = ""
        reg_name = registers[0]
        # 直接打印左侧操作数的寄存器
        if reg_name in x64_regs:
            d.step()
            reg_str = ''.join(f"{reg_name:<3}={getattr(d.regs,reg_name):#018x}")

        # 处理指针，内存访问
        elif "["in reg_name and mnemonic != "nop":
            # print(reg_name)
            insn = next(md.disasm(CODE,1))
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
                    d.step()
                    try:
                        mem_data_qword = int.from_bytes(d.memory[(mem_addr&0xffffffffffffffff),8], "little")
                        reg_str = f"mem={mem_data_qword:#018x}"
                    except Exception as e:
                        reg_str = f"mem=[get error]"
                else:
                    mem_addr = getattr(d.regs, base) + getattr(d.regs, index) * scale + disp
                    d.step()
                    try:
                        mem_data_qword = int.from_bytes(d.memory[(mem_addr&0xffffffffffffffff),8], "little")
                        reg_str = f"mem={mem_data_qword:#018x}"
                    except Exception as e:
                        # print(f"Error reading memory at {hex(mem_addr)}: {e},rip={hex(rip())}")
                        # print(f"[{base} + {index}*{scale} + {hex(disp)}]")
                        # d.pprint_regs()
                        # d.print_maps()
                        # exit(1)
                        reg_str = f"mem=[get error]"
                        # d.step()
            else:
                d.step()
        else:
            d.step()

        # 遇到call时打印参数寄存器
        if mnemonic == "call":
            # d.step()
            reg_str = " ".join(f"{r:<3}={getattr(d.regs,r):#018x}" for r in args_regs)

        elif "j" in mnemonic and not "jmp" in mnemonic:
            # d.step()
            # 根据不同的跳转指令添加对应的标志位
            if mnemonic == "js" or mnemonic == "jns":
                reg_str += f" SF={sf()}"
            elif mnemonic == "jo" or mnemonic == "jno":
                reg_str += f" OF={of()}"
            elif mnemonic == "jz" or mnemonic == "jnz":
                reg_str += f" ZF={zf()}"
            elif mnemonic == "jp" or mnemonic == "jnp":
                reg_str += f" PF={pf()}"
            elif mnemonic == "jc" or mnemonic == "jnc":
                reg_str += f" CF={cf()}" 
        
        flag_regs_after = {"OF": of(), "SF": sf(), "ZF": zf(), "CF": cf(), "PF": pf(), "AF": af()}
        for b,a in zip(flag_regs_before, flag_regs_after):
            if flag_regs_before[b] != flag_regs_after[a]:
                reg_str += f" {b}={hex(flag_regs_after[a])}"

        if rip_addr >= binary_info["base"] and rip_addr <= binary_info["end"]:
            f.write(f"{hex(rip_addr)}\t{binary_nick_name}!{hex(rip_addr-base_addr)}\t{mnemonic:<6}\t{op_str:<30}\t{reg_str}\n")
        else:
            f.write(f"{hex(rip_addr)}\t!unkonwn_file\t{mnemonic:<6}\t{op_str:<30}\t{reg_str}\n")
    f.close()
    d.kill()

def trace_pid(pid:int, filepath, startaddr:int, maxlen:int, output:str, inputdata:list):
    """
    通过attach启动追踪
    """
    attach_timer = threading.Timer(TIMEOUT, exit_program_pid_attach)
    attach_timer.daemon = True
    attach_timer.start()

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    # 取程序名称
    binary_file_name = get_binary_name(filepath)

    # 判断追踪程序是否需要输入参数
    d = debugger(filepath,
                auto_interrupt_on_command=True, continue_to_binary_entrypoint=False,escape_antidebug=True)
    p = d.attach(pid)

    attach_timer.cancel()

    global count
    count = 0
    # read系统调用的回调函数，处理程序标准输入
    def handle_read(inputdata):
        global count
        p.sendline(inputdata[count].encode())
        count += 1

    # hook read的系统调用
    if len(inputdata) > 0: d.handle_syscall("read",on_enter=handle_read(inputdata))
    
    # 获取寄存器的值
    rip  = lambda: d.regs.rip
    zf = lambda: (d.regs.eflags & 0x40) >> 6
    sf = lambda: (d.regs.eflags & 0x80) >> 7
    pf = lambda: (d.regs.eflags & 0x4) >> 2
    cf = lambda: (d.regs.eflags & 0x1) >> 0
    of = lambda: (d.regs.eflags & 0x800) >> 11
    af = lambda: (d.regs.eflags & 0x10) >> 4
    
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
                break

    # 如果初始位置正确，取消计时器
    timer.cancel()

    # 获取程序以及标准库的数据，包括名称、路径、起止地址、导出符号(不能在太前面运行，用于确保所有库已经加载进去)
    lib_info = get_libs_info(d,binary_file_name)
    dump_registers_to_file(d, f)
    
    binary_nick_name = f"\'{binary_file_name}\'" if len(binary_file_name) < 12 else f"\'{binary_file_name[0:10:] + ".."}\'"
    for i in range(maxlen):
        # 检查最终是否已到最大值
        if d.dead or d.zombie:
            print(f"追踪程序已退出。退出代码：{d.exit_code}; 退出信号：{d.exit_signal}")
            f.close()
            exit(0)

        rip_addr = rip()
        try:
            # 读取当前指令
            CODE = d.memory[rip_addr,16]
        except RuntimeError as e:
                print(f"追踪程序意外结束。退出代码：{d.exit_code}; 退出信号：{d.exit_signal}",e)
                f.close()
                exit(0)
        # 解析当前指令
        address, size, mnemonic, op_str = next(md.disasm_lite(CODE, 0x1))
        # 获取标志位，用于跟踪指令执行前后的变化
        flag_regs_before = {"OF": of(), "SF": sf(), "ZF": zf(), "CF": cf(), "PF": pf(), "AF": af()}
        # 获取左右两边的操作数
        registers = [reg.strip() for reg in op_str.split(',')]
        # 处理标准库函数
        lib_func_handler=handle_lib_func(d,rip_addr,f,lib_info,binary_info)
        if lib_func_handler: continue

        # 右侧打印寄存器和内存
        reg_str = ""
        reg_name = registers[0]
        # 直接打印左侧操作数的寄存器
        if reg_name in x64_regs:
            d.step()
            reg_str = ''.join(f"{reg_name:<3}={getattr(d.regs,reg_name):#018x}")

        # 处理指针，内存访问
        elif "["in reg_name and mnemonic != "nop":
            # print(reg_name)
            insn = next(md.disasm(CODE,1))
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
                    d.step()
                    try:
                        mem_data_qword = int.from_bytes(d.memory[(mem_addr&0xffffffffffffffff),8], "little")
                        reg_str = f"mem={mem_data_qword:#018x}"
                    except Exception as e:
                        reg_str = f"mem=[get error]"
                else:
                    mem_addr = getattr(d.regs, base) + getattr(d.regs, index) * scale + disp
                    d.step()
                    try:
                        mem_data_qword = int.from_bytes(d.memory[(mem_addr&0xffffffffffffffff),8], "little")
                        reg_str = f"mem={mem_data_qword:#018x}"
                    except Exception as e:
                        reg_str = f"mem=[get error]"
            else:
                d.step()
        else:
            d.step()

        # 遇到call时打印参数寄存器
        if mnemonic == "call":

            reg_str = " ".join(f"{r:<3}={getattr(d.regs,r):#018x}" for r in args_regs)

        elif "j" in mnemonic and not "jmp" in mnemonic:

            # 根据不同的跳转指令添加对应的标志位
            if mnemonic == "js" or mnemonic == "jns":
                reg_str += f" SF={sf()}"
            elif mnemonic == "jo" or mnemonic == "jno":
                reg_str += f" OF={of()}"
            elif mnemonic == "jz" or mnemonic == "jnz":
                reg_str += f" ZF={zf()}"
            elif mnemonic == "jp" or mnemonic == "jnp":
                reg_str += f" PF={pf()}"
            elif mnemonic == "jc" or mnemonic == "jnc":
                reg_str += f" CF={cf()}" 
        
        flag_regs_after = {"OF": of(), "SF": sf(), "ZF": zf(), "CF": cf(), "PF": pf(), "AF": af()}
        for b,a in zip(flag_regs_before, flag_regs_after):
            if flag_regs_before[b] != flag_regs_after[a]:
                reg_str += f" {b}={hex(flag_regs_after[a])}"

        if rip_addr >= binary_info["base"] and rip_addr <= binary_info["end"]:
            f.write(f"{hex(rip_addr)}\t{binary_nick_name}!{hex(rip_addr-base_addr)}\t{mnemonic:<6}\t{op_str:<30}\t{reg_str}\n")
        else:
            f.write(f"{hex(rip_addr)}\t!unkonwn_file\t{mnemonic:<6}\t{op_str:<30}\t{reg_str}\n")
    f.close()
    d.kill()

def parse_args():
    parser = argparse.ArgumentParser(description="Linux trace tool")

    # 选择文件启动还是通过pid附加启动，两者之间必选一个
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--file', type=str, help='需要启动的程序路径')
    group.add_argument('-p', '--pid', type=int, help='要attach的进程ID')

    parser.add_argument("-F", "--filepath", help="程序文件路径(在通过pid附加时必须使用)", type=str, default="")

    # 可选参数，指定开始trace的地址(十六进制的相对地址)，默认从程序的入口点开始。例如：0x1231
    parser.add_argument('-s', '--start', type=lambda x: int(x, 0), default=0,
                        help='可选参数，开始追踪的地址(十六进制，整数)，默认从入口点开始')

    # 可选参数，指定最大的追踪数量，默认100000条
    parser.add_argument('-m', '--max-trace', type=int, default=100000,
                        help='可选参数，最大的追踪数量，默认100000条')

    # 可选参数，运行程序的环境变量，仅在通过文件启动时有效。输入格式 key=value1 key2=value2
    parser.add_argument('-e', '--env', nargs='*',default=None,
                        help='程序运行需要的环境变量，多个环境变量以空格分隔，例如, KEY1=VAL1 KEY2=VAL2')

    # 可选参数，指定输出的追踪文件名称
    parser.add_argument('-o', '--output', type=str, default='Ltrace.asm',
                        help='可选参数，指定输出的文件路径,默认 ./Ltrace.asm')
    
    # 可选参数，程序标准输入流需要输入的数据，如果中途有多次输入，用空格分隔
    parser.add_argument('-i', '--input', nargs='*',
                        help='可选参数，程序使用标准输入流需要输入的数据，多个数据用空格分隔,例如: data1 data2 data3')
    
    # 可选参数，添加程序的启动参数，只有再选择通过文件启动才有效
    parser.add_argument('-a', '--args', nargs=argparse.REMAINDER,
                    help='可选参数，添加程序的启动参数，只有再选择通过文件启动才有效，多个参数用空格分隔(只能放在最后一个参数)')

    return parser.parse_args()

def main():

    args = parse_args()
    env = (dict(item.split("=", 1) for item in args.env)) if args.env else {}
    inputs = args.input or []

    if not args.pid:
        print(f"文件: {args.file} 参数: {args.args} 开始地址: {args.start} 最大trace数量: {args.max_trace} 输出文件: {args.output} 环境变量： {env} 输入流: {inputs}")
        t = threading.Thread(target=timer_thread, daemon=True)
        t.start()
        try:
            trace_file(args.file,args.args,args.start,args.max_trace,args.output,env,inputs)
        except Exception as e:
            print("出现未知错误",e)

    else:
        t = threading.Thread(target=timer_thread, daemon=True)
        t.start()
        print(f"文件: {args.filepath}  开始地址: {args.start} 最大trace数量: {args.max_trace} 输出文件: {args.output} 输入流: {inputs}")
        try:
            trace_pid(args.pid, args.filepath, args.start, args.max_trace, args.output, inputs)
        except PermissionError as e:
            print("没有附加权限，程序通过ptrace进行追踪，请检查你的 ptrace_scope 文件，是否允许非父进程附加\n",e)
        except Exception as e:
            print("出现未知错误",e)
       
if __name__ == '__main__':
    main()
