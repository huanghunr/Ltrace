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
    os._exit(1)
    

def exit_program_pid_attach():
    """
    当计时器超时时执行的函数，用于退出程序。
    """
    print(f"没有找到pid，请检查pid是否正确，或者程序是否已经退出")
    os._exit(1)

args_regs = [
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"
]

x32_regs = [
    
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip",

    "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",

    "al", "bl", "cl", "dl", "sil", "dil", "bpl", "spl",

    "ah", "bh", "ch", "dh"
]

def format_rflags_string(eflags_value):
    """
    解析 RFLAGS 寄存器值，并以字符串形式返回关键标志位的状态。
    """
    # 提取各个标志位
    zf = (eflags_value >> 6) & 1
    sf = (eflags_value >> 7) & 1
    cf = (eflags_value >> 0) & 1
    of = (eflags_value >> 11) & 1
    pf = (eflags_value >> 2) & 1
    af = (eflags_value >> 4) & 1

    # 格式化为字符串
    flags_str = f"ZF={hex(zf)} SF={hex(sf)} CF={hex(cf)} OF={hex(of) } PF={hex(pf)} AF={hex(af)}"
    
    return flags_str

def dump_registers_to_file(d, f):
    """
    打印寄存器的初始值
    """
    regs = d.regs
    general_regs = [
        "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip",
        'eflags',
        'cs', 'ss', 'ds', 'es', 'fs', 'gs'
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
    for i in range(8):
        xmm = getattr(regs, f"xmm{i}")
        ymm = getattr(regs, f"ymm{i}")
        f.write(f"xmm{i}=0x{xmm:x}    ")
        f.write(f"ymm{i}=0x{ymm:x}    ")
    f.write("\n-----------\n")

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
            # 跳过匿名映射
            if not path or not path.startswith("/"):
                continue
            # 跳过程序本身
            if binary_file_name in path:
                continue
            # 处理标准库
            if path not in libs_info:
                lib_name = path.split("/")[-1]
                libs_info[path] = {"name": lib_name, "base": m.start, "end": m.end, "symbol":{}}
            else:
                libs_info[path]["base"] = min(libs_info[path]["base"], m.start)
                libs_info[path]["end"] = max(libs_info[path]["end"], m.end)
        # 获取标准库的导出符号
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

def handle_lib_func(d,eipaddr, f, lib_info, binary_info, pass_ptrace):
    """
    处理标准库函数
    """
    for lib_path in lib_info:
        libc_base = lib_info[lib_path]["base"]
        libc_end = lib_info[lib_path]["end"]
        # 检查当前指令是否在标准库内
        if eipaddr >= libc_base and eipaddr <= libc_end:
            # 获取函数名称
            if eipaddr in lib_info[lib_path]["symbol"]:
                func_name = lib_info[lib_path]["symbol"][eipaddr]
            else:
                func_name = f"unknown_lib_function({lib_info[lib_path]["name"]})"
            f.write(f"{hex(eipaddr)}\t\'{lib_info[lib_path]["name"]}\'!{hex(eipaddr-libc_base)}\t{func_name:<6}\n")
            try:
                while(1):
                    # 检查追踪程序是否已经退出
                    if d.dead or d.zombie:
                        print(f"追踪程序已退出。退出代码：{d.exit_code}; 退出信号：{d.exit_signal}")
                        f.close()
                        exit(0)
                    # 处理ptrace反调试
                    if pass_ptrace and d.syscall_number == 101 and d.syscall_arg0 == 0:
                        d.syscall_return = 0
                    d.step()
                    eip = d.regs.eip
                    # 如果在链接器内就运行到链接器的结束
                    if "ld-linux-x86-64.so.2" in lib_path:
                        if eip < lib_info[lib_path]["base"] or eip > lib_info[lib_path]["end"]:
                            return 1
                    # 如果在标准库内就运行到程序内再继续
                    if eip >= binary_info["base"] and eip <= binary_info["end"]:
                        return 1
            except RuntimeError as e:
                    print(f"追踪程序意外结束。退出代码：{d.exit_code}; 退出信号：{d.exit_signal}",e)
                    f.close()
                    exit(0)
    return 0

def trace_file_x32(filepath:str, args: list, startaddr:int, maxlen:int, output:str, env:dict, inputdata:list, pass_ptrace:bool):
    """
    通过二进制文件启动追踪
    """
    # 计时器
    t = threading.Thread(target=timer_thread, daemon=True)
    t.start()

    md = Cs(CS_ARCH_X86, CS_MODE_32)
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

    # 发送程序需要输入的数据
    for i in range(len(inputdata)): 
        p.sendline(inputdata[i].encode())
    # pass_ptrace(d)

    # 获取寄存器的值
    eip  = lambda: d.regs.eip
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

    # 打印寄存器的初始值
    dump_registers_to_file(d, f)
    
    binary_nick_name = f"\'{binary_file_name}\'" if len(binary_file_name) < 12 else f"\'{binary_file_name[0:10:] + ".."}\'"
    # 主循环
    for i in range(maxlen):
        # 检查最终是否已到最大值
        if d.dead or d.zombie:
            print(f"追踪程序已退出。退出代码：{d.exit_code}; 退出信号：{d.exit_signal}")
            f.close()
            exit(0)

        eip_addr = eip()
        try:
            # 读取当前指令
            CODE = d.memory[eip_addr,16]
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
        lib_func_handler=handle_lib_func(d,eip_addr,f,lib_info,binary_info,pass_ptrace)
        if lib_func_handler: continue

        # 右侧打印寄存器和内存
        reg_str = ""
        reg_name = registers[0]
        # 直接打印左侧操作数的寄存器
        if reg_name in x32_regs:
            d.step()
            reg_str = ''.join(f"{reg_name:<3}={getattr(d.regs,reg_name):#018x}")

        # 处理指针，内存访问
        elif "["in reg_name and mnemonic != "nop":

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
                elif index is None:
                    mem_addr = getattr(d.regs, base) + disp
                    d.step()
                    try:
                        mem_data_qword = int.from_bytes(d.memory[(mem_addr&0xffffffff),4], "little")
                        reg_str = f"mem={mem_data_qword:#018x}"
                    except Exception as e:
                        reg_str = f"mem=[get error]"
                else:
                    mem_addr = getattr(d.regs, base) + getattr(d.regs, index) * scale + disp
                    d.step()
                    try:
                        mem_data_qword = int.from_bytes(d.memory[(mem_addr&0xffffffff),4], "little")
                        reg_str = f"mem={mem_data_qword:#018x}"
                    except Exception as e:
                        # print(f"Error reading memory at {hex(mem_addr)}: {e},eip={hex(eip())}")
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
        # 处理ptrace反调试
        elif mnemonic == "syscall":
            if pass_ptrace and d.syscall_number == 101 and d.syscall_arg0 == 0:
                d.syscall_return = 0
        # 获取指令执行后的标志位
        flag_regs_after = {"OF": of(), "SF": sf(), "ZF": zf(), "CF": cf(), "PF": pf(), "AF": af()}
        for b,a in zip(flag_regs_before, flag_regs_after):
            if flag_regs_before[b] != flag_regs_after[a]:
                reg_str += f" {b}={hex(flag_regs_after[a])}"
        # 检查指令所在的位置，打印指令信息
        if eip_addr >= binary_info["base"] and eip_addr <= binary_info["end"]:
            f.write(f"{hex(eip_addr)}\t{binary_nick_name}!{hex(eip_addr-base_addr)}\t{mnemonic:<6}\t{op_str:<30}\t{reg_str}\n")
        else:
            f.write(f"{hex(eip_addr)}\t!unkonwn_file\t{mnemonic:<6}\t{op_str:<30}\t{reg_str}\n")
    f.close()
    d.kill()

def trace_pid_x32(pid:int, filepath, startaddr:int, maxlen:int, output:str, inputdata:list,pass_ptrace:bool):
    """
    通过attach启动追踪
    """
    # 计时器
    t = threading.Thread(target=timer_thread, daemon=True)
    t.start()

    # 计时器用于判断是否找到pid
    attach_timer = threading.Timer(TIMEOUT, exit_program_pid_attach)
    attach_timer.daemon = True
    attach_timer.start()

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    # 取程序名称
    binary_file_name = get_binary_name(filepath)

    # 判断追踪程序是否需要输入参数
    d = debugger(filepath,
                auto_interrupt_on_command=True, continue_to_binary_entrypoint=False,escape_antidebug=True)
    p = d.attach(pid)

    attach_timer.cancel()

    #输入程序需要输入的数据
    for i in range(len(inputdata)): 
        p.sendline(inputdata[i].encode())
    
    # 获取寄存器的值
    eip  = lambda: d.regs.eip
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

    # 打印寄存器的初始值
    dump_registers_to_file(d, f)
    
    binary_nick_name = f"\'{binary_file_name}\'" if len(binary_file_name) < 12 else f"\'{binary_file_name[0:10:] + ".."}\'"
    for i in range(maxlen):
        # 检查最终是否已到最大值
        if d.dead or d.zombie:
            print(f"追踪程序已退出。退出代码：{d.exit_code}; 退出信号：{d.exit_signal}")
            f.close()
            exit(0)

        eip_addr = eip()
        try:
            # 读取当前指令
            CODE = d.memory[eip_addr,16]
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
        lib_func_handler=handle_lib_func(d,eip_addr,f,lib_info,binary_info,pass_ptrace)
        if lib_func_handler: continue

        # 右侧打印寄存器和内存
        reg_str = ""
        reg_name = registers[0]
        # 直接打印左侧操作数的寄存器
        if reg_name in x32_regs:
            d.step()
            reg_str = ''.join(f"{reg_name:<3}={getattr(d.regs,reg_name):#018x}")

        # 处理指针，内存访问
        elif "["in reg_name and mnemonic != "nop":
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
                        mem_data_qword = int.from_bytes(d.memory[(mem_addr&0xffffffff),4], "little")
                        reg_str = f"mem={mem_data_qword:#018x}"
                    except Exception as e:
                        reg_str = f"mem=[get error]"
                else:
                    mem_addr = getattr(d.regs, base) + getattr(d.regs, index) * scale + disp
                    d.step()
                    try:
                        mem_data_qword = int.from_bytes(d.memory[(mem_addr&0xffffffff),4], "little")
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
        # 处理ptrace反调试
        elif mnemonic == "syscall":
            if pass_ptrace and d.syscall_number == 101 and d.syscall_arg0 == 0:
                d.syscall_return = 0
        # 获取指令执行后的标志位
        flag_regs_after = {"OF": of(), "SF": sf(), "ZF": zf(), "CF": cf(), "PF": pf(), "AF": af()}
        for b,a in zip(flag_regs_before, flag_regs_after):
            if flag_regs_before[b] != flag_regs_after[a]:
                reg_str += f" {b}={hex(flag_regs_after[a])}"
        # 检查指令所在的位置，打印指令信息
        if eip_addr >= binary_info["base"] and eip_addr <= binary_info["end"]:
            f.write(f"{hex(eip_addr)}\t{binary_nick_name}!{hex(eip_addr-base_addr)}\t{mnemonic:<6}\t{op_str:<30}\t{reg_str}\n")
        else:
            f.write(f"{hex(eip_addr)}\t!unkonwn_file\t{mnemonic:<6}\t{op_str:<30}\t{reg_str}\n")
    f.close()
    d.kill()

