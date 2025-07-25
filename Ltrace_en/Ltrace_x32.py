from libdebug import debugger
import os,sys,time
import signal
import threading
from capstone import *
from capstone.x86 import *
from pwn import ELF,context
from elftools.elf.elffile import ELFFile

context.log_level ="error"
TIMEOUT = 10

def timer_thread():
    """
    A thread that displays an elapsed time counter.
    """
    start = time.perf_counter()
    while True:
        elapsed = time.perf_counter() - start
        sys.stdout.write(f"\rTime: {elapsed:.2f} seconds> ")
        sys.stdout.flush()
        time.sleep(0.1)

def exit_program(d):
    """
    Function executed when the timer times out, used to exit the program.
    """
    print(f"The starting address is incorrect. The program may not reach this address. Please set it again.")
    os.kill(d.pid,signal.SIGKILL)
    os._exit(1)
    

def exit_program_pid_attach():
    """
    Function executed when the timer times out while attaching, used to exit the program.
    """
    print(f"PID not found. Please check if the PID is correct or if the program has already exited.")
    os._exit(1)

# Note: In the 32-bit cdecl calling convention, arguments are passed on the stack, not in registers.
# This list might be for a different convention or for general-purpose monitoring.
args_regs = [
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"
]

# A comprehensive list of x86 (32-bit) registers
x32_regs = [
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip",

    "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",

    "al", "bl", "cl", "dl",
    # Note: sil, dil, bpl, spl are for 64-bit mode. This might be an error in the original list.
    # For 32-bit, only the low 8 bits of eax, ebx, ecx, edx are addressable as al, bl, cl, dl, ah, bh, ch, dh.
    "ah", "bh", "ch", "dh"
]

def format_rflags_string(eflags_value):
    """
    Parses the EFLAGS register value and returns the status of key flags as a string.
    """
    # Extract individual flag bits
    zf = (eflags_value >> 6) & 1
    sf = (eflags_value >> 7) & 1
    cf = (eflags_value >> 0) & 1
    of = (eflags_value >> 11) & 1
    pf = (eflags_value >> 2) & 1
    af = (eflags_value >> 4) & 1

    # Format as a string
    flags_str = f"ZF={hex(zf)} SF={hex(sf)} CF={hex(cf)} OF={hex(of)} PF={hex(pf)} AF={hex(af)}"
    
    return flags_str

def dump_registers_to_file(d, f):
    """
    Dumps the initial values of the registers to a file.
    """
    regs = d.regs
    general_regs = [
        "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip",
        'eflags',
        'cs', 'ss', 'ds', 'es', 'fs', 'gs'
    ]

    # General-purpose registers
    for i in range(0, len(general_regs), 3):
        line = ""
        for reg in general_regs[i:i+3]:
            val = getattr(regs, reg)
            line += f"{reg:<8} 0x{val:08x}    "
        f.write(line.rstrip() + "\n")

    f.write(format_rflags_string(regs.eflags) + "\n")

    # MMX/ST registers
    for i in range(8):
        mm = getattr(regs, f"mm{i}")
        st = getattr(regs, f"st{i}")
        f.write(f"mm{i}=0x{mm:x}    ")
        f.write(f"st{i}={st}    ")
    f.write("\n")

    # XMM/YMM registers
    for i in range(8):
        xmm = getattr(regs, f"xmm{i}")
        # YMM registers are part of AVX extensions, usually in 64-bit, but check for availability.
        ymm_val = getattr(regs, f"ymm{i}", "N/A")
        f.write(f"xmm{i}=0x{xmm:x}    ")
        if ymm_val != "N/A":
            f.write(f"ymm{i}=0x{ymm_val:x}    ")
    f.write("\n-----------\n")

def get_binary_name(filepath):
    """
    Gets the name of the program from its file path.
    """
    path = filepath.split("/")
    return path[-1]

def get_libs_info(d, binary_file_name):
    """
    Gets information about the program's loaded libraries, including name, path, start/end addresses, and exported symbols.
    """
    try:
        libs_info = {}
        maps = d.maps
        for m in maps:
            path = m.backing_file
            # Skip anonymous mappings
            if not path or not path.startswith("/"):
                continue
            # Skip the program itself
            if binary_file_name in path:
                continue
            # Handle standard libraries
            if path not in libs_info:
                lib_name = path.split("/")[-1]
                libs_info[path] = {"name": lib_name, "base": m.start, "end": m.end, "symbol":{}}
            else:
                libs_info[path]["base"] = min(libs_info[path]["base"], m.start)
                libs_info[path]["end"] = max(libs_info[path]["end"], m.end)
        
        # Get exported symbols for each standard library
        for i in libs_info:
            lib = ELF(i)
            libs_info[i]["symbol"] = {libs_info[i]["base"] + addr: name for name, addr in lib.symbols.items()}

        return libs_info
    except Exception as e:
        d.print_maps()
        d.kill()
        print(e)
        print("Error: Could not read standard libraries. Please terminate all processes related to the traced program before continuing.")
        exit(0)

def get_binary_info(d, binary_file_name):
    """
    Gets information about the program binary, including its name, path, and start/end addresses.
    """
    try:
        binary_info = {}
        maps = d.maps
        for m in maps:
            path = m.backing_file
            if not path or not path.startswith("/"):
                continue
            if binary_file_name in path:
                if not binary_info:
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
        print("Error: Could not read program information. Please terminate all processes related to the traced program before continuing.")
        exit(0)

def get_entrypoint(filepath):
    """
    Gets the program's entry point from the ELF header.
    """
    try:
        with open(filepath, "rb") as f:
            elf = ELFFile(f)
        return elf.header.e_entry
    except Exception as e:
        print("Error: Could not get the program's entry point. The ELF file might be corrupt. Please specify the start address manually or attach using a PID.")
        print(e)
        exit(0)

def handle_lib_func(d, eip_addr, f, lib_info, binary_info, pass_ptrace):
    """
    Handles execution flow when inside a standard library function.
    It steps through the library code until execution returns to the main binary.
    """
    for lib_path in lib_info:
        libc_base = lib_info[lib_path]["base"]
        libc_end = lib_info[lib_path]["end"]
        # Check if the current instruction is inside this library
        if libc_base <= eip_addr <= libc_end:
            # Get the function name if available
            if eip_addr in lib_info[lib_path]["symbol"]:
                func_name = lib_info[lib_path]["symbol"][eip_addr]
            else:
                func_name = f"sub_{eip_addr-libc_base:x}"
            
            f.write(f"{hex(eip_addr)}\t'{lib_info[lib_path]['name']}'!{func_name:<6}\n")
            
            try:
                while True:
                    # Check if the traced program has exited
                    if d.dead or d.zombie:
                        print(f"Traced program has exited. Exit code: {d.exit_code}; Exit signal: {d.exit_signal}")
                        f.close()
                        exit(0)
                    
                    # Handle ptrace anti-debugging
                    if pass_ptrace and d.syscall_number == 24 and d.syscall_arg0 == 0: # ptrace syscall is 26 in x86, not 101. Assuming this is for x86.
                        d.syscall_return = 0
                    
                    d.step()
                    eip = d.regs.eip
                    
                    # If execution is in the linker, run until it exits the linker's memory space
                    if "ld-linux" in lib_path: # More generic check for ld.so
                        if not (lib_info[lib_path]["base"] <= eip <= lib_info[lib_path]["end"]):
                            return 1
                            
                    # If execution returns to the main binary, stop stepping through the library
                    if binary_info["base"] <= eip <= binary_info["end"]:
                        return 1

            except RuntimeError as e:
                print(f"Traced program terminated unexpectedly. Exit code: {d.exit_code}; Exit signal: {d.exit_signal}", e)
                f.close()
                exit(0)
    return 0

def trace_file_x32(filepath:str, args: list, startaddr:int, maxlen:int, output:str, env:dict, inputdata:list, pass_ptrace:bool):
    """
    Starts tracing by launching a 32-bit binary file.
    """
    # Start the timer thread
    t = threading.Thread(target=timer_thread, daemon=True)
    t.start()

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    # Get program name
    binary_file_name = get_binary_name(filepath)

    # Check if the traced program requires arguments
    if args: 
        d = debugger(argv= [filepath] + args,
                     auto_interrupt_on_command=True,continue_to_binary_entrypoint=False,escape_antidebug=True,env=env)
    else: 
        d = debugger(filepath,
                     auto_interrupt_on_command=True, continue_to_binary_entrypoint=False,escape_antidebug=True,env=env)
    p = d.run()
    pid = d.pid

    # Send input data to the program
    for i in range(len(inputdata)): 
        p.sendline(inputdata[i].encode())

    # Lambda functions to get register values
    eip  = lambda: d.regs.eip
    zf = lambda: (d.regs.eflags & 0x40) >> 6
    sf = lambda: (d.regs.eflags & 0x80) >> 7
    pf = lambda: (d.regs.eflags & 0x4) >> 2
    cf = lambda: (d.regs.eflags & 0x1) >> 0
    of = lambda: (d.regs.eflags & 0x800) >> 11
    af = lambda: (d.regs.eflags & 0x10) >> 4
    
    # Get information about the binary file, including start and end addresses
    binary_info = get_binary_info(d, binary_file_name)

    # A timer to check if the initial position is valid
    timer = threading.Timer(TIMEOUT, exit_program, args=(d,))
    timer.daemon = True
    timer.start()
    f = open(output, "w")

    # Run to the specified start address, or the entry point by default if not specified
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

    # If the initial position is correct, cancel the timer
    timer.cancel()

    # Get data for the program and standard libraries (must be run after libraries are loaded)
    lib_info = get_libs_info(d, binary_file_name)

    # Dump the initial values of the registers
    dump_registers_to_file(d, f)
    
    binary_nick_name = f"'{binary_file_name}'" if len(binary_file_name) < 12 else f"'{binary_file_name[0:10]}..'"
    # Main tracing loop
    for i in range(maxlen):
        # Check if the maximum instruction count has been reached or program exited
        if d.dead or d.zombie:
            print(f"Traced program has exited. Exit code: {d.exit_code}; Exit signal: {d.exit_signal}")
            f.close()
            exit(0)

        eip_addr = eip()
        try:
            # Read the current instruction
            CODE = d.memory[eip_addr, 16]
        except RuntimeError as e:
            print(f"Traced program terminated unexpectedly. Exit code: {d.exit_code}; Exit signal: {d.exit_signal}", e)
            f.close()
            exit(0)
            
        # Disassemble the current instruction
        address, size, mnemonic, op_str = next(md.disasm_lite(CODE, 0x1))
        # Get the flag registers to track changes
        flag_regs_before = {"OF": of(), "SF": sf(), "ZF": zf(), "CF": cf(), "PF": pf(), "AF": af()}
        # Get the operands
        registers = [reg.strip() for reg in op_str.split(',')]
        
        # Handle standard library function calls
        if handle_lib_func(d, eip_addr, f, lib_info, binary_info, pass_ptrace):
            continue

        # String to hold register and memory state for printing
        reg_str = ""
        reg_name = registers[0] if registers else ""
        
        # Directly print the destination operand register
        if reg_name in x32_regs:
            d.step()
            reg_str = ''.join(f"{reg_name:<3}={getattr(d.regs,reg_name):#010x}")

        # Handle pointers and memory access
        elif "[" in reg_name and mnemonic != "nop":
            insn = next(md.disasm(CODE, 1))
            op = insn.operands[0]
            if op.type == X86_OP_MEM:
                base = insn.reg_name(op.mem.base)
                index = insn.reg_name(op.mem.index)
                seg = insn.reg_name(op.mem.segment)
                scale = op.mem.scale
                disp = op.mem.disp
                if seg is not None:
                    d.step()
                elif index is None:
                    mem_addr = getattr(d.regs, base) + disp
                    d.step()
                    try:
                        mem_data_dword = int.from_bytes(d.memory[(mem_addr & 0xffffffff), 4], "little")
                        reg_str = f"mem={mem_data_dword:#010x}"
                    except Exception as e:
                        reg_str = f"mem=[error reading]"
                else:
                    mem_addr = getattr(d.regs, base) + getattr(d.regs, index) * scale + disp
                    d.step()
                    try:
                        mem_data_dword = int.from_bytes(d.memory[(mem_addr & 0xffffffff), 4], "little")
                        reg_str = f"mem={mem_data_dword:#010x}"
                    except Exception as e:
                        reg_str = f"mem=[error reading]"
            else:
                d.step()
        else:
            d.step()

        # When a 'call' is encountered, print argument-related registers
        if mnemonic == "call":
            # For 32-bit, args are on the stack, but we can still monitor registers.
            reg_str = " ".join(f"{r:<3}={getattr(d.regs,r):#010x}" for r in args_regs)

        elif "j" in mnemonic and "jmp" not in mnemonic:
            # Add corresponding flags for different jump instructions
            if mnemonic in ["js", "jns"]:
                reg_str += f" SF={sf()}"
            elif mnemonic in ["jo", "jno"]:
                reg_str += f" OF={of()}"
            elif mnemonic in ["jz", "jnz", "je", "jne"]:
                reg_str += f" ZF={zf()}"
            elif mnemonic in ["jp", "jnp"]:
                reg_str += f" PF={pf()}"
            elif mnemonic in ["jc", "jnc", "jb", "jnb", "jae", "jnae"]:
                reg_str += f" CF={cf()}"
                
        # Handle ptrace anti-debugging
        elif mnemonic == "syscall":
            if pass_ptrace and d.syscall_number == 24 and d.syscall_arg0 == 0:
                d.syscall_return = 0
                
        # Get the flags after the instruction execution and note changes
        flag_regs_after = {"OF": of(), "SF": sf(), "ZF": zf(), "CF": cf(), "PF": pf(), "AF": af()}
        for b, a in zip(flag_regs_before, flag_regs_after):
            if flag_regs_before[b] != flag_regs_after[a]:
                reg_str += f" {b}={hex(flag_regs_after[a])}"
                
        # Check the instruction's location and print instruction information
        if binary_info["base"] <= eip_addr <= binary_info["end"]:
            f.write(f"{hex(eip_addr)}\t{binary_nick_name}!{hex(eip_addr-base_addr)}\t{mnemonic:<6}\t{op_str:<30}\t{reg_str}\n")
        else:
            f.write(f"{hex(eip_addr)}\t!unknown_file\t{mnemonic:<6}\t{op_str:<30}\t{reg_str}\n")
            
    f.close()
    d.kill()

def trace_pid_x32(pid:int, filepath:str, startaddr:int, maxlen:int, output:str, inputdata:list, pass_ptrace:bool):
    """
    Starts tracing by attaching to a running 32-bit process.
    """
    # Start the timer thread
    t = threading.Thread(target=timer_thread, daemon=True)
    t.start()

    # Timer to check if the PID is found
    attach_timer = threading.Timer(TIMEOUT, exit_program_pid_attach)
    attach_timer.daemon = True
    attach_timer.start()

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    # Get program name
    binary_file_name = get_binary_name(filepath)

    # Initialize debugger and attach to the process
    d = debugger(filepath,
                 auto_interrupt_on_command=True, continue_to_binary_entrypoint=False,escape_antidebug=True)
    p = d.attach(pid)

    attach_timer.cancel()

    # Send input data to the program
    for i in range(len(inputdata)): 
        p.sendline(inputdata[i].encode())
    
    # Lambda functions to get register values
    eip  = lambda: d.regs.eip
    zf = lambda: (d.regs.eflags & 0x40) >> 6
    sf = lambda: (d.regs.eflags & 0x80) >> 7
    pf = lambda: (d.regs.eflags & 0x4) >> 2
    cf = lambda: (d.regs.eflags & 0x1) >> 0
    of = lambda: (d.regs.eflags & 0x800) >> 11
    af = lambda: (d.regs.eflags & 0x10) >> 4
    
    # Get information about the binary file, including start and end addresses
    binary_info = get_binary_info(d, binary_file_name)

    # A timer to check if the initial position is valid (if startaddr is used)
    timer = threading.Timer(TIMEOUT, exit_program, args=(d,))
    timer.daemon = True
    timer.start()
    f = open(output, "w")

    # If a start address is specified, set a breakpoint and continue until it's hit
    if startaddr != 0:
        base_addr = binary_info["base"]
        bp1 = d.breakpoint(startaddr, hardware=True, file = binary_file_name)
        while 1:
            d.cont()
            d.wait()
            if bp1.hit_on(d):
                d.breakpoints[base_addr+startaddr].disable()
                break

    # If the initial position is correct, cancel the timer
    timer.cancel()

    # Get data for the program and standard libraries (must be run after libraries are loaded)
    lib_info = get_libs_info(d, binary_file_name)

    # Dump the initial values of the registers
    dump_registers_to_file(d, f)
    
    binary_nick_name = f"'{binary_file_name}'" if len(binary_file_name) < 12 else f"'{binary_file_name[0:10]}..'"
    for i in range(maxlen):
        # Check if the traced program has exited
        if d.dead or d.zombie:
            print(f"Traced program has exited. Exit code: {d.exit_code}; Exit signal: {d.exit_signal}")
            f.close()
            exit(0)

        eip_addr = eip()
        try:
            # Read the current instruction
            CODE = d.memory[eip_addr, 16]
        except RuntimeError as e:
            print(f"Traced program terminated unexpectedly. Exit code: {d.exit_code}; Exit signal: {d.exit_signal}", e)
            f.close()
            exit(0)
            
        # Disassemble the current instruction
        address, size, mnemonic, op_str = next(md.disasm_lite(CODE, 0x1))
        # Get the flag registers to track changes
        flag_regs_before = {"OF": of(), "SF": sf(), "ZF": zf(), "CF": cf(), "PF": pf(), "AF": af()}
        # Get the operands
        registers = [reg.strip() for reg in op_str.split(',')]
        
        # Handle standard library function calls
        if handle_lib_func(d, eip_addr, f, lib_info, binary_info, pass_ptrace):
            continue

        # String to hold register and memory state for printing
        reg_str = ""
        reg_name = registers[0] if registers else ""
        
        # Directly print the destination operand register
        if reg_name in x32_regs:
            d.step()
            reg_str = ''.join(f"{reg_name:<3}={getattr(d.regs,reg_name):#010x}")

        # Handle pointers and memory access
        elif "[" in reg_name and mnemonic != "nop":
            insn = next(md.disasm(CODE, 1))
            op = insn.operands[0]
            if op.type == X86_OP_MEM:
                base = insn.reg_name(op.mem.base)
                index = insn.reg_name(op.mem.index)
                seg = insn.reg_name(op.mem.segment)
                scale = op.mem.scale
                disp = op.mem.disp
                if seg is not None:
                    d.step()
                elif index is None:
                    mem_addr = getattr(d.regs, base) + disp
                    d.step()
                    try:
                        mem_data_dword = int.from_bytes(d.memory[(mem_addr & 0xffffffff), 4], "little")
                        reg_str = f"mem={mem_data_dword:#010x}"
                    except Exception as e:
                        reg_str = f"mem=[error reading]"
                else:
                    mem_addr = getattr(d.regs, base) + getattr(d.regs, index) * scale + disp
                    d.step()
                    try:
                        mem_data_dword = int.from_bytes(d.memory[(mem_addr & 0xffffffff), 4], "little")
                        reg_str = f"mem={mem_data_dword:#010x}"
                    except Exception as e:
                        reg_str = f"mem=[error reading]"
            else:
                d.step()
        else:
            d.step()

        # When a 'call' is encountered, print argument-related registers
        if mnemonic == "call":
            reg_str = " ".join(f"{r:<3}={getattr(d.regs,r):#010x}" for r in args_regs)

        elif "j" in mnemonic and "jmp" not in mnemonic:
            # Add corresponding flags for different jump instructions
            if mnemonic in ["js", "jns"]:
                reg_str += f" SF={sf()}"
            elif mnemonic in ["jo", "jno"]:
                reg_str += f" OF={of()}"
            elif mnemonic in ["jz", "jnz", "je", "jne"]:
                reg_str += f" ZF={zf()}"
            elif mnemonic in ["jp", "jnp"]:
                reg_str += f" PF={pf()}"
            elif mnemonic in ["jc", "jnc", "jb", "jnb", "jae", "jnae"]:
                reg_str += f" CF={cf()}"
                
        # Handle ptrace anti-debugging
        elif mnemonic == "syscall":
            if pass_ptrace and d.syscall_number == 24 and d.syscall_arg0 == 0:
                d.syscall_return = 0
                
        # Get the flags after the instruction execution and note changes
        flag_regs_after = {"OF": of(), "SF": sf(), "ZF": zf(), "CF": cf(), "PF": pf(), "AF": af()}
        for b, a in zip(flag_regs_before, flag_regs_after):
            if flag_regs_before[b] != flag_regs_after[a]:
                reg_str += f" {b}={hex(flag_regs_after[a])}"
                
        # Check the instruction's location and print instruction information
        base_addr = binary_info["base"]
        if binary_info["base"] <= eip_addr <= binary_info["end"]:
            f.write(f"{hex(eip_addr)}\t{binary_nick_name}!{hex(eip_addr-base_addr)}\t{mnemonic:<6}\t{op_str:<30}\t{reg_str}\n")
        else:
            f.write(f"{hex(eip_addr)}\t!unknown_file\t{mnemonic:<6}\t{op_str:<30}\t{reg_str}\n")
            
    f.close()
    d.kill()