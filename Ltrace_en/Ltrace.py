from Ltrace_x32 import trace_file_x32, trace_pid_x32
from Ltrace_x64 import trace_file_x64, trace_pid_x64
from elftools.elf.elffile import ELFFile
import argparse

def is_64_bit_elf(filepath):
    """Checks if the given file is a 64-bit ELF binary."""
    with open(filepath, 'rb') as f:
        elf = ELFFile(f)
        return elf.elfclass == 64

def parse_args():
    """Parses command-line arguments for the tracer."""
    parser = argparse.ArgumentParser(description="A simple instruction tracer for Linux ELF binaries.")

    # A mutually exclusive group: the user must choose to either trace a new file or attach to a PID.
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--file', type=str, 
                       help='The path of the program to execute and trace.')
    group.add_argument('-p', '--pid', type=int, 
                       help='The Process ID (PID) to attach to for tracing.')

    parser.add_argument("-F", "--filepath", type=str, default="",
                        help="The program's file path (required when attaching with -p/--pid).")

    # Optional argument: Specify the starting address for the trace.
    parser.add_argument('-s', '--start', type=lambda x: int(x, 0), default=0,
                        help='The address (hex or int) to start tracing from. Defaults to the entry point.')

    # Optional argument: Specify the maximum number of instructions to trace.
    parser.add_argument('-m', '--max-trace', type=int, default=1000000,
                        help='The maximum number of instructions to trace. Defaults to 1,000,000.')

    # Optional argument: Set environment variables for the program (file mode only).
    parser.add_argument('-e', '--env', nargs='*', default=None,
                        help='Environment variables for the program, e.g., KEY1=VAL1 KEY2=VAL2.')

    # Optional argument: Specify the output file name.
    parser.add_argument('-o', '--output', type=str, default='Ltrace.asm',
                        help='The path for the output trace file. Defaults to ./Ltrace.asm.')
    
    # Optional argument: Provide standard input to the program.
    parser.add_argument('-i', '--input', nargs='*',
                        help='Data to send to the program\'s standard input, separated by spaces (e.g., data1 data2).')
    
    # Optional argument: Enable anti-debugging bypass techniques.
    parser.add_argument('-pa', '--pass-antidebug', type=int, choices=[0, 1], default=0,
                        help='Enable anti-debugging bypass. 0=disabled, 1=enabled. Default: 0.')
    
    # Optional argument: Add arguments for the program being traced (file mode only).
    parser.add_argument('-a', '--args', nargs=argparse.REMAINDER,
                        help='Arguments for the program being traced. This must be the final option provided.')

    return parser.parse_args()

def main():
    args = parse_args()

    # Process environment variables and standard input data.
    env = dict(item.split("=", 1) for item in args.env) if args.env else {}
    inputs = args.input or []

    # Determine if anti-debugging bypass is enabled.
    pass_ptrace = args.pass_antidebug == 1

    print("If the program seems to hang or produces no output, please check the following:")
    print("1. Does the program require input? (Use the -i flag)")
    print("2. Is the specified start address correct and reachable?")
    print("3. Has the program already exited or crashed?")
    print("If necessary, terminate with Ctrl+C and manually kill any remaining processes.")
    print("-" * 30)

    # If tracing a new program from a file
    if args.file:
        print(f"File: {args.file}")
        print(f"Arguments: {args.args}")
        print(f"Start Address: {hex(args.start)}")
        print(f"Max Trace Count: {args.max_trace}")
        print(f"Output File: {args.output}")
        print(f"Environment: {env}")
        print(f"Input Stream: {inputs}")
        print(f"Anti-Debugging: {'Enabled' if pass_ptrace else 'Disabled'}")

        try:
            if is_64_bit_elf(args.file):
                trace_file_x64(args.file, args.args, args.start, args.max_trace, args.output, env, inputs, pass_ptrace)
            else:
                trace_file_x32(args.file, args.args, args.start, args.max_trace, args.output, env, inputs, pass_ptrace)
        except Exception as e:
            print(f"An unknown error occurred: {e}")

    # If attaching to an existing process
    else:
        if not args.filepath:
            print("Error: The -F/--filepath argument is required when attaching with -p/--pid.")
            return

        print(f"Attaching to PID: {args.pid}")
        print(f"File Path: {args.filepath}")
        print(f"Start Address: {hex(args.start) if args.start != 0 else 'Current EIP/RIP'}")
        print(f"Max Trace Count: {args.max_trace}")
        print(f"Output File: {args.output}")
        print(f"Input Stream: {inputs}")
        print(f"Anti-Debugging: {'Enabled' if pass_ptrace else 'Disabled'}")

        try:
            if is_64_bit_elf(args.filepath):
                trace_pid_x64(args.pid, args.filepath, args.start, args.max_trace, args.output, inputs, pass_ptrace)
            else:
                trace_pid_x32(args.pid, args.filepath, args.start, args.max_trace, args.output, inputs, pass_ptrace)
        except PermissionError as e:
            print("\nPermission denied for attaching. Check ptrace_scope settings.")
            print("You may need to run 'echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope' or run as root.")
            print(f"Original error: {e}")
        except Exception as e:
            print(f"An unknown error occurred: {e}")

if __name__ == '__main__':
    main()