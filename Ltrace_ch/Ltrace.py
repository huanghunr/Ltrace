from Ltrace_x32 import trace_file_x32,trace_pid_x32
from Ltrace_x64 import trace_file_x64,trace_pid_x64
from elftools.elf.elffile import ELFFile
import argparse

def is_64_bit_elf(filepath):
    with open(filepath, 'rb') as f:
        elf = ELFFile(f)
        return elf.elfclass == 64
    
def parse_args():
    parser = argparse.ArgumentParser(description="Linux trace tool")

    # 选择文件启动还是通过pid附加启动，两者之间必选一个
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--file', type=str, help='需要启动的程序路径')
    group.add_argument('-p', '--pid', type=int, help='要attach的进程ID')

    parser.add_argument("-F", "--filepath", help="程序文件路径(在通过pid附加时必须使用，通过文件启动请使用 -f)", type=str, default="")

    # 可选参数，指定开始trace的地址(十六进制的相对地址)，默认从程序的入口点开始。例如：0x1231
    parser.add_argument('-s', '--start', type=lambda x: int(x, 0), default=0,
                        help='可选参数，开始追踪的地址(十六进制，整数)，默认从入口点开始')

    # 可选参数，指定最大的追踪数量，默认1000000条
    parser.add_argument('-m', '--max-trace', type=int, default=1000000,
                        help='可选参数，最大的追踪数量，默认1000000条')

    # 可选参数，运行程序的环境变量，仅在通过文件启动时有效。输入格式 key=value1 key2=value2
    parser.add_argument('-e', '--env', nargs='*',default=None,
                        help='程序运行需要的环境变量，多个环境变量以空格分隔，例如, KEY1=VAL1 KEY2=VAL2')

    # 可选参数，指定输出的追踪文件名称
    parser.add_argument('-o', '--output', type=str, default='Ltrace.asm',
                        help='可选参数，指定输出的文件路径,默认 ./Ltrace.asm')
    
    # 可选参数，程序标准输入流需要输入的数据，如果中途有多次输入，用空格分隔
    parser.add_argument('-i', '--input', nargs='*',
                        help='可选参数，程序使用标准输入流需要输入的数据，多个数据用空格分隔,例如: data1 data2 data3')
    
    # 可选参数，是否启动绕过反调试功能
    parser.add_argument('-pa','--pass-antidebug', type=int, choices=[0, 1], default=0,
                        help='可选参数，是否启动绕过反调试功能，0表示不绕过，1表示绕过，默认不绕过')
    
    # 可选参数，添加程序的启动参数，只有再选择通过文件启动才有效
    parser.add_argument('-a', '--args', nargs=argparse.REMAINDER,
                    help='可选参数，添加程序的启动参数，只有再选择通过文件启动才有效，多个参数用空格分隔(只能放在最后一个参数)')

    return parser.parse_args()

def main():
    args = parse_args()

    # 处理环境变量与输入流
    env = dict(item.split("=", 1) for item in args.env) if args.env else {}
    inputs = args.input or []

    # 是否绕过反调试
    pass_ptrace = args.pass_antidebug == 1

    print("如果程序在输出文件中长时间没有输出，请检查：")
    print("1. 是否需要输入数据；2. 起始位置是否正确；3. 程序是否已退出。")
    print("必要时用 Ctrl+C 终止程序，并手动杀掉残留进程。")

    # 如果是启动新程序进行追踪
    if not args.pid:
        print(f"文件: {args.file}")
        print(f"参数: {args.args}")
        print(f"开始地址: {args.start}")
        print(f"最大 trace 数量: {args.max_trace}")
        print(f"输出文件: {args.output}")
        print(f"环境变量: {env}")
        print(f"输入流: {inputs}")
        print(f"反调试: {'绕过' if pass_ptrace else '不绕过'}")

        try:
            if is_64_bit_elf(args.file):
                trace_file_x64(args.file, args.args, args.start, args.max_trace, args.output, env, inputs, pass_ptrace)
            else:
                trace_file_x32(args.file, args.args, args.start, args.max_trace, args.output, env, inputs, pass_ptrace)
        except Exception as e:
            print("出现未知错误:", e)

    # 如果是 attach 已有进程
    else:
        print(f"文件: {args.filepath}")
        print(f"开始地址: {args.start}")
        print(f"最大 trace 数量: {args.max_trace}")
        print(f"输出文件: {args.output}")
        print(f"输入流: {inputs}")
        print(f"反调试: {'绕过' if pass_ptrace else '不绕过'}")

        try:
            if is_64_bit_elf(args.filepath):
                trace_pid_x64(args.pid, args.filepath, args.start, args.max_trace, args.output, inputs, pass_ptrace)
            else:
                trace_pid_x32(args.pid, args.filepath, args.start, args.max_trace, args.output, inputs, pass_ptrace)
        except PermissionError as e:
            print("没有附加权限。请检查 ptrace_scope 设置是否允许非父进程附加。\n", e)
        except Exception as e:
            print("出现未知错误:", e)

if __name__ == '__main__':
    main()