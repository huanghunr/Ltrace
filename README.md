# Ltrace
Ltrace 是一个在linux x64下基于capstone和libdebug开发的指令trace工具。它拥有超快的速度，和一定的反混淆反反调试能力。
项目还在开发中，这里是demo

使用方法
```
usage: libdebug_trace.py [-h] (-f FILE | -p PID) [-a ...] [-s START] [-m MAX_TRACE] [-e [ENV ...]] [-o OUTPUT] [-i [INPUT ...]]

Linux trace tool

options:
  -h, --help            show this help message and exit
  -f, --file FILE       Path to the executable file to be traced
  -p, --pid PID         PID of the process to attach to
  -a, --args ...        Arguments for the target program (use "--" to separate them)(only valid with --file)
  -s, --start START     Trace start address (default: 0; accepts hex like 0x400000)
  -m, --max-trace MAX_TRACE
                        Maximum number of instructions to trace (default: 100000)
  -e, --env [ENV ...]   Environment variables for the process, e.g., KEY1=VAL1 KEY2=VAL2
  -o, --output OUTPUT   Output trace file name (default: Ltrace.asm)
  -i, --input [INPUT ...]
                        Inputs to be passed to the program via stdin (multiple inputs separated by space)
```


## 感谢
[libdebug](https://github.com/libdebug/libdebug/tree/d88a893963d02482e00d4516bdaf4f25a8c14c4b)
[capstone](https://github.com/capstone-engine/capstone)