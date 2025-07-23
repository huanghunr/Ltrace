# Ltrace
Ltrace 是一个在linux x64下基于capstone和libdebug开发的指令trace工具。它拥有超快的速度，和一定的反混淆反反调试能力。

项目还在开发中，这里是demo

依赖
```
pip install capstone
pip install libdebug
pip install pwntools
```


使用方法
```
usage: libdebug_trace.py [-h] (-f FILE | -p PID) [-F FILEPATH] [-s START] [-m MAX_TRACE] [-e [ENV ...]] [-o OUTPUT] [-i [INPUT ...]] [-a ...]

Linux trace tool

options:
  -h, --help            show this help message and exit
  -f, --file FILE       需要启动的程序路径
  -p, --pid PID         要attach的进程ID
  -F, --filepath FILEPATH
                        程序文件路径(在通过pid附加时必须使用)
  -s, --start START     可选参数，开始追踪的地址(十六进制，整数)，默认从入口点开始
  -m, --max-trace MAX_TRACE
                        可选参数，最大的追踪数量，默认100000条
  -e, --env [ENV ...]   程序运行需要的环境变量，多个环境变量以空格分隔，例如, KEY1=VAL1 KEY2=VAL2
  -o, --output OUTPUT   可选参数，指定输出的文件路径,默认 ./Ltrace.asm
  -i, --input [INPUT ...]
                        可选参数，程序使用标准输入流需要输入的数据，多个数据用空格分隔,例如: data1 data2 data3
  -a, --args ...        可选参数，添加程序的启动参数，只有再选择通过文件启动才有效，多个参数用空格分隔(只能放在最后一个参数)
```
未来计划
1.兼容x32
2.添加更多的反调试绕过功能
3.性能优化
4.跳转提示

## 感谢
[libdebug](https://github.com/libdebug/libdebug/tree/d88a893963d02482e00d4516bdaf4f25a8c14c4b)
[capstone](https://github.com/capstone-engine/capstone)