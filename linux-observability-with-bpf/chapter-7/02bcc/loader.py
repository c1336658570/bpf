#!/usr/bin/python3

# sudo python loader.py
# 代码跑不了

# XDP程序也可以使用 BCC 编译、加载和运行 。

from bcc import BPF
import time
import sys

# 程序包含两部分，实际的加载逻辑和循环打印数据包数量。

# 实际的加载逻辑
device = "wlp1s0"
# 读取文件 program.c 来打开程序。
b = BPF(src_file="program.c")
# load_func函数构建bpf系统调用。将myprogram函数用作程序的主函数，程序类型设定为BPF.XDP（BPF_PROG_TYPE_XDP）。
fn = b.load_func("myprogram", BPF.XDP)
b.attach_xdp(device, fn, 0)
# 使用get_table访问BPF映射packetcnt。
packetcnt = b.get_table("packetcnt")

# 循环打印数据包计数
# 两个循环。外层循环获取键盘事件，并在有信号中断程序时终止。当外层部循环中断时，将调用remove_xdp 函数从接口上释放 XDP 程序。
# 内层循环负责从 packetcnt 映射中获取值，并以下面的格式打印：protocol：counter pkt/s：
prev = [0] * 256
print("Printing packet counts per IP protocol-number, hit CTRL+C to stop")
while 1:
    try:
        for k in packetcnt.keys():
            val = packetcnt.sum(k).value
            i = k.value
            if val:
                delta = val - prev[i]
                prev[i] = val
                print("{}: {} pkt/s".format(i, delta))
        time.sleep(1)
    except KeyboardInterrupt:
        print("Removing filter from device")
        break

b.remove_xdp(device, 0)
