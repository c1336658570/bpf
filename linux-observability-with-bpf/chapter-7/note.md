find . -type f -exec grep -l "XDP_SETUP_PROG_HW" {} +

find . -type f -exec grep -l "XDP_SETUP_PROG" {} +



pkg-config --modversion libbpf

 sudo bpftool btf list

lscpu

llc --version

objdump -s 01bpf_program_kern.o 

llvm-objdump -d 01bpf_program_kern.o 



转发 (XDP_TX)
转发数据包。这可能在数据包被修改前或修改后发生。转发数据包意味着将接收到的数据包发送回数据包到达的同一网卡。

重定向 (XDP_REDIRECT)
与 XDP_TX 相似，重定向也用于传递 XDP 数据包，但是重定向是通过另一个网卡传输或者传入到 BPF 的 cpumap 中。对于传入到 BPF 的 cpumap场景，则 CPU 将继续为网卡的接收队列提供 XDP 处理，井将处理上层内核栈的数据包推送给远程 CPU ，这类似于 XDP_PASS ，但是 XDP 的BPF 程序可以继续为传入的高负载提供服务，而不仅是暂时把当前数据包推送到上层内核枝。

传递 (XDP_PASS)
将数据包传递到普通网络栈进行处理。这等效于没有 XDP 的默认数据包处理行为。这可以通过以下两种方式之一来完成:

- 正常方式接收数据包，分配元数据 sk_buff 结构并且将接收数据包入栈，然后将数据包引导到另一个 CPU 进行处理。它允许原始接口到用户空间进行处理。这可能发生在数据包被修改之前或被修改之后 。
- 通用接受卸载 ( GRO ) 方式接 收大的数据包，并且合并相同连接的数据包 。经过处理后 ， GRO 最终将数据包传入"正常接收"流 。

错误(XDP_ABORTED)
表示 eBPF 程序错误，并导致数据包被丢弃。程序不应该将它作为返回码。例如，如果程序除以零 ，则将返回 XDP_ABORTED。XDP_ABORTED的值始终为零。我们可以通 过 trace_xdp_exception 跟踪点进行额外监控来检 测不良行为。

```c
enum xdp_action {
	XDP_ABORTED = 0,
	XDP_DROP,
	XDP_PASS,
	XDP_TX,
	XDP_REDIRECT,
};
```

![截图 2023-12-09 16-31-12](/home/cccmmf/bpf/linux-observability-with-bpf/chapter-7/image/截图 2023-12-09 16-31-12.png)

iproute2中提供的 ip 命令具有充当 XDP 前端的能力，可以将 XDP 程序编译成 ELF 文件并加载它，并且完全支持映射、映射重定位、尾部调用和对象持久化。

因为加载 XDP 程序可以表示为对现有网络接口的配置，所以可以使用对网络设备配置的命令 ip link 的 一部分作为加载器。

```bash
sudo ip link set dev wlp1s0 xdp obj program.o sec mysection
# ip			调用ip命令。
# link			配置网络接口。
# set			更改设备属性。
# dev wlp1s0	指定我们要在其上操作和加载XDP程序的网络设备。
# xdp obj program.o		从名为 program.o 的 ELF 文件(对象)中加载 XDP 程序。该命令的xdp 部分告诉系统当本地驱动可用时，使用本机驱动程序，否则回退到使用通用驱动程序。你也可以通过使用更具体的选择器来强制使用一种模式:xdpgeneric 使用通用 XDP 模式。xdpdrv 使用原生 XDP 模式。xdpoffload 使用卸载 XDP 模式。
# sec mysection			指定 section 名为 mysection ，此为从 ELF 文件中加载的 BPF 程序。如果未指定， section 默认为 prog 。如果程序中未指定任何 section ，则必须在 ip 调用中指定 sec.text 。
```

当执行完上面那条值令，电脑直接没网了，然后通过下面的值令恢复

```bash
sudo ip link set dev wlp1s0 xdp off		
# 卸载附加的程序井关闭设备的 XDP:
```

```bash
sudo nmap -sS 10.30.0.138
Starting Nmap 7.80 ( https://nmap.org ) at 2023-12-09 17:10 CST
Nmap scan report for cccmmf.lan (10.30.0.138)
Host is up (0.000013s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
8000/tcp open  http-alt

Nmap done: 1 IP address (1 host up) scanned in 0.21 seconds



sudo nmap -sS 10.30.0.138: 运行Nmap工具进行TCP SYN扫描，-sS选项表示使用TCP SYN扫描方式。sudo用于获取足够的权限。
Nmap版本和开始时间:

Starting Nmap 7.80 ( https://nmap.org ) at 2023-12-09 16:49 CST: 显示Nmap的版本信息以及扫描的开始时间。
扫描报告:

Nmap scan report for cccmmf.lan (10.30.0.138): 报告扫描目标为cccmmf.lan，对应IP地址为10.30.0.138。
主机存活状态:

Host is up (0.000011s latency): 主机存活，显示主机的存活状态和延迟时间。
端口扫描结果:

Not shown: 998 closed ports: 未显示的端口表示有998个端口处于关闭状态，即未响应。
PORT STATE SERVICE: 列出了扫描到的端口及其状态。
22/tcp open ssh: 22端口是开放的，正在运行SSH服务。
8000/tcp open http-alt: 8000端口是开放的，正在运行HTTP服务（可能是替代HTTP端口，http-alt）。
扫描结束信息:

Nmap done: 1 IP address (1 host up) scanned in 0.24 seconds: 扫描已完成，总共扫描了1个IP地址（1台主机处于活动状态），耗时0.24秒。
综合来看，这个Nmap扫描显示了目标主机的IP地址、主机存活状态、开放的端口及其服务。在这个例子中，主机开放了SSH服务（端口22）和HTTP服务（端口8000）。


本来执行完sudo ip link set dev wlp1s0 xdp obj program.o sec mysection之后执行sudo nmap -sS 10.30.0.138用来测试sudo ip link set dev wlp1s0 xdp obj program.o sec mysection是否成功，但是必须得从其他机子测试，本机测试不行。
验证其所有功能的另一项测试是尝试通过浏览器或执行任何 HTTP 请 求来访问该程序 。将 10.30.0.138 定位为目标时，任何类型的测试都将失败 。
```





