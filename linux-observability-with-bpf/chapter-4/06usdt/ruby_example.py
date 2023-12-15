import argparse
from bcc import BPF, USDT

# 被ruby程序使用

# 定义BPF程序的源代码字符串。以下代码片段实现了BPF程序获取跟踪点信息，井将其打印在跟踪日志中
# BCC 内置函数 bpf_usdt_readarg 和 bpf_usdt_readarg_p来读取应用程序每次执行时设置的参数。
bpf_source = """
#include <uapi/linux/ptrace.h>
int trace_latency(struct pt_regs *ctx) {
  char method[64];
  u64 latency;

  // 通过USDT读取第一个参数，将其存储在method数组中
  bpf_usdt_readarg_p(1, ctx, &method, sizeof(method));
  // 通过USDT读取第二个参数，将其存储在latency变量中
  bpf_usdt_readarg(2, ctx, &latency);

  bpf_trace_printk("method %s took %d ms", method, latency);
}
"""

# 创建命令行参数解析器
parser = argparse.ArgumentParser()
# 因为我们正在追踪系统中运行的特定应用程序，所以需要将程序附加到指定的进程标识符上
# 添加一个可选参数，用于指定PID
# "-p", "--pid": 这是参数的名称，其中 -p 是参数的短名称，--pid 是参数的长名称。在命令行中，用户可以选择使用 -p 或 --pid 来指定该参数。
# type=int: 这是参数值的数据类型，指定为整数 (int)。这意味着当用户提供参数值时，解析器将尝试将其转换为整数类型。
# help="Process ID": 这是参数的帮助文本，提供有关参数用途的简要描述。在运行脚本时，用户可以通过添加 -h 或 --help 选项来查看帮助文本，以了解可用的参数和其描述。
parser.add_argument("-p", "--pid", type = int, help = "Process ID")
# 解析命令行参数
args = parser.parse_args()

# 创建USDT对象，关联指定的PID
usdt = USDT(pid = int(args.pid))
# 启用探针将程序加载到内核中并打印跟踪日志。
usdt.enable_probe(probe = "latency", fn_name = "trace_latency")
# 创建BPF对象，传入BPF程序源代码和已经配置好的USDT对象
bpf = BPF(text = bpf_source, usdt = usdt)
# 打印BPF跟踪日志
bpf.trace_print()
