import argparse
from bcc import BPF, USDT

# 定义BPF程序的源代码字符串
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
# 添加一个可选参数，用于指定PID
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
