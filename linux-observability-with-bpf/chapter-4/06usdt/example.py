from bcc import BPF, USDT

bpf_source = """
#include <uapi/linux/ptrace.h>
int trace_binary_exec(struct pt_regs *ctx) {
  u64 pid = bpf_get_current_pid_tgid();
  bpf_trace_printk("New hello_usdt process running with PID: %d\\n", pid);
}
"""

# 创建一个USDT对象(之前的示例中没有)。USDT不是BPF的一部分，所以可以直接使用它们，无须与BPF虚拟机交互。
# USDT与BPF彼此独立，它们的用法独立于BPF代码。
usdt = USDT(path = "./hello_usdt")
# 将BPF函数附加到应用探针上用来跟踪程序执行。
usdt.enable_probe(probe = "probe - main", fn_name = "trace_binary_exec")
# 使用创建的跟踪点定义来初始化BPF环境，通知BCC生成代码将BPF程序与二进制文件中定义的探针连接起来。
# 当两者建立连接之后，我们可以通过打印BPF程序生成的跟踪信息，来发现示例中二进制的执行情况。
bpf = BPF(text = bpf_source, usdt_contexts = [usdt])
bpf.trace_print()
