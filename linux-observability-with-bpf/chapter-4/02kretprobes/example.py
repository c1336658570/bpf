from bcc import BPF

# kretprobes

"""
kretprobes是在内核指令有返回值时插入BPF程序。通常，我们会在一个BPF程序中同时使用kprobes和kretprobes，
以便获得对内核指令的全面了解。
"""

"""
定义实现BPF程序的函数。内核将在execve系统调用结束后立即执行它。宏PT_REGS_RC用来从这个特定
上下文中读取BPF寄存器的返回值。我们还使用bpf_trace_print在调试日志中打印命令及其返回值。
"""

# 定义一个BPF程序，该程序将在execve系统调用返回时触发
bpf_source = """
#include <uapi/linux/ptrace.h>

int ret_sys_execve(struct pt_regs *ctx) {
  int return_value;
  char comm[16];
  bpf_get_current_comm(&comm, sizeof(comm));
  return_value = PT_REGS_RC(ctx);

  bpf_trace_printk("program: %s, return: %d\\n", comm, return_value);
  return 0;
}
"""

# 初始化BPF程序井将它加载到内核中。
bpf = BPF(text=bpf_source)
# 获取execve系统调用的名称
execve_function = bpf.get_syscall_fnname("execve")
# 这里附加函数为attach_kretprobe。将BPF程序与execve系统调用的返回关联，以便在每次execve返回时执行BPF程序
bpf.attach_kretprobe(event=execve_function, fn_name="ret_sys_execve")
# 输出跟踪日志，显示每次execve系统调用返回时执行的程序名称和返回值
bpf.trace_print()
