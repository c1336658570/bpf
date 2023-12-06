from bcc import BPF

# 用户空间探针

"""
用户空间探针允许在用户空间运行的程序中设置动态标志。它们等同于内核探针，用户空间探针是运行在用户空间的监测程序。
当我们定义uprobe时，内核会在附加的指令上创建陷阱。当程序执行到该指令时，内核将触发事件
以回调函数的方式调用探针函数。uprobes也可以访问程序链接到的任何库，只要知道指令的名称，就可以跟踪对应的调用。
"""

bpf_source = """
int trace_go_main(struct pt_regs *ctx) {
  // 使用函数bpf_get_current_pid_tgid获取hello-bpf程序的进程标识符(PID)。
  u64 pid = bpf_get_current_pid_tgid();
  bpf_trace_printk("New hello-bpf process running with PID: %d\\n", pid);
  return 0;
}
"""

bpf = BPF(text = bpf_source)
# 将该程序附加到uprobe。这个调用需要知道要跟踪的对象hello-bpf，此为目标文件的绝对路径。
# 程序还需要设置正在跟踪对象的符号main.main，及要运行的BPF程序。
# 这样，每次系统中运行hello-bpf时，我们将在跟踪中获得一条新日志。
bpf.attach_uprobe(name = "./hello-bpf", sym = "main.main", fn_name = "trace_go_main")
bpf.trace_print()
