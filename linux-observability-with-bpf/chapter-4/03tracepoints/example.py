from bcc import BPF

# 跟踪点

"""
查看系统支持的跟踪点sudo ls /sys/kernel/debug/tracing/events/

查看/sys/kernel/debug/tracing/events/bpf目录下定义的事件可以查看BPF可用的所有的跟踪点:
目前内核已经没有bpf目录了，只有bpf_trace和bpf_test_run。这俩目录下有enable和filter两个文件，
如果enable文件内容是0，表示禁用跟踪点。如果该文件内容为1，表示跟踪点已启用
filter文件用来编写表达式定义内核跟踪子系统过滤事件。BPF不会使用该文件。

# 查询所有内核插桩和跟踪点
sudo bpftrace -l

# 使用通配符查询所有的系统调用跟踪点
sudo bpftrace -l 'tracepoint:syscalls:*'

# 使用通配符查询所有名字包含"execve"的跟踪点
sudo bpftrace -l '*execve*'

# 查询execve入口参数格式
sudo bpftrace -lv tracepoint:syscalls:sys_enter_execve

# 查询execve返回值格式
sudo bpftrace -lv tracepoint:syscalls:sys_exit_execve

"""

# 下面代码不能运行，trace_bpf_prog_load在内核4.18之后的内核删除了。

# 声明定义BPF程序的函数。
bpf_source = """
int trace_bpf_prog_load(void *ctx) {
  char comm[16];
  bpf_get_current_comm(&comm, sizeof(comm));

  bpf_trace_printk("%s is loading a BPF program", comm);
  return 0;
}
"""

"""
bpf = BPF(text = bpf_source)
# 首先是指定要跟踪的子系统，这里是bpf:，然后是子系统中的跟踪点bpf_prog_load。
# 这意味着每次内核执行bpf_prog_load函数时，该程序将会收到该事件，并打印执行bpf_prog_load指令的应用程序名称。
bpf.attach_tracepoint(tp = "bpf:bpf_prog_load", fn_name = "trace_bpf_prog_load")
bpf.trace_print()
"""



bpf_source = """
// 定义一个BPF程序，该程序将在net_dev_xmit tracepoint触发时被执行
int trace_net_dev_xmit(struct pt_regs *ctx) {
  char comm[16];

  // 获取当前正在执行的程序的名称
  bpf_get_current_comm(&comm, sizeof(comm));

  // 打印跟踪信息，指示正在加载BPF程序的进程
  bpf_trace_printk("%s is loading a BPF program", comm);
  return 0;
}
"""

# 使用BPF类加载BPF程序到内核中
bpf = BPF(text = bpf_source)
# 将BPF程序与net_dev_xmit tracepoint关联，以便在每次tracepoint触发时执行BPF程序
bpf.attach_tracepoint(tp = "net:net_dev_xmit", fn_name = "trace_net_dev_xmit")
# 输出跟踪日志，显示每次net_dev_xmit tracepoint触发时执行的程序名称
bpf.trace_print()