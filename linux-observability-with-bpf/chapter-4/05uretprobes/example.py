from bcc import BPF

# uretprobes

# uretprobes是kretprobes井行探针，适用于用户空间程序使用。它将BPF程序附加到指令返回值之上，允许通过BPF代码从寄存器中访问返回值。

# uprobes和uretprobes的结合使用可以编写更复杂的BPF程序。两者的结合可以为我们提供应用程序运行时的全面了解。
# 你可以在函数运行前及结束后注入跟踪代码，则能够收集更多数据来衡量应用程序行为。
# 一个常见的用例是在无须修改应用程序的前提下，衡量一个函数执行所需的时间。

bpf_source = """
// 创建一个BPF哈希映射。该映射允许在uprobe和uretprobe函数之间共享数据。使用应用程序PID作为键，并将函数的启动时间存储为值。
BPF_HASH(cache, u64, u64);

int trace_start_time(struct pt_regs *ctx) {
  u64 pid = bpf_get_current_pid_tgid();
  // 像内核探针一样，以纳秒为单位捕获系统的当前时间。
  u64 start_time_ns = bpf_ktime_get_ns();
  // 在cache中创建一个元素保存程序PID和当前时间。假设当前时间是应用程序的启动时间。
  cache.update(&pid, &start_time_ns);
  return 0;
}
"""

bpf_source += """
int print_duration(struct pt_regs *ctx) {
  // 获取应用程序的PID。下面需要使用PID找到函数开始时间，我们能够使用映射查找函数获取函数运行前保存的启动时间。
  u64 pid = bpf_get_current_pid_tgid();
  u64 *start_time_ns = cache.lookup(&pid);
  if (start_time_ns == 0) {
    return 0;
  }
  // 通过当前时间减去启动时间计算出函数的执行时间。
  u64 duration_ns = bpf_ktime_get_ns() - *start_time_ns;
  // 在跟踪日志中打印延迟时间，以便我们可以在终端中看到。
  bpf_trace_printk("Function call duration: %d\\n", duration_ns);
  return 0;
}
"""

# 将这两个BPF函数附加到正确的bpf探针上
bpf = BPF(text = bpf_source)
bpf.attach_uprobe(name = "./hello-bpf", sym = "main.main", fn_name = "trace_start_time")
bpf.attach_uretprobe(name = "./hello-bpf", sym = "main.main", fn_name = "print_duration")
bpf.trace_print()

# 用户空间探针虽然功能强大，但是它不稳定。如果应用程序函数被重新命名，BPF程序执行将终止。使用USDT解决该问题
