from bcc import BPF

# sudo python bcc_example.py 

# Perf事件

# 使用Perf事件来获得二进制执行信息，以及对获得的信息进行分类，并打印出系统中执行最频繁的程序。

bpf_source = """
#include <uapi/linux/ptrace.h>

// 使用宏BPF_PERF_OUTPUT声明一个名为events的Perf事件映射。这个宏由BCC提供，用于方便地声明Perf事件映射。
BPF_PERF_OUTPUT(events);

int do_sys_execve(struct pt_regs *ctx, void *filename, void *argv, void *envp) {
  char comm[16];
  bpf_get_current_comm(&comm, sizeof(comm));

  // 获取内核中执行的程序名后，将它发送到用户空间进行聚合。我们使用perf_submit函数实现这个功能。这个函数使用新的信息更新Perf事件映射。
  events.perf_submit(ctx, &comm, sizeof(comm));
  return 0;
}
"""

# 初始化BPF程序，将BPF程序附加到kprobe上，当系统中一个新程序被执行时，这个BPF程序将被触发。
bpf = BPF(text = bpf_source)
execve_function = bpf.get_syscall_fnname("execve")
bpf.attach_kprobe(event = execve_function, fn_name = "do_sys_execve")

# 从 Python 标准库导人依赖库。我们将使用 Python 的 Counter 来聚合从 BPF 程序收到的事件 。
from collections import Counter
# 声明计数器来保存程序信息。使用程序名作为键，值将是计数器。
aggregates = Counter()

# 使用aggregate_programs函数收集Perf事件映射的数据。
def aggregate_programs(cpu, data, size):
  comm = bpf["events"].event(data)
  # 当我们收到一个相同程序名的事件，程序计数器的值会增加。
  aggregates[comm] += 1

# 使用open_perf_buffer函数，在每次从Perf事件映射接收到一个事件时，通知BCC需要执行aggregate_programs函数。
bpf["events"].open_perf_buffer(aggregate_programs)
while True:
    try:
      # 在打开环形缓存器之后，BCC将一直拉取事件直到这个Python程序被中断。
      # Python程序运行时间越长，处理的信息越多。为此，我们使用perf_buffer_poll函数。
      bpf.perf_buffer_poll()
    except KeyboardInterrupt:
      break

# 使用most_common函数获取计数器的元素列表，并且循环元素列表将系统中执行次数高的程序首先被打印。
for (comm, times) in aggregates.most_common(): 
  print("Program {} executed {} times".format(comm, times))
