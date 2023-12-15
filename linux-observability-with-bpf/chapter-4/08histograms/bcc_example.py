import sys
import signal
from time import sleep

from bcc import BPF

# sudo python bcc_example.py

# 直方图

# 使用kprobes收集函数完成的时间，同时，我们将在一个直方图中累积结果，用于后面对直方图进行可视化。

# 将演示当一个应用程序调用 bpf_prog_load加载 BPF 程序时，如何使用 BCC 直方图对加载的延迟进行可视化。在这个
# 示例中，我们使用 kprobes 收集函数完成的时间，同时，我们将在一个直方图中累积结果，用于后面对直方图进行可视化。

def signal_ignore(signal, frame):
    print()


bpf_source = """
#include <uapi/linux/ptrace.h>

// bpf_prog_load指令调用时，将使用BCL宏创建的BPF哈希映射cache来保存启动时间。
BPF_HASH(cache, u64, u64);
/*
 * 使用宏BPF_HISTOGRAM来创建一个BPF直方图映射。这个宏并不是一个原生BPF映射。
 * BCC包含这个宏，用来帮助你更轻松地创建这些可视化。这个BPF直方图映射的底层实现是使用一些数组映射来保存信息。
 * BCC也包括一些帮助函数，用来帮助你按照桶进行分类及创建最终的直方图。
 */
BPF_HISTOGRAM(histogram);

int trace_bpf_prog_load_start(void *ctx) {
  u64 pid = bpf_get_current_pid_tgid();
  u64 start_time_ns = bpf_ktime_get_ns();
  // 当应用程序触发我们需要跟踪的指令时，程序PID用于保存这些跟踪。
  cache.update(&pid, &start_time_ns);
  return 0;
}
"""

bpf_source += """
int trace_bpf_prog_load_return(void *ctx) {
  u64 *start_time_ns, delta;
  u64 pid = bpf_get_current_pid_tgid();
  start_time_ns = cache.lookup(&pid);
  if (start_time_ns == 0)
    return 0;

  // 计算指令被调用的时间和程序运行到这里的时间之间的差值，我们假设这是指令完成的时间。
  delta = bpf_ktime_get_ns() - *start_time_ns;
  /*
   * 在直方图中保存这个差值。我们将在这行中执行两个操作。首先使用内置函数bpf_log2l为这个差值生成桶标识符。
   * 这个函数会创建一个稳定的值分布。然后使用increment函数向这个桶添加一个新项。
   * 在默认情况下，如果这个桶在直方图中已经存在，increment函数会给该值加1，否则它将创建一个值为1的新桶。
   * 因此你无须担心该值是否已存在。
   */
  histogram.increment(bpf_log2l(delta));
  return 0;
}
"""

# 将上面两个函数附加到有效的kprobes探针上，在屏幕上打印直方图，以便查看延迟分布。
# 同时，我们在这部分中初始化BPF程序井等待事件生成直方图
bpf = BPF(text=bpf_source)    # 初始化BPF将函数附加到kprobes探针上。
bpf.attach_kprobe(event="bpf_prog_load", fn_name="trace_bpf_prog_load_start")
bpf.attach_kretprobe(event="bpf_prog_load",
                     fn_name="trace_bpf_prog_load_return")


# 让程序等待以便我们可以从系统中收集尽可能多的事件。
try:
    sleep(300)
except KeyboardInterrupt:
    signal.signal(signal.SIGINT, signal_ignore)

# 在终端中打印包含跟踪事件分布的直方图映射。这是另一个BCC宏，用来获取直方图映射。
bpf["histogram"].print_log2_hist("msecs")
