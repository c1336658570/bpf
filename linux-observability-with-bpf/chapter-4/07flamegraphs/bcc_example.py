#!/usr/bin/python
import errno
import signal
import sys
from time import sleep

from bcc import BPF, PerfSWConfig, PerfType

# sudo python ./bcc_example.py "$(pgrep -nx go)" > ./profile.out
# ./flamegraph.pl ./profile.out > ./flamegraph.svg && firefox ./flamegraph.svg  生成火焰图

# 构建一个简单的BPF分析器，用来打印从用户空间应用程序中收集的检跟踪信息。我们将使用收集的跟踪信息生成on-CPU图。

def signal_ignore(signal, frame):
    print()


bpf_source = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>
#include <linux/sched.h>

// 初始化一个分析器结构体，用于保存分析器接收的每个栈帧的引用标识符。我们将使用这些标识符找到正在执行的代码路径。
struct trace_t {
  int stack_id;
};

// 初始化一个BPF哈希映射，使用该映射聚合相同栈帧出现的频率。火焰图脚本将使用这个聚合值决定相同代码的执行频率。
BPF_HASH(cache, struct trace_t);

/*
 * BCC 提供了一些工具，可以帮助你聚合和可视化栈跟踪，主要是宏BPF_STACK_TRACE。
 * 使用这个宏生成一个BPF_MAP_TYPE_STACK_TRACE类型的BPF映射，用来保存BPF程序收集的栈信息。
 * 最重要的是该BPF映射在方法上进行了增强，包括提供了从程序的上下文提取栈信息的方法，以及为聚合后提供了遍历收集到栈信息的方法。
 */
/*
 * 初始化BPF栈跟踪映射，并为该映射设置一个最大值，这个最大值会根据处理数据的多少而有所不同。
 * 所以，最好让这个值作为一个变量，我们知道分析的Go程序数据不是非常大，因此10000个元素足够了。
 */
BPF_STACK_TRACE(traces, 10000);
"""

bpf_source += """
int collect_stack_traces(struct bpf_perf_event_data *ctx) {
  /*
   * 验证当前BPF上下文中程序进程ID是Go程序的进程ID。否则，事件将被忽略。
   * 此刻，我们还没有定义PROGRAM_PID的值。这个字符串将在BPF程序初始化之前由分析器的Python代码替换。
   * 这是因为目前BCC初始化BPF程序有一个限制:我们无益从用户空间传递任何变量，通常这些字符串将在BPF程序初始化之前被替换。
   */
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  if (pid != PROGRAM_PID)
    return 0;

  /*
   * 创建trace来聚合程序栈的使用情况。我们可以使用内置函数get_stackid从程序上下文中获取栈ID。
   * 这个函数是BCC为栈跟踪映射添加的帮助函数之一。同时，我们可以使用标志BPF_F_USER_STACK
   * 设置要获得用户空间程序的栈ID，这里，我们会忽略内核中发生的调用。
   */
  struct trace_t trace = {
    .stack_id = traces.get_stackid(&ctx->regs, BPF_F_USER_STACK)
  };

  // 为trace增加计数以保持对相同代码正在被执行的频率的跟踪。
  cache.increment(trace);
  return 0;
}
"""

# 将栈跟踪收集器附加到内核的所有Perf事件上:

program_pid = int(sys.argv[1])  # 第一个参数是正在分析的Go程序的进程ID。
# 使用Python的内置replace函数，将BPF程序中的字符串PROGRAM_PID替换为提供的分析器的参数。
bpf_source = bpf_source.replace('PROGRAM_PID', str(program_pid))

bpf = BPF(text=bpf_source)
# 将BPF程序附加到所有软件Perf事件上，这样将忽略任何其他事件(例如，硬件事件)。
# 同时，我们也正在配置BPF程序使用CPU时钟作为时间源，以便测量执行时间。
bpf.attach_perf_event(ev_type=PerfType.SOFTWARE,
                      ev_config=PerfSWConfig.CPU_CLOCK,
                      fn_name='collect_stack_traces',
                      sample_period=1)

# 实现的代码是当分析器被中断时，将栈跟踪打印到标准输出上

exiting = 0
try:
    sleep(300)
except KeyboardInterrupt:
    exiting = 1
    signal.signal(signal.SIGINT, signal_ignore)

print("dumping the results")
# 遍历所有收集的跟踪信息并按顺序打印。
for trace, acc in sorted(bpf['cache'].items(), key=lambda cache: cache[1].value):
    line = []
    # 验证我们获得的枝标识符是否有效，如果按标识符有效，将代码的具体行与该校标识符关联。如果获得了一个无效值，将在火焰图中使用一个占位符表示。
    if trace.stack_id < 0 and trace.stack_id == -errno.EFAULT:
        line = ['Unknown stack']
    else:
        stack_trace = list(bpf['traces'].walk(trace.stack_id))
        # 逆序遍历栈跟踪映射的所有条目。像你在任何枝跟踪中期望的那样，我们想要在顶部看到第一个最近执行的代码路径。
        for stack_address in reversed(stack_trace):
            # 使用BCC的帮助函数sym，将栈帧的内存地址转换为源代码中的函数名。
            function_name = bpf.sym(stack_address, program_pid).decode('utf-8')
            if function_name == '[unknown]':
                continue
            line.extend([function_name])

    if len(line) < 1:
        continue
    # 对使用分号分隔的栈跟踪行进行格式化。这个格式是后面火焰图脚本期待的格式，我们将使用这个格式生成可视化图表。
    frame = ";".join(line)
    sys.stdout.write("%s %d\n" % (frame, acc.value))
    if exiting:
        exit()
