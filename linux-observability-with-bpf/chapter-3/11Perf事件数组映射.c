#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <asm/ptrace.h>
#include <linux/types.h>

/**
 * 这种类型映射将perf_events数据存储在环形缓存区中，用于BPF程序和用户空间程序进行实时通信。
 * 映射类型定义为 BPF_MAP_TYPE_PERF_EVENT_ARRAY。它可以将内核跟踪工具发出的事件转发给用户空间程序，以便做进一步处理。
*/

// 此代码实现了对计算机上执行的所有程序进行跟踪。在进入BPF程序代码之前，我们需要声明内核发送到用户空间的event结构体
// 定义结构体用于存储捕获的数据
struct data_t {
  __u32 pid;
  char program_name[16];
};

// 创建映射用来发送event到用户空间
struct bpf_map_def SEC("maps") events = {
  .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
  .key_size = sizeof(int),
  .value_size = sizeof(__u32),
  .max_entries = 2,
};

// 创建BPF程序用来捕获数据并发送到用户空间
SEC("kprobe/sys_exec")
int bpf_capture_exec(struct pt_regs *ctx) {
  struct data_t data;

  // bpf_get_current_pid_tgid返回当前进程标识符
  data.pid = bpf_get_current_pid_tgid() >> 32;

  // bpf_get_current_comm加载当前可执行文件的名称
  bpf_get_current_comm(&data.program_name, sizeof(data.program_name));

  // bpf_perf_event_output发送捕获的数据到用户空间
  // 使用bpf_perf_event_output函数将data附加到映射上。
  bpf_perf_event_output(ctx, &events, 0, &data, sizeof(data));
  
  return 0;
}
