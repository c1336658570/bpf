#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>

/* 程序数组映射
 * 映射类型定义为BPF_MAP_TYPE_PROG_ARRAY。这种类型保存对BPF程序的引用，即BPF程序的文件描述符。
 * 程序数组映射类型可以与帮助函数bpf_tail_call结合使用，实现在程序之间跳转，
 * 突破单个BPF程序最大指令的限制，并且可以降低实现的复杂性。
 * 
 * 使用这个专用映射时，你要考虑如下事情。首先要记住的是键和值的大小都必须为四个字节。
 * 第二点要记住的是当跳到新程序时，新程序将使用相同的内存栈，因此程序不会耗尽所有有效的内存。
 * 最后，如果跳转到映射中不存在的程序，尾部调用将失败，返回继续执行当前程序。
 */

// 声明新的程序映射，键和值大小将为四个字节
struct bpf_map_def SEC( " maps") programs = {
  .type = BPF_MAP_TYPE_PROG_ARRAY,
  .key_size = 4,
  .value_size = 4,
  .max_entries = 1024,
};

// 需要声明要跳转到的程序。编写一个BPF程序，程序唯一的目的是返回0。
int key = 1;
struct bpf_insn prog[] = {
  BPF_MOV64_IMM(BPF_REG_0, 0),  // assign r0 = 0
  BPF_EXIT_INSN(),              // return r0
};

// 使用bpf_prog_load将它加载到内核中，然后将程序的文件描述符添加到程序映射中。
int prog_fd = bpf_prog_load(BPF_PROG_TYPE_KPROBE, prog, sizeof(prog), "GPL");
bpf_map_update_elem(&programs, &key, &prog_fd, BPF_ANY);

// 编写另一个BPF程序跳到它。只有相同类型的BPF程序才能跳转。这里，我们会将程序附加到kprobe跟踪上
SEC("kprobe/seccomp_phase1")
int bpf_kprobe_program(struct pt_regs *ctx) {
  int key=1;/* dispatch into next BPF program */
  bpf_tail_call(ctx, &programs, &key);

  /* fall through when the program descriptor is not in the map */
  char fmt[] ="missing program in prog_array map\n";
  bpf_trace_printk(fmt, sizeof(fmt));
  
  return 0;
  // 这里我们使用bpf_tail_call和BPF_MAP_TYPE_PROG_ARRAY，可以最多达到32次嵌套调用。这个明确的限制可以防止无限循环和内存耗尽。
}