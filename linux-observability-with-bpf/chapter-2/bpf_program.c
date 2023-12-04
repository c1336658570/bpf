// 当检测到execve系统调用跟踪点被执行时，BPF程序将运行。
// clang -O2 -target bpf -c bpf_program.c -o bpf_program.o 
#include <linux/bpf.h>
#include <bpf/bpf.h>
#define SEC(NAME) __attribute__((section(NAME), used))

static int (*bpf_trace_printk)(const char *fmt, int fmt_size,
                               ...) = (void *)BPF_FUNC_trace_printk;

// 使用SEC属性告知BPF虚拟机何时运行此程序。当检测到execve系统调用跟踪点被执行时，BPF程序将运行
SEC("tracepoint/syscalls/sys_enter_execve")  
int bpf_prog(void *ctx) {
  char msg[] = "Hello, BPF World!";
  // 使用函数bpf_trace_printk在内核跟踪日志中打印消息，可以在文件/sys/kernel/debug/tracing/trace_pipe中查看。
  bpf_trace_printk(msg, sizeof(msg));
  return 0;
}

// 指定程序许可证。因为Linux内核采用GPL许可证，所以它只能加载GPL许可证的程序。
char _license[] SEC("license") = "GPL";
