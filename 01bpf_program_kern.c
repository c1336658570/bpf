// 当检测到execve系统调用跟踪点被执行时，BPF程序将运行。
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/version.h>
// #include <uapi/linux/bpf.h>
// #define SEC(NAME) __attribute__((section(NAME), used))

// 可以通过cat /proc/kallsyms| grep __x64_sys_write查看支持哪些kprobe
// __stringify 是一个预处理宏，用于将参数转换为字符串文字。
#ifdef __x86_64__
#define SYSCALL(SYS) "__x64_" __stringify(SYS)
#elif defined(__s390x__)
#define SYSCALL(SYS) "__s390x_" __stringify(SYS)
#else
#define SYSCALL(SYS)  __stringify(SYS)
#endif

// bpf_trace_printk的实现原理在/usr/src/linux-source-6.2.0/linux-source-6.2.0/include/linux/filter.h中
// 在其中的267行，BPF_FUNC_trace_printk本质是个枚举，bpf_trace_printk的调用最后回转换为call 6，
// 最终转换为BPF_EMIT_CALL
// static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) = (void *)BPF_FUNC_trace_printk;

// SEC宏用于指定BPF程序在哪个tracepoint上执行。在这里，指定在sys_enter_execve tracepoint上执行。
// SEC("tracepoint/syscalls/sys_enter_execve") // 定义BPF程序在sys_enter_execve tracepoint上执行
// 使用SEC属性告知BPF虚拟机何时运行此程序。当检测到execve系统调用跟踪点被执行时，BPF程序将运行
// SEC("tracepoint/syscalls/sys_enter_execve")
SEC(("kprobe/" SYSCALL(sys_write)))
// SEC("kprobe/sys_bpf")  
int bpf_prog(void *ctx) {
  char msg[] = "Hello, BPF World!";
  // 使用函数bpf_trace_printk在内核跟踪日志中打印消息，可以在文件/sys/kernel/debug/tracing/trace_pipe中查看。
  // bpf_trace_printk声明在/usr/include/bpf/bpf_helper_defs.h
  bpf_trace_printk(msg, sizeof(msg));
  return 0;
}

// 指定程序许可证。因为Linux内核采用GPL许可证，所以它只能加载GPL许可证的程序。
char _license[] SEC("license") = "GPL";

u32 _version SEC("version") = LINUX_VERSION_CODE;   // 指定BPF程序的版本号为Linux内核版本号