from bcc import BPF

# kprobes

"""
内核探针几乎可以在任何内核指令上设置动态标志或中断，并且系统损耗最
小。当内核到达这些标志时，附加到探针的代码将被执行，之后内核将恢复
正常模式。内核探针可以提供系统中发生事件的信息，例如，系统中打开的
文件和正在执行的二进制文件。
"""

"""
kprobes允许在执行任何内核指令之前插入BPF程序。你需要知道插入点的函数签名，前面已提到内核探针不是稳定的ABI，
所以在不同的内核版本中运行相同程序设置探针时需要谨慎。当内核执行到设置探针的指令时，
它将从代码执行处开始运行BPF程序，在BPF程序执行完成后将返回至插入BPF程序处继续执行。
"""

"""
BPF 程序调用帮助函数 bpf_get_current_comm 获得当前内核正在
运行的命令名，并将它保存在 comm 变量中。因为内核对命令名有 16 个
字符的限制，所以我们将其定义为固定长度的数组。获得命令名后，打
印至调试跟踪，运行该 Python 脚本将在控制台看到 BPF 获得的所有命令名。
"""
# 定义一个BPF程序，该程序会在每次发生execve系统调用时被触发
bpf_source = """
#include <uapi/linux/ptrace.h>

int do_sys_execve(struct pt_regs *ctx) {
  char comm[16];
  // 获得当前内核正在运行的命令名，并将它保存在 comm 变量中。因为内核对命令名有 16 个字符的限制，所以我们将其定义为固定长度的数组。
  bpf_get_current_comm(&comm, sizeof(comm));
  bpf_trace_printk("executing program: %s\\n", comm);
  return 0;
}
"""
# 使用BPF类加载BPF程序到内核中
bpf = BPF(text=bpf_source)
# 将BPF程序与execve系统调用关联。该系统调用的名称在不同的内核版本中是不同的，
# BCC提供了获得该系统调用名称的功能，你无须记住正在运行的内核版本下该系统调用的名称。
# 获取execve系统调用的名称，该名称在不同的内核版本中可能会有所不同
execve_function = bpf.get_syscall_fnname("execve")
# 将BPF程序与execve系统调用关联，以便在每次调用execve时执行BPF程序
bpf.attach_kprobe(event=execve_function, fn_name="do_sys_execve")
# 输出跟踪日志，显示每次execve系统调用时执行的程序名称
bpf.trace_print()
