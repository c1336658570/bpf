# BPF启动

```bash
uname -a                                                           18:34:49
Linux cccmmf 6.2.0-36-generic #37~22.04.1-Ubuntu SMP PREEMPT_DYNAMIC Mon Oct  9 15:34:04 UTC 2 x86_64 x86_64 x86_64 GNU/Linux
```

```bash
sudo apt install -y bison build-essential cmake flex git libedit-dev pkg-config libmnl-dev zlib1g-dev libssl-dev libelf-dev libcap-dev libfl-dev llvm clang pkg-config gcc-multilib luajit libluajit-5.1-dev libncurses5-dev libclang-dev clang-tools
```

```bash
sudo apt install linux_souce-6.2.0
cd /usr/src/linux-source-6.2.0
sudo tar xvf linux-source-6.2.0.tar.bz2
cd linux-source-6.2.0/
sudo cp -v /boot/config-$(uname -r) .config
sudo make headers_install && sudo make modules_prepare
```

```bash
cd samples/bpf
sudo touch hello_kern.c
```

```c
#include <linux/ptrace.h>       // 引入ptrace头文件           ptrace.h包含了ptrace相关的定义
#include <linux/version.h>      // 引入Linux内核版本相关的头文件  version.h包含了Linux内核版本相关的宏
#include <uapi/linux/bpf.h>     // 引入BPF相关的头文件          bpf.h包含了BPF相关的定义
#include <bpf/bpf_helpers.h>    // 引入BPF辅助函数的头文件      bpf_helpers.h包含了BPF程序中使用的辅助函数
#include "trace_common.h"       // 引入trace_common.h头文件，该文件可能包含一些共用的定义

// SEC宏用于指定BPF程序在哪个tracepoint上执行。在这里，指定在sys_enter_execve tracepoint上执行。
SEC("tracepoint/syscalls/sys_enter_execve") // 定义BPF程序在sys_enter_execve tracepoint上执行
// 这是BPF程序的入口点，接受一个指向struct pt_regs结构体的指针作为参数。
int bpf_prog(struct pt_regs *ctx) {         // BPF程序的入口点，接受pt_regs结构体作为参数
  char msg[] = "Hello, BPF World!";         // 要打印的消息
  // 使用BPF辅助函数bpf_trace_printk打印消息到trace_pipe中，这是一个特殊的内核文件，可用于收集BPF程序的输出。
  bpf_trace_printk(msg, sizeof(msg));       // 使用BPF辅助函数bpf_trace_printk打印消息到trace_pipe文件中
  return 0;                                 // 返回0表示BPF程序执行成功
}

// 指定了BPF程序的许可证为GPL（通用公共许可证）。这是必要的，因为BPF程序可能会与内核代码交互，因此必须遵守内核的许可证。
char _license[] SEC("license") = "GPL";     // 指定BPF程序的许可证为GPL
// u32 _version SEC("version") = LINUX_VERSION_CODE; 定义了BPF程序的版本号，此处使用了Linux内核的版本号。
u32 _version SEC("version") = LINUX_VERSION_CODE;   // 指定BPF程序的版本号为Linux内核版本号
```

```bash
sudo touch hello_user.c
```

```c
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#define DEBUGFS "/sys/kernel/debug/tracing/"     // 定义trace_pipe文件所在的路径
// 函数声明：从文件加载并运行BPF程序
int load_bpf_file(char *filename);

// 函数声明：从trace_pipe文件读取追踪数据
void read_trace_pipe(void);

// 从文件加载并运行BPF程序
int load_bpf_file(char *path) {
  struct bpf_object *obj;           // BPF对象
  struct bpf_program *prog;         // BPF程序
  struct bpf_link *link = NULL;     // BPF程序链接
  // 打印正在加载的BPF文件路径
  printf("%s\n", path);

  // 打开BPF对象文件
  obj = bpf_object__open_file(path, NULL);
  if (libbpf_get_error(obj)) {
    fprintf(stderr, "ERROR: opening BPF object file failed\n");
    return 0;
  }

  // 加载BPF对象文件
  if (bpf_object__load(obj)) {
    fprintf(stderr, "ERROR: loading BPF object file failed\n");
    goto cleanup;
  }

  // 查找BPF程序
  prog = bpf_object__find_program_by_name(obj, "bpf_prog");
  if (!prog) {
    printf("finding a prog in obj file failed\n");
    goto cleanup;
  }

  // 将BPF程序链接到内核
  link = bpf_program__attach(prog);
  if (libbpf_get_error(link)) {
    fprintf(stderr, "ERROR: bpf_program__attach failed\n");
    link = NULL;
    goto cleanup;
  }

  // 读取trace_pipe文件
  read_trace_pipe();

cleanup:
  // 销毁BPF程序链接和BPF对象
  bpf_link__destroy(link);
  bpf_object__close(obj);
  return 0;
}

// 从trace_pipe文件读取追踪数据
void read_trace_pipe(void) {
  int trace_fd;

  // 打开trace_pipe文件
  trace_fd = open(DEBUGFS "trace_pipe", O_RDONLY, 0);
  if (trace_fd < 0) return;

  // 无限循环读取并输出trace_pipe文件中的数据
  while (1) {
    static char buf[4096];
    ssize_t sz;

    // 读取trace_pipe文件的数据
    sz = read(trace_fd, buf, sizeof(buf) - 1);
    if (sz > 0) {
      buf[sz] = 0;
      // 输出读取到的数据
      puts(buf);
    }
  }
}

int main(int argc, char **argv) {
  // 调用load_bpf_file函数加载BPF程序
  if (load_bpf_file("hello_kern.o") != 0) {
    printf("The kernel didn't load the BPF program\n");
    return -1;
  }
}
```

```makefile
为samples/bpf/makefile添加
tprogs-y += hello
hello-objs := hello_user.o
always-y += hello_kern.o

sudo make VMLINUX_BTF=/sys/kernel/btf/vmlinux
sudo ./hello
```

