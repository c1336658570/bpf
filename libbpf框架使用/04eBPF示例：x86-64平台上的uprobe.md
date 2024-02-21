# eBPF示例：x86-64平台上的uprobe

[toc]

**重点：示例代码中只适用于uprobe没有strip的可执行文件，如果可执行文件被strip了，怎么办？**



## 回顾

上节视频详细讲解了kprobe的原理和在 libbpf-bootstrap 框架上的示例代码分析；

这节视频讲下 libbpf-bootstrap 框架上的 uprobe 示例代码；



## libbpf-bootstrap 中的 uprobe 示例代码

```shell
# 代码路径: libbpf-bootstrap/examples/c/
uprobe.bpf.c  uprobe.c
```

uprobe 要能正常工作，需要满足2个条件：

- 被attach的接口名称
- 接口所在可执行文件路径

在 libbpf-bootstrap 框架中，有2种写法：

1. 在内核层的ebpf程序中，通过`SEC()` 给ebpf提供 被attach的接口名称和接口所在的文件路径；
2. 在用户层的ebpf程序中，通过 `bpf_program__attach_uprobe_opts` 接口提供 被attach的接口名称和接口所在的文件路径；



## 改造示例代码

为了简单起见，`uprobed_sub` 改成和 `uprobe_add` 同一种写法；

为了模拟更真实的使用场景，把示例代码中的 `uprobed_add` 和 `uprobed_sub` 独立到一个测试代码中：

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* It's a global function to make sure compiler doesn't inline it. */
int uprobed_add(int a, int b)
{
	return a + b;
}

int uprobed_sub(int a, int b)
{
	return a - b;
}

int main(int argc, char * argv[])
{
    int i = 0;

    for (i = 0;; i++) {
		/* trigger our BPF programs */
		uprobed_add(i, i + 1);
		uprobed_sub(i * i, i);

		/* 为了好验证结果 */
		if (i >= 10) {
			i = 0;
		}

		sleep(1);
	}
}
```



再改造下 uprobe.c 代码，把 `uprobed_add` 和 `uprobed_sub`  所在的测试代码进程ID通过参数传进来：

```c
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "uprobe.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct uprobe_bpf *skel;
	int err, i, attach_pid;
	char binary_path[256] = {};
	LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);

	if (2 != argc) {
		fprintf(stderr, "usage:%s attach_pid\n", argv[0]);
		return -1;
	}

	attach_pid = atoi(argv[1]);
	sprintf(binary_path, "/proc/%d/exe", attach_pid);

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Load and verify BPF application */
	skel = uprobe_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Attach tracepoint handler */
	uprobe_opts.func_name = "uprobed_add";
	uprobe_opts.retprobe = false;
	/* uprobe/uretprobe expects relative offset of the function to attach
	 * to. libbpf will automatically find the offset for us if we provide the
	 * function name. If the function name is not specified, libbpf will try
	 * to use the function offset instead.
	 */
	skel->links.uprobe_add = bpf_program__attach_uprobe_opts(skel->progs.uprobe_add,
								 attach_pid, binary_path,
								 0 /* offset for function */,
								 &uprobe_opts /* opts */);
	if (!skel->links.uprobe_add) {
		err = -errno;
		fprintf(stderr, "Failed to attach uprobe: %d\n", err);
		goto cleanup;
	}

	/* we can also attach uprobe/uretprobe to any existing or future
	 * processes that use the same binary executable; to do that we need
	 * to specify -1 as PID, as we do here
	 */
	uprobe_opts.func_name = "uprobed_add";
	uprobe_opts.retprobe = true;
	skel->links.uretprobe_add = bpf_program__attach_uprobe_opts(
		skel->progs.uretprobe_add, attach_pid, binary_path,
		0 /* offset for function */, &uprobe_opts /* opts */);
	if (!skel->links.uretprobe_add) {
		err = -errno;
		fprintf(stderr, "Failed to attach uprobe: %d\n", err);
		goto cleanup;
	}

	/* Attach tracepoint handler */
	uprobe_opts.func_name = "uprobed_sub";
	uprobe_opts.retprobe = false;
	/* uprobe/uretprobe expects relative offset of the function to attach
	 * to. libbpf will automatically find the offset for us if we provide the
	 * function name. If the function name is not specified, libbpf will try
	 * to use the function offset instead.
	 */
	skel->links.uprobe_sub = bpf_program__attach_uprobe_opts(skel->progs.uprobe_sub,
								 attach_pid, binary_path,
								 0 /* offset for function */,
								 &uprobe_opts /* opts */);
	if (!skel->links.uprobe_sub) {
		err = -errno;
		fprintf(stderr, "Failed to attach uprobe: %d\n", err);
		goto cleanup;
	}

	/* we can also attach uprobe/uretprobe to any existing or future
	 * processes that use the same binary executable; to do that we need
	 * to specify -1 as PID, as we do here
	 */
	uprobe_opts.func_name = "uprobed_sub";
	uprobe_opts.retprobe = true;
	skel->links.uretprobe_sub = bpf_program__attach_uprobe_opts(
		skel->progs.uretprobe_sub, attach_pid, binary_path,
		0 /* offset for function */, &uprobe_opts /* opts */);
	if (!skel->links.uretprobe_sub) {
		err = -errno;
		fprintf(stderr, "Failed to attach uprobe: %d\n", err);
		goto cleanup;
	}

	/* Let libbpf perform auto-attach for uprobe_sub/uretprobe_sub
	 * NOTICE: we provide path and symbol info in SEC for BPF programs
	 */
	err = uprobe_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to auto-attach BPF skeleton: %d\n", err);
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	for (i = 0;; i++) {
		/* trigger our BPF programs */
		fprintf(stderr, ".");
		sleep(1);
	}

cleanup:
	uprobe_bpf__destroy(skel);
	return -err;
}

```



## 问题：可执行文件被strip，找不到被attach的接口符号，怎么办？

- strip命令的功能是**用于从文件中去除指定符号或调试信息**，可以针对一般文件与函数库文件进行操作，能够减少文件占用空间大小。

```bash
strip a.out
```

1. 在 strip 可执行文件前，先备份一下；
2. 对没有strip的可执行文件进行反汇编，并查找 uprobe_add 和 uprobe_sub 符号的汇编指令地址：

```shell
objdump -d test_uprobe.unstriped

000000000000064a <uprobed_add>:
000000000000065e <uprobed_sub>:
```

3. 通过命令 `cat /proc/attach_pid/maps` (attach_pid 是uprobe需要跟踪的进程ID) 获取有可执行属性的attach_pid 的偏移地址：

```
起始地址     -结束地址       属性 偏移地址  主从设备号 inode编号                文件名
55fde9ec5000-55fde9ec6000 r-xp 00000000 08:01 32672410                   test_uprobe
55fdea0c5000-55fdea0c6000 r--p 00000000 08:01 32672410                   test_uprobe
55fdea0c6000-55fdea0c7000 rw-p 00001000 08:01 32672410                   test_uprobe
7fb077d9b000-7fb077f82000 r-xp 00000000 103:02 11558371                  /lib/x86_64-linux-gnu/libc-2.27.so
7fb077f82000-7fb078182000 ---p 001e7000 103:02 11558371                  /lib/x86_64-linux-gnu/libc-2.27.so
7fb078182000-7fb078186000 r--p 001e7000 103:02 11558371                  /lib/x86_64-linux-gnu/libc-2.27.so
7fb078186000-7fb078188000 rw-p 001eb000 103:02 11558371                  /lib/x86_64-linux-gnu/libc-2.27.so
7fb078188000-7fb07818c000 rw-p 00000000 00:00 0 
7fb07818c000-7fb0781b5000 r-xp 00000000 103:02 11543405                  /lib/x86_64-linux-gnu/ld-2.27.so
7fb07838b000-7fb07838d000 rw-p 00000000 00:00 0 
7fb0783b5000-7fb0783b6000 r--p 00029000 103:02 11543405                  /lib/x86_64-linux-gnu/ld-2.27.so
7fb0783b6000-7fb0783b7000 rw-p 0002a000 103:02 11543405                  /lib/x86_64-linux-gnu/ld-2.27.so
7fb0783b7000-7fb0783b8000 rw-p 00000000 00:00 0 
7ffed92ea000-7ffed930b000 rw-p 00000000 00:00 0                          [stack]
7ffed9383000-7ffed9386000 r--p 00000000 00:00 0                          [vvar]
7ffed9386000-7ffed9388000 r-xp 00000000 00:00 0                          [vdso]
7fffffffe000-7ffffffff000 --xp 00000000 00:00 0                          [uprobes]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
```

4. uprobe.c 文件中的 `bpf_program__attach_uprobe_opts` 接口：

```
uprobe_opts.func_name 不要赋值，因为二进制文件中已经找不到函数对应的符号
func_offset 参数赋值 = 第2步获取的函数符号汇编指令地址 + 第3步获取的偏移地址
```

