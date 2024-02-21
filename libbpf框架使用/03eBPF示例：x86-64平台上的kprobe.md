# eBPF示例：x86-64平台上的kprobe

[toc]

## 回顾

前面2节视频讲了 eBPF基础 和 libbpf-bootstrap基础，这节视频讲下 libbpf-bootstrap中kprobe在x86-64平台上的示例；

重点讲：

- BPF_KPROBE 宏展开
- 低版本内核，不支持CO-RE，如何重新实现kprobe示例功能



## kprobe作用

可以在几乎所有的函数中 **动态** 插入探测点，利用注册的回调函数，知道内核函数是否被调用，被调用上下文，入参以及返回值；

kretprobe 是在 kprobe 的基础上实现；

## kprobe原理

![kprobe原理图](./pictures/kprobe原理图.png)



- 如果用户没有注册kprobe探测点，指令流：`指令1(instr1)` 顺序执行到 `指令4(instr4)`
- 如果用户注册一个kprobe探测点到`指令2(instr2)`，`指令2`被备份，并把`指令2`的入口点替换为断点指令，断点指令是CPU架构相关，如x86-64是int3，arm是设置一个未定义指令；
- 当CPU执行到断点指令时，触发一个 `trap`，在`trap`流程中，
  - 首先，执行用户注册的 `pre_handler` 回调函数；
  - 然后，单步执行前面备份的`指令2(instr2)`；
  - 单步执行完成后，执行用户注册的 `post_handler` 回调函数；
  - 最后，执行流程回到被探测指令之后的正常流程继续执行；

参考：

https://blog.csdn.net/Rong_Toa/article/details/116643875

https://yoc.docs.t-head.cn/linuxbook/Chapter4/tracing.html

https://github.com/eunomia-bpf/bpf-developer-tutorial



## libbpf-bootstrap 中的 kprobe 示例

通过示例代码来了解kprobe的使用方法：

```
libbpf-bootstrap/examples/c/ 目录下的：
kprobe.bpf.c
kprobe.c
```

- kprobe.bpf.c 的功能及演示
- kprobe示例代码的实现逻辑
- BPF_KPROBE 宏展开
- 如果不使用CO-RE，要怎么实现原来的功能



### kprobe.bpf.c 的功能及演示

删除文件时，就会打印被删除文件的文件名，以及返回值

```
rm-12056   [002] ....  4188.004100: 0: KPROBE ENTRY pid = 12056, filename = a.txt
rm-12056   [002] d...  4188.004180: 0: KPROBE EXIT: pid = 12056, ret = 0
```



### do_unlinkat 接口定义

```c
// linux-5.4.150/include/linux/syscalls.h
extern long do_unlinkat(int dfd, struct filename *name);

// linux-5.4.150/include/linux/fs.h
struct filename {
	const char		*name;	/* pointer to actual string */
	const __user char	*uptr;	/* original userland pointer */
	int			refcnt;
	struct audit_names	*aname;
	const char		iname[];
};
```



### kprobe示例代码的实现逻辑

在kprobe.bpf.c 中

```c
SEC("kprobe/do_unlinkat")    //在内核的 do_unlinkat 入口处注册一个 kprobe 探测点
SEC("kretprobe/do_unlinkat") //在内核的 do_unlinkat 返回时注册一个 kretprobe 探测点

// 使用 BPF_KPROBE 和 BPF_KRETPROBE 宏来定义探测点的回调函数
```

kprobe.c 中的 open, load, attach



### BPF_KPROBE 宏展开

clang编译器预编译的示例：

```shell
clang -E -c test.c -o test.i
```

```bash
make kprobe V=1		# 编译时显示详细的编译指令
```



clang编译器预编译 kprobe.bpf.c

```shell
/home/zhanglong/Desktop/clang-16/clang -g -O2 -target bpf -D__TARGET_ARCH_x86		      \
	     -I.output -I../../libbpf/include/uapi -I../../vmlinux/x86/ -I/home/zhanglong/workdir/disk1/workdir/embeded_work/my_note/eBPF/note/src/x86-64/libbpf-bootstrap/blazesym/include -idirafter /home/zhanglong/workdir/disk1/software/llvm-clang/clang+llvm-16.0.0-x86_64-linux-gnu-ubuntu-18.04/lib/clang/16/include -idirafter /usr/local/include -idirafter /usr/include/x86_64-linux-gnu -idirafter /usr/include		      \
	     -E -c kprobe.bpf.c -o .output/kprobe.tmp.bpf.i

```



```c
 __attribute__((section("kprobe/do_unlinkat"), used))

# 相当于kprobe原理中用户定义的回调函数
int do_unlinkat(struct pt_regs *ctx);

static inline int ____do_unlinkat(struct pt_regs *ctx, int dfd, struct filename *name); 

int do_unlinkat(struct pt_regs *ctx) 
{
    return ____do_unlinkat(ctx, (void *)((ctx)->di), (void *)((ctx)->si));	// di第一个参数，si第二个参数
} 

static inline int ____do_unlinkat(struct pt_regs *ctx, int dfd, struct filename *name)
{
    pid_t pid;
    const char *filename;

    pid = bpf_get_current_pid_tgid() >> 32;
    filename = ({ 
        typeof((name)->name) __r; 
        ({ 
            bpf_probe_read_kernel((void *)(&__r), sizeof(*(&__r)), (const void *)__builtin_preserve_access_index(&((typeof(((name))))(((name))))->name)); 
        }); 
        __r; 
    });

    ({ 
        static const char ____fmt[] = "KPROBE ENTRY pid = %d, filename = %s\n"; 
        bpf_trace_printk(____fmt, sizeof(____fmt), pid, filename); 
    });
    return 0;
}
```



- 不借助 BPF_KPROBE 宏要怎么实现？
- do_unlinkat 函数名可改吗？
- 参数一定要定义2个吗？只有1个行不行？都不要行不行？



不借助BPF_KPROBE

```c
SEC("kprobe/do_unlinkat")
int do_unlinkat(struct pt_regs *ctx)
{
	pid_t pid;
	const char *filename;

	struct filename *name = (struct filename *)((ctx)->si);

	pid = bpf_get_current_pid_tgid() >> 32;
	filename = BPF_CORE_READ(name, name);
	bpf_printk("KPROBE ENTRY pid = %d, filename = %s\n", pid, filename);
	return 0;
}
```



### 不使用CO-RE功能

如果内核版本过低，不支持CO-RE，要怎么实现？

```c
// libbpf-bootstrap/examples/c/.output/bpf/bpf_helper_defs.h
long (*bpf_probe_read_user)(void *dst, __u32 size, const void *unsafe_ptr);
long (*bpf_probe_read_kernel)(void *dst, __u32 size, const void *unsafe_ptr);
long (*bpf_probe_read_user_str)(void *dst, __u32 size, const void *unsafe_ptr);
long (*bpf_probe_read_kernel_str)(void *dst, __u32 size, const void *unsafe_ptr);
```



不使用CO-RE功能的代码实现：

```c
// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#define __KERNEL__            //参考: bpf_tracing.h 中的定义
#include <linux/bpf.h>        //参考: minimal_legacy.bpf.c
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

//参考: minimal_legacy.bpf.c
typedef unsigned int u32;
typedef int pid_t;

//拷贝: vmlinux/x86/vmlinux.h 中的定义
struct pt_regs {
        long unsigned int r15;
        long unsigned int r14;
        long unsigned int r13;
        long unsigned int r12;
        long unsigned int bp;
        long unsigned int bx;
        long unsigned int r11;
        long unsigned int r10;
        long unsigned int r9;
        long unsigned int r8;
        long unsigned int ax;
        long unsigned int cx;
        long unsigned int dx;
        long unsigned int si;
        long unsigned int di;
        long unsigned int orig_ax;
        long unsigned int ip;
        long unsigned int cs;
        long unsigned int flags;
        long unsigned int sp;
        long unsigned int ss;
};

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/do_unlinkat")
int BPF_KPROBE(do_unlinkat, int dfd, void *name)
{
	pid_t pid;
	const char *filename;
	int refcnt;

	pid = bpf_get_current_pid_tgid() >> 32;
	
	bpf_probe_read_kernel(&filename, sizeof(filename), name+0);
	bpf_probe_read_kernel(&refcnt, sizeof(refcnt), name+16);
	
	bpf_printk("KPROBE ENTRY pid = %d, refcnt=%d filename = %s\n", pid, refcnt, filename);
	return 0;
}
```

