# eBPF：arm平台上的uprobe

[toc]

这节视频讲下在`arm 32`平台上的 ebpf uprobe 的使用方法；和 x86-64 上的使用方法有好些不同点；

Linux 内核版本：4.9.88



## 回顾

在上节视频中，交叉编译了 `zlib`, `libelf`, `libbpf-bootstrap`

交叉编译前需要先执行 `build_env.sh`

```shell
#！/bin/sh
# 指定交叉编译工具链的绝对地址
export PATH=$PATH:/home/zhanglong/Desktop/imx6ull_dev/sdk/ToolChain/arm-buildroot-linux-gnueabihf_sdk-buildroot/bin

# 指定目标平台类型
export ARCH=arm

# 指定交叉编译器
export CROSS_COMPILE=arm-buildroot-linux-gnueabihf-

# 指定交叉编译好的 zlib 和 libelf 库的头文件路径
export EXTRA_CFLAGS="-I/home/zhanglong/Desktop/ebpf/note/src/arm32/extra_libs/elfutils-0.189/_install/include -I/home/zhanglong/Desktop/ebpf/note/src/arm32/extra_libs/zlib-1.3/_install/include"

# 指定交叉编译好的 zlib 和 libelf 库(.a)文件路径
export EXTRA_LDFLAGS="-L/home/zhanglong/Desktop/ebpf/note/src/arm32/extra_libs/elfutils-0.189/_install/lib -L/home/zhanglong/Desktop/ebpf/note/src/arm32/extra_libs/zlib-1.3/_install/lib"
```



编译

```shell
source build_env.sh  # 只需执行一次
make clean
make uprobe
```



## 移植 x86-64 平台上的uprobe代码

1. 把 `eBPF示例：x86-64平台上的uprobe` 这节视频讲解中改造过的代码拷贝过来；

   涉及到3个文件:

   -  `test_uprobe.c`

     应用层的测试代码，定义了 `uprobed_add` 和 `uprobed_sub` 2个函数，然后在 `main` 函数中循环调用；

     测试目的：ebpf uprobe 在arm 32平台上是否可以正确获取 `uprobed_add` 和 `uprobed_sub` 2个函数的入口参数和返回值；

   - `uprobe.bpf.c` 

     ebpf 在内核层的代码，定义 `uprobe` 探测点的回调函数：

     应用层 `uprobed_add` 函数进入和返回时的回调函数；

     应用层 `uprobed_sub` 函数进入和返回时的回调函数；

   - `uprobe.c` 

     ebpf 在应用层的代码，负责把 `uprobe.bpf.c` 编译得到的字节码加载到内核，以及把 `uprobe.bpf.c` 文件中定义的回调函数 attach 到应用层测试代码中函数的 `uprobe` 探测点；

​	为了简单起见，不再 `strip` 测试代码的可执行程序，直接通过测试代码中的函数名来 `attach`；（如果对这部分内容不清楚的，可以再回去看看 `eBPF示例：x86-64平台上的uprobe` 这节视频）



2. 直接编译 测试代码 和 ebpf

   ```shell
   # 编译测试代码
   arm-buildroot-linux-gnueabihf-gcc test_uprobe.c -o test_uprobe
   
   # 编译 ebpf
   make clean
   make uprobe
   ```

​	编译好后，直接运行，报错：

```
libbpf: failed to find valid kernel BTF
libbpf: Error loading vmlinux BTF: -3
```

​	查看BCC文档： https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md

​	BTF 需要 4.18 及以后的内核版本才支持;



3. 修改代码：

   在 `uprobe.bpf.c` 中，去掉 `#include "vmlinux.h"` ，改为 `#include <linux/bpf.h>`

   再次编译ebpf，报错：

   ```
   uprobe.bpf.c:11:5: error: incomplete definition of type 'struct pt_regs'
   ```

   把 `libbpf-bootstrap/vmlinux/arm/vmlinux.h` 中的 `struct pt_regs` 定义拷贝到 `uprobe.bpf.c` 中；

   再次编译ebpf，并执行，报错：

   ```
   libbpf: prog 'uprobe_add': -- BEGIN PROG LOAD LOG --
   0: (79) r4 = *(u64 *)(r1 +8)
   1: (79) r3 = *(u64 *)(r1 +0)
   2: (85) call 2001000000
   invalid func 2001000000
   -- END PROG LOAD LOG --
   ```

   `bpf_helper_defs.h` 头文件中并没有定义 2001000000 的枚举值；

   阅读下 libbpf-bootstrap 开源代码说明文档：https://hub.njuu.cf/libbpf/libbpf-bootstrap
   
   **minimal_Legacy**
   
   ```
   This version of minimal is modified to allow running on even older kernels that 
   do not allow global variables. 
   bpf_printk uses global variables unless BPF_NO_GLOBAL_DATA is defined before 
   including bpf_helpers.h.
   ```
   
   `uprobe.bpf.c` 文件中，增加:
   
   ```c
   #define BPF_NO_GLOBAL_DATA
   ```
   
   再次编译，并执行：
   
   可以正常运行，但是 `uprobed_add` 打印的结果不对；
   
   按照: `eBPF示例：x86-64平台上的kprobe` 视频中的方法，改写下`int BPF_KPROBE(uprobe_add, int a, int b)`
   
   ```c
   int uprobe_add(struct pt_regs *ctx)
   {
   	int a = ctx->uregs[0];
   	int b = ctx->uregs[1];
   	bpf_printk("uprobed_add ENTRY: a = %d, b = %d\n", a, b);
   	return 0;
   }
   ```
   
   在 `eBPF基础` 视频中讲过，ebpf寄存器是64 bit，但是arm32平台寄存器是32 bit，这2个事实存在冲突，用代码来验证下；
   
   ```c
   int uprobe_add(struct pt_regs *ctx)
   {
   	int a = ctx->uregs[0];
   	int b = ctx->uregs[1];
   	bpf_printk("uprobed_add ENTRY: a = %d, b = %d sizeof(uregs[0])=%d\n", a, b, sizeof(ctx->uregs[0]));
   	return 0;
   }
   
   /*
   打印结果
   uprobed_add ENTRY: a = 10, b = 16 sizeof(uregs[0])=8
   即内核层ebpf中, long unsigned int 是 64 bit
   */
   ```
   
   把变量 `a` 和 `b` 用64 bit的格式打印出来：
   
   ```c
   int uprobe_add(struct pt_regs *ctx)
   {
   	int a = ctx->uregs[0];
   	int b = ctx->uregs[1];
   
   	bpf_printk("uprobed_add ENTRY: a = 0x%llx, b = 0x%llx\n", a, b);
   	return 0;
   }
   
   /*
   打印结果：
   uprobed_add ENTRY: a = 0x700000006, b = 0x700000010
   */
   ```
   
   根据打印结果和 `test_uprobe.c` 代码分析可知，变量 a 的低32bit是 `test_uprobe.c` 中 `uprobed_add` 函数的第一个参数，高32bit是第二个参数；
   
   强制把 `struct pt_regs` 中的 `long unsigned int` 改为 `unsigned int`（强制变为32 bit）
   
   ```c
   struct pt_regs {
           unsigned int uregs[18];
   };
   ```
   
   结果正确；
   
   再来解决编译警告的问题：
   
   ```c
   // 修改 libbpf-bootstrap/libbpf/src/bpf_tracing.h
   #if defined(bpf_target_arm)
   #define ___bpf_kretprobe_args0()       ctx
   #define ___bpf_kretprobe_args1(x)      ___bpf_kretprobe_args0(), (unsigned int)PT_REGS_RC(ctx)
   #define ___bpf_kretprobe_args(args...) ___bpf_apply(___bpf_kretprobe_args, ___bpf_narg(args))(args)
   #else
   #define ___bpf_kretprobe_args0()       ctx
   #define ___bpf_kretprobe_args1(x)      ___bpf_kretprobe_args0(), (void *)PT_REGS_RC(ctx)
   #define ___bpf_kretprobe_args(args...) ___bpf_apply(___bpf_kretprobe_args, ___bpf_narg(args))(args)
   #endif
   
   #if defined(bpf_target_arm)
   #define ___bpf_kprobe_args0()           ctx
   #define ___bpf_kprobe_args1(x)          ___bpf_kprobe_args0(), (unsigned int)PT_REGS_PARM1(ctx)
   #define ___bpf_kprobe_args2(x, args...) ___bpf_kprobe_args1(args), (unsigned int)PT_REGS_PARM2(ctx)
   #define ___bpf_kprobe_args3(x, args...) ___bpf_kprobe_args2(args), (unsigned int)PT_REGS_PARM3(ctx)
   #define ___bpf_kprobe_args4(x, args...) ___bpf_kprobe_args3(args), (unsigned int)PT_REGS_PARM4(ctx)
   #define ___bpf_kprobe_args5(x, args...) ___bpf_kprobe_args4(args), (unsigned int)PT_REGS_PARM5(ctx)
   #define ___bpf_kprobe_args6(x, args...) ___bpf_kprobe_args5(args), (unsigned int)PT_REGS_PARM6(ctx)
   #define ___bpf_kprobe_args7(x, args...) ___bpf_kprobe_args6(args), (unsigned int)PT_REGS_PARM7(ctx)
   #define ___bpf_kprobe_args8(x, args...) ___bpf_kprobe_args7(args), (unsigned int)PT_REGS_PARM8(ctx)
   #define ___bpf_kprobe_args(args...)     ___bpf_apply(___bpf_kprobe_args, ___bpf_narg(args))(args)
   #else
   #define ___bpf_kprobe_args0()           ctx
   #define ___bpf_kprobe_args1(x)          ___bpf_kprobe_args0(), (void *)PT_REGS_PARM1(ctx)
   #define ___bpf_kprobe_args2(x, args...) ___bpf_kprobe_args1(args), (void *)PT_REGS_PARM2(ctx)
   #define ___bpf_kprobe_args3(x, args...) ___bpf_kprobe_args2(args), (void *)PT_REGS_PARM3(ctx)
   #define ___bpf_kprobe_args4(x, args...) ___bpf_kprobe_args3(args), (void *)PT_REGS_PARM4(ctx)
   #define ___bpf_kprobe_args5(x, args...) ___bpf_kprobe_args4(args), (void *)PT_REGS_PARM5(ctx)
   #define ___bpf_kprobe_args6(x, args...) ___bpf_kprobe_args5(args), (void *)PT_REGS_PARM6(ctx)
   #define ___bpf_kprobe_args7(x, args...) ___bpf_kprobe_args6(args), (void *)PT_REGS_PARM7(ctx)
   #define ___bpf_kprobe_args8(x, args...) ___bpf_kprobe_args7(args), (void *)PT_REGS_PARM8(ctx)
   #define ___bpf_kprobe_args(args...)     ___bpf_apply(___bpf_kprobe_args, ___bpf_narg(args))(args)
   #endif
   ```

​	再重新编译 uprobe

```shell
make clean; make uprobe
```



**ebpf kprobe 和 uprobe 在arm 32平台的处理方法一样，这里就不再详细讲了；**

