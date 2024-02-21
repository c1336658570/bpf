# eBPF内存泄露检测代码实现<完整版>

[toc]

**说明：**

**eBPF内存泄露检测代码实现是在 libbpf-bootstrap 框架下开发，需要的基础知识请参考之前的ebpf系列视频**

**本节视频使用的是 `Ubuntu18.04 x86-64` 平台**



## 目标

- 支持如下用户态内存分配接口的内存泄露检测

```c
void *malloc(size_t size);
void *calloc(size_t nmemb, size_t size);
void *realloc(void *ptr, size_t size);
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
void *memalign(size_t alignment, size_t size);
void *valloc(size_t size);
void *pvalloc(size_t size);
void *aligned_alloc(size_t alignment, size_t size);
int posix_memalign(void **memptr, size_t alignment, size_t size);
```



- 实现可执行文件一启动就开始内存泄露检测



## BPF_KRETPROBE 宏展开

因为 `malloc uretprobe` 中的 `bpf_get_stackid` 接口涉及到一个 `struct pt_regs *ctx` 的参数，

```c
info.stack_id = bpf_get_stackid(ctx, &stack_traces, USER_STACKID_FLAGS);
```

参考 <eBPF示例：x86-64平台上的kprobe> 视频中 `BPF_KPROBE` 宏展开方法，对 `BPF_KRETPROBE` 宏进行展开：

```c
SEC("uretprobe")
int BPF_KRETPROBE(malloc_exit, void * address)
{
    /* malloc uretuprobe 的处理逻辑 */
}

//////////////////////// 宏展开 ////////////////////////

__attribute__((section("uretprobe"), used))
// 函数的声明
int malloc_exit(struct pt_regs *ctx);
static inline int ____malloc_exit(struct pt_regs *ctx, void * address); 

// 函数的定义
int malloc_exit(struct pt_regs *ctx) {
    return ____malloc_exit(ctx, (void *)((ctx)->ax));
}

static inline int ____malloc_exit(struct pt_regs *ctx, void * address)
{
    /* malloc uretuprobe 的处理逻辑 */
}

/* 对于uprobe和uretprobe
 * struct pt_regs: 保存用户态的寄存器上下文，可以存放用户态接口的参数或者返回值
 * 不同的平台, struct pt_regs 中成员变量的定义不一样：
 * x86-64平台(libbpf-bootstrap/vmlinux/x86/vmlinux.h)：
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
 * arm32 平台(libbpf-bootstrap/vmlinux/arm/vmlinux.h)：
 	struct pt_regs {
        long unsigned int uregs[18];
    };
 * 
 * 参考头文件： libbpf-bootstrap/libbpf/src/bpf_tracing.h
 * 假设 uprobe 和 uretprobe attach 到 void *malloc(size_t size) 接口：
 * malloc 的第一个参数可以通过 PT_REGS_PARM1(ctx)获取，在 x86-64 平台上：
 *    size = PT_REGS_PARM1(ctx) = ctx->di
 * malloc 的返回值可以通过 PT_REGS_RC(ctx)获取，在 x86-64 平台上：
 *    malloc的返回值 void * address = PT_REGS_RC(ctx) = ctx->ax
 * 使用 PT_REGS_PARM1 和 PT_REGS_RC 宏可以屏蔽平台之间的差异；
 */
```



## 提取公共的代码

针对 `malloc` 和 `free` 的内存泄露检测逻辑抽象图：

![memleak处理流程-逻辑抽象.jpg](/home/cccmmf/bpf/libbpf框架使用/pictures/memleak处理流程-逻辑抽象.jpg)



`malloc`内存分配接口：  `分配的内存大小size`，`分配的内存指针ptr`，`stack_id`，经过 

- `malloc uprobe`
- `malloc uretuprobe`
- `free uprobe`

处理逻辑后，最终输出一个内存统计信息 `union combined_alloc_info`

现在把`malloc uprobe`，`malloc uretuprobe`，`free uprobe` 处理逻辑提取成公共代码：

```c
/* 通用的内存分配 uprobe的处理逻辑
 * 内存分配接口(malloc, calloc等)进入后就会被调用
 * size: 分配内存的大小, 比如 malloc 的第一个参数
 */
static int gen_alloc_enter(size_t size)
{
	const pid_t pid = bpf_get_current_pid_tgid() >> 32;

	bpf_map_update_elem(&sizes, &pid, &size, BPF_ANY);

	return 0;
}

/* 通用的内存分配 uretprobe的处理逻辑
 * 内存分配接口(malloc, calloc等)返回时就会被调用
 * ctx: struct pt_regs 指针, 参考 BPF_KRETPROBE 的宏展开
 * address: 分配成功的内存指针, 比如 malloc 的返回值
 */
static int gen_alloc_exit2(void *ctx, u64 address)
{
	const u64 addr = (u64)address;
	const pid_t pid = bpf_get_current_pid_tgid() >> 32;
	struct alloc_info info;

	const u64 * size = bpf_map_lookup_elem(&sizes, &pid);
	if (NULL == size) {
		return 0;
	}

	__builtin_memset(&info, 0, sizeof(info));
	info.size = *size;

	bpf_map_delete_elem(&sizes, &pid);

	if (0 != address) {
		info.stack_id = bpf_get_stackid(ctx, &stack_traces, USER_STACKID_FLAGS);

		bpf_map_update_elem(&allocs, &addr, &info, BPF_ANY);

		union combined_alloc_info add_cinfo = {
			.total_size = info.size,
			.number_of_allocs = 1
		};

		union combined_alloc_info * exist_cinfo = bpf_map_lookup_elem(&combined_allocs, &info.stack_id);
		if (NULL == exist_cinfo) {
			bpf_map_update_elem(&combined_allocs, &info.stack_id, &add_cinfo, BPF_NOEXIST);
		}
		else {
			__sync_fetch_and_add(&exist_cinfo->bits, add_cinfo.bits);
		}
	}

	return 0;
}

/* 把 gen_alloc_exit2 接口中的2个参数精简为1个参数 
 * 参考 BPF_KRETPROBE 的宏展开过程
 */
static int gen_alloc_exit(struct pt_regs *ctx)
{
	return gen_alloc_exit2(ctx, PT_REGS_RC(ctx));
}

/* 通用的内存释放 uprobe的处理逻辑
 * 内存释放接口(free, munmap等)进入后就会被调用
 * address: 需要释放的内存指针, 比如 free 的第一个参数
 */
static int gen_free_enter(const void *address)
{
	const u64 addr = (u64)address;

	const struct alloc_info * info = bpf_map_lookup_elem(&allocs, &addr);
	if (NULL == info) {
		return 0;
	}

	union combined_alloc_info * exist_cinfo = bpf_map_lookup_elem(&combined_allocs, &info->stack_id);
	if (NULL == exist_cinfo) {
		return 0;
	}

	const union combined_alloc_info sub_cinfo = {
		.total_size = info->size,
		.number_of_allocs = 1
	};

	__sync_fetch_and_sub(&exist_cinfo->bits, sub_cinfo.bits);

	bpf_map_delete_elem(&allocs, &addr);

	return 0;
}
```



`memleak.bpf.c` 中 `malloc` 和 `free` 的 `uprobe`和`uretprobe`代码实现：

```c
SEC("uprobe")
int BPF_KPROBE(malloc_enter, size_t size)
{
	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(malloc_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(free_enter, void * address)
{
	return gen_free_enter(address);
}
```



用宏来简化 `memleak.c` (用户态的ebpf)中的 `bpf_program__attach_uprobe_opts` 接口调用：

参考：https://github.com/eunomia-bpf/bpf-developer-tutorial 中 memleak 的实现

```c
#define __ATTACH_UPROBE(skel, sym_name, prog_name, is_retprobe) \
	do { \
		LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts, \
				.func_name = #sym_name, \
				.retprobe = is_retprobe); \
		skel->links.prog_name = bpf_program__attach_uprobe_opts( \
				skel->progs.prog_name, \
				attach_pid, \
				binary_path, \
				0, \
				&uprobe_opts); \
	} while (false)

#define __CHECK_PROGRAM(skel, prog_name) \
	do { \
		if (!skel->links.prog_name) { \
			perror("no program attached for " #prog_name); \
			return -errno; \
		} \
	} while (false)

#define __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, is_retprobe) \
	do { \
		__ATTACH_UPROBE(skel, sym_name, prog_name, is_retprobe); \
		__CHECK_PROGRAM(skel, prog_name); \
	} while (false)

/* ATTACH_UPROBE_CHECKED 和 ATTACH_UPROBE 宏的区别是:
 * ATTACH_UPROBE_CHECKED 会检查elf文件中(比如 libc.so)中是否存在 uprobe attach 的符号(比如malloc)
 * 如果不存在，返回错误；
 * ATTACH_UPROBE 发现符号不存在时不会返回错误，直接跳过这个符号的uprobe attach,继续往下执行；
 */
#define ATTACH_UPROBE(skel, sym_name, prog_name) __ATTACH_UPROBE(skel, sym_name, prog_name, false)
#define ATTACH_URETPROBE(skel, sym_name, prog_name) __ATTACH_UPROBE(skel, sym_name, prog_name, true)

#define ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name) __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, false)
#define ATTACH_URETPROBE_CHECKED(skel, sym_name, prog_name) __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, true)

```



`bpf_program__attach_uprobe_opts` 替换：

```c
int main(int argc, char **argv)
{
    uprobe_opts.func_name = "malloc";
    uprobe_opts.retprobe = false;
    skel->links.malloc_enter = bpf_program__attach_uprobe_opts(skel->progs.malloc_enter,
        attach_pid, binary_path, 0, &uprobe_opts);
    if (!skel->links.malloc_enter) {
        err = -errno;
        fprintf(stderr, "Failed to attach uprobe: %d\n", err);
        goto cleanup;
    }

    uprobe_opts.func_name = "malloc";
    uprobe_opts.retprobe = true;
    skel->links.malloc_exit = bpf_program__attach_uprobe_opts(
        skel->progs.malloc_exit, attach_pid, binary_path, 0, &uprobe_opts);
    if (!skel->links.malloc_exit) {
        err = -errno;
        fprintf(stderr, "Failed to attach uprobe: %d\n", err);
        goto cleanup;
    }

    uprobe_opts.func_name = "free";
    uprobe_opts.retprobe = false;
    skel->links.free_enter = bpf_program__attach_uprobe_opts(skel->progs.free_enter,
        attach_pid, binary_path, 0, &uprobe_opts);
    if (!skel->links.free_enter) {
        err = -errno;
        fprintf(stderr, "Failed to attach uprobe: %d\n", err);
        goto cleanup;
    }
    
    return 0;
}

//////////////////////// 替换为 ////////////////////////

int attach_uprobes(struct memleak_bpf *skel)
{
	ATTACH_UPROBE_CHECKED(skel, malloc, malloc_enter);
	ATTACH_URETPROBE_CHECKED(skel, malloc, malloc_exit);
	ATTACH_UPROBE_CHECKED(skel, free, free_enter);

	return 0;
}

int main(int argc, char **argv)
{
    err = attach_uprobes(skel);
    if (err) {
        fprintf(stderr, "failed to attach uprobes\n");
        goto cleanup;
    }
    
    return 0;
}
```

修改后的代码，编译验证通过；



## posix_memalign 的内存泄露检测实现过程

`posix_memalign` 接口定义：

```c
int posix_memalign(void **memptr, size_t alignment, size_t size);
void *malloc(size_t size);
//posix_memalign 对应的内存释放接口
void free(void *ptr);
```

`posix_memalign` 和 `malloc` 对于内存泄露检测来说，最大的区别就是 分配的内存指针 返回方式不一样：

`malloc` : 通过接口返回值返回 分配的内存指针，直接通过 `uretprobe` 就可以获取 分配的内存指针；

`posix_memalign`：把 `分配的内存指针` 保存到 `用户态的指针变量中(memptr)`，因为 `用户态的指针变量(memptr)` 在`uprobe`中获取，而把 `分配的内存指针` 保存到`用户态的指针变量(memptr)`是在 `uretprobe` 中，所以需要一个 ebpf 的 hash map 来临时存储在`uprobe`中获取到的 `用户态的指针变量(memptr)`；

![memleak处理流程-posix_memalign.jpg](/home/cccmmf/bpf/libbpf框架使用/pictures/memleak处理流程-posix_memalign.jpg)



修改测试代码：

```c
static void * alloc_v3(int alloc_size)
{
    void * memptr = NULL;
    posix_memalign(&memptr, 128, 1024);
    return memptr;
}
```



`memleak.bpf.c` 中的代码实现：

```c
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64); // pid
	__type(value, u64); // 用户态指针变量 memptr
	__uint(max_entries, 10240);
} memptrs SEC(".maps");

SEC("uprobe")
int BPF_KPROBE(posix_memalign_enter, void **memptr, size_t alignment, size_t size)
{
	const u64 memptr64 = (u64)(size_t)memptr;
	const u64 pid = bpf_get_current_pid_tgid() >> 32;
	bpf_map_update_elem(&memptrs, &pid, &memptr64, BPF_ANY);

	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(posix_memalign_exit)
{
	const u64 pid = bpf_get_current_pid_tgid() >> 32;
	u64 *memptr64;
	void *addr;

	memptr64 = bpf_map_lookup_elem(&memptrs, &pid);
	if (!memptr64)
		return 0;

	bpf_map_delete_elem(&memptrs, &pid);

    //通过 bpf_probe_read_user 读取保存在用户态指针变量(memptr64)中的 分配成功的内存指针
	if (bpf_probe_read_user(&addr, sizeof(void*), (void*)(size_t)*memptr64))
		return 0;

	const u64 addr64 = (u64)(size_t)addr;

	return gen_alloc_exit2(ctx, addr64);
}
```



`memleak.c ` 中的代码实现：

```c
// 在 attach_uprobes 接口中增加代码：
int attach_uprobes(struct memleak_bpf *skel)
{
    /* ...... */
	ATTACH_UPROBE_CHECKED(skel, posix_memalign, posix_memalign_enter);
	ATTACH_URETPROBE_CHECKED(skel, posix_memalign, posix_memalign_exit);
    /* ...... */
}
```



## 内存泄露检测的完整实现

```c
//void *malloc(size_t size);
void *calloc(size_t nmemb, size_t size);
void *realloc(void *ptr, size_t size);
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
void *memalign(size_t alignment, size_t size);
void *valloc(size_t size);
void *pvalloc(size_t size);
void *aligned_alloc(size_t alignment, size_t size);
//int posix_memalign(void **memptr, size_t alignment, size_t size);
```

剩下的内存分配接口和 `malloc` 相差不大，都是通过返回值来获取分配成功的内存指针，就不一一讲解了；

`memleak.bpf.c` 文件中增加如下代码，uprobe 和 uretprobe 处理逻辑调用的都是之前定义的通用接口：

```c
SEC("uprobe")
int BPF_KPROBE(calloc_enter, size_t nmemb, size_t size)
{
	return gen_alloc_enter(nmemb * size);
}

SEC("uretprobe")
int BPF_KRETPROBE(calloc_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(realloc_enter, void *ptr, size_t size)
{
	gen_free_enter(ptr);

	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(realloc_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(mmap_enter, void *address, size_t size)
{
	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(mmap_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(munmap_enter, void *address)
{
	return gen_free_enter(address);
}

SEC("uprobe")
int BPF_KPROBE(aligned_alloc_enter, size_t alignment, size_t size)
{
	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(aligned_alloc_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(valloc_enter, size_t size)
{
	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(valloc_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(memalign_enter, size_t alignment, size_t size)
{
	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(memalign_exit)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KPROBE(pvalloc_enter, size_t size)
{
	return gen_alloc_enter(size);
}

SEC("uretprobe")
int BPF_KRETPROBE(pvalloc_exit)
{
	return gen_alloc_exit(ctx);
}
```



`memleak.c` 文件中的 `attach_uprobes` 接口中增加如下代码：

```c
int attach_uprobes(struct memleak_bpf *skel)
{
    /* ...... */

	ATTACH_UPROBE_CHECKED(skel, calloc, calloc_enter);
	ATTACH_URETPROBE_CHECKED(skel, calloc, calloc_exit);

	ATTACH_UPROBE_CHECKED(skel, realloc, realloc_enter);
	ATTACH_URETPROBE_CHECKED(skel, realloc, realloc_exit);

	ATTACH_UPROBE_CHECKED(skel, mmap, mmap_enter);
	ATTACH_URETPROBE_CHECKED(skel, mmap, mmap_exit);

	ATTACH_UPROBE_CHECKED(skel, memalign, memalign_enter);
	ATTACH_URETPROBE_CHECKED(skel, memalign, memalign_exit);

	ATTACH_UPROBE_CHECKED(skel, free, free_enter);
	ATTACH_UPROBE_CHECKED(skel, munmap, munmap_enter);

	// the following probes are intentinally allowed to fail attachment

	// deprecated in libc.so bionic
	ATTACH_UPROBE(skel, valloc, valloc_enter);
	ATTACH_URETPROBE(skel, valloc, valloc_exit);

	// deprecated in libc.so bionic
	ATTACH_UPROBE(skel, pvalloc, pvalloc_enter);
	ATTACH_URETPROBE(skel, pvalloc, pvalloc_exit);

	// added in C11
	ATTACH_UPROBE(skel, aligned_alloc, aligned_alloc_enter);
	ATTACH_URETPROBE(skel, aligned_alloc, aligned_alloc_exit);
    
    /* ...... */
}
```

修改后的代码，编译验证通过；



## C++中的new可以被内存泄露检测吗？

测试代码：

```c++
static void * alloc_v3(int alloc_size)
{
    void * ptr = new char[alloc_size];
    
    return ptr;
}

// main 函数中 
// free(ptr); 
// 改为
// delete [] (char *)ptr;
```



检测结果：

```
stack_id=0x3d21 with outstanding allocations: total_size=8 nr_allocs=2
  0 [<00007f71f1a1a298>] operator new(unsigned long)+0x18
  1 [<000055deb2ba2741>] alloc_v2(int)+0x15 test_memleak.cpp:33
  2 [<000055deb2ba2760>] alloc_v1(int)+0x15 test_memleak.cpp:40
  3 [<000055deb2ba27a0>] main+0x36 test_memleak.cpp:53
  4 [<00007f71f15b7c87>] __libc_start_main+0xe7
  5 [<05a6258d4c544155>]
```

打印的堆栈不完整，没看到调用 new 的接口，也没有看到 new 对应的文件名和行号，用 `ldd` 命令查看测试程序使用的`libstdc++`库：

```shell
# ldd test_memleak
	linux-vdso.so.1 (0x00007fff74deb000)
	libstdc++.so.6 => /usr/lib/x86_64-linux-gnu/libstdc++.so.6 (0x00007f50e191e000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f50e152d000)
	libm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007f50e118f000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f50e1ea9000)
	libgcc_s.so.1 => /lib/x86_64-linux-gnu/libgcc_s.so.1 (0x00007f50e0f77000)

# ls -la /usr/lib/x86_64-linux-gnu/libstdc++.so.6
lrwxrwxrwx 1 root root 19 3月  10  2020 /usr/lib/x86_64-linux-gnu/libstdc++.so.6 -> libstdc++.so.6.0.25

# file /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.25
/usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.25: ELF 64-bit LSB shared object, x86-64, version 1 (GNU/Linux), dynamically linked, BuildID[sha1]=f2119a44a99758114620c8e9d8e243d7094f77f6, stripped

## 可以看到 libstdc++.so.6.0.25 被striped掉了，堆栈不完整应该是这个原因；

```



## 如何实现可执行文件一启动就开始内存泄露检测？

![memleak处理流程-内存泄露启动流程.jpg](/home/cccmmf/bpf/libbpf框架使用/pictures/memleak处理流程-内存泄露启动流程.jpg)

上图左边就是现在的内存泄露检测启动流程；

如何实现上图右边的启动流程？

参考 https://www.kernel.org/doc/html/latest/trace/ftrace.html 中的 `Single thread tracing` 章节，写个内存泄露检测的启动脚本`start_memleak.sh`：

```shell
#!/bin/bash

# 使用示例： 
# sh start_memleak.sh ./test/test_memleak

# $$ 表示脚本运行的当前进程ID号，使用示例中的 test_memleak 启动时，就会继承这个进程ID
# 启动内存泄露检测工具 memleak 时，就可以预先知道测试程序 test_memleak 的进程ID
sudo ./memleak $$ &

# $@ 表示传给脚本的所有参数的列表，即使用示例中的 ./test/test_memleak
exec "$@"
```

这个shell脚本就可以先启动 `memleak` 再启动测试程序 `test_memleak`；

因为 `memleak` 用的是`sudo`，且在后台运行，结束后需要执行 `sudo killall memleak` 把 `memleak` 进程退出；

