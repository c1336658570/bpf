# eBPF内存泄露检测代码实现<一>

[toc]

## 目标

这节视频的目标是用ebpf代码实现内存泄露检测工具的第一个简单版本，只检测 malloc 和 free，并打印如下的内存泄露堆栈；（指令地址对应符号名，文件名，行号的解析放到下节视频中讲解）

```
stack_id=0x2d81 with outstanding allocation: total_size=20 nr_alloc=5
[  0] 0x55e8fbd196f2
[  1] 0x55e8fbd19711
[  2] 0x55e8fbd19730
[  3] 0x55e8fbd19770
[  4] 0x7f5bb944ec87
[  5] 0x5f6258d4c544155
```

代码实现参考开源项目：

https://github.com/eunomia-bpf/bpf-developer-tutorial

​	bpf-developer-tutorial/src/16-memleak



## 测试代码

`test_memleak.c`

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void * alloc_v3(int alloc_size)
{
    void * ptr = malloc(alloc_size);
    
    return ptr;
}

static void * alloc_v2(int alloc_size)
{
    void * ptr = alloc_v3(alloc_size);

    return ptr;
}

static void * alloc_v1(int alloc_size)
{
    void * ptr = alloc_v2(alloc_size);

    return ptr;
}

int main(int argc, char * argv[])
{
    const int alloc_size = 4;
    void * ptr = NULL;
    int i = 0;

    for (i = 0; ; i++)
    {
        ptr = alloc_v1(alloc_size);

        sleep(2);

        if (0 == i % 2)
        {
            free(ptr);
        }
    }

    return 0;
}
```

```bash
ldd memleak_test		# 查看该程序使用的libc库的路径
```



编译：

```shell
gcc -g test_memleak.c -o test_memleak
```



## 内存泄露检测工具的第一个版本

结构体和maps

```c
#ifndef __MEMLEAK_H
#define __MEMLEAK_H

#define ALLOCS_MAX_ENTRIES 1000000
#define COMBINED_ALLOCS_MAX_ENTRIES 10240

struct alloc_info {
	__u64 size;
	int stack_id;
};

/* 为了节省内存和方便整形数据的原子操作,把 combined_alloc_info 定义为联合体
 * 其中 total_size 占 40bit, number_of_allocs 占 24bit, 联合体总大小为 64bit
 * 2个combined_alloc_info联合体的 bits 字段相加, 相当于对应的 total_size 相加, 
 * 和对应的 number_of_allocs 相加;
 */
union combined_alloc_info {
	struct {
		__u64 total_size : 40;
		__u64 number_of_allocs : 24;
	};
	__u64 bits;
};

#endif /* __MEMLEAK_H */
```

```c
#define KERN_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP)
#define USER_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK)

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, pid_t); // pid
	__type(value, u64); // size for alloc
	__uint(max_entries, 10240);
} sizes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64); /* alloc return address */
	__type(value, struct alloc_info);
	__uint(max_entries, ALLOCS_MAX_ENTRIES);
} allocs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64); /* stack id */
	__type(value, union combined_alloc_info);
	__uint(max_entries, COMBINED_ALLOCS_MAX_ENTRIES);
} combined_allocs SEC(".maps");

/* value： stack id 对应的堆栈的深度
 * max_entries: 最大允许存储多少个stack_id（每个stack id都对应一个完整的堆栈）
 * 这2个值可以根据应用层的使用场景,在应用层的ebpf中open之后load之前动态设置
 */
struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__type(key, u32); /* stack id */
	//__type(value, xxx);       memleak_bpf__open 之后再动态设置
	//__uint(max_entries, xxx); memleak_bpf__open 之后再动态设置
} stack_traces SEC(".maps");
```



```c
static const int perf_max_stack_depth = 127;
static const int stack_map_max_entries = 10240;
```

