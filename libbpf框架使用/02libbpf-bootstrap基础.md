# libbpf-bootstrap 基础

[TOC]

### 源码下载

https://github.com/libbpf/libbpf-bootstrap

```shell
# 克隆源码，如果是手动下载，需要注意把子仓库也要下载下来
git clone --recurse-submodules https://github.com/libbpf/libbpf-bootstrap

# 如果是通 git clone 下载源码，可以查看修改记录
git log
```



### 源码目录

```shell
blazesym  bpftool  examples  libbpf  LICENSE  README.md  tools  vmlinux
# blazesym -- Rust语言中的符号库，如果用C语言开发，就不用关注；
# bpftool  -- 是 libbpf-bootstrap 框架的核心bpf工具，下面章节会介绍
# examples -- 示例代码，包括 c语言 和 Rust语言
# libbpf   -- 开发eBPF的基础代码库，下面章节会介绍
# tools    -- 生成 vmlinux.h 文件的工具
# vmlinux  -- 存放CO-RE(Compile Once – Run Everywhere)依赖的 vmlinux.h 头文件
```



### 问题：libbpf 和 libbpf-bootstrap 有什么关系？

**libbpf** 

是对bpf syscall(系统调用) 的基础封装，提供了 open, load, attach, maps操作, CO-RE, 等功能：

- open

  从elf文件中提取 eBPF的字节码程序，maps等；

  ```c
  LIBBPF_API struct bpf_object *bpf_object__open(const char *path);
  ```
  
  
  
- load

​	把 eBPF字节码程序，maps等加载到内核	

```c
LIBBPF_API int bpf_object__load(struct bpf_object *obj);
```



- attach 

  把eBPF程序attch到挂接点

```c
LIBBPF_API struct bpf_link *bpf_program__attach(......);
LIBBPF_API struct bpf_link *bpf_program__attach_perf_event(......);
LIBBPF_API struct bpf_link *bpf_program__attach_kprobe(......);
LIBBPF_API struct bpf_link *bpf_program__attach_uprobe(......);
LIBBPF_API struct bpf_link *bpf_program__attach_ksyscall(......);
LIBBPF_API struct bpf_link *bpf_program__attach_usdt(......);
LIBBPF_API struct bpf_link *bpf_program__attach_tracepoint(......);
......
```



- maps的操作

```c
LIBBPF_API int bpf_map__lookup_elem(......);
LIBBPF_API int bpf_map__update_elem(......);
LIBBPF_API int bpf_map__delete_elem(......);
......
```

  

- CO-RE(Compile Once – Run Everywhere)

​	CO-RE可以实现eBPF程序一次编译，在不同版本的内核中正常运行；下面的章节会详细展开讲；

```c
bpf_core_read(dst, sz, src)
bpf_core_read_user(dst, sz, src)
BPF_CORE_READ(src, a, ...)
BPF_CORE_READ_USER(src, a, ...)
```



- 其它辅助功能



**libbpf-bootstrap：**

基于 libbpf 开发出来的eBPF内核层代码，通过bpftool工具直接生成用户层代码操作接口，极大减少开发人员的工作量；

eBPF一般都是分2部分：内核层代码 + 用户层代码

内核层代码：跑在内核层，负责实现真正的eBPF功能

用户层代码：跑在用户层，负责 open, load, attach eBPF内核层代码到内核，并负责用户层和内核层的数据交互；

在 libbpf-bootstrap 框架中，开发一个eBPF功能，一般需要2个基础代码文件，比如需要开发个minimal的eBPF程序，需要 minimal.bpf.c 和 minimal.c，如果前面的2个文件还需要公共的头文件，可以定义头文件：minimal.h

minimal.bpf.c 是内核层代码，被 clang 编译器编译成 minimal.tmp.bpf.o

bpftool 工具通过 minimal.tmp.bpf.o 自动生成 minimal.skel.h 头文件：

```shell
clang -g -O2 -target bpf -c minimal.bpf.c -o minimal.tmp.bpf.o
bpftool gen object minimal.bpf.o minimal.tmp.bpf.o
bpftool gen skeleton minimal.bpf.o > minimal.skel.h
```

minimal.skel.h 头文件中就包含了 minimal.bpf.c 对应的elf文件数据，以及用户层需要的 open, load, attach 等接口；

```c
// hello.bpf.c 对应的 elf 文件数据:
static inline const void *minimal_bpf__elf_bytes(size_t *sz);

// open load attach 操作接口:
static inline struct minimal_bpf *minimal_bpf__open(void);
static inline int minimal_bpf__load(struct minimal_bpf *obj);
static inline struct minimal_bpf *minimal_bpf__open_and_load(void);
static inline int minimal_bpf__attach(struct minimal_bpf *obj);

// 注意： 以上的接口都是 libbpf-bootstrap 根据开发人员编写的 minimal.bpf.c 文件，直接自动生成的接口;
// minimal.bpf.c --> bpftool --> 自动生成简洁的 minimal.skel.h
// minimal.skel.h 头文件中的接口可以非常简单的操作eBPF程序；
```



### eBPF程序的生命周期

4个阶段: `open`, ` load`, ` attach`, ` destroy`

- open 阶段

  从 clang 编译器编译得到的eBPF程序elf文件中抽取 maps, eBPF程序, 全局变量等；但是还未在内核中创建，所以还可以对 maps, 全局变量 进行必要的修改；如：

```c
//	libbpf-bootstrap/examples/c/minimal.c

/* Open BPF application */
skel = minimal_bpf__open();

/* eBPF内核层代码中定义的全局变量初始化 */
skel->bss->my_pid = getpid();

/* 还可以通过 bpf_map__set_value_size 和 bpf_map__set_max_entries 2个接口对eBPF内核层代码中
 * 定义的 maps 进行修改;
 */
```

- load 阶段

  maps，全局变量 在内核中被创建，eBPF字节码程序加载到内核中，并进行校验；但这个阶段，eBPF程序虽然存在内核中，但还不会被运行，还可以对内核中的maps进行初始状态的赋值；

- attach 阶段

  eBPF程序被attach到挂接点，eBPF相关功能开始运行，比如：eBPF程序被触发运行，更新maps, 全局变量等；

- destroy 阶段

  eBPF程序被 detached，eBPF用到的资源将会被释放；

在 libbpf-bootstrap中，4个阶段对应的用户层接口：

```c
// open 阶段，xxx：根据eBPF程序文件名而定
xxx_bpf__open(...);

// load 阶段，xxx：根据eBPF程序文件名而定
xxx_bpf__load(...);

// attach 阶段，xxx：根据eBPF程序文件名而定
xxx_bpf__attach(...);

// destroy 阶段，xxx：根据eBPF程序文件名而定
xxx_bpf__destroy(...);

//以上接口都是libbpf-bootstrap根据开发人员的eBPF文件自动生成，
//如果eBPF程序文件名为 hello.bpf.c,
//自动生成的用户层接口：
hello_bpf__open(...);
hello_bpf__load(...);
hello_bpf__attach(...);
hello_bpf__destroy(...);

//如果eBPF程序文件名为 minimal.bpf.c
//自动生成的用户层接口：
minimal_bpf__open(...);
minimal_bpf__load(...);
minimal_bpf__attach(...);
minimal_bpf__destroy(...);
```



eBPF程序生命周期更详细的介绍：

https://nakryiko.com/posts/bcc-to-libbpf-howto-guide/#bpf-skeleton-and-bpf-app-lifecycle



### CO-RE(Compile Once – Run Everywhere)

一次编译，可以运行在不同版本的内核中

为什么需要这样的功能？

假设内核有个结构体 `struct foo`，但是在不同版本的内核，定义有变化：

```c
//4.x的内核版本
struct foo {
    int a;
    int b;
    int c;
}

//5.x的内核版本
struct foo {
    int a;
    int b;
    int x;  //新版本内核中新增了一个字段
    int c;
}

// eBPF程序访问struct foo结构体中的字段c:
SEC("kprobe/xxx")
int BPF_KPROBE(xxx, struct foo * p_foo)
{
    int read_c;

    /* bpf_probe_read_kernel 的函数声明：
     * long bpf_probe_read_kernel(void *dst, __u32 size, const void *unsafe_ptr);
     */

    //如果是4.x内核
    bpf_probe_read_kernel(&read_c, sizeof(int), p_foo + 2 * sizeof(int));

    //如果是5.x内核
    bpf_probe_read_kernel(&read_c, sizeof(int), p_foo + 3 * sizeof(int));
}

// 因为不同内核版本中, struct foo 中的c字段偏移变了，所以不同版本的内核必须要编写2个不同的eBPF程序
// 这会对eBPF工具的发布造成非常大的问题
```

为了解决这个问题，需要3个方面的配合：

1. BTF (BPF Type Format)

   运行中的内核提供当前内核中各种数据类型的BTF描述，用户空间可以通过 `/sys/kernel/btf/vmlinux` 访问当前内核的BTF信息；

   通过bpftool工具，把BTF格式的 vmlinux 转化成C语言格式的头文件 vmlinux.h，vmlinux.h 包好了当前内核中的所有数据类型的定义；

   ```shell
   bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
   ```

   BTF 详细介绍：https://www.kernel.org/doc/html/latest/bpf/btf.html#

   

2. clang 编译器需要支持记录结构体字段重定位的信息

   ```c
   #define bpf_core_read(dst, sz, src)					    \
   	bpf_probe_read_kernel(dst, sz, (const void *)__builtin_preserve_access_index(src))
   
   // __builtin_preserve_access_index 就是让 clang 编译器编译时增加结构体字段重定位的信息
   // 比如：
   bpf_core_read(&read_c, sizeof(int), p_foo->c)
   //宏展开：
   bpf_probe_read_kernel(&read_c, sizeof(int), __builtin_preserve_access_index(p_foo->c))
   //clang编译器编译这段代码时，就会增加描述信息：访问 c 字段时需要根据当前内核的BTF信息重新计算偏移量
   ```
   
   
   
3. eBPF loader

   libbpf 加载eBPF程序到内核时，会先找到 clang 编译器记录的重定位信息，根据当前运行中的内核提供的BTF信息，重新计算需要访问的字段的偏移量；

   ```tex
   比如上面的 struct foo 结构体，如果内核开启了 CONFIG_DEBUG_INFO_BTF 的内核配置选项，在编译内核时，
   struct foo 结构体就会被编译进内核的BTF信息中，内核运行时，可以通过访问 /sys/kernel/btf/vmlinux
   文件就可以知道 struct foo 结构体具体的定义，也就可以动态计算得到 c 字段的偏移量;
   
   如果在编写eBPF程序时，通过clang编译器的 __builtin_preserve_access_index 明确告诉libbpf加载
   eBPF程序时，需要动态计算 c 字段的偏移量，从而避免在eBPF程序中手动写死 c 字段的偏移量；
   
   eBPF程序就可以只编译一次，在不同版本的内核中正常运行！
   ```

如何在 libbpf-bootstrap 中使用或者不使用 CO-RE

```c
//在内核层的eBPF程序中，包含 vmlinux.h 头文件就说明需要使用 CO-RE 功能, 否则就是不使用
#include "vmlinux.h"

//使用CO-RE需要内核打开 CONFIG_DEBUG_INFO_BTF 配置选项，如果内核版本过低，不支持这个配置选项，
//就不要使用 CO-RE，即不要包含 vmlinux.h 头文件

// vmlinux.h 头文件，在 libbpf-bootstrap/vmlinux/ 目录下有预先提供特定版本内核相关的 vmlinux.h
// 使用过程中，运行中的内核版本没必要和libbpf-bootstrap/vmlinux/ 目录下预先提供的 vmlinux.h
// 对应的内核版本完全匹配上，不匹配上也可以用

// 手动生成自己的 vmlinux.h, 可以参考：libbpf-bootstrap/tools/gen_vmlinux_h.sh
```

CO-RE 更详细的介绍：https://nakryiko.com/posts/bpf-portability-and-co-re/



### x86-64 平台上的编译

- clang 编译器

  版本要求： at least v11 or later

  不同版本 clang 编译下载： https://releases.llvm.org/download.html

  在 ubuntu18.04 上，我下载了 16.0.0 版本的 clang 编译器

  ```shell
  ~/Desktop/clang-16/clang --version
  ```

- 修改 libbpf-bootstrap/examples/c/ 目录下的Makefile

  ```shell
  CLANG ?= /home/zhanglong/Desktop/clang-16/clang
  
  # 可以被编译的 sample 程序
  APPS = minimal minimal_legacy bootstrap uprobe kprobe fentry usdt sockfilter tc ksyscall
  ```

- 编译 libbpf-bootstrap/examples/c/ 目录下的 uprobe 示例代码

  ```shell
  cd libbpf-bootstrap/examples/c/
  make clean
  make uprobe
  ```

  

