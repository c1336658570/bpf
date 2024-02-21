# eBPF内存泄露检测代码实现<二>

[toc]

## 目标

把上节视频中获取到的堆栈中的指令地址解析成 `符号名`，`文件名`，`行号`

```
stack_id=0x3f3 with outstanding allocations: total_size=12  nr_alloc=3
  0 [<0000555b65a096f2>] alloc_v3+0x18 test_memleak.c:8
  1 [<0000555b65a09711>] alloc_v2+0x15 test_memleak.c:15
  2 [<0000555b65a09730>] alloc_v1+0x15 test_memleak.c:22
  3 [<0000555b65a09770>] main+0x36 test_memleak.c:35
  4 [<00007fe8c8a7bc87>] __libc_start_main+0xe7
  5 [<05f6258d4c544155>]
```

使用 `blazesym` 开源代码来完成解析工作： https://hub.njuu.cf/libbpf/blazesym

`libbpf-bootstrap` 开源项目中已经包含了 `blazesym` 子项目；

使用方法请参考: `libbpf-bootstrap/examples/c/profile.c`



**说明：**

**eBPF内存泄露检测代码实现是在 libbpf-bootstrap 框架下开发，需要的基础知识请参考之前的ebpf系列视频**

**本节视频使用的是 `Ubuntu18.04 x86-64` 平台**



## 手动解析

在使用 blazesym 开源代码之前，用手动解析来展示下 `符号名`，`文件名`，`行号` 解析的大概的处理流程；

需要使用的工具：`readelf` 和 `dwarfdump`

`readelf` 工具一般Ubuntu等操作系统都会自带，这里就不用开源代码来编译了；



```bash
./memleak_test &
[1] 22487

sudo ./memleakv1 22487

touch /tmp/memleakv1_quit

stack_id=0x2b2d with outstanding allocations: total_size=8 nr_allocs=2
[  0] 0x56076afcb6f2
[  1] 0x56076afcb711
[  2] 0x56076afcb730
[  3] 0x56076afcb770
[  4] 0x7f5b32afac87
[  5] 0x5f6258d4c544155

touch /tmp/memleakv1_quit
```





### dwarfdump 是什么？

dwarf 相关的 `libdwarf` 和 `dwarfdump` 

请参考：https://wiki.dwarfstd.org/Libdwarf_And_Dwarfdump.md

**dwarf** : 是一种调试信息格式，一般现代的 GCC 和 LLVM 编译器都可以自动生成 `dwarf` 格式的调试信息，调试信息中就包含了 `符号名`，`文件名`，`行号`

**libdwarf**：是C语言库，用于读写 DWARF2, DWARF3, DWARF4 and DWARF5 格式的调试信息；

**dwarfdump**：是使用`libdwarf`库开发的开源工具，以人类可读格式打印 `dwarf` 的调试信息；

使用方法：

```shell
dwarfdump -a test_memleak
```



### 编译 dwarfdump

源码下载：https://www.prevanders.net/dwarf.html

```shell
# 下载当前最新的版本, 比如当前最新版本：libdwarf-0.9.0.tar.xz
tar -axf libdwarf-0.9.0.tar.xz
cd libdwarf-0.9.0
./configure --prefix=$PWD/__install
make
make install
# 编译得到的 dwarfdump 和 libdwarf.a 在 libdwarf-0.9.0/__install/ 目录下
```



### 进程指令地址转换成elf文件指令地址

`ebpf`获取到的是运行中的进程指令地址，而符号名，文件名，行号 都是存储在`elf`文件中，所以解析时需要把进程指令地址转换成`elf`文件中的指令地址；

假设测试程序 `test_memleak`的进程号：22487

ebpf内存泄露检测工具打印出来的堆栈：

```
stack_id=0x2b2d with outstanding allocations: total_size=8 nr_allocs=2
[  0] 0x56076afcb6f2
[  1] 0x56076afcb711
[  2] 0x56076afcb730
[  3] 0x56076afcb770
[  4] 0x7f5b32afac87
[  5] 0x5f6258d4c544155
```

`0x56076afcb6f2` 怎么转换成 `test_memleak` elf文件中的指令地址？

通过 `cat /proc/进程号/maps` 获取进程号中具有可执行权限的指令地址的 起始地址 和 偏移地址：

`cat /proc/22487/maps` 如下所示：

```
起始地址     -结束地址       属性 偏移地址  主从设备号 inode编号                文件名
56076afcb000-56076afcc000 r-xp 00000000 08:01 32658117                   test_memleak
56076b1cb000-56076b1cc000 r--p 00000000 08:01 32658117                   test_memleak
56076b1cc000-56076b1cd000 rw-p 00001000 08:01 32658117                   test_memleak
56076bd3d000-56076bd5e000 rw-p 00000000 00:00 0                          [heap]
7f5b32ad9000-7f5b32cc0000 r-xp 00000000 103:02 11558371                  /lib/x86_64-linux-gnu/libc-2.27.so
7f5b32cc0000-7f5b32ec0000 ---p 001e7000 103:02 11558371                  /lib/x86_64-linux-gnu/libc-2.27.so
7f5b32ec0000-7f5b32ec4000 r--p 001e7000 103:02 11558371                  /lib/x86_64-linux-gnu/libc-2.27.so
7f5b32ec4000-7f5b32ec6000 rw-p 001eb000 103:02 11558371                  /lib/x86_64-linux-gnu/libc-2.27.so
7f5b32ec6000-7f5b32eca000 rw-p 00000000 00:00 0 
7f5b32eca000-7f5b32ef3000 r-xp 00000000 103:02 11543405                  /lib/x86_64-linux-gnu/ld-2.27.so
7f5b330c9000-7f5b330cb000 rw-p 00000000 00:00 0 
7f5b330f3000-7f5b330f4000 r--p 00029000 103:02 11543405                  /lib/x86_64-linux-gnu/ld-2.27.so
7f5b330f4000-7f5b330f5000 rw-p 0002a000 103:02 11543405                  /lib/x86_64-linux-gnu/ld-2.27.so
7f5b330f5000-7f5b330f6000 rw-p 00000000 00:00 0 
7ffd56894000-7ffd568b5000 rw-p 00000000 00:00 0                          [stack]
7ffd569e0000-7ffd569e3000 r--p 00000000 00:00 0                          [vvar]
7ffd569e3000-7ffd569e5000 r-xp 00000000 00:00 0                          [vdso]
7fffffffe000-7ffffffff000 --xp 00000000 00:00 0                          [uprobes]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
```

test_memleak 具有可执行权限的 起始地址=`0x56076afcb000`  偏移地址=`0x00000000`

参考 `blazesym/src/normalize/user.rs` 文件中的 normalize_elf_addr 接口中的计算公式：

```rust
let file_off = virt_addr as u64 - entry.range.start as u64 + entry.offset;
```

elf文件中的指令地址 = 进程中的指令地址 - 起始地址 + 偏移地址

`0x56076afcb6f2` 对应的elf文件指令地址 = `0x56076afcb6f2 - 0x56076afcb000 + 0x00000000` = `0x6f2`



### readelf 解析符号名

`readelf -s test_memleak | grep FUNC` 获取测试程序 `test_memleak` 的符号表中类型为 `FUNC` 的 `entries`

如下所示:

```
     1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND free@GLIBC_2.2.5 (2)
     3: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __libc_start_main@GLIBC_2.2.5 (2)
     5: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND malloc@GLIBC_2.2.5 (2)
     7: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND sleep@GLIBC_2.2.5 (2)
     8: 0000000000000000     0 FUNC    WEAK   DEFAULT  UND __cxa_finalize@GLIBC_2.2.5 (2)
    32: 0000000000000600     0 FUNC    LOCAL  DEFAULT   14 deregister_tm_clones
    33: 0000000000000640     0 FUNC    LOCAL  DEFAULT   14 register_tm_clones
    34: 0000000000000690     0 FUNC    LOCAL  DEFAULT   14 __do_global_dtors_aux
    37: 00000000000006d0     0 FUNC    LOCAL  DEFAULT   14 frame_dummy
    40: 00000000000006da    34 FUNC    LOCAL  DEFAULT   14 alloc_v3
    41: 00000000000006fc    31 FUNC    LOCAL  DEFAULT   14 alloc_v2
    42: 000000000000071b    31 FUNC    LOCAL  DEFAULT   14 alloc_v1
    51: 0000000000000810     2 FUNC    GLOBAL DEFAULT   14 __libc_csu_fini
    52: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND free@@GLIBC_2.2.5
    56: 0000000000000814     0 FUNC    GLOBAL DEFAULT   15 _fini
    57: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __libc_start_main@@GLIBC_
    62: 00000000000007a0   101 FUNC    GLOBAL DEFAULT   14 __libc_csu_init
    63: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND malloc@@GLIBC_2.2.5
    65: 00000000000005d0    43 FUNC    GLOBAL DEFAULT   14 _start
    67: 000000000000073a    96 FUNC    GLOBAL DEFAULT   14 main
    70: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND sleep@@GLIBC_2.2.5
    71: 0000000000000000     0 FUNC    WEAK   DEFAULT  UND __cxa_finalize@@GLIBC_2.2
    72: 0000000000000560     0 FUNC    GLOBAL DEFAULT   11 _init
```

`0x56076afcb6f2` 对应的elf文件指令地址 = `0x6f2`

`00000000000006da` (alloc_v3) < `6f2` < `00000000000006fc` (alloc_v2)

所以 `0x56076afcb6f2` 是执行到了 `alloc_v3` 这个符号名(函数)的内部了；



### dwarfdump 解析文件名和行号

`dwarfdump -i test_memleak | grep DW_TAG_subprogram -A11` 获取测试程序 `test_memleak` 中函数相关的调试信息，如下所示：

```
< 1><0x00000350>    DW_TAG_subprogram
                      DW_AT_external              yes(1)
                      DW_AT_name                  main
                      DW_AT_decl_file             0x00000001 /home/zhanglong/Desktop/ebpf/note/src/x86-64/libbpf-bootstrap/examples/c/test/test_memleak.c
                      DW_AT_decl_line             0x0000001b
                      DW_AT_prototyped            yes(1)
                      DW_AT_type                  <0x00000062>
                      DW_AT_low_pc                0x0000073a
                      DW_AT_high_pc               <offset-from-lowpc> 96 <highpc: 0x0000079a>
                      DW_AT_frame_base            len 0x0001: 0x9c: 
                          DW_OP_call_frame_cfa
                      DW_AT_GNU_all_tail_call_sites yes(1)
--
< 1><0x000003b6>    DW_TAG_subprogram
                      DW_AT_name                  alloc_v1
                      DW_AT_decl_file             0x00000001 /home/zhanglong/Desktop/ebpf/note/src/x86-64/libbpf-bootstrap/examples/c/test/test_memleak.c
                      DW_AT_decl_line             0x00000014
                      DW_AT_prototyped            yes(1)
                      DW_AT_type                  <0x0000008b>
                      DW_AT_low_pc                0x0000071b
                      DW_AT_high_pc               <offset-from-lowpc> 31 <highpc: 0x0000073a>
                      DW_AT_frame_base            len 0x0001: 0x9c: 
                          DW_OP_call_frame_cfa
                      DW_AT_GNU_all_tail_call_sites yes(1)
                      DW_AT_sibling               <0x000003f4>
--
< 1><0x000003f4>    DW_TAG_subprogram
                      DW_AT_name                  alloc_v2
                      DW_AT_decl_file             0x00000001 /home/zhanglong/Desktop/ebpf/note/src/x86-64/libbpf-bootstrap/examples/c/test/test_memleak.c
                      DW_AT_decl_line             0x0000000d
                      DW_AT_prototyped            yes(1)
                      DW_AT_type                  <0x0000008b>
                      DW_AT_low_pc                0x000006fc
                      DW_AT_high_pc               <offset-from-lowpc> 31 <highpc: 0x0000071b>
                      DW_AT_frame_base            len 0x0001: 0x9c: 
                          DW_OP_call_frame_cfa
                      DW_AT_GNU_all_tail_call_sites yes(1)
                      DW_AT_sibling               <0x00000432>
--
< 1><0x00000432>    DW_TAG_subprogram
                      DW_AT_name                  alloc_v3
                      DW_AT_decl_file             0x00000001 /home/zhanglong/Desktop/ebpf/note/src/x86-64/libbpf-bootstrap/examples/c/test/test_memleak.c
                      DW_AT_decl_line             0x00000006
                      DW_AT_prototyped            yes(1)
                      DW_AT_type                  <0x0000008b>
                      DW_AT_low_pc                0x000006da
                      DW_AT_high_pc               <offset-from-lowpc> 34 <highpc: 0x000006fc>
                      DW_AT_frame_base            len 0x0001: 0x9c: 
                          DW_OP_call_frame_cfa
                      DW_AT_GNU_all_tail_call_sites yes(1)
< 2><0x0000044f>      DW_TAG_formal_parameter

```

`DW_AT_low_pc` 和 `DW_AT_high_pc` 描述了 `DW_AT_name` 函数的指令地址范围：

`DW_AT_name`=`alloc_v3` 的指令地址范围： `0x000006da` 到 `0x000006fc`

`0x56076afcb6f2` 对应的elf文件指令地址 = `0x6f2` 

`0x000006da` < `0x6f2` < `0x000006fc`

所以 `0x56076afcb6f2` 执行到了 `alloc_v3` 函数内部，查找 `alloc_v3` 对应的 `DW_AT_decl_file` 值，即可得知是

`test_memleak.c`



`dwarfdump -l test_memleak` 获取测试程序 `test_memleak` 中行号相关的调试信息，如下所示：

```
.debug_line: line number info for a single cu
Source lines (from CU-DIE at .debug_info offset 0x0000000b):

            NS new statement, BB new basic block, ET end of text sequence
            PE prologue end, EB epilogue begin
            IS=val ISA number, DI=val discriminator value
<pc>        [lno,col] NS BB ET PE EB IS= DI= uri: "filepath"
0x000006da  [   7, 0] NS uri: "/home/zhanglong/Desktop/ebpf/note/src/x86-64/libbpf-bootstrap/examples/c/test/test_memleak.c"
0x000006e5  [   8, 0] NS
0x000006f6  [  10, 0] NS
0x000006fa  [  11, 0] NS
0x000006fc  [  14, 0] NS
0x00000707  [  15, 0] NS
0x00000715  [  17, 0] NS
0x00000719  [  18, 0] NS
0x0000071b  [  21, 0] NS
0x00000726  [  22, 0] NS
0x00000734  [  24, 0] NS
0x00000738  [  25, 0] NS
0x0000073a  [  28, 0] NS
0x00000749  [  29, 0] NS
0x00000750  [  30, 0] NS
0x00000758  [  31, 0] NS
0x0000075f  [  33, 0] NS
0x00000766  [  35, 0] NS
0x00000774  [  37, 0] NS
0x0000077e  [  39, 0] NS
0x00000788  [  41, 0] NS
0x00000794  [  33, 0] NS
0x00000798  [  35, 0] NS
0x0000079a  [  35, 0] NS ET
```

`0x000006e5  [   8, 0] NS` 表示指令地址 `0x000006e5` 行号是 第8行

`0x56076afcb6f2` 对应的elf文件指令地址 = `0x6f2` ，通过二分查找法可知，

`0x000006e5` < `0x6f2` < `0x000006f6`

`0x000006e5` 指令地址属于 第 8 行，

所以 `0x56076afcb6f2`  指令地址执行到了 第 8 行；



## blazesym 自动解析

### rust 语言编译环境安装

`blazesym` 使用 `rust` 语言编写，使用前需要安装 `rust` 语言的编译环境

```shell
# 安装前先配置国内镜像源（以下只是示例），可以加速下载
# 设置环境变量 RUSTUP_DIST_SERVER （用于更新 toolchain）：
export RUSTUP_DIST_SERVER=https://mirrors.ustc.edu.cn/rust-static
# RUSTUP_UPDATE_ROOT （用于更新 rustup）：
export RUSTUP_UPDATE_ROOT=https://mirrors.ustc.edu.cn/rust-static/rustup

# 安装 https://www.rust-lang.org/tools/install
# 请 不要 使用Ubuntu的安装命令: sudo apt install cargo，否则可能会出现莫名其妙的问题
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 修改 ~/.cargo/config 文件，配置 rust 使用的国内镜像源，这部分请自行上网查找
```



### `blazesym` 编译

```shell
cd libbpf-bootstrap/blazesym
cargo build --release
```



### `blazesym` 命令行解析

如下两种解析方式结果一样



假设 `rust` 使用的 `cargo` 可执行文件的绝对路径: `/home/zhanglong/.cargo/bin/cargo`



解析进程指令地址，假设：

进程号：22487

进程指令地址：`0x56076afcb6f2`

```shell
cd libbpf-bootstrap/blazesym
sudo /home/zhanglong/.cargo/bin/cargo run -p blazecli -- symbolize process \
	--pid 28473 0x56076afcb6f2
```



解析elf文件指令地址，假设：

elf文件绝对路径:

 `/home/zhanglong/Desktop/ebpf/note/src/x86-64/libbpf-bootstrap/examples/c/test/test_memleak`

elf文件指令地址: `0x6f2`

```shell
cd libbpf-bootstrap/blazesym
sudo /home/zhanglong/.cargo/bin/cargo run -p blazecli -- symbolize elf \
	--path /home/zhanglong/Desktop/ebpf/note/src/x86-64/libbpf-bootstrap/examples/c/test/test_memleak \
	0x6f2
```



## memleak中使用blazesym

使用方法参考: `libbpf-bootstrap/examples/c/profile.c`

```c
// memleak.c 文件中包含头文件
#include <assert.h>
#include "blazesym.h"

// 拷贝 libbpf-bootstrap/examples/c/profile.c 文件中的 
// symbolizer 对象 和 show_stack_trace 接口
// 到 memleak.c
static struct blaze_symbolizer *symbolizer;
static void show_stack_trace(__u64 *stack, int stack_sz, pid_t pid);

// 在 memleak.c 中的 main 函数中初始化和销毁 symbolizer 对象
symbolizer = blaze_symbolizer_new();
if (!symbolizer) {
    fprintf(stderr, "Fail to create a symbolizer\n");
    err = -1;
    goto cleanup;
}

blaze_symbolizer_free(symbolizer);

// 修改 libbpf-bootstrap/examples/c/Makefile 文件
// APPS 变量中去掉 memleak, BZS_APPS 变量中加上 memleak
// 编译 memleak 时，就会自动去编译 blazesym 的 C lib库

// 编译 memleak
cd libbpf-bootstrap/examples/c
make clean
make memleak
```

```bash
./memleak_test &

sudo ./memleakv2 pid

touch /tmp/memleakv2_print
touch /tmp/memleakv2_quit
```



### blazesym 说明

1. `blazesym ` 开源代码目前仅支持 `ELF64` 文件的解析，比如 `x86-64` 和 `arm64` 平台的 `elf` 都可以正常解析，但是还不支持 `ELF32` 文件的解析，比如 `arm32` 平台的 `elf` 就解析不了
2. `blazesym` 为了解析的效率，会缓存整个`elf`文件和符号表，会导致使用 `blazesym` 的 `ebpf` 程序运行后消耗很多内存，如果是在内存紧张的产品上调试内存泄漏，`ebpf`程序可以不解析`符号名`，`文件名`，`行号`，只打印堆栈中的指令地址和 `/proc/进程ID/maps`，然后再在内存充足的PC机上使用上面的手动解析方法对`elf`文件进行指令地址的解析(使用 shell 或者 python 批量处理？)；
3. 如果`elf`可执行文件编译时没有 `-g` 选项，但是没有 `strip`，`blazesym` 就只能解析到 `符号名`，解析不了 `文件名` 和 `行号`； 如果被 `strip` 处理了，那 `符号名`，`文件名`，`行号` 都解析不了；

