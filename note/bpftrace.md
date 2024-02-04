安装 bpftrace

```bash
# Ubuntu 22.04
sudo apt-get install -y bpftrace
```

使用 bpftrace 加上 -l 的参数来查询内核插桩和跟踪点。

```bash
sudo bpftrace -h

# 查询所有内核插桩和跟踪点
sudo bpftrace -l

# 使用通配符查询所有的系统调用跟踪点
sudo bpftrace -l 'tracepoint:syscalls:*'

# 使用通配符查询所有名字包含"execve"的跟踪点
sudo bpftrace -l '*execve*'

# 查看用户程序的uprobe
sudo bpftrace -l "uprobe:/bin/bash:*"
```

另外对于跟踪点来说，可以加上 -v 参数查询函数的入参还有返回值。比如查询系统调用 execve 入口参数（对应系统调用 sys_enter_execve）和返回值（对应系统调用 sys_exit_execve）的示例。

```bash
# 查询execve入口参数格式
$ sudo bpftrace -lv tracepoint:syscalls:sys_enter_execve
tracepoint:syscalls:sys_enter_execve
    int __syscall_nr
    const char * filename
    const char *const * argv
    const char *const * envp

# 查询execve返回值格式
$ sudo bpftrace -lv tracepoint:syscalls:sys_exit_execve
tracepoint:syscalls:sys_exit_execve
    int __syscall_nr
    long ret

# 使用-v选项可以列出tracepoint类型跟踪点的参数:
sudo bpftrace -lv tracepoint:syscalls:sys_enter_shmctl

# 如果BTF可用(内核选项CONFIG_DEBUG_INFO_BTF=y，查看有无/sys/kernel/btf/vmlinux验证),也可以查看结构体struct/union/enum的定义，如：
sudo bpftrace -lv "struct path"

```

```bash
sudo bpftrace -e 'BEGIN { printf("hello world!\n"); } '
sudo bpftrace -l '*vfs_read*'
sudo bpftrace -l 'kretprobe:vfs_read*'
sudo bpftrace -e 'kprobe:vfs_read { printf("ID:%d\n", pid); } '

# 每两秒打印一次
sudo bpftrace -e 'kprobe:vfs_read {@ID = pid} interval:s:2 { printf("ID:%d\n", @ID); } '
# 程序退出时打印最后一次
sudo bpftrace -e 'kprobe:vfs_read {@ID = pid} '

sudo bpftrace -e 'kprobe:vfs_read,kprobe:vfs_readv {@ID = pid; } '


sudo bpftrace -e 'kprobe:vfs_read {@start[pid] = nsecs} kretprobe:vfs_read {@ns[comm] = nsecs - @start[pid]; delete(@start[pid]);}
# 对数据筛选，防止插入BPF程序后，存在已经开始执行的vfs_read，但未执行结束，对结果产生影响
sudo bpftrace -e 'kprobe:vfs_read {@start[pid] = nsecs} kretprobe:vfs_read /@start[pid]/ {@ns[comm] = nsecs - @start[pid]; delete(@start[pid]);}'
sudo bpftrace -e 'kprobe:vfs_read {@start[pid] = nsecs;} kretprobe:vfs_read /@start[pid]/ {@ns[comm] = hist(nsecs - @start[pid]); delete(@start[pid]);}'

# uprobe
sudo bpftrace -e 'uprobe:/home/cccmmf/bpf/note/testbpftrace:add { printf("ID:%d\n", pid); } '
sudo bpftrace -e 'uprobe:/home/cccmmf/bpf/note/testbpftrace:add { @argument1 = arg0; @argument2 = arg1; } '
sudo bpftrace -e 'uprobe:/home/cccmmf/bpf/note/testbpftrace:add { @argument1 = arg0; @argument2 = arg1; printf("arg1 = %d, arg2 = %d\n", @argument1, @argument2);} '

# 查看内核内存分配函数的挂载点
sudo bpftrace -l '*alloc_pages*'
# 目前kprobe已经没有alloc_pages_vma了,linux/mm_types.h头文件定义了struct vm_area_struct结构体，所以需要包含
sudo bpftrace --include linux/mm_types.h -e 'kprobe:alloc_pages_vma {@vma[comm] = ((struct vm_area_struct *)arg2)->vm_start;}'	# vm_start是分配的起始虚拟地址
# 用直方图显示
sudo bpftrace --include linux/mm_types.h -e 'kprobe:alloc_pages_vma {@vma[comm] = hist(((struct vm_area_struct *)arg2)->vm_start);}'
```

```bash
sudo bpftrace -e 'BEGIN { printf("hello, #TDengine!\n"); }'
sudo bpftrace -e 'k:__x64_sys_nanosleep /pid > 100/ { @[comm]++ }'
sudo bpftrace -e 'kprobe:do_nanosleep { printf("PID %d sleeping...\n", pid); }'
sudo bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @[comm] = count(); }'
sudo bpftrace -e 'tracepoint:syscalls:sys_enter_nanosleep { printf("%s is sleeping.\n", comm); }'
sudo bpftrace -l | more
sudo bpftrace -l | wc -l
sudo bpftrace -l '*sys_enter*' | more

# 可以使用-d选项调试bpftrace程序，此时程序不会运行，常被用来检测bpftrace自身的问题。也可以使用```-dd``获得更多调试信息：
sudo bpftrace -d -e 'tracepoint:syscalls:sys_enter_nanosleep { printf("%s enter sleeping\n", comm); }'

# 使用-v选项获得更多程序运行时的信息:
sudo bpftrace -v -e 'tracepoint:syscalls:sys_enter_nanosleep { printf("%s enter sleeping\n", comm); }'



```

使用 -I选项帮助bpftrace程序寻找头文件位置(与gcc相似)，使用–include选项包含头文件，可多次使用：

```bash
cat program.bt
#include <foo.h>

BEGIN { @ = FOO }

sudo bpftrace program.bt
definitions.h:1:10: fatal error: 'foo.h' file not found

# /tmp/include
foo.h

sudo bpftrace -I /tmp/include program.bt
Attaching 1 probe...
```

```bash
sudo bpftrace --include linux/path.h --include linux/dcache.h \
    -e 'kprobe:vfs_open { printf("open path: %s\n", str(((struct path *)arg0)->dentry->d_name.name)); }'
Attaching 1 probe...
open path: .com.google.Chrome.ASsbu2
open path: .com.google.Chrome.gimc10
open path: .com.google.Chrome.R1234s
```

环境变量：sudo bpftrace -h显示出来的信息中的ENVIRONMENT中的信息

```bash
sudo BPFTRACE_MAP_KEYS_MAX=1024 bpftrace -e 'tracepoint:syscalls:sys_enter_execve { printf("%s", comm); join(args->argv); }'
```

- BPFTRACE_STRLEN
  默认值64，使用str()获取BPF stack分配的字符串时返回的长度，当前可以设置的最大值为200，支持更大字符长度的问题仍在讨论中。
- BPFTRACE_NO_CPP_DEMANGLE
  默认为0，默认启用了用户空间堆栈跟踪中的C++符号还原功能，将此环境变量设置为1，可以关闭此功能。
- BPFTRACE_MAP_KEYS_MAX
  单个map中存储的最大key数量，默认4096。
- BPFTRACE_MAX_PROBES
  bpftrace程序支持attach的钩子数量，默认512。
- BPFTRACE_CACHE_USER_SYMBOLS
  默认情况下bpftrace缓存符号的解析结果，如果ASLR没有开启(Address Space Layout Randomization)，仅仅跟踪一个程序的时候，开启此选项可以获得性能上的提升。
- BPFTRACE_BTF
  BTF文件的路径，默认为None
- BPFTRACE_MAX_BPF_PROGS
  bpftrace可构造的最大BPF程序数量，默认值为512.

其它选项

- 使用-f选项指定输出信息格式，比如json

```bash
sudo bpftrace -f json -e 'tracepoint:syscalls:sys_enter_nanosleep { printf("%s enter sleeping\n", comm); }'
```

- 使用-o输出到文本

```bash
sudo bpftrace -f json -o ./sleep.json -e 'tracepoint:syscalls:sys_enter_nanosleep { printf("%s enter sleeping\n", comm); }'
```

