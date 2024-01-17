安装 bpftrace

```bash
# Ubuntu 22.04
sudo apt-get install -y bpftrace
```

使用 bpftrace 加上 -l 的参数来查询内核插桩和跟踪点。

```bash
# 查询所有内核插桩和跟踪点
sudo bpftrace -l

# 使用通配符查询所有的系统调用跟踪点
sudo bpftrace -l 'tracepoint:syscalls:*'

# 使用通配符查询所有名字包含"execve"的跟踪点
sudo bpftrace -l '*execve*'
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

```

