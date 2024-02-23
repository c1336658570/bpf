#include <linux/bpf.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stdint.h>

// 一些函数的实现原理

#define ptr_to_u64(x) ((uint64_t)x)

// bpf函数的的实现
// cmd参数
/*
enum bpf_cmd {
	BPF_MAP_CREATE,             // 创建一个映射, 返回一个引用此此映射的文件描述符。close-on-exec标志会自动设置
	BPF_MAP_LOOKUP_ELEM,        // 在指定的映射中根据key查找一个元素, 并返回他的值
	BPF_MAP_UPDATE_ELEM,        // 指定映射中创建或者更新一个元素
	BPF_MAP_DELETE_ELEM,        // 在指定映射中根据key查找并删除一个元素
	BPF_MAP_GET_NEXT_KEY,       // 在指定映射中根据key查找一个元素, 并返回下一个元素的key
	BPF_PROG_LOAD,              // 验证并加载一个eBPF程序, 返回一个与此程序关联的新文件描述符。 close-on-exec标志也会自动加上
	BPF_OBJ_PIN,
	...
	BPF_PROG_BIND_MAP,
};
*/

// attr参数
/*
union bpf_attr {
  struct {            // 被BPF_MAP_CREATE使用
    __u32 map_type;   // 映射的类型
    __u32 key_size;   // key有多少字节 size of key in bytes
    __u32 value_size; // value有多少字节 size of value in bytes
    __u32 max_entries; // 一个map中最多多少条映射maximum number of entries in a map
    ...
  };

  struct { // 被BPF_MAP_*_ELEM和BPF_MAP_GET_NEXT_KEY使用
    __u32 map_fd;
    __aligned_u64 key;
    union {
      __aligned_u64 value;
      __aligned_u64 next_key;
    };
    __u64 flags;
  };

  struct { // 被BPF_PROG_LOAD使用
    __u32 prog_type;
    __u32 insn_cnt;
    __aligned_u64 insns;   // 'const struct bpf_insn *'
    __aligned_u64 license; // 'const char *'
    __u32 log_level;       // 验证器的详细级别
    __u32 log_size;        // 用户缓冲区的大小 size of user buffer
    __aligned_u64
        log_buf; // 用户提供的char*缓冲区 user supplied 'char *' buffer
    __u32 kern_version;
    // checked when prog_type=kprobe  (since Linux 4.1)
  };

  ...
} __attribute__((aligned(8)));
*/
int bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size) {
  return syscall(__NR_bpf, cmd, attr, size);
}

/**
 * bpf_create_map - 创建具有指定参数的BPF映射。
 * @map_type: 要创建的BPF映射的类型（例如，BPF_MAP_TYPE_HASH，BPF_MAP_TYPE_ARRAY等）。
 * @key_size: BPF映射中键的字节大小。
 * @value_size: BPF映射中值的字节大小。
 * @max_entries: BPF映射可以容纳的最大条目数。
 * @map_flags: 用于BPF映射的附加选项的标志（例如，BPF_F_NO_PREALLOC等）。
 *
 * 此函数用于创建具有指定特性的BPF映射。
 *
 * @return: 成功时返回创建的BPF映射的文件描述符。失败时返回-1。
 * 
 * key_size, value_size属性会在加载时被验证器使用, 来检查程序是否用正确初始化的key来调用bfp_map_*_elem(),
 * 检查映射元素value是否超过指定的value_size。
 * 
 * 例如一个映射创建时key_size为8, eBPF程序调用bpf_map_lookup_elem(map_fd, fp - 4), 程序会被拒绝, 
 * 因为kernel内的助手函数bpf_map_lookup_elem(map_fd, void *key)期望从key指向的位置读入8字节,
 * 但是fp-4(fp是栈顶)起始地址会导致访问栈时越界
 * 
 * 类似的, 如果一个映射用value_size=1创建, eBPF程序包含
 * value = bpf_map_lookup_elem(...);
 * *(u32 *) value = 1;
 * 这个程序会被拒绝执行, 因为他访问的value指针超过了value_size指定的1字节限制
 */

/*
enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC,
	BPF_MAP_TYPE_HASH,
	BPF_MAP_TYPE_ARRAY,
  ...
	BPF_MAP_TYPE_TASK_STORAGE,
};
*/
int bpf_create_map(enum bpf_map_type map_type, unsigned int key_size,
                   unsigned int value_size, unsigned int max_entries, unsigned int map_flags) {
  // 创建BPF映射的属性结构体
  union bpf_attr attr = {
  .map_type = map_type,
  .key_size = key_size,
  .value_size = value_size,
  .max_entries = max_entries,
  .map_flags = map_flags
  };

  // 调用bpf系统调用，执行BPF_MAP_CREATE操作
  return bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
}

// BPF_MAP_LOOKUP_ELEM命令用于在fd指向的映射中根据key查找对应元素
// 如果找到一个元素那么会返回0并把元素的值保存在value中, value必须是指向value_size字节的缓冲区
// 如果没找到, 会返回-1, 并把errno设置为ENOENT
int bpf_lookup_elem(int fd, const void *key, void *value) {
  union bpf_attr attr = {
      .map_fd = fd,
      .key = ptr_to_u64(key),
      .value = ptr_to_u64(value),
  };

  return bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

/*
 * BPF_MAP_UPDATE_ELEM命令在fd引用的映射中用给定的key/value去创建或者更新一个元素
 * flags参数应该被指定为下面中的一个
 * 1.BPF_ANY创建一个新元素或者更新一个已有的
 * 2.BPF_NOEXIST只在元素不存在的情况下创建一个新的元素
 * 3.BPF_EXIST更新一个已经存在的元素
 * 如果成功的话返回0, 出错返回-1, 并且errno会被设置为EINVAL, EPERM, ENOMEM, E2BIG
 * E2BIG表示映射中的元素数量已经到达了创建时max_entries指定的上限
 * EEXIST表示flag设置了BPF_NOEXIST但是key已有对应元素
 * ENOENT表示flag设置了BPF_EXIST但是key没有对应元素
 */
int bpf_update_elem(int fd, const void *key, const void *value, uint64_t flags) {
  union bpf_attr attr = {
      .map_fd = fd,
      .key = ptr_to_u64(key),
      .value = ptr_to_u64(value),
      .flags = flags,
  };

  return bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

// BPF_MAP_DELETE_ELEM命令用于在fd指向的映射汇总删除键为key的元素
// 成功的话返回0, 如果对应元素不存在那么会返回-1, 并且errno会被设置为ENOENT
int bpf_delete_elem(int fd, const void *key) {
  union bpf_attr attr = {
      .map_fd = fd,
      .key = ptr_to_u64(key),
  };

  return bpf(BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
}

// BPF_MAP_GET_NEXT_KEY命令用于在fd引用的映射中根据key查找对应元素, 并设置next_key指向下一个元素的键
// 如果key被找到了, 那么会返回0并设置指针netx_pointer指向下一个元素的键.
// 如果key没找到, 会返回0并设置next_pointer指向映射中第一个元素的键. 
// 如果key就是最后一个元素了, 那么会返回-1, 并设置errno为ENOENT.
// errno其他可能的值为ENOMEM, EFAULT, EPERM, EINVAL. 这个方法可用于迭代map中所有的元素
bpf_get_next_key(int fd, const void *key, void *next_key) {
  union bpf_attr attr = {
      .map_fd = fd,
      .key = ptr_to_u64(key),
      .next_key = ptr_to_u64(next_key),
  };

  return bpf(BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr));
}

// 通过系统调用, 向内核加载一段BPF指令
// BPF_PROG_LOAD命令用于在内核中装载eBPF程序, 返回一个与eBPF程序关联的文件描述符
// prog_type如下
/*
enum bpf_prog_type {
	BPF_PROG_TYPE_UNSPEC,
	BPF_PROG_TYPE_SOCKET_FILTER,
	BPF_PROG_TYPE_KPROBE,
  ...
	BPF_PROG_TYPE_SYSCALL,    // a program that can execute syscalls
};
*/
// insns是struct bpf_insn指令组成的数组
// insn_cnt是insns中指令的个数
// license是许可字符串, 为了与标志为gpl_only的助手函数匹配必须设置GPL
// log_buf是一个调用者分配的缓冲区, 内核中的验证器可以在里面保存验证的log信息. 这个log信息由多行字符串组成, 目的是让程序作者明白为什么验证器认为这个程序是不安全的(相当于编译器的日志), 随着验证器的发展, 输出格式可能会改变
// log_size是log_buf的缓冲区大小, 要是缓冲区不足以保存全部的验证器日志, 那么会返回-1, 并把errno设置为ENOSPC
// log_level是验证器日志的详细级别, 00表示验证器不会提供日志, 在这种情况下log_buf必须是空指针, log_size必须是0
// 对返回的文件描述符调用close()会卸载eBPF程序
#define LOG_BUF_SIZE 65536
char bpf_log_buf[LOG_BUF_SIZE];
int bpf_prog_load(enum bpf_prog_type type, const struct bpf_insn *insns, int insn_cnt, const char *license) {
  union bpf_attr attr = {
    .prog_type = type,                    // 程序类型
    .insns = ptr_to_u64(insns),           // 指向指令数组的指针
    .insn_cnt = insn_cnt,                 // 有多少条指令
    .license = ptr_to_u64(license),       // 指向整数字符串的指针
    .log_buf = ptr_to_u64(bpf_log_buf),   // log输出缓冲区
    .log_size = LOG_BUF_SIZE,             // log缓冲区大小
    .log_level = 1,                       // log等级
    // 0: 不记录任何日志信息。
    // 1: 记录错误信息。
    // 2: 记录警告信息。
    // 3: 记录信息性的消息。
    // 4: 记录调试信息。
  };

  return bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
}
