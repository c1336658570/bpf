// gcc -o 1create_map 1create_map.c
// clang -o2 1create_map.c -o 1create_map 
#include <linux/bpf.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <errno.h>

// 创建BPF映射

#ifdef ASD      // 通过预处理注释     union bpf_attr的成员
union bpf_attr {
  struct { /* Used by BPF_MAP_CREATE */
    __u32 map_type;
    __u32 key_size;    /* size of key in bytes */
    __u32 value_size;  /* size of value in bytes */
    __u32 max_entries; /* maximum number of entries
                          in a map */
  };

  struct { /* Used by BPF_MAP_*_ELEM and BPF_MAP_GET_NEXT_KEY
              commands */
    __u32 map_fd;
    __aligned_u64 key;
    union {
      __aligned_u64 value;
      __aligned_u64 next_key;
    };
    __u64 flags;
  };

  struct { /* Used by BPF_PROG_LOAD */
    __u32 prog_type;
    __u32 insn_cnt;
    __aligned_u64 insns;   /* 'const struct bpf_insn *' */
    __aligned_u64 license; /* 'const char *' */
    __u32 log_level;       /* verbosity level of verifier */
    __u32 log_size;        /* size of user buffer */
    __aligned_u64 log_buf; /* user supplied 'char *'
                              buffer */
    __u32 kern_version;
    /* checked when prog_type=kprobe
       (since Linux 4.1) */
  };
} __attribute__((aligned(8)));
#endif

#ifdef ASD
#define	EPERM		 1	/* Operation not permitted */
#define	ENOENT		 2	/* No such file or directory */
#define	ESRCH		 3	/* No such process */
#define	EINTR		 4	/* Interrupted system call */
#define	EIO		 5	/* I/O error */
#define	ENXIO		 6	/* No such device or address */
#define	E2BIG		 7	/* Argument list too long */
#define	ENOEXEC		 8	/* Exec format error */
#define	EBADF		 9	/* Bad file number */
#define	ECHILD		10	/* No child processes */
#define	EAGAIN		11	/* Try again */
#define	ENOMEM		12	/* Out of memory */
#define	EACCES		13	/* Permission denied */
#define	EFAULT		14	/* Bad address */
#define	ENOTBLK		15	/* Block device required */
#define	EBUSY		16	/* Device or resource busy */
#define	EEXIST		17	/* File exists */
#define	EXDEV		18	/* Cross-device link */
#define	ENODEV		19	/* No such device */
#define	ENOTDIR		20	/* Not a directory */
#define	EISDIR		21	/* Is a directory */
#define	EINVAL		22	/* Invalid argument */
#define	ENFILE		23	/* File table overflow */
#define	EMFILE		24	/* Too many open files */
#define	ENOTTY		25	/* Not a typewriter */
#define	ETXTBSY		26	/* Text file busy */
#define	EFBIG		27	/* File too large */
#define	ENOSPC		28	/* No space left on device */
#define	ESPIPE		29	/* Illegal seek */
#define	EROFS		30	/* Read-only file system */
#define	EMLINK		31	/* Too many links */
#define	EPIPE		32	/* Broken pipe */
#define	EDOM		33	/* Math argument out of domain of func */
#define	ERANGE		34	/* Math result not representable */
#endif

#define SEC(NAME) __attribute__((section(NAME), used))

int bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
    return syscall(__NR_bpf, cmd, attr, size);
}

// 从linux-source-6.2.0/tools/lib/bpf抄过来的
struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
};


// 使用bpf系统调用创建BPF映射，从man bpf抄的，linux-6.2.0/tools/util/bpf_counters.c中有这个函数
// 声明在usr/include/bpf/bpf.h
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

int main(void) {
  // 创建一个键和值为无符号整数的哈希表映射
  union bpf_attr my_map = {
    .map_type = BPF_MAP_TYPE_HASH,      // 使用哈希表类型的BPF映射
    .key_size = sizeof(int),            // 键的大小为整数（4字节）
    .value_size = sizeof(int),          // 值的大小为整数（4字节）
    .max_entries = 100,                 // 映射中的最大条目数为100
    .map_flags = BPF_F_NO_PREALLOC,     // 额外的映射标志，此处设置为不进行预分配
  };
  int fd = bpf(BPF_MAP_CREATE, &my_map, sizeof(my_map));
  if (fd == -1) {
    printf("fd2 = %d\n", fd);
    // 通过errno来进行区分。如果属性无效，内核将errno变量设置为EINVAL。
    // 如果用户没有足够的权限执行操作，内核将errno变量设置为EPERM。
    // 最后，如果没有足够的内存保存映射，内核将errno变量设置为ENOMEM。
    // errno为1即EPERM，表示没有执行权限，需要加sudo
    printf("errno = %d\n", errno);
  }
  // bpf_map_create封装了我们上面使用的代码，可以容易地按需初始化映射。底层仍然是通过bpf系统调用来创建映射。
  // 声明在usr/include/bpf/bpf.h
  int fd2 = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(int), sizeof(int), 100, BPF_F_NO_PREALLOC);
  if (fd2 == -1) {
    printf("fd2 = %d\n", fd2);
    printf("errno = %d\n", errno);
  }

}
// 如果知道程序将使用的映射类型，也可以预定义映射。这有助于预先对程序使用的映射获取更直观的理解
// 使用section属性来定义映射，本示例中为SEC("maps")。这个宏告诉内核该结构是BPF映射，并告诉内核创建相应的映射。
// 定义一个BPF映射，使用SEC("maps")将其标记为maps部分，以便加载到BPF程序中
// linux-source-6.2.0/tools/lib/bpf中有bpf_map_def的定义
struct bpf_map_def SEC("maps") my_map2 = {
  .type = BPF_MAP_TYPE_HASH,      // 映射类型为哈希表
  .key_size = sizeof(int),
  .value_size = sizeof(int),
  .max_entries = 100,
  .map_flags = BPF_F_NO_PREALLOC,
};
// 这里没有与映射相关联的文件描述符，内核使用map_data全局变量保存BPF映射信息。
// 如果映射是第一个映射，就可以通过map_data[0].fd获得