#include <errno.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <bpf/bpf.h>

// 更新BPF映射元素

static const char *file_path = "/sys/fs/bpf/my_array";

#ifndef __LIBBPF_BPF_H
int bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
    return syscall(__NR_bpf, cmd, attr, size);
}
// 从linux-6.2.0/tools/lib/bpf/bpf.c抄过来的
static inline __u64 ptr_to_u64(const void *ptr)
{
	return (__u64) (unsigned long) ptr;
}

// 从man bpf 抄过来的，man bpf中的函数名为bpf_update_elem
// 在tools/lib/bpf/bpf.h中，也在usr/include/bpf/bpf.h
int bpf_map_update_elem(int fd, const void *key, const void *value, uint64_t flags) {
  union bpf_attr attr = {
    .map_fd = fd,
    .key    = ptr_to_u64(key),
    .value  = ptr_to_u64(value),
    .flags  = flags,
  };

  return bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

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
#endif


int main(int argc, char **argv) {
  int key, value, fd, added, pinned;

  // linux-6.2.0/tools/util/bpf_counters.c中有这个函数
  // 声明在usr/include/bpf/bpf.h
  fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(int), sizeof(int), 100, 0);
  if (fd < 0) {
    printf("Failed to create map: %d (%s)\n", fd, strerror(errno));
    return -1;
  }

  key = 1, value = 1234;
  // 向映射中添加一个新值。此时，因为映射是空的，任何更新行为都是可以的。
  // 第4个参数有三个值，0表示存在就更新，不存在就创建，1表示仅在元素不存在时，内核创建元素，2表示，仅在元素存在时，更新元素
  // BPF_ANY表示0，BPF_NOEXIST表示1,BPF_EXIST表示2。
  // 内核的函数是这个，只有第一个参数和用户的不同long bpf_map_update_elem(struct bpf_map *map, 
  // const void *key, const void *value, u64 flags)在bpf/bpf_helpers.h中
  // 用户的在tools/lib/bpf/bpf.h中，也在usr/include/bpf/bpf.h都存在声明
  added = bpf_map_update_elem(fd, &key, &value, BPF_ANY); // 可以在man bpf中找到这个函数定义
  if (added < 0) {
    printf("Failed to update map: %d (%s)\n", added, strerror(errno));
  } else {
    printf("Map updated with new element\n");
  }

  key = 1, value = 5678;
  int result;
  // 已经在映射中创建了一个键为1的元素，所以调用bpf_map_update_elem的返回值将为-1。errno 值将设置为EEXIST
  result = bpf_map_update_elem(fd, &key, &value, BPF_NOEXIST);
  if (result == 0) {
    printf("Map updated with new element\n");
  } else {
    printf("Failed to update map with new value : %d (%s)\n", result, strerror(errno));
  }

  // 书上说尝试更新不存在的元素，返回-1。这里其实返回0,添加成功了，因为这里使用的是数组，数组的元素个数不能改变，key都是已经存在的。
  // 如果这里是哈希就会返回-1更新失败
  key = 99, value = 5678;
  result = bpf_map_update_elem(fd, &key, &value, BPF_EXIST);
  if (result == 0) {
    printf("Map updated with new element\n");
  } else {
    printf("Failed to update map with new value : %d (%s)\n", result, strerror(errno));
  }

  // 在/usr/include/bpf/bpf.h
  pinned = bpf_obj_pin(fd, file_path);
  if (pinned < 0) {
    printf("Failed to pin map to the file system: %d (%s)\n", pinned,
           strerror(errno));
    return -1;
  }
  

  return 0;
}
