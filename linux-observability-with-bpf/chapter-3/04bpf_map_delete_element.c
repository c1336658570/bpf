// gcc 04bpf_map_delete_element.c -o 04bpf_map_delete_element -lbpf
#include <errno.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <bpf/bpf.h>

// 删除BPF映射元素

int bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
    return syscall(__NR_bpf, cmd, attr, size);
}

int bpf_delete_elem(int fd, const void *key) {
  union bpf_attr attr = {
      .map_fd = fd,
      .key = (unsigned long long )key,
  };

  return bpf(BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
}

int main(int argc, char **argv) {
  int key, value, fd, added, pinned;

  fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(int), sizeof(int), 100, 0);
  if (fd < 0) {
    printf("Failed to create map: %d (%s)\n", fd, strerror(errno));
    return -1;
  }

  key = 1, value = 1234;

  added = bpf_map_update_elem(fd, &key, &value, BPF_ANY);
  if (added < 0) {
    printf("Failed to update map: %d (%s)\n", added, strerror(errno));
  } else {
    printf("Map updated with new element\n");
  }

  key = 2, value = 4567;
  added = bpf_map_update_elem(fd, &key, &value, BPF_ANY);
  if (added < 0) {
    printf("Failed to update map: %d (%s)\n", added, strerror(errno));
  } else {
    printf("Map updated with new element\n");
  }


  int result;
  key = 1, value = 0;
  result = bpf_map_lookup_elem(fd, &key, &value);
  if (result < 0) {
    // 处理查询失败的情况
    printf("Failed to read value from the map: %d (%s)\n", result, strerror(errno));
    return -1;
  }
  // 打印查询到的值
  printf("Value read from the map: '%d'\n", value);


  key = 2;
  // 内核long bpf_map_delete_elem(struct bpf_map *map, const void *key)
  // 按理说应该删除成功，不知道为什么一直删除失败，errno是EINVAL(Invalid argument)
  // 知道原因了，数组映射的一个缺点是映射中的元素不能删除，无法使数组变小。
  // 如果在数组映射上使用bpf_map_delete_elem，调用将失败，得到EINVAL错误。
  // BPF_MAP_TYPE_HASH可以删除元素
  result = bpf_map_delete_elem(fd, &key); // EINVAL
  if (result == 0) {
    printf("Element deleted from the map\n");
  } else {
    printf("Failed to delete element from the map: %d (%s)\n", result, strerror(errno));
  }

  return 0;
}


