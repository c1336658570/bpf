// clang -o loader loader.c -lbpf
// sudo ./loader bpf_program.o 
// ping -c 100 127.0.0.1      对本机pin100此，生成ICMP流量
#include <arpa/inet.h>
#include <assert.h>
#include <bpf/bpf.h>
#include "./sock_example.h"
#include <errno.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <bpf/libbpf.h>

char bpf_log_buf[BPF_LOG_BUF_SIZE];

int main(int argc, char **argv) {
  int sock = -1, i, key;
  int tcp_cnt, udp_cnt, icmp_cnt;
  struct bpf_object *obj;
	struct bpf_program *prog;
	int map_fd, prog_fd;
  int err;

  char filename[256];
  snprintf(filename, sizeof(filename), "%s", argv[1]);

  obj = bpf_object__open_file(filename, NULL);
	if (libbpf_get_error(obj)) {
		return -1;
  }

  // prog = bpf_object__next_program(obj, NULL);    // 这个接口ubuntu带的libbpf还不支持，所以用下面这个，内核中直接编译支持
  prog = bpf_program__next(NULL, obj);
	bpf_program__set_type(prog, BPF_PROG_TYPE_SOCKET_FILTER);

  
  // const char *program_title = bpf_program__title(prog, true);    // 已经弃用的接口，用bpf_program__section_name替代
  const char *program_title = bpf_program__section_name(prog);
  printf("Program Title: %s\n", program_title);

  err = bpf_object__load(obj);
	if (err)
		return -1;

	prog_fd = bpf_program__fd(prog);
	map_fd = bpf_object__find_map_fd_by_name(obj, "countmap");

  // 使用open_raw_sock函数打开环回接口lo
  sock = open_raw_sock("lo");

  // 将BPF程序附加到lo的套接宇描述符上。通过设置SO_ATTACH_BPF选项将BPF程序附加到接口lo打开的原始套接字上。
  if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd))) {
    printf("setsockopt %s\n", strerror(errno));
    return 0;
  }

  // 使用for循环和bpf_map_lookup_e1em查找数组映射上的元素，分别读取和打印TCP、UDP和ICMP数据包的数量。
  for (i = 0; i < 10; i++) {
    key = IPPROTO_TCP;
    assert(bpf_map_lookup_elem(map_fd, &key, &tcp_cnt) == 0);

    key = IPPROTO_UDP;
    assert(bpf_map_lookup_elem(map_fd, &key, &udp_cnt) == 0);

    key = IPPROTO_ICMP;
    assert(bpf_map_lookup_elem(map_fd, &key, &icmp_cnt) == 0);

    printf("TCP %d UDP %d ICMP %d packets\n", tcp_cnt, udp_cnt, icmp_cnt);
    sleep(1);
  }
}
