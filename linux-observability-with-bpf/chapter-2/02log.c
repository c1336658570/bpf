// clang -O2 -target bpf -c 02log.c  -o 02log.o
#include <linux/bpf.h>

#define SEC(NAME) __attribute__((section(NAME), used))

static int (*bpf_trace_printk)(const char *fmt, int fmt_size,
                               ...) = (void *)BPF_FUNC_trace_printk;

#define LOG_BUF_SIZE 65536

char bpf_log_buf[LOG_BUF_SIZE];

struct my_bpf_attr {
  __u32 map_type;
  __u32 key_size;
  __u32 value_size;
  __u32 max_entries;
};

union my_bpf_attr_ttr {
  struct {
    __u32 prog_type;
    __u32 insn_cnt;
    __u64 insns;
    __u64 license;
    __u64 log_buf;
    __u32 log_size;
    __u32 log_level;
  };
  char padding[128];  // Ensure the struct size is 128 bytes
};

SEC("prog")
int my_bpf_program(struct __sk_buff *skb) {
  // Your eBPF logic here

  // Log a message with log_level = 1
  char msg[] = "Hello from eBPF program!";
  bpf_trace_printk(msg, sizeof(msg));

  return 0;
}

char _license[] SEC("license") = "GPL";

int main(void) {
  union my_bpf_attr_ttr attr;

  // Load the eBPF program with logging
  attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
  attr.insn_cnt = 1;
  attr.insns = ptr_to_u64(my_bpf_program);
  attr.license = ptr_to_u64(_license);
  attr.log_buf = ptr_to_u64(bpf_log_buf);
  attr.log_size = LOG_BUF_SIZE;
  attr.log_level = 1;

  bpf(BPF_PROG_LOAD, &attr, sizeof(attr));

  // Your eBPF program is now loaded with logging enabled

  return 0;
}
