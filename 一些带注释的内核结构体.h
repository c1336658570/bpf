#include <linux/types.h>
#include <linux/stddef.h>
#include <asm/byteorder.h>
#include <linux/bpf_common.h>

struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	ihl:4,		// 首部长度（ihl）
		version:4;		// 版本（version）
#elif defined (__BIG_ENDIAN_BITFIELD)
	__u8	version:4,
  		ihl:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	__u8	tos;					// 服务类型（tos）
	__be16	tot_len;		// 总长度（tot_len）
	__be16	id;					// 报文标识（id），即标志位
	__be16	frag_off;		// 分段标识（frag）3位		分段偏移（offset），即片偏移13位
	// 三个bit位。第一位保留，未使用。第二位是DF（Don’t Fragment），如果为1，表示未发生分片。第三位是MF
	//（More Fragment），如果为1，表示发生了分片，并且除了分片出的最后一个报文中此标志为0，其余报文中此标志均为1。
	__u8	ttl;					// 生存时间（ttl）
	__u8	protocol;			// 协议（protocol）
	__sum16	check;			// 头部校验和（check）
	__struct_group(/* no tag */, addrs, /* no attrs */,
		__be32	saddr;		// 源地址（saddr）
		__be32	daddr;		// 目的地址（daddr）
	);
	/*The options start here. */		// 选项（option） 变长且最大不超过40字节。
};

struct __sk_buff {
	__u32 len;              // 数据包的总长度
	__u32 pkt_type;         // 数据包类型，表示数据包的种类，如数据、广播、多播等
	__u32 mark;             // 数据包标记
	__u32 queue_mapping;    // 队列映射
	__u32 protocol;         // 网络协议类型，如 ETH_P_IP、ETH_P_IPV6
	__u32 vlan_present;     // VLAN 标志，表示是否存在 VLAN 标签
	__u32 vlan_tci;         // VLAN 标签信息
	__u32 vlan_proto;       // VLAN 协议类型
	__u32 priority;         // 数据包的优先级
	__u32 ingress_ifindex;  // 入口网络接口的索引
	__u32 ifindex;          // 当前网络接口的索引
	// 表示网络接口的索引号，是一个无符号的32位整数。在Linux系统中，每个网络接口（例如网络卡、虚拟网络接口）
	// 都有一个唯一的整数索引，用于在系统内部标识和区分不同的网络接口。
	// ifconfig		ip link show		ip addr show		ls /sys/class/net/		netstat -i		nmcli device show查看
	__u32 tc_index;         // Traffic Control 索引
	__u32 cb[5];            // 用于 BPF 程序的扩展空间
	__u32 hash;             // 数据包的哈希值
	__u32 tc_classid;       // Traffic Control 类别 ID
	__u32 data;             // 数据包的起始位置
	__u32 data_end;         // 数据包的结束位置
	__u32 napi_id;          // NAPI（New API） ID

	/* Accessed by BPF_PROG_TYPE_sk_skb types from here to ... */
	__u32 family;           // 协议族，如 AF_INET、AF_INET6
	__u32 remote_ip4;       // 远程 IPv4 地址，以网络字节序存储
	__u32 local_ip4;        // 本地 IPv4 地址，以网络字节序存储
	__u32 remote_ip6[4];    // 远程 IPv6 地址，以网络字节序存储
	__u32 local_ip6[4];     // 本地 IPv6 地址，以网络字节序存储
	__u32 remote_port;      // 远程端口号，以网络字节序存储
	__u32 local_port;       // 本地端口号，以主机字节序存储
	/* ... here. */

	__u32 data_meta;        // 数据包元数据
	__bpf_md_ptr(struct bpf_flow_keys *, flow_keys);  // 指向表示流的 BPF 结构体指针
	__u64 tstamp;           // 时间戳
	__u32 wire_len;         // 数据包的总长度（包括头部和数据）
	__u32 gso_segs;         // GSO (Generic Segmentation Offload) 段数
	__bpf_md_ptr(struct bpf_sock *, sk);            // 指向表示套接字的 BPF 结构体指针
	__u32 gso_size;         // GSO 的大小
};

struct bpf_map_skeleton {
	const char *name;					// 映射（map）的名称
	struct bpf_map **map;			// 指向 BPF 映射的指针的指针，用于存储 BPF 映射的指针。
	void **mmaped;						// 指向映射内存映射区域的指针的指针，用于存储映射的内存映射区域的指针。这可能用于管理映射在内存中的位置。
};

struct bpf_prog_skeleton {
	const char *name;									// 程序（prog）的名称
	struct bpf_program **prog;				// 指向 BPF 程序的指针的指针，用于存储 BPF 程序的指针。
	struct bpf_link **link;						// 指向 BPF 程序链接的指针的指针，用于存储 BPF 程序链接的指针。链接可能表示程序与其他程序或内核的连接关系。
};

struct bpf_object_skeleton {
	// 用于前向/后向兼容性的结构体大小
	size_t sz;

	// BPF 对象的名称
	const char *name;
	// 指向 BPF 对象的数据的指针
	const void *data;
	// BPF 对象的数据大小
	size_t data_sz;

	// 指向指针的指针，用于存储 BPF 对象的指针
	struct bpf_object **obj;

	// BPF 对象包含的映射（map）的数量
	int map_cnt;
	// sizeof(struct bpf_skeleton_map) 的大小
	int map_skel_sz;					/* sizeof(struct bpf_skeleton_map) */
	// 指向 BPF 映射的骨架的指针
	struct bpf_map_skeleton *maps;

	// BPF 对象包含的程序（prog）的数量
	int prog_cnt;
	// sizeof(struct bpf_skeleton_prog) 的大小
	int prog_skel_sz;				/* sizeof(struct bpf_skeleton_prog) */
	// 指向 BPF 程序的骨架的指针
	struct bpf_prog_skeleton *progs;
};