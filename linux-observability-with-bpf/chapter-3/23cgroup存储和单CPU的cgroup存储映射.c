/*
 * cgroup存储和单CPU的cgroup存储映射
 *
 * 这两种映射类型用来帮助开发人员将 BPF 程序附加到 cgroup 上。像我们在第 2
 * 章中介绍的 BPF 程序类型，你可以使用 BPF_PROG_TYPE_CGROUP_SKB 将 BPF
 * 程序附加到 cgroup 上和从 cgroup 移除，并且使用特定 cgroup 来实现 BPF
 * 程序运行时隔离。这两种映射类型分别被定义为 BPF_MAP_TYPE_CGROUP_STORAGE 和
 * BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE 。
 *
 * 从开发人员的角度来看，这两种类型的映射类似于哈希表映射。内核提供了一个结构帮助函数
 * bpf_cgroup_storage_key 可以为该映射生成包括 cgroup
 * 节点标识和附件类型信息的键。你可以为映射添加任何值，只有附加到 cgroup 的 BPF
 * 程序可以访问这些值。
 *
 * 这种映射有两个限制。首先是无法从用户空间创建映射中的新元素。内核中的BPF程序可以使用bpf_map_update_elem创建元素。
 * 但是，如果从用户空间使用该方法，在键不存在的情况下，bpf_map_update_elem将失败，errno设置为ENOENT。
 * 第二个限制是不能从该映射中删除元素，bpf_map_delete_elem总会失败，errno将被设置为EINVAL。
 * 与上面其他相似的映射相比，两种映射的主要不同是BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE保存每个CPU的哈希表。
 */