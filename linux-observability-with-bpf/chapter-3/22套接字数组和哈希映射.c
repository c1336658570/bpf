/**
 * 套接字数组和哈希映射
 * 
 * BPF_MAP_TYPE_SOCKMAP和BPF_MAP_TYPE_SOCKHASH是两种保存内核中打开套接宇引用的专用映射。
 * 跟上述映射类型一样，这种类型映射也可以与帮助函数bpf_redirect_map一起使用，
 * 在当前XDP程序到其他套接字的缓冲区之间转发套接字。
 * 
 * 它们的主要区别是其中一个使用数组存储套接字，而另一个使用哈希表存储套接字。
 * 使用哈希表的优势是可以通过键直接访问套接字，无须遍历完整映射查找。内核中的套接字由五元组键标识。
 * 这五个元组包括建立双向网络连接的基本信息。当使用哈希映射时，你可以使用这个五元组作为查找键。 
*/