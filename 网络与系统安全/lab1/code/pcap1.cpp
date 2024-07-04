#include <pcap.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <ctime>
#include <netinet/in.h>  // For inet_ntoa
#include <arpa/inet.h>   // For inet_ntoa


// 以太网帧头部结构体
struct ether_header {
    uint8_t ether_dhost[6]; // 目标MAC地址
    uint8_t ether_shost[6]; // 源MAC地址
    uint16_t ether_type;    // 以太网类型字段，用于标识上层协议
} __attribute__((packed));

// IPv4头部结构体
struct iphdr {
    uint8_t  ihl_version;     // IP头部长度和版本号（4位版本号，4位头部长度）
    uint8_t  tos;             // 服务类型（Type of Service）
    uint16_t tot_len;         // 总长度，包括头部和数据部分
    uint16_t id;              // 标识字段，用于分片和重组
    uint16_t frag_off;        // 标志和片偏移
    uint8_t   ttl;             // 生存时间
    uint8_t  protocol;           // 协议（例如，TCP为6，UDP为17）
    uint16_t check;         // 头部校验和
    in_addr saddr;           // 源IP地址
    in_addr daddr;           // 目的IP地址
} __attribute__((packed));

// TCP头部结构体
struct tcphdr {
    uint16_t source;         // 源端口号
    uint16_t dest;           // 目的端口号
    uint32_t seq;             // 序列号
    uint32_t ack_seq;         // 确认号
    uint16_t  doff : 4;         // 数据偏移，表示TCP头部长度
    uint8_t  flags;           // 控制标志位（例如，SYN、ACK、FIN等）
    uint16_t window;         // 窗口大小，用于流量控制
    uint16_t checksum;         // 校验和
    uint16_t urgent_ptr;      // 紧急指针，用于紧急数据
} __attribute__((packed));

// UDP头部结构体
struct udphdr {
    uint16_t uh_sport; /* 源端口号 */
    uint16_t uh_dport; /* 目的端口号 */
    uint16_t uh_ulen;  /* UDP 长度 */
    uint16_t uh_sum;  /* 校验和 */
} __attribute__((packed));

// 错误处理函数
void handle_pcap_error(char *pcap_error) {
    fprintf(stderr, "Pcap error: %s\n", pcap_error);
    exit(1);
}

// 回调函数，用于处理捕获的每个数据包
void packet_handler(u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data) {
    // 解析以太网头部
    const u_char *eth_header = pkt_data;
    auto *eth = (struct ether_header *)eth_header;
    // 解析ip头部
    const u_char *ip_header = eth_header + sizeof(struct ether_header);
    auto *ip = (struct iphdr *)ip_header;


    // 打印捕获的数据包长度
    printf("##############Captured packet with length: %d###############\n", pkt_header->len);
    // 将时间戳转换为本地时间
    time_t rawtime = pkt_header->ts.tv_sec;
    struct tm *timeinfo = localtime(&rawtime);
    // 使用strftime函数格式化时间
    char time_buffer[80];
    strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
    // 打印格式化后的时间字符串
    printf("#     Capture time: %s.%06ld\n", time_buffer, pkt_header->ts.tv_usec);
    char filename[100]; // 确保这个数组足够大以容纳完整的文件名
    snprintf(filename, sizeof(filename), "out/capture_%s.txt", time_buffer);

    // 尝试打开文件以写入数据
    FILE *file = fopen(filename, "w");
    if (file == NULL) {
        perror("Error opening file");
    }

    printf("#     ---------------以太网帧信息:---------------\n");
    // 打印目标MAC地址和源MAC地址
    printf("#     Destination MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
           eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
    printf("#     Source MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
           eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    // 打印以太网类型字段
    printf("#     Ether Type: 0x%04x\n", ntohs(eth->ether_type));

    fprintf(file,"#     ---------------ip层信息：---------------\n");
    printf("#     ---------------ip层信息：---------------\n");
    // 通过inet_ntoa()函数将二进制IP地址转换为点分十进制格式的字符串
    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip->saddr), src_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->daddr), dst_ip_str, INET_ADDRSTRLEN);

    // 提取版本号和头部长度
    uint8_t version = (ip->ihl_version >> 4) & 0x0F;
    uint8_t header_length = (ip->ihl_version & 0x0F) * 4; // 头部长度以 4 字节为单位

    printf("#     IP Version: %d\n", version);
    printf("#     IP Header Length: %d bytes\n", header_length);
    printf("#     Total Length: %d bytes\n", ntohs(ip->tot_len));
    printf("#     Protocol: %d\n", ip->protocol);
    printf("#     Source IP Address: %s\n", src_ip_str);
    printf("#     Destination IP Address: %s\n", dst_ip_str);

    fprintf(file,"#     Source IP Address: %s\n", src_ip_str);
    fprintf(file,"#     Destination IP Address: %s\n", dst_ip_str);

    // 判断传输层协议
    const u_char *trans_header = ip_header + sizeof(struct iphdr);
    if (ip->protocol == IPPROTO_TCP) {
        fprintf(file,"#     ---------------TCP 层信息：---------------\n");
        printf("#     ---------------TCP 层信息：---------------\n");
        auto *tcp = (struct tcphdr *)trans_header;
        printf("#     Src-Port=%d, Dst-Port=%d\n",
               ntohs(tcp->source), ntohs(tcp->dest));
        fprintf(file,"#     Src-Port=%d, Dst-Port=%d\n",
                ntohs(tcp->source), ntohs(tcp->dest));
    } else if (ip->protocol == IPPROTO_UDP) {
        fprintf(file,"#     ---------------UDP 层信息：---------------\n");
        printf("#     ---------------UDP 层信息：---------------\n");
        auto *udp = (struct udphdr *)trans_header;
        printf("#     Src-Port=%d, Dst-Port=%d\n",
               ntohs(udp->uh_sport), ntohs(udp->uh_dport));
        fprintf(file,"#     Src-Port=%d, Dst-Port=%d\n",
                ntohs(udp->uh_sport), ntohs(udp->uh_dport));
    } else {
        printf("#     Unknown Protocol\n");
    }
    printf("############################################################\n\n\n");


}

int main() {
    char error_buffer[PCAP_ERRBUF_SIZE];

    // 打开设备进行捕包
    pcap_t *handle = pcap_open_live("wlp0s20f3", 65535, 0, 1000, error_buffer);
    if (handle == NULL) {
        handle_pcap_error(error_buffer);
    }

    char filter_exp[] = "ip";
    struct bpf_program filter;
    if (pcap_compile(handle, &filter, filter_exp, 0, 0) == -1) {
        handle_pcap_error(pcap_geterr(handle));
    }
    if (pcap_setfilter(handle, &filter) == -1) {
        handle_pcap_error(pcap_geterr(handle));
    }

    // 开始捕包
    printf("Start capture ip pcap...\n");
//    设置捕包数
    pcap_loop(handle, 1, packet_handler, NULL);

    // 关闭设备和释放资源
    pcap_freecode(&filter);
    pcap_close(handle);

    return 0;
}