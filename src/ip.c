#include "net.h"
#include "ip.h"
#include "ethernet.h"
#include "arp.h"
#include "icmp.h"

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac)
{
    // TO-DO
    // Step1 ：首先判断数据长度，如果数据长度小于IP头部长度，则认为数据包不完整，丢弃不处理
    if (buf->len < 20)
        return;

    // Step2 ：接下来做报头检测，检查内容至少包括：
    // IP头部的版本号是否为IPv4，总长度字段小于或等于收到的包的长度等，如果不符合这些要求，则丢弃不处理。
    ip_hdr_t *hdr = buf->data;
    if ((hdr->version != IP_VERSION_4) || (swap16(hdr->total_len16) > buf->len)) //或许要补充
    {
        return;
    }

    // Step3 ：先把IP头部的头部校验和字段用其他变量保存起来，
    uint16_t chk = hdr->hdr_checksum16;
    // 接着将该头部校验和字段置0，
    hdr->hdr_checksum16 = 0;
    // 然后调用checksum16函数来计算头部校验和，
    // 如果与IP头部的首部校验和字段不一致，丢弃不处理，
    if (chk != checksum16(hdr, hdr->hdr_len * IP_HDR_LEN_PER_BYTE))
    {
        return;
    }
    // printf("\n校验和ok\n");
    //如果一致，则再将该头部校验和字段恢复成原来的值。
    hdr->hdr_checksum16 = chk;
    // Step4 ：对比目的IP地址是否为本机的IP地址，如果不是，则丢弃不处理。
    if ((hdr->dst_ip[0] == net_if_ip[0]) && (hdr->dst_ip[1] == net_if_ip[1]) && (hdr->dst_ip[2] == net_if_ip[2]) && (hdr->dst_ip[3] == net_if_ip[3]))
    {
        // printf("\nip地址ok\n");
    }
    else
    {
        return;
    }
    // Step5 ：如果接收到的数据包的长度大于IP头部的总长度字段，则说明该数据包有填充字段，
    if (buf->len > swap16(hdr->total_len16))
    {
        //可调用buf_remove_padding()函数去除填充字段。
        buf_remove_padding(buf, buf->len - swap16(hdr->total_len16));
    }

    // Step6 ：调用buf_remove_header()函数去掉IP报头。
    buf_t temp = *buf;
    buf_remove_header(buf, hdr->hdr_len * IP_HDR_LEN_PER_BYTE);
    // Step7 ：调用net_in()函数向上层传递数据包。
    if (net_in(buf, hdr->protocol, hdr->src_ip) == -1) //??这里之前用的src_mac导致错了
    // int ans = net_in(buf, hdr->protocol, hdr->src_ip);
    // if(ans == -1)
    {
        //如果是不能识别的协议类型，即调用icmp_unreachable()返回ICMP协议不可达信息。
        // icmp_unreachable(buf, hdr->src_ip, ICMP_CODE_PROTOCOL_UNREACH);
        icmp_unreachable(&temp, hdr->src_ip, ICMP_CODE_PROTOCOL_UNREACH);
    }
}

/**
 * @brief 处理一个要发送的ip分片
 *
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf)
{
    // TO-DO
    // Step1 ：调用buf_add_header()增加IP数据报头部缓存空间
    buf_add_header(buf, 20); //??

    // Step2 ：填写IP数据报头部字段
    ip_hdr_t *hdr = (ip_hdr_t *)buf->data;
    hdr->hdr_len = 5;
    hdr->version = IP_VERSION_4;
    hdr->tos = 0; //
    // hdr->total_len16 = swap16(20 + buf->len);
    hdr->total_len16 = swap16(buf->len); //草??
    hdr->id16 = swap16(id);
    // hdr->flags_fragment16 = swap16((uint32_t)offset + (mf << 13));//??

    if (mf == 1)
    {
        hdr->flags_fragment16 = swap16(offset + IP_MORE_FRAGMENT);
    }
    else
    {
        hdr->flags_fragment16 = swap16(offset);
    }

    hdr->ttl = 64; // TTL值被发送端设置，常设置为64。
    hdr->protocol = protocol;
    for (int i = 0; i < 4; i++)
    {
        hdr->dst_ip[i] = ip[i];
        hdr->src_ip[i] = net_if_ip[i];
    }
    hdr->hdr_checksum16 = 0;
    hdr->hdr_checksum16 = checksum16(hdr, 20); //??, 这里是16+4??
    arp_out(buf, ip);
}

/**
 * @brief 处理一个要发送的ip数据包
 *
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol)
{
    // TO-DO
    static int ip_id = -1;
    ip_id++;
    buf_t *ip_buf = NULL;

    // int ip_max_length = 1500 - hdr->hdr_len*4;
    int length = buf->len;
    int ip_max_length = 1480; //??
    // Step1 ：首先检查从上层传递下来的数据报包长是否大于IP协议最大负载包长（1500字节（MTU） 减去IP首部长度）

    //如果没有超过IP协议最大负载包长，则直接调用ip_fragment_out()函数发送出去
    if (length <= ip_max_length)
    {
        ip_fragment_out(buf, ip, protocol, ip_id, 0, 0);
    }
    else
    {
        //如果超过IP协议最大负载包长
        uint16_t ip_offset = 0;
        while (length > ip_max_length)
        {
            ip_buf = (buf_t *)malloc(sizeof(buf_t));
            buf_init(ip_buf, ip_max_length);
            for (int i = 0; i < ip_max_length; i++)
            {
                // *(ip_buf->data + i) = buf->payload[(BUF_MAX_LEN / 2 - length)];
                *(ip_buf->data + i) = *(buf->data + (buf->len - length));

                length--;
            }
            ip_fragment_out(ip_buf, ip, protocol, ip_id, ip_offset, 1);
            ip_offset += (ip_max_length / IP_HDR_OFFSET_PER_BYTE);
        }

        ip_buf = (buf_t *)malloc(sizeof(buf_t));
        buf_init(ip_buf, length);
        int temp = length;
        for (int i = 0; i < temp; i++)
        {
            // *(ip_buf->data + i) = buf->payload[BUF_MAX_LEN / 2 - length];
            *(ip_buf->data + i) = *(buf->data + (buf->len - length));
            length--;
        }
        ip_fragment_out(ip_buf, ip, protocol, ip_id, ip_offset, 0);
    }
}

/**
 * @brief 初始化ip协议
 *
 */
void ip_init()
{
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}