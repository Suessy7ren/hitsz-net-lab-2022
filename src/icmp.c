#include "net.h"
#include "icmp.h"
#include "ip.h"

/**
 * @brief 发送icmp响应
 *
 * @param req_buf 收到的icmp请求包
 * @param src_ip 源ip地址
 */
static void icmp_resp(buf_t *req_buf, uint8_t *src_ip)
{
    // TO-DO
    // Step1 ：调用buf_init()来初始化txbuf，然后封装报头和数据，数据部分可以拷贝来自接收的回显请求报文中的数据
    buf_t new_buf;
    buf_init(&new_buf, req_buf->len);
    icmp_hdr_t *hdr = (icmp_hdr_t *)new_buf.data;
    memcpy(new_buf.data, req_buf->data, req_buf->len);
    hdr->type = ICMP_TYPE_ECHO_REPLY;
    hdr->code = 0;
    hdr->checksum16 = 0;
    // hdr->id16 = ((icmp_hdr_t*)(req_buf->data))->id16;//应该不用swap
    // hdr->seq16 = ((icmp_hdr_t*)(req_buf->data))->seq16;//同上

    // Step2 ：填写校验和，ICMP的校验和和IP协议校验和算法是一样的
    hdr->checksum16 = checksum16(new_buf.data, req_buf->len);

    // Step3 ：调用ip_out()函数将数据报发送出去
    ip_out(&new_buf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, uint8_t *src_ip)
{
    // TO-DO
    icmp_hdr_t *hdr = buf->data;//犯了个简单错误，指针没有指向data
    // Step1 ：首先做报头检测，如果接收到的包长小于ICMP头部长度，则丢弃不处理
    if (buf->len < 8)
        return;

    // Step2 ：接着，查看该报文的ICMP类型是否为回显请求
    if (hdr->type == ICMP_TYPE_ECHO_REQUEST)
    {
        // Step3 ：如果是，则调用icmp_resp()函数回送一个回显应答（ping 应答）
        icmp_resp(buf, src_ip);
    }
}

/**
 * @brief 发送icmp不可达
 *
 * @param recv_buf 收到的ip数据包
 * @param src_ip 源ip地址
 * @param code icmp code，协议不可达或端口不可达
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code)
{
    // TO-DO

    // Step1 ：首先调用buf_init()来初始化txbuf，填写ICMP报头首部
    ip_hdr_t *recv_hdr = recv_buf->data;
    buf_t new_buf;
    buf_init(&new_buf, 4 * recv_hdr->hdr_len + 16); // ip首部+icmp首部+前8字节
     //这里忘记乘4了，导致报文不全
    icmp_hdr_t *hdr = new_buf.data;
    hdr->type = ICMP_TYPE_UNREACH;
    hdr->code = code;
    hdr->checksum16 = 0;
    hdr->id16 = 0;
    hdr->seq16 = 0;

    // Step2 ：接着，填写ICMP数据部分，包括IP数据报首部和IP数据报的前8个字节的数据字段，填写校验和
     memcpy(new_buf.data+8, recv_buf->data, (4 * recv_hdr->hdr_len +8));
     //这里忘记乘4了，导致报文没有全copy到
    // for (int i = 0; i < recv_hdr->hdr_len + 8; i++)
    // {
    //     new_buf.data[i + 8] = recv_buf->data[i];
    // }
    hdr->checksum16 = checksum16(new_buf.data, recv_hdr->hdr_len*4 + 16);

    // Step3 ：调用ip_out()函数将数据报发送出去
    ip_out(&new_buf, src_ip, NET_PROTOCOL_ICMP);
    // ip_out(&new_buf, recv_hdr->src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 初始化icmp协议
 *
 */
void icmp_init()
{
    net_add_protocol(NET_PROTOCOL_ICMP, icmp_in);
}