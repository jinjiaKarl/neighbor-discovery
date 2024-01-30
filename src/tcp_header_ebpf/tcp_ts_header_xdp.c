#include <linux/bpf.h>
// #include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>

#define MAX_PACKET_OFF 0xffff
#define MAX_TCP_OPTIONS 10


struct packet_t {
    u32 start;
    u32 end;
};
BPF_PERF_OUTPUT(packet);


static int parse_tcp_ts(struct tcphdr* tcph, void *data_end, __u32 *tsval, __u32 *tsecr)
{
    int len = tcph->doff << 2;
    // void* +- 1, move 1 byte
    void *opt_end = (void *)tcph + len;
    __u8 *pos = (__u8 *)(tcph + 1);//Current pos in TCP options
    // __u8 *pos = (__u8 *)tcph + sizeof(struct tcphdr);
    __u8 i, opt;
    volatile __u8 opt_size;
    if (tcph + 1 > data_end || len <= sizeof(struct tcphdr))
		return -1;

    #pragma unroll
    for (i = 0; i < MAX_TCP_OPTIONS; i++) 
    {
        if (pos + 1 > (__u8 *)opt_end || pos + 1 > (__u8 *)data_end)
        {
            bpf_trace_printk("parse_tcp_ts() :: pos + 1 > (__u8 *)opt_end || pos + 1 > (__u8 *)data_end\n");
            return -1;
        }

        opt = *pos;

        if (opt == 0)
        {
            bpf_trace_printk("parse_tcp_ts() :: opt == 0\n");

            return -1;
        }

        if (opt == 1)
        {
            pos++;
            bpf_trace_printk("parse_tcp_ts() :: opt == 1\n");
            continue;
        }

        if (pos + 2 > (__u8 *)opt_end || pos + 2 > (__u8 *)data_end)
        {
            bpf_trace_printk("parse_tcp_ts() :: pos + 2 > (__u8 *)opt_end || pos + 2 > (__u8 *)data_end\n");

            return -1;
        }

        opt_size = *(pos + 1);

        if (opt_size < 2)
        {
            bpf_trace_printk("parse_tcp_ts() :: opt_size < 2\n");

            return -1;
        }

        if (opt == 8 && opt_size == 10) 
        {
            bpf_trace_printk("opt = 8");
            if (pos + 10 > (__u8 *)opt_end )
            {
                bpf_trace_printk("parse_tcp_ts() :: pos + 10 > (__u8 *)opt_end\n");
                return -1;
            }

            bpf_trace_printk("pos = %p pos + 10 = %p data_end = %p\n",pos, pos + 10 , (__u8 *)data_end);
            if ((pos + 10) > (__u8 *)data_end)
            {
                bpf_trace_printk("parse_tcp_ts() :: pos + 10 > (__u8 *)data_end\n");
                bpf_trace_printk("pos + 10 = %p data_end = %p\n",pos + 10 , (__u8 *)data_end);
                return -1;   
            }


            *tsval = *(__u32 *)(pos + 2);
            *tsecr = *(__u32 *)(pos + 6);

            bpf_trace_printk("parse_tcp_ts() tcp tsval: %u tsecr: %u\n", *tsval, *tsecr);
            return 0;
        }

        pos += opt_size;
    }

    bpf_trace_printk("parse_tcp_ts() :: Reached end (return -1).\n");

    return -1;
}

int parse_header(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct packet_t pkt = {};
    __builtin_memset(&pkt, 0, sizeof(pkt));

    struct ethhdr *eth = data;    
    
    // why we need to check
    if (eth + 1 > (struct ethhdr*) data_end)
    {
        return XDP_DROP;
    }

    if (eth->h_proto != htons(ETH_P_IP))
    {
        return XDP_PASS;
    }

    struct iphdr *iph = data + sizeof(struct ethhdr);

    if (iph + 1 > (struct iphdr*)data_end)
    {
        return XDP_DROP;
    }

    if (iph->protocol != IPPROTO_TCP)
    {
        return XDP_PASS;
    }

    // NOTE: there is a header length in IP header, the unit is 4 bytes
    struct tcphdr *tcph = data + sizeof(struct ethhdr) + (iph->ihl * 4);


    if (tcph + 1 > (struct tcphdr*)data_end)
    {
        return XDP_DROP;
    }

    // xdp only handle rx packet
    if (ntohs(tcph->dest) != 8080 && ntohs(tcph->source) != 8080)
    {
        return XDP_PASS;
    }

    int len = tcph->doff << 4;

    __u32 senderts = 0;
    __u32 recvts = 0;

    parse_tcp_ts(tcph, data_end, &senderts, &recvts);
    if (senderts != 0 || recvts != 0)
    {
        pkt.start = senderts;
        pkt.end = recvts;
        packet.perf_submit(ctx, &pkt, sizeof(pkt));
    }
    return XDP_PASS;
}
