#!/usr/bin/env python3
from bcc import BPF
import time
from socket import inet_ntop, AF_INET
from struct import pack
import sys

# XDP is an in-kernel fast-path, that operates on raw-frames “inline” before they reach the normal Linux Kernel network stack.
# getting timestamp option from tcp header
# download BCC: https://github.com/iovisor/bcc/blob/master/INSTALL.md
# recomended to use Ubuntu 22.04

if len(sys.argv) != 2:
    print("Usage: {} DEVICE".format(sys.argv[0]))
    exit(1)

with open("tcp_ts_header_xdp.c", "r") as f:
    bpf_text = f.read()

port = 65432

bpf_text = bpf_text.replace("FILTER_PORT",
                        f"if (pkt.sport != {port} && pkt.dport != {port}) {{return 0;}} ")
b = BPF(text=bpf_text)

device = sys.argv[1]
fn = b.load_func("parse_header", BPF.XDP)
BPF.attach_xdp(device, fn)

	# bpf_trace_printk("trace_tcp4connect %x %x %d\\n", saddr, daddr, ntohs(dport));

def print_event(cpu, data, size):
    event = b["packet"].event(data)
    packet = {
        "start": event.start,
        "end": event.end,
    }
    print(f"{packet}")

b["packet"].open_perf_buffer(print_event)

while True:
    try:
        # b.perf_buffer_poll()
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        print(f"{msg}")
        # time.sleep(1)
    except KeyboardInterrupt:
        break;
print("Removing filter from device")
b.remove_xdp(device)
