### About pycbpf
---

Inspired by [cbpfc](https://github.com/cloudflare/cbpfc).

pycbpf2c converts tcpdump filter args to C code which can be injected to a BCC script.

This aims to provide native python support, so bcc can import it directly.

And it provides a BCC script for dump filtered packet to pcap format.


You can save packets to a pcap file like below to sniffer packet from ```dev_queue_xmit```
```
python3 -m pycbpf.c2ebpf -i eth0 -w file.pcap <tcpdump expresion>
```

Or you can pipe output to stdout and use tcpdump analyze
```
python3 -m pycbpf.c2ebpf -i eth0 <tcpdump expresion> | tcpdump -r -
```


Of course you can generate a C program from tcpdump expresion and implement your own bcc script.
Command line below will generate the C program, which can be used directly in BCC.
```
python3 -m pycbpf.cbpf2c <tcpdump expression>
```
import package
```
from bcc import BPF
from pycbpf import cbpf2c, filter2cbpf
```
generate cbpf and compile to C program, and enable BPF for trace
```
prog = filter2cbpf.cbpf_prog(["ip"])
prog_c = cbpf2c.cbpf_c(prog)
cfun = prog_c.compile_cbpf_to_c()
test_text = bpf_text%cfun
bpf_ctx = BPF(text=test_text, debug=4)
```

For example, filter ```ip``` packets, will generate C program
```
static inline u32
cbpf_filter_func (const u8 *const data, const u8 *const data_end) {
      __attribute__((unused)) u32 A, X, M[16];
      __attribute__((unused)) const u8 *indirect;

      if (data + 12 > data_end) { return 0; }
      A = bpf_ntohs(*((u16 *)(data + 12)));
      if (A != 0x800) {goto label3;}
      return 262144;
label3:
      return 0;
}
```
Use the inline function ```cbpf_filter_func``` in you trace program and handle return value properly.

see ```c2ebpf.py``` as an example to save packets to pcap files