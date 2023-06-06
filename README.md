### About pycbpf
---

Inspired by [cbpfc](https://github.com/cloudflare/cbpfc).

pycbpf2c converts tcpdump filter expression to C code which can be injected to a BCC script.

This aims to provide native python support, so BCC can import it directly.

And it provides a BCC script for dump filtered packet to pcap format.

### Simple usecase

You can save packets to a pcap file like below to sniffer packet from ```dev_queue_xmit```
```
python3 -m pycbpf.c2ebpf -i eth0 -w file.pcap <tcpdump expresion>
```

Or with no pcap file specified, you need to pipe output to tcpdump
```
python3 -m pycbpf.c2ebpf -i eth0 <tcpdump expresion> | tcpdump -r - -nev
```

### Examples of usage

Of course you can generate a C program from tcpdump expresion and implement your own BCC script.
Cmdline below will generate the C program, which can be used directly in BCC.
```
python3 -m pycbpf.cbpf2c <tcpdump expression>
```

Steps to use it in python:

1 - Install and import packages

```
pip3 install pycbpf
```

```
from bcc import BPF
from pycbpf import cbpf2c, filter2cbpf
```
2 - Generate cbpf and compile to C program, and enable BPF for trace. Write you test_text with space reserved for the generated code. Use the inline function ```cbpf_filter_func``` in you trace program and handle return value properly.
```
test_text = """

/* reserve space for the generated code cbpf_filter_func */
%s

your_func()
{
      u32 datalen = 0;
      u32 ret = 0;
      u8 *data;
      ...

      ret = cbpf_filter_func(data, data + datalen);
      if (!ret) {
            return 0;
      }

      filter_event.perf_submit(ctx, &e, sizeof(e));
}

"""

prog = filter2cbpf.CbpfProg(["ip"])
prog_c = cbpf2c.CbpfC(prog)
cfun = prog_c.compile_cbpf_to_c()
test_text = bpf_text%cfun
bpf_ctx = BPF(text=test_text, debug=0)
```
3 - write bcc perf event callback
```
def filter_events_cb(_cpu, data, _size):
      # print some data
      # or write to pcap files

bctx['filter_event'].open_perf_buffer(filter_events_cb)
```
---
### Further explain


As for the code generated from cbpf, for example, filter ```ip``` packets, will generate C program:
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

It follows what cbpf code tells us to do:
```
(000) ldh      [12]
(001) jeq      #0x800           jt 2	jf 3
(002) ret      #262144
(003) ret      #0
```
A little explain about the cbpf code and cbpf_filter_func above:

First read 2 byte at offset 12.

Test the data read, if equal to 0x0800, jump to 002, else jump to 003. We name the position to labelX, X is the PC value.

If label is right after last instruction, it will be ignored.
002 and 003 will return value and exit the function.


see ```c2ebpf.py``` as an example to save packets to pcap files



---
### LICENSE
pycbpf is MIT licensed, as found in the LICENSE file
