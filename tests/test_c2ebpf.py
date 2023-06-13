import subprocess
from pycbpf import c2ebpf


def test_xdp_cap():
    c2ebpf.main(["-i", "any", "-w", "txa.pcap", "-c", "10", "ip"])
    res = subprocess.run(
        ["tcpdump", "-r", "txa.pcap", "ip"],
        stdout=subprocess.PIPE,
        shell=False,
        check=True,
    )
    lines = res.stdout.decode("utf-8").split("\n")
    assert len(lines) == 11
