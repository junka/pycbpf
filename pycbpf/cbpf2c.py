"""
The above code defines a class `CbpfC` that can compile a BPF filter program into a C function, and
includes a main function that takes command line arguments to generate and print the C function.
"""
import argparse
import libpcap as pcap
from .filter2cbpf import CbpfProg


class CbpfC:  # pylint: disable=too-few-public-methods
    """
    BPF compile to C class
    ref https://www.kernel.org/doc/Documentation/networking/filter.txt
    The BPF architecture consists of the following basic elements:
    Element          Description

    A                32 bit wide accumulator
    X                32 bit wide X register
    M[]              16 x 32 bit wide misc registers aka "scratch memory
                    store", addressable from 0 to 15

    A program, that is translated by bpf_asm into "opcodes" is an array that
    consists of the following elements (as already mentioned):

    op:16, jt:8, jf:8, k:32

    The element op is a 16 bit wide opcode that has a particular instruction
    encoded. jt and jf are two 8 bit wide jump targets, one for condition
    "jump if true", the other one "jump if false". Eventually, element k
    contains a miscellaneous argument that can be interpreted in different
    ways depending on the given instruction in op.

    The instruction set consists of load, store, branch, alu, miscellaneous
    and return instructions that are also represented in bpf_asm syntax. This
    table lists all bpf_asm instructions available resp. what their underlying
    opcodes as defined in linux/filter.h stand for:
    Instruction      Addressing mode      Description

    ld               1, 2, 3, 4, 12       Load word into A
    ldi              4                    Load word into A
    ldh              1, 2                 Load half-word into A
    ldb              1, 2                 Load byte into A
    ldx              3, 4, 5, 12          Load word into X
    ldxi             4                    Load word into X
    ldxb             5                    Load byte into X

    st               3                    Store A into M[]
    stx              3                    Store X into M[]

    jmp              6                    Jump to label
    ja               6                    Jump to label
    jeq              7, 8, 9, 10          Jump on A == <x>
    jneq             9, 10                Jump on A != <x>
    jne              9, 10                Jump on A != <x>
    jlt              9, 10                Jump on A <  <x>
    jle              9, 10                Jump on A <= <x>
    jgt              7, 8, 9, 10          Jump on A >  <x>
    jge              7, 8, 9, 10          Jump on A >= <x>
    jset             7, 8, 9, 10          Jump on A &  <x>

    add              0, 4                 A + <x>
    sub              0, 4                 A - <x>
    mul              0, 4                 A * <x>
    div              0, 4                 A / <x>
    mod              0, 4                 A % <x>
    neg                                   !A
    and              0, 4                 A & <x>
    or               0, 4                 A | <x>
    xor              0, 4                 A ^ <x>
    lsh              0, 4                 A << <x>
    rsh              0, 4                 A >> <x>

    tax                                   Copy A into X
    txa                                   Copy X into A

    ret              4, 11                Return
    """

    def __init__(self, bpf):
        self._pc = 0
        self._jump_labels = {}
        self._alu_ops = {
            pcap.BPF_ADD: "+",
            pcap.BPF_SUB: "-",
            pcap.BPF_MUL: "*",
            pcap.BPF_DIV: "/",
            pcap.BPF_AND: "&",
            pcap.BPF_LSH: "<<",
            pcap.BPF_RSH: ">>",
            pcap.BPF_MOD: "%",
            pcap.BPF_XOR: "^",
        }
        self._bpf = bpf

    def _jump_label(self, pos):
        self._jump_labels[pos] = f"label{pos}"
        return f"label{pos}"

    def _jump_cases(self, ins, cond, neg):
        if ins.jf == 0:
            next_pc = self._pc + 1 + ins.jt
            return f"if (A {cond} {self._alu_src(ins)}) {{goto {self._jump_label(next_pc)};}}"
        if ins.jt == 0:
            next_pc = self._pc + 1 + ins.jf
            return f"if (A {neg} {self._alu_src(ins)}) {{goto {self._jump_label(next_pc)};}}"
        fstr = f"if (A {cond} {self._alu_src(ins)})"
        fstr += f"{{goto {self._jump_label(self._pc + 1 + ins.jt)};}}"
        fstr += f" else {{ goto {self._jump_label(self._pc + 1 + ins.jf)};}}"
        return fstr

    @classmethod
    def _ld_dst(cls, ins):
        if pcap.BPF_CLASS(ins.code) == pcap.BPF_LD:
            return "A"
        # elif pcap.BPF_CLASS(ins.code) == pcap.BPF_LDX:
        return "X"

    @classmethod
    def _alu_src(cls, ins):
        if pcap.BPF_SRC(ins.code) == pcap.BPF_K:
            return f"0x{ins.k:x}"
        # elif pcap.BPF_SRC(ins.code) == pcap.BPF_X:
        return "X"

    def _load_data_size(self, ins, data):
        check = ""
        if pcap.BPF_SIZE(ins.code) == pcap.BPF_B:
            width = 1
        elif pcap.BPF_SIZE(ins.code) == pcap.BPF_H:
            width = 2
        elif pcap.BPF_SIZE(ins.code) == pcap.BPF_W:
            width = 4
        if data == "data":
            check = f"if (data + {ins.k} + {width} > data_end) {{ return 0; }}\n\t"
        elif data == "indirect":
            # ref https://www.kernel.org/doc/Documentation/networking/filter.txt
            check = "if (data + X > data_end) {return 0;}\n\t"
            check += "indirect = data + X;\n\t"
            check += f"if (indirect + {ins.k} + {width} > data_end) {{return 0;}}\n\t"

        if pcap.BPF_SIZE(ins.code) == pcap.BPF_B:
            return f"{check}{self._ld_dst(ins)} = *({data} + {ins.k});"
        if pcap.BPF_SIZE(ins.code) == pcap.BPF_H:
            return f"{check}{self._ld_dst(ins)} = bpf_ntohs(*((u16 *)({data} + {ins.k})));"
        if pcap.BPF_SIZE(ins.code) == pcap.BPF_W:
            return f"{check}{self._ld_dst(ins)} = bpf_ntohl(*((u32 *) ({data} + {ins.k})));"
        return ""

    def compile_cbpf_to_c(self) -> str:
        """
        ref https://github.com/iovisor/bpf-docs/blob/master/eBPF.md
        LD/LDX/ST/STX opcode structure:

        msb      lsb
        +---+--+---+
        |mde|sz|cls|
        +---+--+---+
        BPF_SIZE
        BPF_MODE
        BPF_CLASS
        The sz field specifies the size of the memory location. The mde field is the
        memory access mode. uBPF only supports the generic "MEM" access mode.

        ALU/ALU64/JMP opcode structure:

        msb      lsb
        +----+-+---+
        |op  |s|cls|
        +----+-+---+
        BPF_OP
        BPF_SRC
        BPF_CLASS
        If the s bit is zero, then the source operand is imm. If s is one, then the source
        operand is src. The op field specifies which ALU or branch operation is to be performed.
        """
        ctext = """\nstatic inline u32
cbpf_filter_func (const u8 *const data, const u8 *const data_end) {
	__attribute__((unused)) u32 A, X, M[16];
	__attribute__((unused)) const u8 *indirect;
"""
        for ins in self._bpf.ins:
            ctext += "\n"
            if self._jump_labels.get(self._pc) is not None:
                ctext += self._jump_labels.get(self._pc) + ":\n"
            ctext += "\t" + self._convert_insn(ins)
            self._pc += 1
        ctext += "\n}"
        return ctext

    # ref https://github.com/the-tcpdump-group/libpcap/blob/master/bpf_filter.c
    # ref bpf(7) https://www3.physnet.uni-hamburg.de/physnet/Tru64-Unix/HTML/MAN/MAN7/0012____.HTM
    def _convert_insn(self, ins) -> str:  # pylint: disable=too-many-return-statements,too-many-branches
        if pcap.BPF_CLASS(ins.code) == pcap.BPF_LD or pcap.BPF_CLASS(ins.code) == pcap.BPF_LDX:
            if pcap.BPF_MODE(ins.code) == pcap.BPF_IMM:
                mstr = f"{self._ld_dst(ins)} = {ins.k};"
            elif pcap.BPF_MODE(ins.code) == pcap.BPF_IND:
                mstr = self._load_data_size(ins, "indirect")
            elif pcap.BPF_MODE(ins.code) == pcap.BPF_ABS:
                mstr = self._load_data_size(ins, "data")
            elif pcap.BPF_MODE(ins.code) == pcap.BPF_MEM:
                mstr = f"{self._ld_dst(ins)} = M[{ins.k}];"
            elif pcap.BPF_MODE(ins.code) == pcap.BPF_LEN:
                mstr = f"{self._ld_dst(ins)} = data_end - data;"
            elif pcap.BPF_MODE(ins.code) == pcap.BPF_MSH:
                mstr = self._load_data_size(ins, "data") + "X = (X & 0xF)<< 2;"
            return mstr

        if pcap.BPF_CLASS(ins.code) == pcap.BPF_ST:
            return f"M[{ins.k}] = A;"
        if pcap.BPF_CLASS(ins.code) == pcap.BPF_STX:
            return f"M[{ins.k}] = X;"

        if pcap.BPF_CLASS(ins.code) == pcap.BPF_ALU:
            if pcap.BPF_OP(ins.code) == pcap.BPF_NEG:
                alustr = "A = -A;"
            elif pcap.BPF_OP(ins.code) > pcap.BPF_XOR:
                alustr = "NOT Support"
            else:
                alustr = f"A {self._alu_ops.get(pcap.BPF_OP(ins.code))}= {self._alu_src(ins)};"
            return alustr

        if pcap.BPF_CLASS(ins.code) == pcap.BPF_JMP:
            #  Conditional jt/jf targets replaced with jt/fall-through:
            # While the original design has constructs such as "if (cond) jump_true;
            # else jump_false;", they are being replaced into alternative constructs like
            # "if (cond) jump_true; /* else fall-through */".
            if pcap.BPF_OP(ins.code) == pcap.BPF_JA:
                jstr = f"goto {self._jump_label(ins.k)}"
            elif pcap.BPF_OP(ins.code) == pcap.BPF_JEQ:
                jstr = self._jump_cases(ins, "==", "!=")
            elif pcap.BPF_OP(ins.code) == pcap.BPF_JGT:
                jstr = self._jump_cases(ins, ">", "<=")
            elif pcap.BPF_OP(ins.code) == pcap.BPF_JGE:
                jstr = self._jump_cases(ins, ">=", "<")
            elif pcap.BPF_OP(ins.code) == pcap.BPF_JSET:
                jstr = self._jump_cases(ins, "&", "|")
            return jstr

        if pcap.BPF_CLASS(ins.code) == pcap.BPF_RET:
            if pcap.BPF_RVAL(ins.code) == pcap.BPF_A:
                rstr = "return A;"
            else:
                rstr = f"return {ins.k};"
            return rstr

        # if pcap.BPF_CLASS(ins.code) == pcap.BPF_MISC:
        if pcap.BPF_MISCOP(ins.code) == pcap.BPF_TAX:
            miscstr = "X = A;"
        elif pcap.BPF_MISCOP(ins.code) == pcap.BPF_TXA:
            miscstr = "A = X;"
        else:
            miscstr = "Invalid ins"
        return miscstr


def main():
    """
    This function takes command line arguments for running tcpdump and compiles
    a C function for a given filter.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface",
                        help="interface name to run tcpdump")
    parser.add_argument('filter', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.filter and len(args.filter) > 0:
        prog = CbpfProg(args.filter)
        prog_c = CbpfC(prog)
        cfun = prog_c.compile_cbpf_to_c()
        print(cfun)


if __name__ == '__main__':
    main()
