from binaryninja.architecture import Architecture
from binaryninja.function import RegisterInfo, InstructionInfo, InstructionTextToken
from binaryninja.enums import InstructionTextTokenType

from .instr import decode, tT, REGS


class TS(Architecture):
    name = 'ts:ts'
    address_size = 4
    max_instr_length = 16

    regs = { r:RegisterInfo(r, 4) for r in REGS }
    stack_pointer = 'sp'

    def get_instruction_info(self, data, addr):

        r = decode(data, addr)

        if r is None:
            h = InstructionInfo()
            h.length = 12
            return h

        return r[1]

    def get_instruction_text(self, data, addr):

        r = decode(data, addr)

        if r is None:
            return [tT('unk')], 12

        return r[0], r[1].length

    def get_instruction_low_level_il(self, data, addr, il):

        r = decode(data, addr)

        if r is None:
            return 12

        if len(r) >= 3:
            fn = r[2]

            if fn is not None:
                if type(fn) is list:
                    for f in fn:
                        h = f(il)
                        if h is not None:
                            il.append(h)
                else:
                    h = fn(il)
                    if h is not None:
                        il.append(h)

            return r[1].length

        return 12

