
from binaryninja.function import RegisterInfo, InstructionInfo, InstructionTextToken
from binaryninja.enums import InstructionTextTokenType, BranchType, LowLevelILOperation
from binaryninja.architecture import Architecture
from binaryninja.lowlevelil import LowLevelILLabel

# binary ninja text helpers
def tI(x): return InstructionTextToken(InstructionTextTokenType.InstructionToken, x)
def tR(x): return InstructionTextToken(InstructionTextTokenType.RegisterToken, x)
def tS(x): return InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, x)
def tM(x): return InstructionTextToken(InstructionTextTokenType.BeginMemoryOperandToken, x)
def tE(x): return InstructionTextToken(InstructionTextTokenType.EndMemoryOperandToken, x)
def tA(x,d): return InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, x, d)
def tT(x): return InstructionTextToken(InstructionTextTokenType.TextToken, x)
def tN(x,d): return InstructionTextToken(InstructionTextTokenType.IntegerToken, x, d)

REGS = ['r%d' % x for x in range(4)]
REGS += ['sp', 'hlt', 'ret']


def u32(dat):
    x = 0
    x += dat[0]
    x += (dat[1] << 8)
    x += (dat[2] << 16)
    x += (dat[3] << 24)
    return x

def u16(dat):
    x = 0
    x += dat[0]
    x += (dat[1] << 8)
    return x

def il_jump(il, dest, is_call=False):

    if is_call:
        il.append(il.call(dest))
    else:
        # lookup label 
        t = None
        if il[dest].operation == LowLevelILOperation.LLIL_CONST:
            t = il.get_label_for_address(Architecture['ts:ts'], il[dest].constant)

        # if the label doesn't exist, create a new one
        indirect = False
        if t is None:
            t = LowLevelILLabel()
            indirect = True

        # if it doesn't exist, create and jump
        if indirect:
            il.mark_label(t)
            il.append(il.jump(dest))
        else:
            # just goto label
            il.append(il.goto(t))

def il_branch(il, cond, tdest, fdest):
    
    # lookup the true branch
    t_target = None
    if il[tdest].operation == LowLevelILOperation.LLIL_CONST:
        t_target = il.get_label_for_address(Architecture['ts:ts'], il[tdest].constant)

    # if the label doesn't exist, create a new one
    indirect = False
    if t_target is None:
        t_target = LowLevelILLabel()
        indirect = True

    # create the false branch
    f_target = LowLevelILLabel()

    # create the if_expr
    il.append(il.if_expr(cond, t_target, f_target))

    # handle true target if indirect
    if indirect:
        il.mark_label(t_target)
        il.append(il.jump(tdest))

    # mark false branch
    il.mark_label(f_target)

def read_data(b):

    mode = b & 0b11
    val = b >> 2

    if mode == 0:
        return (
            [tN(hex(val), val)],
            lambda il: il.const(4,val)
        )
    elif mode == 1:
        return (
            [tR(REGS[val])],
            lambda il: il.reg(4, REGS[val])
        )
    elif mode == 2:
        return (
            [tM('['), tA(hex(val*4), val*4), tE(']')],
            lambda il: il.load(4, il.const(4, val*4))
        )
    elif mode == 3:
        return (
            [tM('['), tR(REGS[val]), tE(']')],
            lambda il: il.load(4, il.mult(4, il.const(4,4), il.reg(4, REGS[val])))
        )

def get_known_read_type(b):
    mode = b & 0b11
    val = b >> 2

    if mode == 0:
        return val
    else:
        return None


def write_data(a):
    mode = a & 0b11
    val = a >> 2

    if mode == 0:
        return (
            [tT('???')],
            lambda il, dat: il.const(4,0)
        )
    elif mode == 1:
        return (
            [tR(REGS[val])],
            lambda il, dat: il.set_reg(4, REGS[val], dat)
        )
    elif mode == 2:
        return (
            [tM('['), tA(hex(val*4), val*4), tE(']')],
            lambda il, dat: il.store(4, il.const(4, val*4), dat)
        )
    elif mode == 3:
        return (
            [tM('['), tR(REGS[val]), tE(']')],
            lambda il, dat: il.store(4, il.mult(4, il.const(4,4), il.reg(4, REGS[val])), dat)
        )

def out(a):
    info = InstructionInfo()
    info.length = 8
    info.add_branch(BranchType.UnresolvedBranch)

    rtok, ril = read_data(a)

    tok = [tI('out'), tT(' '), *rtok]
    
    fn = lambda il: il.jump(il.reg(4, 'hlt'))

    return (tok, info, fn)

def write(a,b):
    info = InstructionInfo()
    info.length = 12

    rtok, ril = read_data(b)
    wtok, wil = write_data(a)

    tok = [tI('set'), tT(' '), *wtok, tS(', '), *rtok]
    
    fn = lambda il: wil(il, ril(il))

    return (tok, info, fn)

def simple(a,b,op,name):
    info = InstructionInfo()
    info.length = 12

    wtok, wil = write_data(a)
    rtok_1, ril_1 = read_data(a)
    rtok_2, ril_2 = read_data(b)

    tok = [tI(name), tT(' '), *wtok, tS(', '), *rtok_1, tS(', '), *rtok_2]
    
    fn = lambda il: wil(il, op(il, ril_1, ril_2))

    return (tok, info, fn)

def neg(a,b):
    info = InstructionInfo()
    info.length = 12

    wtok, wil = write_data(a)
    rtok_1, ril_1 = read_data(b)

    tok = [tI('neg'), tT(' '), *wtok, tS(', '), *rtok_1]
    
    fn = lambda il: wil(il.sub(4, il.const(4,0), ril_1(il)))

    return (tok, info, fn)

def clip(a,b):
    info = InstructionInfo()
    info.length = 12

    wtok, wil = write_data(a)
    rtok_1, ril_1 = read_data(b)

    tok = [tI('clip'), tT(' '), *wtok, tS(', '), *rtok_1]
    
    fn = lambda il: wil(il.and_expr(4, il.const(4,0xffff), ril_1(il)))

    return (tok, info, fn)


def branch_inst(a, b, addr):
    info = InstructionInfo()
    info.length = 12

    br = get_known_read_type(a)
    if br is not None:
        info.add_branch(BranchType.TrueBranch, addr + 12 + (br * 4)) 

    info.add_branch(BranchType.FalseBranch, addr + 12)

    rtok_1, ril_1 = read_data(a)
    rtok_2, ril_2 = read_data(b)

    tok = [tI('bz'), tT(' '), *rtok_2, tS(', '), tA(hex(addr + 12 + (br*4)), (addr + 12 + (br*4)))]
    
    fn = []
    r1 = lambda il: ril_1(il)
    r2 = lambda il: il.const(4, 0)
    tdest = lambda il: il.add(4, il.const(4, addr + 12), il.mult(4, ril_1(il), il.const(4,4)))
    fdest = lambda il: il.const(4, addr + 12)

    fn = lambda il: il_branch(il, il.compare_equal(4, r1(il), r2(il)), tdest(il), fdest(il))

    return (tok, info, [fn])

def call_instr(a):
    info = InstructionInfo()
    info.length = 8

    br = get_known_read_type(a)
    if br is not None:
        info.add_branch(BranchType.CallDestination, br * 4)

    rtok_1, ril_1 = read_data(a)

    tok = [tI('call'), tT(' '), tA(hex(br * 4), br*4)]

    fn = lambda il: il_jump(il, il.const(4, br*4), is_call=True)

    return (tok, info, fn)

def jump_instr(a, addr):
    info = InstructionInfo()
    info.length = 8

    br = get_known_read_type(a)
    target = (addr+8)+(br*4)
    target = target &  0xffff
    if br is not None:
        info.add_branch(BranchType.UnconditionalBranch, target)

    rtok_1, ril_1 = read_data(a)

    tok = [tI('jmp'), tT(' '), tA(hex(target), target)]

    fn = lambda il: il_jump(il, il.const(8, target), is_call=False)

    return (tok, info, fn)

def ret_instr():
    info = InstructionInfo()
    info.length = 4

    info.add_branch(BranchType.UnresolvedBranch)
    
    tok = [tI('ret')]

    return (tok, info, None)

def named(op, len):
    info = InstructionInfo()
    info.length = len

    tok = [tI(op)]

    fn = lambda il: il.nop()

    return (tok, info, fn)

def op11(dat):
    info = InstructionInfo()
    info.length = 16

    a = u32(dat[4:])
    b = u32(dat[8:])
    c = u32(dat[12:])

    rtok_1, ril_1 = read_data(a)
    rtok_2, ril_2 = read_data(b)
    rtok_3, ril_3 = read_data(c)

    tok = [tI('setobj'), tT(' '), *rtok_1, tS(', '), *rtok_2, tS(', '), *rtok_3]

    return (tok, info, None)

def op12(dat):
    info = InstructionInfo()
    info.length = 16

    a = u32(dat[4:])
    b = u32(dat[8:])
    c = u32(dat[12:])

    rtok_1, ril_1 = read_data(a)
    rtok_2, ril_2 = read_data(b)
    rtok_3, ril_3 = read_data(c)

    tok = [tI('getobj'), tT(' '), *rtok_1, tS(', '), *rtok_2, tS(', '), *rtok_3]

    return (tok, info, None)


def decode(dat, addr):

    if len(dat) < 16:
        dat = dat + (b'\x00' * (16-len(dat)))

    x = u32(dat)
    a = u32(dat[4:])
    b = u32(dat[8:])

    if x == 0: return out(a)
    elif x == 1: return write(a,b)
    elif x == 2: return simple(a, b, lambda il,a,b: il.add(4,a(il),b(il)), 'add')
    elif x == 3: return simple(a, b, lambda il,a,b: il.mult(4,a(il),b(il)), 'mul')
    elif x == 4: return simple(a, b, lambda il,a,b: il.and_expr(4,a(il),b(il)), 'and')
    elif x == 5: return simple(a, b, lambda il,a,b: il.or_expr(4,a(il),b(il)), 'or')
    elif x == 7: return simple(a, b, lambda il,a,b: il.or_expr(4,a(il),b(il)), 'sne')
    elif x == 8: return neg(a,b)
    elif x == 9: return jump_instr(a, addr)
    elif x == 10: return branch_inst(a, b, addr)
    elif x == 11: return op11(dat)
    elif x == 12: return op12(dat)
    elif x == 13: return clip(a,b)
    elif x == 14: return call_instr(a)
    elif x == 15: return ret_instr()

    
    return None
