"""
A plugin to introspect GHC's runtime (RTS)

References:

    https://gitlab.haskell.org/ghc/ghc/wikis/dwarf
    https://gitlab.haskell.org/ghc/ghc/wikis/commentary/rts/storage/stack
    https://gitlab.haskell.org/ghc/ghc/wikis/commentary/rts/storage/heap-objects
"""

from __future__ import print_function

if sys.version_info.major == 2:
    range = xrange

# Common types
StgClosure_p = gdb.lookup_type("StgClosure").pointer()
StgInfoTable_p = gdb.lookup_type("StgInfoTable").pointer()
StgRetInfoTable_p = gdb.lookup_type("StgRetInfoTable").pointer()
StgTSO_p = gdb.lookup_type("StgTSO").pointer()
StgWord_p = gdb.lookup_type('StgWord').pointer()

# Assumes TABLES_NEXT_TO_CODE

class InfoTsos(gdb.Command):
    "List all TSOs"

    def __init__(self):
        gdb.Command.__init__(self, "info tsos", gdb.COMMAND_STACK, gdb.COMPLETE_NONE)

    def invoke(self, _arg, _from_tty):
        for t in all_tsos():
            print("TSO {} ({})".format(t.id(), t.status()))
            for obj in t.walk_stack():
                obj.print_frame()
            print()

def all_tsos():
    # See rts/Threads.c:printAllThreads
    n_caps = gdb.parse_and_eval('n_capabilities')
    caps = gdb.parse_and_eval('capabilities')
    n_gcgens = gdb.parse_and_eval('RtsFlags.GcFlags.generations')
    gcgens = gdb.parse_and_eval('generations')

    for i in range(n_caps):
        cap = (caps + i).dereference()
        t = TSO(cap['run_queue_hd'])
        while t is not None and not t.is_end():
            yield t
            t = t.link()

    for i in range(n_gcgens):
        g = (gcgens + i).dereference()
        t = TSO(g['threads'])
        while t is not None and not t.is_end():
            yield t
            t = t.global_link()

class TSO:
    "A StgTSO object"

    def __init__(self, p):
        self.tso = p.dereference()

    def addr(self):
        return self.tso.address

    def is_end(self):
        end = gdb.parse_and_eval('&stg_END_TSO_QUEUE_closure').cast(StgTSO_p)
        return self.addr() == end

    def link(self):
        l = self.tso["_link"]
        return TSO(l)

    def global_link(self):
        l = self.tso["global_link"]
        return TSO(l)

    def id(self):
        return int(self.tso["id"])

    def status(self):
        what = int(self.tso["what_next"])
        if what == TSO.ThreadKilled:
            return "killed"
        elif what == TSO.ThreadComplete:
            return "completed"
        else:
            why = int(self.tso["why_blocked"])
            return TSO.why_str.get(why, "status {}".format(why))

    def walk_stack(self):
        # see rts/Printer.c:printTSO
        stack = self.tso['stackobj'].dereference()
        sp = stack['sp']
        base = stack['stack'].cast(StgWord_p)
        top = base + int(stack['stack_size'])
        #print("    stack", sp, "->", top)
        while int(sp) < int(top):
            obj = Closure(sp)
            yield obj
            sp += obj.frame_size()

    # from rts/Constants.h
    ThreadRunGHC = 1
    ThreadInterpret = 2
    ThreadKilled = 3
    ThreadComplete = 4

    NotBlocked = 0
    BlockedOnMVar = 1
    BlockedOnBlackHole = 2
    BlockedOnRead = 3
    BlockedOnWrite = 4
    BlockedOnDelay = 5
    BlockedOnSTM = 6
    BlockedOnDoProc = 7
    BlockedOnCCall = 10
    BlockedOnCCall_Interruptible = 11
    BlockedOnMsgThrowTo = 12
    ThreadMigrating = 13
    BlockedOnMVarRead = 14

    why_str = {
        NotBlocked: "not blocked",
        BlockedOnMVar: "waiting for MVar",
        BlockedOnBlackHole: "waiting for black hole",
        BlockedOnRead: "waiting on read",
        BlockedOnWrite: "waiting on write",
        BlockedOnDelay: "sleep",
        BlockedOnSTM: "blocked on STM",
        BlockedOnDoProc: "blocked on proc",
        BlockedOnCCall: "blocked on ccall",
        BlockedOnCCall_Interruptible: "blocked on interruptible ccall",
        BlockedOnMsgThrowTo: "throwto",
        ThreadMigrating: "migrating",
        BlockedOnMVarRead: "waiting for MVar read",
    }

class Closure:
    "A StgClosure generic heap object"
    def __init__(self, p):
        self.obj = p.cast(StgClosure_p).dereference()

    def frame_size(self):
        # see stack_frame_sizeW()
        retinfo = self.retinfo()
        ctyp = retinfo['i']['type']
        if ctyp == Closure.RET_FUN:
            raise NotImplementedError("barf")
        elif ctyp == Closure.RET_BIG:
            raise NotImplementedError("barf")
        elif ctyp == Closure.RET_BCO:
            raise NotImplementedError("barf")
        else:
            # for 64-bit only
            return 1 + (retinfo['i']['layout']['bitmap'] & 0x3f)

    def info(self):
        info = self.obj['header']['info']
        p = info.cast(StgInfoTable_p) - 1
        return p.dereference()

    def retinfo(self):
        info = self.obj['header']['info']
        p = info.cast(StgRetInfoTable_p) - 1
        return p.dereference()

    def pc(self):
        p = self.obj.address.cast(StgWord_p)
        return int(p.dereference())

    def lineno(self):
        sym = gdb.find_pc_line(self.pc())
        return "{}:{}".format(
            sym.symtab.filename if sym.symtab else '?', sym.line)

    def funcname(self):
        pc = self.pc()
        block = gdb.block_for_pc(pc)
        if block is not None:
            if block.function:
                return zdecode(str(block.function))
            func = gdb.execute("info symbol 0x%x" % block.start, to_string=True)
            if "_info" in func:
                func, _, _ = func.partition("_info")
                return zdecode(func)

        closure = False
        while block and block.superblock:
            block = block.superblock
            closure = True
            if block.function:
                return "closure in " + zdecode(str(block.function))

            func = gdb.execute("info symbol 0x%x" % block.start, to_string=True)
            if "_info" in func:
                func, _, _ = func.partition("_info")
                return "closure in " + zdecode(func)

        func = gdb.execute("info symbol 0x%x" % pc, to_string=True)
        if "_info" in func:
            func, _, _ = func.partition("_info")
        if "No symbol" in func:
            return "??"

        return ("closure in " if closure else "") + zdecode(func)

    def print_frame(self):
        info = self.info()
        typ = int(info['type'])
        func = self.funcname()
        if not func:
            func = str(self.info()['code'].address)
        print("  {} (0x{:x}, type {})".format(
            func, self.pc(), self.types_str.get(typ, typ)))
        print("   ", self.lineno())

    # from rts/storage/ClosureTypes.h
    RET_BCO = 29
    RET_SMALL = 30
    RET_BIG = 31
    RET_FUN = 32
    CATCH_FRAME = 34
    STOP_FRAME = 36
    ATOMICALLY_FRAME = 55

    types_str = {
        RET_BCO: "bytecode",
        RET_SMALL: "small",
        CATCH_FRAME: "catch",
        STOP_FRAME: "stop",
        ATOMICALLY_FRAME: "atomically",
    }

def zdecode(s):
    res = ""
    while s:
        idx_z = s.find("z")
        idx_Z = s.find("Z")
        if idx_z < 0 and idx_Z < 0:
            res += s
            return res
        elif idx_z < 0:
            idx = idx_Z
        elif idx_Z < 0:
            idx = idx_z
        else:
            idx = min(idx_z, idx_Z)
        res += s[:idx]
        tok = s[idx:idx+2]
        s = s[idx+2:]
        res += ztrans.get(tok, tok)
    return res

ztrans = {
    "zz": "z",
    "za": "&",
    "zd": "$",
    "zh": "#",
    "zi": ".",
    "zm": "-",
    "zu": "_",
}

InfoTsos()
