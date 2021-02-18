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
StgRetFun_p = gdb.lookup_type("StgRetFun").pointer()
StgRetInfoTable_p = gdb.lookup_type("StgRetInfoTable").pointer()
StgTSO_p = gdb.lookup_type("StgTSO").pointer()
StgWord_p = gdb.lookup_type('StgWord').pointer()

# Assumes TABLES_NEXT_TO_CODE

class InfoTsos(gdb.Command):
    "List all TSOs"

    def __init__(self):
        gdb.Command.__init__(self, "info tsos", gdb.COMMAND_STACK, gdb.COMPLETE_NONE)

    def invoke(self, argstr, _from_tty):
        args = argstr.split()
        only_running = "-r" in args
        compact = "-c" in args
        for t in all_tsos():
            if only_running and not t.running():
                continue
            print("TSO {} ({})".format(t.id(), t.status()))
            for obj in t.walk_stack():
                obj.print_frame(compact=compact)
            print()

class InfoTsoProfile(gdb.Command):
    "Dump stack traces of running TSOs as profile samples"

    def __init__(self):
        gdb.Command.__init__(self, "info tsoprofile", gdb.COMMAND_STACK, gdb.COMPLETE_NONE)

    def invoke(self, argstr, _from_tty):
        args = argstr.split()
        uniq = "-u" in args
        verbose = "-v" in args
        for t in running_tsos():
            try:
                stack = []
                prev = None
                for obj in t.walk_stack():
                    f = obj.cached_funcname()
                    if not verbose:
                        if f == "??" or f.startswith("stg_"):
                            # skip
                            continue
                    if uniq and f == prev:
                        continue
                    stack.append(f)
                    prev = f
                stack.reverse()
                print("PROFILE;" + ";".join(stack))
            except gdb.MemoryError as err:
                print("error:", err)

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

def running_tsos():
    n_caps = gdb.parse_and_eval('n_capabilities')
    caps = gdb.parse_and_eval('capabilities')

    for i in range(n_caps):
        cap = (caps + i).dereference()
        tso_p = cap['r']['rCurrentTSO']
        if not tso_p:
            continue
        yield TSO(tso_p)

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

    def running(self):
        what = int(self.tso["what_next"])
        if what == TSO.ThreadKilled:
            return False
        elif what == TSO.ThreadComplete:
            return False
        else:
            why = int(self.tso["why_blocked"])
            return why == TSO.NotBlocked

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

# Helpers to extract function names.

def pc_funcname(pc):
    try:
        func = gdb.execute("info symbol 0x%x" % pc, to_string=True)
    except Exception:
        return None
    if "_info" in func:
        func, _, _ = func.partition(" ")
        return func
    return None

def block_funcname(b):
    if b.function:
        return str(b.function)

    # At least in GHC 8.8, the start of a block is not a correct
    # approximation to retrieve a reliable symbol name, and may point
    # to a totally different symbol.
    #return pc_funcname(b.start)
    return None

def guess_funcname(pc):
    """
    Heuristical resolution of parent function name using line tables.
    """
    sym = gdb.find_pc_line(pc)
    if not sym.symtab:
        return None
    pcline = sym.line
    line = 0
    f = None
    for l in sym.symtab.linetable():
        if l.line > pcline:
            continue
        if l.line > line:
            try:
                s = gdb.block_for_pc(l.pc).function
            except Exception:
                s = None
            if s is None:
                continue
            if "zm" in s.name and "zi" in s.name and "_" in s.name:
                # looks like an ordinary function from a package
                line = l.line
                f = s.name
    return f

def clean_funcname(f):
    """
    Decodes and strips symbol name from any GHC decorations
    """
    if f is None:
        return None
    f = zdecode(f)
    if f.endswith("_ret_info"):
        f = f[:-len("_ret_info")]
    if f.endswith("_info"):
        f = f[:-len("_info")]
    return f

def pretty_funcname(f):
    """
    >>> pretty_funcname("aesonzm1zi4zi6zi0zmI0PKQM6ADfIKvzzTI4BNoug_DataziAttoparsecziTime_zdwf_info")
    'aeson:Data.Attoparsec.Time_$wf'
    """
    if f is None:
        return None
    f = clean_funcname(f)
    if '-' in f:
        # strip package version number and hash
        pkg, _, f = f.partition('_')
        pkg, _, _ = pkg.partition('.')
        pkg = pkg.rstrip("1234567890-")
        return pkg + ":" + f
    return f

class Closure:
    "A StgClosure generic heap object"
    def __init__(self, p):
        self.obj = p.cast(StgClosure_p).dereference()

    def frame_size(self):
        # see stack_frame_sizeW()
        retinfo = self.retinfo()
        ctyp = retinfo['i']['type']
        if ctyp == Closure.RET_FUN:
            size = self.obj.cast(StgRetFun_p).dereference()['size']
            return StgRetFun_p.target().sizeof // StgRetFun_p.sizeof + size
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

    funcname_cache = {}

    def cached_funcname(self):
        pc = self.pc()
        if pc not in self.funcname_cache:
            f = self.funcname(pretty=True)
            self.funcname_cache[pc] = f
        else:
            f = self.funcname_cache[pc]
        return f

    def funcname(self, pretty=False):
        clean = pretty_funcname if pretty else clean_funcname

        pc = self.pc()
        try:
            block = gdb.block_for_pc(pc)
        except Exception:
            block = None
        if block is not None:
            func = block_funcname(block)
            if func:
                return clean(func)

        # Try a parent block
        closure = False
        while block and block.superblock:
            block = block.superblock
            closure = True
            func = block_funcname(block)
            if func:
                return clean(func) + ":closure"

        func = pc_funcname(pc)
        if func:
            func = clean(func)
            if closure:
                func += ":closure"
            return func

        # Try heuristics
        if pretty and func is None:
            func = guess_funcname(pc)
            if func:
                func = clean(func)
                return func + ":??"

        return "??"

    def print_frame(self, compact=False):
        info = self.info()
        typ = int(info['type'])
        func = self.funcname(pretty=compact)
        if not func:
            func = str(self.info()['code'].address)

        pc = self.pc()
        if compact:
            sym = gdb.find_pc_line(pc)
            if sym.symtab:
                print("  0x{:016x} in {} at {}:{}".format(
                    pc, func, sym.symtab.filename, sym.line))
            else:
                print("  0x{:016x} in {}".format(pc, func))
        else:
            print("  {} (0x{:x}, type {})".format(
                func, pc, self.types_str.get(typ, typ)))
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
    """
    See https://gitlab.haskell.org/ghc/ghc/-/wikis/commentary/compiler/symbol-names

    >>> zdecode("base_TextziParserCombinatorsziReadP_zdfAlternativePzuzdczlzbzg_info")
    'base_Text.ParserCombinators.ReadP_$fAlternativeP_$c<|>_info'
    >>> zdecode("timezm1zi9zi3_DataziTimeziLocalTimeziInternalziTimeZZone_TimeZZone_con_info")
    'time-1.9.3_Data.Time.LocalTime.Internal.TimeZone_TimeZone_con_info'
    """
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
    "ZC": "ZC",
    "ZL": "(",
    "ZM": "[",
    "ZN": "]",
    "ZR": ")",
    "ZZ": "Z",
    "za": "&",
    "zb": "|",
    "zd": "$",
    "ze": "=",
    "zg": ">",
    "zh": "#",
    "zi": ".",
    "zl": "<",
    "zm": "-",
    "zn": "!",
    "zp": "+",
    "zq": "'",
    "zs": "/",
    "zt": "*",
    "zu": "_",
    "zz": "z",
}

InfoTsos()
InfoTsoProfile()
