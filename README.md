An experimental GDB plugin to introspect GHC runtime

# Commands

* info tsos : displays information about light threads (TSOs) in a
  running process.

# Sample output

A stack trace from binary distribution of GHCi (no line information)

```
TSO 98 (waiting for MVar)
  stg_block_takemvar (type small)
    ?:0
  stg_catch_frame (type catch)
    ?:0
  0x7f729849ff18 (type small)
    ?:0
  base_GHC.IO.FD_$wreadRawBufferPtr (type small)
    ?:0
  base_GHC.IO.FD_$w$cfillReadBuffer (type small)
    ?:0
  base_GHC.IO.Handle.Internals_hLookAhead_2 (type small)
    ?:0
  base_GHC.IO.Handle.Text_hGetChar2 (type small)
    ?:0
```
