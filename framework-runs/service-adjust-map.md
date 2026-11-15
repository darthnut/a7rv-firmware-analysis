# The host-side adjustment command vocabulary of the Sony a7R V factory tool

**Subject.** `adjstctl.elf` (the on-target adjustment/diagnostic CLI) and `libtestcmd.so` (its command-framing
library) — the two host-side objects that turn a *command name* into an *opcode on the wire*.
**Scope.** What the tool *holds* and what the tool *sends*. The camera-side handler of each command is out of
scope and is not described anywhere in this document.
**Method constraint that shapes this document.** Not one function *body* was read (see
[How this was checked](#how-this-was-checked)). Everything below comes from ELF metadata, symbol tables,
relocation tables and raw byte dumps. Claims that are not direct measurements are tagged **HYPOTHESIS**.

Nothing here reproduces key material, the firmware image, or any device-specific secret: the artefacts below
are command names, table offsets and 32-bit identifiers, which are the thing being documented.

Artifacts examined (all from the unpacked rootfs of the user's own a7R V firmware):

```
$ ls -l /srv/a7rv/a7rv-fw/fs/a15/bin/adjstctl.elf /srv/a7rv/a7rv-fw/fs/a15/lib/libtestcmd.so /srv/a7rv/a7rv-fw/fs/a15/lib/libosal_uipc.so
-r--r--r--. 1 claude claude 141488 Oct 30  2025 /srv/a7rv/a7rv-fw/fs/a15/bin/adjstctl.elf
-r--r--r--. 1 claude claude  43752 Oct 30  2025 /srv/a7rv/a7rv-fw/fs/a15/lib/libosal_uipc.so
-r--r--r--. 1 claude claude  18504 Oct 30  2025 /srv/a7rv/a7rv-fw/fs/a15/lib/libtestcmd.so
```

---

## Part A — the command vocabulary, and how big each family is

### A.1 The vocabulary is one flat static table of 1779 entries

`adjstctl.elf` is AArch64 `ET_EXEC` (non-PIE). Its `.rodata` is 129 KB and almost all of it is one table:

```
$ readelf -SW /srv/a7rv/a7rv-fw/fs/a15/bin/adjstctl.elf | grep -E 'rodata|text|data|bss|got|plt|rela'
[ 8] .rela.dyn         RELA            0000000000400b58 000b58 000030 18   A  4   0  8
[ 9] .rela.plt         RELA            0000000000400b88 000b88 000300 18  AI  4  21   8
[11] .plt              PROGBITS        0000000000400ea0 000ea0 000220 10  AX  0   0 16
[12] .text             PROGBITS        00000000004010c0 0010c0 000974 00  AX  0   0  8
[14] .rodata           PROGBITS        0000000000401a48 001a48 01f845 00  A  0   0  8
```

The table occupies **vaddr `0x401a64` … `0x420ebc`** = 131,704 bytes = **1779 records × 72 bytes**, each record

```c
struct adjcmd {          /* 72 bytes */
    uint32_t  f0;        /* +0x00 : group tag, 125 distinct values (see A.4) */
    uint32_t  f1;        /* +x04  : the command id = (u16 code, u16 block) (see B.3) */
    char      name[64];  /* +0x08 : NUL-terminated command name */
};
```

Phase was pinned by three independent measurements, all this session:

```
$ objdump -s --start-address=0x401a48 --stop-address=0x401a88 /srv/a7rv/a7rv-fw/fs/a15/bin/adjstctl.elf
 401a48 01000200 00000000 00000000 00000000  ................
 401a58 00000000 00000000 00000000 00000000  ................
 401a68 01010110 4150505f 54455354 434d4400  ....APP_TESTCMD.
```
→ record 0 begins at `0x401a64`: `f0 = 00000000`, `f1` (LE `01 01 01 10`) `= 0x10010101`, name at `0x401a6c`.

```
$ objdump -s --start-address=0x420e70 --stop-address=0x420ed0 ...
 420e70 00000000 ab091983 ffff0000 554e4b4e   ............UNKN
 420e80 4f574e00 00000000 00000000 00000000   OWN.............
 420ec0 6d6f6465 3a202020 30782530327800 72   mode:   0x%02x.r
```
→ the last record (`ROW 1778` @ `0x420e74`) is the sentinel `UNKNOWN` with `f1 = 0x0000ffff`; the table ends at
`0x420ebc`, and `0x420ec0` starts the tool's `printf` format strings (Part B.4).

Third measurement — the stride decode itself, plus the padding shape of the `name[64]` field:

```
decoded=1779 distinct_first_tokens=250 max_name_len=39 longest=WLAN_GEN_DYNAMIC_FACTORY_INFO_FOR_MULTI
records_nul_padded_after_name=1779 space_padded=0 other_padding=0 empty=0
hexchars=256176 records_in_stream=1779 decoded=1779
```

→ the dumped region is exactly `256176` hex chars = `1779 × 72` bytes with nothing left over; all **1779**
records decode to a printable name; every one is NUL-terminated with pure-`00` padding to 64 bytes (no space
padding, no empty record); longest name is 39 characters, so `name[64]` is a fixed field, not a compacted one.

### A.2 Counts by verb family (name prefix, measured)

```
$ objdump -s --start-address=0x401a64 --stop-address=0x420ebc <elf> | awk '<decode 72-byte records>'
LOAD_     1
EXEC_     97
SET_      64
WRITE_    9
GET_      57
READ_     23
DIAG_     50
C_DIAG    3
ADJ_      2
ADJSTART  1
ADJEND    1
AFADJ     1
total=1779 names_containing_ADJ=84 distinct_first_tokens=250
```

So: **read-ish (`GET_` + `READ_`) = 80, write/execute-ish (`EXEC_` + `SET_` + `WRITE_` + `LOAD_`) = 171,
diagnostics (`DIAG_` + `C_DIAG`) = 53, adjustment (`ADJ_`, `ADJSTART`, `ADJEND`, `AFADJ_`) = 5 explicit**, and
**84 names contain the substring `ADJ`** anywhere — the adjustment surface is much wider than the 5 that lead
with it, because adjustment verbs are embedded inside subsystem families (`PANELEVF_EVF_ADJ_TEMP_INIT`,
`A_AS_BRGAIN_ADJ`, `S_LC_ADJ_STAT_RST`, `KEYSTONE_ADJ`, `OUTSIDE_EVF_OLED_TMP_ADJ`, …).

### A.3 Counts by subsystem family (first token, top 16 by frequency, measured)

```
198 A
181 S
 97 EXEC
 86 DD
 84 C
 64 SET
 57 GET
 52 MPR
 50 DIAG
 47 WLAN
 28 IB
 27 G
 25 PANELEVF
 25 CTP
 25 AVBB
 23 READ
```

`A` (198) and `S` (181) are single-letter namespace prefixes (`A_INF_ADJ`, `S_TC_ADJ_MODE`, …), not one
subsystem. There are **250 distinct first tokens** in total, i.e. the vocabulary is not a handful of big
families — it is ~250 namespaces, the largest holding 11 % of the commands. **Do not read this as ~1779
independent commands to try**: the counts are a map of a manufacturing vocabulary, not a menu.

### A.4 Two structural groupings inside the table (measured)

```
f0_tags=125 tags_in_one_contiguous_run=122 total_runs=131
entries_with_f1_byte3_nonzero=525 of 1779 ; distinct_f1_high16=520
distinct_f1_low16=153 distinct_f1_high16=520 entries=1779
```

* **`f0` (the word before the id): 125 distinct values, and 122 of the 125 appear in exactly one contiguous
  run of the table** (131 runs total = **130** `f0` boundaries, measured). The table is physically sorted by
  `f0`, so `f0` is a block-of-entries tag. Its semantics are **not** established here, and it is *not* the
  name-prefix family: of those 130 `f0` boundaries, only **54** coincide with a change of the name's first
  token — the other **76** happen *inside* one first-token family, and **79 of the 250** first-token families
  are split across 2 or more `f0` tags. **HYPOTHESIS:** `f0` is a destination/router tag (module handle or
  hash) used by the IPC layer, not a human-meaningful family key. Not shown.
* **`f1` is the command id** — 1778 distinct values out of 1779 entries; see B.3 for its structure and the
  single collision.

---

## Part B — framing: how a command name becomes bytes on the wire

### B.1 Toolchain reality — read this before trusting any sentence in this part

The brief said to use the `ghidra_svc` Ghidra project for these two binaries and, if one is missing, to do
that part from `nm`/`strings`/`readelf` **and say so**. Both are missing from every Ghidra project reachable
in this session (four servers, four projects, exact program lists in the footer), and this box has an
x86-only binutils (`objdump: can't disassemble for architecture UNKNOWN!`), no capstone, no llvm-objdump.
**No instruction of `testcmd_sndmsg`, `cmdline_get_id`, `cmdline_get_opts` or any other function was read.**
The framing path below is therefore assembled from *import/export symbols, relocations and literal strings*,
which pins **who calls whom** exactly, and **not** the order of instructions inside any function. Sentences
about call order inside a function body are tagged **HYPOTHESIS**.

### B.2 The layering (measured from `.dynsym` / `DT_NEEDED`)

`adjstctl.elf` → `libtestcmd.so` → `libosal_uipc.so`. It does not skip a layer:

```
$ readelf -dW .../bin/adjstctl.elf | grep NEEDED
 (NEEDED)  Shared library: [libosal_uipc.so]
 (NEEDED)  Shared library: [libtestcmd.so]
 (NEEDED)  Shared library: [libpthread.so.0]   ... libstdc++ / libm / libdl / libgcc_s / libc / librt
```

`adjstctl.elf`'s complete import set is 36 symbols; the interesting half:

```
$ readelf -sW .../bin/adjstctl.elf | grep 'UND' | awk '{print $8}' | sort
cmdline_get_ibfile   cmdline_get_id      cmdline_get_ifile  cmdline_get_obfile
cmdline_get_opts     cmdline_get_sync    cmdline_init       cmdline_read_data_from_args
cmdline_read_data_from_file              cmdline_read_data_from_ibfile
cmdline_show_revision cmdline_show_usage cmdline_write_bindata_to_stdout
cmdline_write_data_to_obfile             testcmd_sndmsg
mmap@GLIBC_2.17  munmap@GLIBC_2.17  open@GLIBC_2.17  close@GLIBC_2.17
strncmp@GLIBC_2.17  strtoul@GLIBC_2.17  fopen/fclose/fprintf/fputc/fwrite/fread-free...
```

Two facts fall out of that list, both measured:

1. **`adjstctl` never calls the IPC layer directly.** No `osal_*` symbol is imported by `adjstctl`. Its only
   send entry point is `testcmd_sndmsg`. It also imports **no** `socket`/`connect`/`ioctl`/`send` — so from
   the tool's own symbol view the framing boundary is exactly one function wide.
2. **`adjstctl` mmaps physical memory** (`open` + `mmap` + `munmap`, and the literal `/dev/mem` sits in its
   `.rodata` at `0x42122a`, right after the option names — `step` @ `0x42121e`, `getlog` @ `0x421223`). **HYPOTHESIS:** a mailbox/queue region is mapped for the payload, since no other
   device I/O is imported. Which mapping `osal_snd_msg` ultimately uses is camera-side/`libosal_uipc`
   internals — not read, not claimed.

`libtestcmd.so` is where the framing lives. Its exports and its own imports:

```
$ readelf -sW .../lib/libtestcmd.so | awk '$4=="FUNC" && $5=="GLOBAL"{...}'   (exports, vaddr/size)
testcmd_cb      0x1a18/300   testcmd_init    0x1e1c/32    testcmd_sndmsg  0x1e3c/264
do_read         0x19b0/52    do_write        0x19e4/52    do_wait         0x1b44/60
__rcvmsg        0x1b80/120   testcmd_rcvmsg  0x1f44/120   testcmd_run_scenario 0x1bf8/548
cmdline_init    0x1ffc/64    cmdline_get_opts 0x28d8/280  cmdline_get_id  0x29f0/128
cmdline_get_sync 0x2838/20   cmdline_get_sid 0x284c/68    cmdline_get_size 0x2b0c/312
cmdline_get_ibfile 0x28b8/16 cmdline_get_ifile 0x28a8/16  cmdline_get_obfile 0x28c8/16
cmdline_read_data_from_args 0x2220/144  cmdline_read_data_from_ibfile 0x22f8/164
cmdline_read_data_from_file 0x249c/180  cmdline_write_data_to_obfile 0x239c/164
cmdline_write_data_via_args 0x2658/144  cmdline_write_data_via_file 0x26e8/184
cmdline_write_bindata_to_stdout 0x2a70/156  cmdline_setup_cb 0x2c44/116
cmdline_setup_logio 0x2828/16  cmdline_show_usage 0x27a0/136  cmdline_show_revision 0x1fbc/64

$ readelf -sW .../lib/libtestcmd.so | grep 'UND' | grep osal     (its IPC imports)
osal_set_msg_src  osal_msg_size  osal_snd_msg  osal_rcv_msg_tmo  osal_get_msg_src
osal_valloc_msg_wait  osal_unreg_msg_queue_cb  osal_reg_sync_msg_queue_cb
osal_snd_sync_msg  osal_free_msg  osal_reg_msg_queue_cb
```

Crossing off the 31 exports of `libtestcmd` against the 15 `cmdline_*`/`testcmd_*` imports of `adjstctl`:
`adjstctl` uses **15** of them, and notably **not** `testcmd_rcvmsg`, `testcmd_cb`, `testcmd_init`,
`cmdline_setup_cb`, `cmdline_get_sid`, `cmdline_get_size`, `do_read`, `do_write`, `do_wait`, `__rcvmsg` —
those exist but are internal to `libtestcmd`'s own send/wait path.

**The framing path, as far as symbols can prove it:**

```
argv  →  cmdline_get_opts (getopt_long, caller-supplied option table)
      →  cmdline_read_data_from_args / _from_file / _from_ibfile   (payload bytes)
      →  cmdline_get_id / cmdline_get_sync                          (id + sync flag)
      →  testcmd_sndmsg                                             (the single send call in adjstctl)
      →  osal_snd_msg  |  osal_snd_sync_msg   (+ osal_msg_size, osal_set_msg_src)
      →  libosal_uipc.so                                            (out of this document)
reply ←  osal_rcv_msg_tmo / osal_valloc_msg_wait → __rcvmsg / testcmd_rcvmsg / testcmd_cb
         →  "rcv msg from 0x%x size %d @ %p\n"
```

The sync/async fork is a measured *choice of symbol*, not a read of the branch: `libtestcmd` imports both
`osal_snd_msg` and `osal_snd_sync_msg`, `adjstctl` imports `cmdline_get_sync`, so the sync flag selects the
pair. Which one runs for which command is **HYPOTHESIS**.

`libtestcmd`'s entire `.rodata` is 129 bytes and contains every string the framing layer can print:

```
$ objdump -s --start-address=0x2cd8 --stop-address=0x2d59 .../lib/libtestcmd.so
 2cd8  ...  rcv msg from 0x%x size %d @ %p..
 2cf8  ...  13:44:18.Oct 31 2025.1.7.verion: %s @ %s %s..r.r      ← build stamp "1.7", Oct 31 2025 (sic "verion")
 2d28  b\0Usage: %s %s\0o
 2d38  ptions\0 0x%02x \0
 2d48  wb\0%c:0x%x\0%s:%s\0
```

Two things worth stating: the framing layer prints payload bytes as `"0x%02x "` and `"0x%02x"`/`"%c:0x%x"`,
and **it owns no `getopt` option string and no long-option names** — the option vocabulary is supplied by the
caller (B.4). That is how the same `libtestcmd` can serve several front-ends.

### B.3 Name → opcode: the table at `0x401a64`, and the id's own structure

The name→id mapping is *not* a hash and *not* a per-command function pointer. It is the flat table of A.1:
`adjstctl` is non-PIE, its `.rela.dyn` is 3 entries (`__gmon_start__`, `stdout`, one more) and contains **no
`R_AARCH64_RELATIVE`**, so nothing points at the table by relocation — each name is reached at a fixed
absolute address, and a 72-byte stride scan decodes all 1779 records cleanly. `strncmp` is imported by
`adjstctl` (`UND strncmp@GLIBC_2.17`) and `strtoul` too — **HYPOTHESIS:** lookup is a linear `strncmp` over
the table (that is what those two imports plus a flat table imply); the loop itself was not read.

The id word `f1` is itself structured. Reading it as two little-endian `u16` halves
(`u16 block` at `f1+0`, `u16 code` at `f1+2`):

```
  PANELEVF_ADJ_START           f1=0x00010302 -> high16=0x0001 low16=0x0302
  PANELEVF_ADJ_END             f1=0x00050302 -> high16=0x0005 low16=0x0302
  PANELEVF_EVF_ADJ_TEMP_INIT   f1=0x00070302 -> high16=0x0007 low16=0x0302
  PANELEVF_EVF_ADJ_TEMP_STAR   f1=0x00080302 -> high16=0x0008 low16=0x0302
  PANELEVF_EVF_ADJ_TEMP_CONF   f1=0x00090302 -> high16=0x0009 low16=0x0302
  PANELEVF_EVF_ADJ_TEMP_INFO   f1=0x000a0302 -> high16=0x000a low16=0x0302
  PANELEVF_EVF_ADJ_TEMP_END    f1=0x000b0302 -> high16=0x000b low16=0x0302
  PANELEVF_EVF_OLED_W_WB_RIGHT f1=0x001b0302 -> high16=0x001b low16=0x0302
distinct_f1_low16=153 distinct_f1_high16=520 entries=1779
```

Measured: **153 distinct `block` values, 520 distinct `code` values**; inside a subsystem run the `block` half
is constant and `code` increments by 1 (0x0007→0x000b above). The tool's own CLI words corroborate the split
— its usage line and display strings are literally `[adjust_block] [adjust_code]` and
`"adjust block: 0x%04x, code: 0x%04x"` (B.4) — and start/end pairs land in one block: `ADJSTART`
block `0x0501` code `0x0001` vs `ADJEND` block `0x0501` code `0x0002`; `ADJ_MIC_SENSE` block `0x0303` code
`0x0001` vs `ADJ_MIC_SENSE_RESULT` block `0x0303` code `0x0002`. **The byte layout (two u16s, block first) is
measured; the labels "block"/"code" for the two halves are inference** from the format strings and the pairing
consistency.

**The mapping is not injective in either direction** (measured, Part C.3): two names share one id, and one
name appears with two ids.

A `strings` trap, worth recording because it looks like data: run naively, `strings -t x` over this region
emits 1779 name-like strings, **184 of which begin with `@`** (`@DIAG_READ_SENSOR_ALL`, `@RAM_READ`,
`@KEYSTONE_ADJ`, …). They are **not** a second "router" namespace: the `@` (0x40) is the most-significant byte
of the preceding id word (`195` records have `f1` byte 3 == `0x40`; `0` of the 1779 stride-decoded names
begin with `@`).

```
 416b00 00000000 00000000 00000000 8d02a280
 416b10 060c0340 44494147 5f524541 445f5345   ...@DIAG_READ_SE
 416b20 4e534f52 5f414c4c 00000000 00000000   NSOR_ALL........
```
→ record @`0x416b0c`: `f0=0x80a2028d`, `f1=0x40030c06`, name `DIAG_READ_SENSOR_ALL`. Measured across the
whole table: **525** of 1779 entries have a non-zero `f1` byte 3, **195** of them have it equal to `0x40`, and
184 of `strings`' outputs come out as `@NAME` (the 195-vs-184 difference was not chased down — unexamined).

### B.4 The tool's own option surface, decoded from `.rodata`

Immediately after the table, `0x420ec0`, sits `adjstctl`'s format-string pool, then a **`struct option[]`
array for `getopt_long`** (32-byte entries: `name`, `has_arg`, `flag`, `val`), and then the long-option names
and help text — all in `adjstctl`, not in `libtestcmd` (matching B.2's finding that `libtestcmd` owns no
option strings).

```
$ objdump -s --start-address=0x420ec0 --stop-address=0x42128d /srv/a7rv/a7rv-fw/fs/a15/bin/adjstctl.elf
 420ec0 ... mode:   0x%02x  res:    0x%02x  step:   0x%02x
 420ef0 ... addr:   0x%02lx  datasz: 0x%02lx
 420f10 ... adjust block: 0x%04x, code: 0x%04x 
 420f30 OSAL ID: 0x%08lx  cmdname: %s\n
 420f50 01124200 00000000 ...      ← struct option { .name=0x421201 "ver",    has_arg=0, flag=0, val=0 }
 420f70 05124200 00000000 01000000 00000000 ... "ifile",  has_arg=required_argument, val=1
 420f90 0b124200 ... "ibfile" val=2 ; 420fb0 "obfile" val=3 ; 420fd0 "abid" has_arg=0 val=4
 420ff0 "step" has_arg=required_argument val=5 ; 421010 "getlog" has_arg=0 val=6
 421030 00000000 ... ← {NULL,0,0,0} terminator
 421050 "\t--ver\n\t\tshow version number of testcmd module\n\n"
 421084 "\t--ifile ifile\n\t\tpayload text filename to input\n\n"
 4210b4 "\t--ibfile ibfile\n\t\tpayload binary filename to input\n\n"
 4210e4 "\t--obfile obfile\n\t\tpayload binary filename to output\n\n"
 421124 "\t--abid\n\t\tshow supported adjust block ID\n\n"
 42114c "\t--step\n\t\tset step number\n\n"
 421168 "\t--getlog\n\t\tuse for GetLog command\n\n"
 421188 "<options> [adjust_block] [adjust_code] [size]:[data] ...\n\n"
 4211c7 "\tsize\n\t\tb|w|d|digit\n\t\tdata\n\t\tdecimal or hex(0x) or string\n\n"
 421201 ver 421205 ifile 42120b ibfile 421212 obfile 421219 abid 42121e step 421223 getlog
 42122b "/dev/mem"
```

So the host-side frame, in the tool's own words, is
**`<options> [adjust_block] [adjust_code] [size]:[data]`** — a `(block, code)` pair plus a payload length and
payload — and `size` accepts `b|w|d` or a digit, `data` accepts decimal, `0x` hex, or a string. `--abid`
("show supported adjust block ID") is what walks the table and prints `OSAL ID: 0x%08lx  cmdname: %s` lines,
i.e. the tool itself calls `f1` the *OSAL ID* of a `cmdname`. **HYPOTHESIS:** the on-wire frame is a header
carrying at least `block`, `code`, `mode`, `res`, `step`, `addr`, `datasz` — those seven words are the
`printf` fields sitting next to the table, but the actual header layout was **not** observed; it is built
inside `testcmd_sndmsg`, which was never disassembled.

---

## Part C — three commands traced as far as the host side allows

All rows below come from the same 72-byte-stride dump of `0x401a64…0x420ebc`; `vaddr` is the record address,
`f1` is the id word, and `(block, code)` is `f1` read as two LE `u16`s.

```
ROW    0 vaddr=0x401a64 f0=0x00000000 f1=0x10010101  APP_TESTCMD
ROW    5 vaddr=0x401bcc f0=0x01050244 f1=0x10040102  AFADJ_FORMAT
ROW  115 vaddr=0x403abc f0=0x905f023c f1=0x00010303  ADJ_MIC_SENSE
ROW  116 vaddr=0x403b04 f0=0x90580253 f1=0x00020303  ADJ_MIC_SENSE_RESULT
ROW  856 vaddr=0x410b24 f0=0x92f00961 f1=0x00010501  ADJSTART
ROW  857 vaddr=0x410b6c f0=0x90660232 f1=0x00020501  ADJEND
ROW 1034 vaddr=0x413d34 f0=0x90800911 f1=0x00010901  ADC_GET_DATA
ROW 1039 vaddr=0x413e9c f0=0x00720207 f1=0x00010902  ADC_GET_DATA
ROW 1197 vaddr=0x416b0c f0=0x80a2028d f1=0x40030c06  DIAG_READ_SENSOR_ALL
ROW 1778 vaddr=0x420e74 f0=0x831909ab f1=0x0000ffff  UNKNOWN
```

### C.1 `ADJSTART` (row 856) and `ADJEND` (row 857) — the adjustment session brackets

* `ADJSTART` @ `0x410b24`, id `0x00010501` → **block `0x0501`, code `0x0001`**; `f0 = 0x92f00961`.
* `ADJEND` @ `0x410b6c`, id `0x00020501` → **block `0x0501`, code `0x0002`**; `f0 = 0x90660232`.
* The two records are adjacent (72 bytes apart), share a block, differ by `code` 1 vs 2. `UNKNOWN` (`code`
  `0xffff` in the id space) terminates the vocabulary.
* **Host side, exactly:** the name resolves to that id in the table; the id is handed to `cmdline_get_id`'s
  result path and out through `testcmd_sndmsg` → `osal_snd_msg`/`osal_snd_sync_msg`. Payload would come from
  `--ifile`/`--ibfile`/args, and `[size]:[data]` if supplied.
* **Not established:** the names read as "start adjusting" / "stop adjusting" — nothing in `adjstctl`'s
  symbols or strings says what a start/end pair brackets on the device, and this document does not guess. The
  names are the tool's, the semantics are the camera's.

### C.2 `ADJ_MIC_SENSE` (115) + `ADJ_MIC_SENSE_RESULT` (116), and `DIAG_READ_SENSOR_ALL` (1197)

* `ADJ_MIC_SENSE` @ `0x403abc` → block `0x0303`, code `0x0001`; `ADJ_MIC_SENSE_RESULT` @ `0x403b04` → block
  `0x0303`, code `0x0002`. Same block, adjacent records, request/result pair — same shape as C.1, so
  request/result bracketing inside one block is the table's general pattern, not a coincidence of one pair.
* `DIAG_READ_SENSOR_ALL` @ `0x416b0c` → block `0x0c06`, code `0x4003`; `f0 = 0x80a2028d`. This is also the
  row that produced the phantom `@DIAG_READ_SENSOR_ALL` string (B.3): the `@` is byte 3 of `f1` (`0x40`),
  **not** a name prefix. A map built from `strings` instead of a stride decode would carry 184 fake `@…`
  commands (measured this session: 184 `@`-prefixed name strings in the table region, 0 in the stride decode).
* Host-side framing for `DIAG_READ_SENSOR_ALL` is the same one-function send path as C.1. What "sensor all"
  addresses is camera-side.

### C.3 `ADC_GET_DATA` — one name, two ids; and one id, two names

```
ROW 1034 vaddr=0x413d34 f0=0x90800911 f1=0x00010901  ADC_GET_DATA     (block 0x0901, code 0x0001)
ROW 1039 vaddr=0x413e9c f0=0x00720207 f1=0x00010902  ADC_GET_DATA     (block 0x0902, code 0x0001)

ROW   33 vaddr=0x4023ac f1=0x10030201 (bytes LE: 01 02 03 10) APPFWINFRA_INPUT_GETEVENT
ROW   34 vaddr=0x4023f4 f1=0x10030201 (bytes LE: 01 02 03 10) APPFWINFRA_TP_GETEVENT
```

* `ADC_GET_DATA` exists twice with different ids **and** different `f0` tags — two entries the vocabulary
  spells identically. A name-keyed lookup cannot select between them without an extra key (e.g. the block
  given positionally), or the first match wins. Which, is **HYPOTHESIS** — not readable without the
  unmatched loop.
* `APPFWINFRA_INPUT_GETEVENT` and `APPFWINFRA_TP_GETEVENT` share id `0x10030201` (block `0x0201`, code
  `0x1003`). It is the only such collision in 1779 entries (1778 distinct ids), so `id → name` is ambiguous
  exactly once, while `name → id` is ambiguous at least once (C.3 first half). Any reverse-dump of traffic by
  id will hit that ambiguity once; any name-based tool will hit the other one.

---

## Part D — scope, and why this is not a run guide

**Boundary, stated once and enforced above.** Everything written here was read from the *sender*: `adjstctl`'s
own read-only data (its command table, its `getopt` option table, its format strings) and the symbol boundary
between `adjstctl`, `libtestcmd` and `libosal_uipc`. **Nothing in this document describes what the camera does
with any command** — not what `ADJSTART` opens, not what `DIAG_READ_SENSOR_ALL` reads, not what the reply to
`ADC_GET_DATA` contains. Where the path reaches `libosal_uipc.so` or the device, this document stops and says
so. The names of the commands are the tool's labels for its own operations; they are not evidence of device
behaviour.

**Safety — read this before treating any row as a knob.** These are **manufacturing calibration and
adjustment operations**. The `EXEC_`/`SET_`/`WRITE_`/`LOAD_` forms (171 of them) and the 84 names containing
`ADJ` write into the camera's calibration state: sensor/AF/gyro/mic/OLED-white-balance/keystone adjustment
families are all present in the vocabulary (`AFADJ_FORMAT`, `ADJ_MIC_SENSE`, `PANELEVF_EVF_ADJ_TEMP_*`,
`A_AS_BRGAIN_ADJ`, `KEYSTONE_ADJ`, `S_LC_ADJ_STAT_RST`, …). A write form can persist a wrong value into a
calibration region, and a `*_FORMAT` / `*_STAT_RST` form can discard it. **No command in this document is
safe.** Not `GET_`-prefixed ones either — a name that begins `GET_` is a label on the host side, not a
guarantee about the device-side effect, and no device-side effect was read. `ADJSTART`/`ADJEND` bracket
something; that something was not observed here and may be a state the camera does not expect to enter
outside a production line.

This is a **map for understanding the host-side protocol**, not a run guide: no command here was executed,
nothing was sent to a device, and nothing in this session tested any invocation. If you are working on your
own body of work with your own unit and a need to exercise one of these, do it on a unit you can afford to
miscalibrate, and record state before and after — this document gives you no basis for a safety claim.

**Not for redistribution of secrets.** No key material, no firmware bytes and no device-specific identifier
appears here. Table offsets, command names and 32-bit command ids are the documented object; they are stable
across units of the same firmware and are not secrets.

---

## How this was checked

Every claim above was produced in this session by the commands quoted next to it. Summary of the tooling and
of the gaps:

**Binaries touched (read-only, on the user's own extracted firmware):**
`fs/a15/bin/adjstctl.elf`, `fs/a15/lib/libtestcmd.so`, `fs/a15/lib/libosal_uipc.so` (listed only).

**Commands run:** `ls -l`; `readelf -SW` / `-sW` / `-rW` / `-dW`; `objdump -s --start-address=…
--stop-address=…`; `strings -t x`; `awk` (GNU awk 5.3.2) to decode the 72-byte records out of `objdump -s` hex
columns, taking only columns 2–5 and requiring each to match `^[0-9a-f]{8}$`. Three parser bugs were found and
fixed during this session, each of which had produced a wrong number in an earlier draft: (i) objdump's ASCII
sidebar column was being parsed as data (gave a bogus 2228 records); (ii) the address column is **6** hex
digits for this binary, so requiring 8 made the parser return 0 records; (iii) `sprintf("%c",0)` is *not* an
empty string in gawk, so a naive "stop at NUL" name read ran on to the full 64 bytes — the corrected reader
breaks on the `00` byte and is the source of the padding statistics in A.1 and of the 250-token count (an
earlier, un-trimmed pass over the same bytes reported 261 tokens; the trimmed 250 is right). Every count in
Parts A–C was re-run this session after those fixes; the final verification run reported
`decoded=1779 distinct_first_tokens=250`, `f1_byte3_nonzero=525`, `f0_transitions=130`, and
`strings_in_table_region=1779 containing_@NAME=184`.

**Zero Ghidra function bodies were opened, and that is not an oversight.** All four Ghidra MCP servers were
queried with `list_project_binaries`:

| server | programs in project |
|---|---|
| `ghidra_svc` | `/libsencore.so`, `/sen.elf`, `/libIMDB.so`, `/libInfraSSHManager.so` |
| `ghidra_avcam` | `/av-cam.bin` |
| `ghidra_cpapp` | `/cpapp-b.bin` |
| `ghidra_plugins` | `/libpro00.so-1a073e` |

`adjstctl.elf` and `libtestcmd.so` are in **none** of them. `import_binary` was not run: the tools were
declared read-only for this task, so the brief's fallback was taken instead ("if one is missing, do that part
from `nm`/`strings`/`readelf` and say so") — which is why Part B is symbol/byte based.

**No disassembler was available.** This box's binutils is x86-targeted (`objdump -d` on these AArch64 objects
fails with `can't disassemble for architecture UNKNOWN!`); no `capstone`, no `llvm-objdump`; `eu-objdump` and
`python3` were blocked by the permission layer. Consequence, restated plainly: **`testcmd_sndmsg`,
`cmdline_get_id`, `cmdline_get_opts`, `cmdline_read_data_from_args`, `testcmd_cb`, `__rcvmsg`, `do_read`,
`do_write`, `do_wait` were located (vaddr + size from `.dynsym`) and never read.** Their vaddrs/sizes in B.2
are measurements; any sentence about the order of operations inside them is tagged **HYPOTHESIS**.

**No task/todo list was kept**, contrary to the brief: no `TodoWrite`/`Task*` tool exists in this session's
toolset. Progress was tracked in-line instead.

**Still unresolved (each of these is a real gap, not a footnote):**
1. **`f0` semantics.** 125 values, 122 confined to one contiguous run, agrees with the name's subsystem only
   ~61 % of the time. Router tag? module hash? Unknown.
2. **`f1`'s field labels.** The two-u16 layout is measured; that the low half is the tool's `adjust_block`
   and the high half `adjust_code` is inference from `"adjust block: 0x%04x, code: 0x%04x"`, the usage line,
   and the start/end pairing. It could be the other way round.
3. **The wire header layout.** `mode`/`res`/`step`/`addr`/`datasz` appear as `printf` fields next to the
   table; their on-wire order, widths and whether they live in the message or in a local struct were not
   observed.
4. **The lookup loop.** `strncmp` + a flat non-PIE table strongly implies a linear scan, and the tie-break
   for the duplicate `ADC_GET_DATA` name was not observed.
5. **Sync vs async per command.** Both send symbols are imported and a sync flag is parsed; which commands use
   `osal_snd_sync_msg` is unknown.
6. **`/dev/mem` + `mmap` in `adjstctl`.** Present, unexplained. It may be the payload/queue region or an
   unrelated register-access path; not read.
7. **Whether `f0` is also sent.** It sits in the record but never appears in any format string; the tool
   prints `OSAL ID` (`f1`) and `cmdname` only.
8. **Whether a second copy of the table exists.** Only one region satisfies the stride/fit/sentinel tests;
   nothing ruled out a copy elsewhere in the 129 KB of `.rodata`.
