# How the a7R V stands up SSH in service mode — `libInfraSSHManager.so` (a15 host side)

**Scope.** Static reverse-engineering of the user's own Sony a7R V firmware, for a public research
write-up. This document maps the **host-side (a15 Linux) SSH manager**: how service mode starts
`sshd`, generates its host key, and provisions the login credential. What a remote client does
*over* the resulting SSH session is explicitly **out of scope** — see Part D.
Mechanism, paths, and field layouts only; **no key material and no credential bytes appear here**,
and the firmware binary is not reproduced.

**Binary.** `/srv/a7rv/a7rv-fw/fs/a15/lib/libInfraSSHManager.so` — AArch64 shared object, built
with `GCC: (crosstool-NG …) 6.4.0 … 20201211 (Sony CE Linux 14.0.1.0)` (strings @0xe3d8).
Analysed in the `ghidra_svc` Ghidra project. Ghidra virtual addresses = file offset + `0x100000`
(verified repeatedly this session: e.g. `nm -D` gives `_ZTVN7network15InfraSshManager17SshControllerImplE`
at file offset `0x11dc40`; `search_symbols_by_name` returns it at `0011dc40`; the vtable entries read at
`0x11dc50` point at e.g. `0x00109e30` = `nm` offset `0x9e30` + `0x100000`).

**One-sentence summary.** A service-mode client sends a numbered command over OSAL IPC; the
manager checks two in-memory state flags, and — if the host key is present — runs the literal
string `/usr/sbin/sshd` as a message to an on-device command-executor task; the host key is
persisted in the Sony Backup (NVRAM-style) store so it survives reboots, and the login
credential is provisioned by a separate command as a `crypt(3)` SHA-256 hash in a tmpfs file
consumed by sshd's PAM path.

---

## Part A — Verb surface and command strings

### Module entry points

```
$ nm -D .../libInfraSSHManager.so | grep ' InfraSSHManager_'
000000000000720c T InfraSSHManager_Init
0000000000007304 T InfraSSHManager_Exit
```

(Not decompiled this session — described by name only.)

### Controller verbs (from `nm -D`, this session)

All `SshControllerImpl::execute*Cmd` verbs, with Ghidra VAs (file offset + 0x100000), the request
command ID that reaches them (from the decompiled dispatcher `doMsgReceiptProcess` @0x10a9b8 **and**
the controller vtable read at 0x11dc50 — both this session), and the response ID each verb sends:

| Request ID | Verb (`nm` file offset → VA) | vtable slot | Response ID | Meaning |
|---|---|---|---|---|
| `0x10000000` | `executeStopSshdCmd` 0x9f48 → 0x109f48 | +0x48 | `0x20000000` | stop sshd |
| `0x10000001` | `executeSetAuthInfoCmd` 0xa534 → 0x10a534 | +0x30 | `0x20000001` | set login user+password |
| `0x10000002` | `executeDeleteHostKeyCmd` 0xa03c → 0x10a03c | +0x38 | `0x20000002` | delete persisted host key |
| `0x10000003` | `executeNotifyCamRemoteCmd` 0xa1e4 → 0x10a1e4 | +0x40 | `0x20000003` | cam-remote service-state change |
| `0x10000004` | `executeResetPamFailureCountCmd` 0x9bc0 → 0x109bc0 | +0x50 | `0x20000004` | reset PAM failure tally |
| `0x10000005` | `executeStartSshdCmd` 0x9e30 → 0x109e30 | +0x58 | `0x20000005` | start sshd |
| `0x30000000` | `executeRegisterNotifyEventCmd` 0xa144 → 0x10a144 | +0x20 | inline | subscribe to events |
| `0x30000001` | `executeUnregisterNotifyEventCmd` 0xa104 → 0x10a104 | +0x28 | inline | unsubscribe |

Request↔response pairing rule (VERIFIED — every verb's `decompile_function` call this session shows
its literal response ID, and the dispatcher read this session shows the request-ID switch):
request `0x1000000x` → response `0x2000000x`, same low nibble. Out-of-band event: fingerprint
notification ID `0x40000000` (`sendFingerPrintEvt` @0x10a424).

Controller vtable `_ZTVN7network15InfraSshManager17SshControllerImplE` @0x11dc40, vptr 0x11dc50
(`read_bytes` 0x11dc50, 104 bytes, this session) — slot targets (little-endian u64):
`+0x10=0x109970` (initialize), `+0x18=0x109cdc` (finalize), `+0x20=0x10a144`, `+0x28=0x10a104`,
`+0x30=0x10a534`, `+0x38=0x10a03c`, `+0x40=0x10a1e4`, `+0x48=0x109f48`, `+0x50=0x109bc0`,
`+0x58=0x109e30` — exactly matching the `nm -D` verb addresses above, which pins the
dispatcher-ID→verb mapping (VERIFIED).

Constructor injection, from `nm -D`:

```
_ZN7network15InfraSshManager17SshControllerImplC2ERNS0_9MsgSenderERNS0_18SshFunctionWrapperERNS0_12StateManagerERNS0_15PasswordManagerE
```

i.e. `SshControllerImpl(MsgSender&, SshFunctionWrapper&, StateManager&, PasswordManager&)`, stored at
`this+0x8 / +0x10 / +0x18 / +0x20` as used throughout the decompiled bodies.

### Key strings (strings -t x, file offsets, this session)

| File offset | String | Role (per decompiled call sites below) |
|---|---|---|
| 0xb163 / 0xb172 | `SSHD_START_CMD` / `/usr/sbin/sshd` | start command |
| 0xb0e1 / 0xb0ef | `SSHD_STOP_CMD` / `/bin/busybox killall sshd` | stop command |
| 0xb109 / 0xb11f | `CREATE_HOST_KEY_SHELL` / `/usr/bin/create_host_key.sh` | host-key generation script |
| 0xafbd / 0xafd4 | `GET_FINGER_PRINT_SHELL` / `/usr/bin/get_finger_print.sh` | fingerprint script |
| 0xb058 / 0xb075 | `/sbin/pam_tally2 --reset -u ` / `PAM_FAILURE_COUNT_RESET_CMD` | PAM tally reset |
| 0xb015 | `/tmp_network/ssh/ssh_host_ecdsa_key` | host private key (+ `ssh_host_ecdsa_key.pub` @0xb13b) |
| 0xb047 / 0xb039 | `/tmp_network/ssh` / `/var/run/sshd` | directories created by `createSshdDirectory` |
| 0xaeef | `/tmp_network/ssh/ssh_name_password` | credential file |
| 0xafa4 | `/var/run/sshd.pid` | pid file read by `getSshdPid` |
| 0xb0b7 / 0xb091 | `/tmp_network/ssh/ssh_auth_failed_count` / `…/ssh_session_count` | manager's own accounting files |
| 0xaff1 | `/tmp_network/ssh/tmp_finger_print` | fingerprint scratch file |
| 0xae98 / 0xaedc / 0xaee9 / 0xaeeb | `./0123456789A-Za-z` / `$rounds=5000` / `$` / `,` | crypt(3) + password-file separators |

`NEEDED` (from `strings`/`nm -d` of the ELF header section, this session, matching prior notes)
includes `libSTMcmdexecute.so`, `libInfraNetworkCommon.so`, `libNetworkMsgHandler.so`, and a
`crypt` library — consistent with the mechanism found in Part B.

### What the manager can do (one paragraph)

`libInfraSSHManager.so` is the a15-side service that owns the camera's SSH daemon: it can **start**
and **stop** `sshd`, **provision the login identity** (username + password → crypt hash file),
**generate, persist, restore, and delete the SSH host key**, **reset the PAM authentication-failure
tally**, and **publish the host-key fingerprint** as an event to a registered subscriber. It never
talks to a network client itself: commands arrive over Sony's OSAL message IPC from a network
message handler (`doMsgReceiptProcess`), and it drives the system by sending command *strings* to a
separate command-executor task (Part B.1) rather than by calling libc exec functions. The five shell
commands it can cause to run are: `/usr/sbin/sshd`, `/bin/busybox killall sshd`,
`/usr/bin/create_host_key.sh`, `/usr/bin/get_finger_print.sh`, and `/sbin/pam_tally2 --reset -u <user>`.

---

## Part B — The start-sshd path, decompiled

Call chain (every link decompiled this session; IDs verified per Part A):

```
doMsgReceiptProcess 0x10a9b8   (dispatcher: switch on request ID)
 └─ 0x10000005 → controller slot +0x58
    executeStartSshdCmd 0x109e30
     ├─ StateManager::isSshdStarted 0x107c38   (gate 1: already running → skip)
     ├─ StateManager::isKeyValid    0x107c28   (gate 2: host key must be present)
     └─ SshFunctionWrapper::startSshd 0x10908c
          └─ SshFunctionWrapper::executeIMSystem 0x108ed8   "/usr/sbin/sshd"
               └─ OSAL IPC → endpoint 0x94020a ("IM" command-executor task)
```

Directory setup and key restore happen once earlier, at module init (§B.3), not per start.

### B.1 How a command is run — OSAL IPC, not libc exec

Import check, this window (`ghidra_svc list_imports` with query
`^(system|popen|fork|execv|execl|execve|execvp|posix_spawn|clone)$`): **zero matches** —
the module contains no direct process-creation imports. Instead `executeIMSystem` (VERIFIED,
decompiled 0x108ed8, this window) is a synchronous OSAL message exchange:

```c
sVar3 = strnlen(param_1,0x100);
if (0xff < sVar3) { iVar2 = -0x400; goto LAB_00108fb4; }        // command longer than 255 → error
iVar2 = osal_dynamic_id(0x2a,0x94,&local_14);                    // temp source id for the reply
iVar2 = osal_valloc_msg_wait(0x94020a,&local_8,0x104,1);         // 0x104-byte msg for endpoint 0x94020a
osal_set_msg_src(local_8,uVar1);
*local_8 = 0x940023;                                             // message type: "IM system" command
strncpy((char *)(local_8 + 1),param_1,0x100);                    // 256-byte command buffer
iVar2 = osal_snd_msg(0x94020a,local_8);
iVar2 = osal_rcv_msg_tmo(local_14,&local_10,0xffffffff);         // infinite wait for completion
*param_2 = local_10[1];                                          // exit code, reply word 1
```

So a command string is posted to OSAL endpoint **0x94020a** with command word **0x940023**; the
reply's second word is the process exit status. HYPOTHESIS (not proven here): the endpoint's owner
is the task in `libSTMcmdexecute.so` (a `NEEDED` dependency), which presumably shells the string out
— the *how* lives in that other library, not in this one, and was not decompiled.

The sshd launch itself (VERIFIED, `startSshd` decompiled 0x10908c, this window):

```c
FUN_00108664(0,"SSHD_START_CMD");
cVar1 = executeIMSystem(this,"/usr/sbin/sshd",&local_4);
if ((cVar1 != '\0') && (FUN_00108664(1,"SSHD_START_CMD"), local_4 != 0)) {
  cVar1 = '\0';                                                  // nonzero exit → report failure
  FUN_00108720(8,3,0x136); FUN_00108720(0,0x200,local_4);        // log 310 / 512+exitcode
}
```

**The exact launch string is `/usr/sbin/sshd`, with no arguments** — all sshd configuration comes
from its compiled-in/`/etc` defaults on the a15 rootfs (out of scope here). No PID redirection or
daemonizing flags are passed; the manager later *reads* `/var/run/sshd.pid` (B.3 stop path), so the
daemon is expected to self-daemonize and write that file.

### B.2 Host key: `create_host_key.sh` — invoked, but **not** on the start path, and **not** per boot

`createKey` (VERIFIED, decompiled 0x109004, this session) does invoke the script:

```c
FUN_00108664(0,"CREATE_HOST_KEY_SHELL");
executeIMSystem(this,"/usr/bin/create_host_key.sh",&local_4);    // → OSAL endpoint 0x94020a
```

but its call sites are **only inside `executeSetAuthInfoCmd`** (decompiled this window, 0x10a534 —
see Part C.2: key generated when credentials are first set, and **rotated** when credentials
change). The boot/start path never regenerates:

* `initialize` (VERIFIED, decompiled 0x109970 + disassembled 70 instructions to 0x1099ec, this
  session) calls wrapper slots `+0x10` (createSshdDirectory), `+0x18`, `+0x20`, then slot `+0x38` =
  `createKeyFromBackup`; if it returns nonzero it tail-calls `setKeyGenerateState(1)`. The
  decompiler emitted a spurious "could not recover jumptable" warning; the disassembly shows the
  function ends at the `setKeyGenerateState` branch — **`initialize` never calls `createKey`**
  (VERIFIED by `disassemble 0x109970, count=70`).

* `createKeyFromBackup` (VERIFIED, decompiled 0x10885c, this window) restores the key from the
  Sony Backup store:

```c
__string = calloc(1,0x259);
iVar1 = Backup_nread(0x3000000,__string,600);       // backup item 0x3000000, up to 600 bytes
…
p_Var2 = (_IO_FILE *)wrapFopen("/tmp_network/ssh/ssh_host_ecdsa_key","w");
lVar4 = wrapFwrite(__string,sVar3,1,p_Var2);
…
wrapChMod("/tmp_network/ssh/ssh_host_ecdsa_key",0x180);   // 0600
```

* `updateBackupKey` (VERIFIED, decompiled 0x1097e8, this window) is the inverse — after the script
  creates a key, the file content is read back (`readHostKeyData`, decompiled 0x1096b4: `fopen` "r" +
  `fgets` loop) and persisted:

```c
util_wrapper_strncpy(__ptr,local_20,0x259);
iVar1 = Backup_write(0x300,0x3000000,__ptr);
if (-1 < iVar1) { Backup_sync_subsystem(0x300); … }   // commit subsystem 0x300
```

**Answer to the tmpfs question:** `/tmp_network` is tmpfs (given by the task brief; mount itself not
re-verified here), yet the host key **survives reboot** — proven mechanism: it is persisted in the
Backup (NVRAM-style) store as **item `0x3000000` in subsystem `0x300`** and rewritten to
`/tmp_network/ssh/ssh_host_ecdsa_key` at every `initialize` (`Backup_nread` above). Generation
happens only when auth info is first set with no key present, or on credential rotation.
`deleteBackupKey` (VERIFIED, 0x1089a4) clears the persisted copy by writing a zeroed 601-byte
buffer + sync; `executeDeleteHostKeyCmd` (VERIFIED, 0x10a03c) calls exactly that (tmpfs file left as
is until unmount). `finalize` (VERIFIED, 0x109cdc) does the converse: deletes the tmpfs files
(`deleteKey` 0x108d68, `wrapRemove` of key + `.pub`) but **keeps the backup** — so the camera's host
identity is stable across reboots *and* across SSH on/off cycles, and changes only on credential
rotation or explicit delete. The key *type* (ECDSA) is inferred from the path constants —
HYPOTHESIS, since the contents of `/usr/bin/create_host_key.sh` were not read this session.

### B.3 Directories and modes (the `wrap*` wrappers)

`createSshdDirectory` (VERIFIED, decompiled 0x108e38, this session) creates, in order:
`/var/run/sshd`, then `/tmp_network/ssh` — each via `isDirectoryExist` → `makeDirectory` (bodies of
the two `is*Exist` helpers not decompiled; described by name/call site only). `makeDirectory`
(VERIFIED, 0x108e14):

```c
wrapMkdir(param_1,0x1ad);        // mkdir(path, 0755)
```

`0x1ad` = octal `0755` (dir mode). The only `chmod` seen on the provisioning path is on the restored
key file: `wrapChMod("/tmp_network/ssh/ssh_host_ecdsa_key", 0x180)` = octal `0600` (createKeyFromBackup,
quoted in B.2). The wrapper symbols (`wrapMkdir`, `wrapChMod`, `wrapFopen`, `wrapFwrite`, `wrapFlock`,
`wrapRemove`, `wrapCrypt`, `wrapGetRandom`, `wrapRandom`, `wrapSrandom`, `wrapGettimeOfDay`,
`wrapFileNo`, `wrapFgets`, `wrapFclose`, `util_wrapper_strncpy`) appear in `.dynstr` (`nm -D`, this
session) — thin libc shims, presumably with logging; their bodies were not decompiled.

### B.4 Stop path (for completeness of the "start/stop" surface)

`executeStopSshdCmd` (VERIFIED, 0x109f48) → if `isSshdStarted`: wrapper `stopSshd` (VERIFIED,
0x1095d4): read pid via `getSshdPid` (VERIFIED, 0x10949c: `wrapFopen("/var/run/sshd.pid","r")` +
`wrapFgets(buf,6,fp)`), then `executeIMSystem(this,"/bin/busybox killall sshd",&exit)`; success if
exit 0 **or** `!isProcessAlive(pid)` (VERIFIED, 0x10954c: existence of `/proc/<pid>`), then
`setSshdState(0)`. Not-started → result 0 (also idempotent).

---

## Part C — Gating and authentication

### C.1 What gates sshd start

State lives in `StateManagerImpl` as two in-memory u32 fields (VERIFIED, all four accessors
decompiled this window):

```c
bool isKeyValid()    { return *(int *)(this + 0x8) == 1; }      // TP_HOST_KEY_VALID_STATE
bool isSshdStarted() { return *(int *)(this + 0xc) == 1; }      // TP_SSHD_STATE
void setSshdState(state)       { *(u32*)(this+0xc)=state; FUN_00107cd8(2); }   // 0x107e60
void setKeyGenerateState(state){ *(u32*)(this+0x8)=state; FUN_00107cd8(1); }   // 0x107e6c
```

The enum names `TP_SSHD_STATE` / `TP_HOST_KEY_VALID_STATE` come straight from the mangled symbols
(`nm -D`: `_ZN…StateManagerImpl12setSshdStateEN18DefInfraSshManager13TP_SSHD_STATEE` @0x2f1f,
`…19setKeyGenerateStateEN18DefInfraSshManager23TP_HOST_KEY_VALID_STATEE` @0x2f82). They are header
enum *types*, not runtime strings — no `TP_*` literal exists in `.rodata` (grep over `strings -t x`,
this window). The state setters publish a change notification through `FUN_00107cd8` (VERIFIED,
0x107cd8, this window): an OSAL message (type 2, sub-type 0x300, with kind=1/2 and value byte-swapped
into bits 16–63 of a tag `0x32f2`) sent to endpoint **0x8f013a**, with a fallback sync message
(type 0xf) to `0x8f0313` — i.e. every state transition is reported to a system telemetry/audit
task. (The same `0x8f013a`/`0x10030f2` pattern brackets every dispatched command in
`doMsgReceiptProcess`; consumer of these messages not identified this session.)

`executeStartSshdCmd` (VERIFIED, 0x109e30, decompiled this window) — gating logic verbatim-reduced:

```c
cVar1 = isSshdStarted();                 // state vtable +0x38
if (cVar1 == '\0') {
  uVar5 = 5;                             // default result
  cVar1 = isKeyValid();                  // state vtable +0x30
  if (cVar1 != '\0') {
    cVar1 = startSshd();                 // wrapper vtable +0x58
    if (cVar1 == '\0') { uVar5 = 3; }    // launch failed
    else { uVar5 = 0; setSshdState(1); } // success → state=1
  }                                      // key not valid → result 5
}                                        // already started → uVar5 stays 0 (skip, success)
local_30 = 0x20000005;  uStack_2c = uVar5;  // response {respId,result}, 0x2c bytes
MsgSender->sendAsyncMsgToId(requesterId, &local_30, 0x2c);
```

**Answers:** (1) **The host key must be valid before sshd will start** — `isKeyValid()==false`
short-circuits to result `5` without touching the launch. (2) **Start is idempotent** — if
`isSshdStarted()` the call returns result `0` without launching a second daemon. Result codes:
`0` ok/skipped, `3` launch failed, `5` key not valid. (3) The validity flag is set to 1 only by
`setKeyGenerateState(1)`, which happens in exactly two places: `initialize` after a successful
backup restore, and the set-auth-info path after a successful `create_host_key.sh` +
`updateBackupKey` (0x10a534, quoted in C.2). It is cleared by `finalize` and mid-rotation.

Other gates seen in the decompiled verbs: `SET_AUTH_INFO` is refused (result 4) while sshd is
running — credentials may only be (re)provisioned with the daemon stopped; `STOP` returns 0 when
already stopped.

### C.2 Credentials — what is provisioned and how

Request layout (from `executeSetAuthInfoCmd` 0x10a534, VERIFIED decompiled this window, and
`updateAuthInfo` 0x10845c): payload = `{u32 cmdId, char user[17], char pass[17], …}` — the controller
reads the two strings at `payload+4` and `payload+0x15`; `updateAuthInfo`'s cache writes
(`util_wrapper_strncpy(this+8, param_1, 0x11)` / `util_wrapper_strncpy(this+0x19, param_1+0x11, 0x11)`)
confirm `ST_SET_AUTH_INFO_CMD {char user[17]; char pass[17];}`.

Flow (VERIFIED, 0x10a534):

1. Gate: `isSshdStarted()` → result 4 (must stop first). Empty user or pass → result 1.
2. Compare against cached pair (`getCurrentAuthInfo`, PW slot +0x18); **identical → no change**,
   just `sendFingerPrintEvt`, result 0.
3. Otherwise `updateAuthInfo` (PW slot +0x10); failure → result 4.
4. If `!isKeyValid()`: `createKey` (wrapper +0x30) → `setKeyGenerateState(1)` +
   `updateBackupKey` (wrapper +0x50); create failure → result 2.
5. Else (key present) and old cached credentials were non-empty: **host-key rotation** —
   `deleteKey` (wrapper +0x40) → `setKeyGenerateState(0)` → `createKey` →
   `setKeyGenerateState(1)` + `updateBackupKey` (failure codes 2/4).
6. Success path ends with `sendFingerPrintEvt()` and `resetPamFailureCount(username)`
   (wrapper +0x68; failure is logged only, code 0xb3).
7. Response `0x2c` bytes: `{u32 respId=0x20000001, u32 result, char user[17] @+0x8, char pass[17]
   @+0x19, zero pad}` — built by `util_wrapper_strncpy(acStack_28, <user>, 0x11)` +
   `util_wrapper_strncpy(acStack_28+0x11, <pass>, 0x11)` — **the response echoes both credential
   fields back to the requester** (structure only; values never captured or reproduced here). Sent
   addressed to the requester id via `MsgSender` slot +0x28 =
   `sendAsyncMsgToId(uint id, void* buf, uint size)` → `NetworkMsgHandler::sendAsynMessage(id+8,…)`
   (VERIFIED, 0x107508).

`updateAuthInfo` (VERIFIED, 0x10845c): hashes the password then writes the file, and on success
caches both fields in RAM (`this+0x8`, `this+0x19`, 17 bytes each) — that cache is what step 2
compares against and what `executeResetPamFailureCountCmd` uses as the username (0x109bc0). Note:
Ghidra's sret wiring for the `std::string`-returning `encryptPassword` is partially mangled
(`encryptPassword_abi_cxx11_((char *)this)`); the hashing description below comes from the callee
bodies, which decompile cleanly.

`encryptPassword` (VERIFIED, 0x10820c) + `makeSalt` (VERIFIED, 0x108178) + `getRandom`
(VERIFIED, 0x108138): the stored form is **crypt(3) SHA-256 (glibc `$5$`)** with a fixed cost
parameter and a random 16-char salt:

```c
makeSalt(buf, 0x10);                                   // 16 chars from "./0123456789A-Za-z" (66-char alphabet)
// setting string = "$5" + "$rounds=5000" + "$" + salt   (strings @0xaee9,0xaedc)
wrapCrypt(password, setting);
// entropy: wrapGetRandom(&u,4,1)  [getrandom(2)]; on error falls back to wrapRandom()
//          seeded wrapSrandom(tv_sec ^ tv_usec) from wrapGettimeOfDay
```

`updatePasswordFile` (VERIFIED, 0x108318): the applied file is
`/tmp_network/ssh/ssh_name_password`, written `"w"` as one line `user + ',' + hash` (separator byte
`0x2c` at VA 0x10aeeb, `wrapFwrite`'d under `wrapFlock(fd,2)` LOCK_EX then `wrapFlock(fd,8)` LOCK_UN;
line-length guard `< 0x65`). **So the provisioned identity is a username+password pair consumed via
that file — not an `authorized_keys` entry and not a new UNIX user** (no `adduser`/`shadow` paths
appear anywhere in the module; sshd's read path is outside this binary — HYPOTHESIS that sshd's PAM
config maps this file to logins, supported by the PAM evidence below).

**PAM is definitively in the loop.** `resetPamFailureCount` (VERIFIED, 0x109124) builds and runs:

```c
"/sbin/pam_tally2 --reset -u " + username  →  executeIMSystem(..., &exit)
// on exit 0 also clears the manager's own /tmp_network/ssh/ssh_auth_failed_count
// (wrapper slot +0x28 resetSshAuthFailedCountFile; its body not decompiled)
```

and `executeResetPamFailureCountCmd` (VERIFIED, 0x109bc0) exposes it as its own verb using the
cached username. A `pam_tally2` tally exists only if sshd logins go through PAM's tally module, and
the manager maintains its own auth-failure/session counters alongside — i.e. logins authenticate
against the `$5$` hash file via PAM. Mechanism caveat: the username is concatenated **unescaped**
into the `pam_tally2` command string (17-byte NUL-terminated field). Whether shell metacharacters in
the username field reach a shell depends on the executor task's semantics (in `libSTMcmdexecute.so`,
not decompiled) — HYPOTHESIS, noted as a robustness observation on an owned-device provisioning path,
not pursued further.

`sendFingerPrintEvt` (VERIFIED, 0x10a424) → `createFingerPrint` (VERIFIED, 0x1092bc): runs
`/usr/bin/get_finger_print.sh`, reads one line (`fgets`, ≤0x65 bytes) from `/tmp_network/ssh/tmp_finger_print`,
`extractFingerPrint`s it (body not decompiled), deletes the temp file, and broadcasts a
`{u32 id=0x40000000, char fp[256]}` (0x104-byte) event via `MsgSender` slot +0x20 =
`sendAsyncMsg` — which sends to the single subscriber id stored at `MsgSender+0x40` under a mutex
(VERIFIED, 0x1076c8); subscribers are set via the `0x30000000/1` register/unregister verbs (MsgSender
slots +0x10/+0x18 — targets `0x10764c`/`0x107690`, bodies not decompiled; role inferred from the two
callers). The fingerprint event is how the service-mode client is told which host key to expect.

`executeNotifyCamRemoteCmd` (VERIFIED, 0x10a1e4): stores the 3-word cam-remote setting from
`payload+4/+8/+0xc` and, if any flag transitioned enable→disable (predicate
`isChangeCamRemoteEnableToDisable`, body not decompiled — name/call-site only) while sshd was
running: stop sshd → `setSshdState(0)` → `resetPamFailureCount(cached user)` → `startSshd` →
`setSshdState(1)`. Turning a related remote service off forces an sshd restart + tally reset.

---

## Part D — Scope and safety

This document describes the **host-side a15 manager only** — the mechanism by which the camera's
own service mode stands up its SSH daemon, provisions its host key, and sets its SSH login.
The **remote client's session is out of scope**: nothing here covers what protocol, tooling, or
authentication a service-mode client uses to reach the camera, nor what happens inside an
established SSH session. (Per the repo framing: Investigation 2 established that the
factory/service-mode authentication chain "ends in sshd provisioning"; this document maps that
endpoint — the two questions "who may reach this dispatcher, and over what transport?" live on the
remote side of the line and were deliberately not investigated.)

Nothing here is an exploit or a how-to: every path shown is the device's designed provisioning path
for its owner's own service mode, documented for interoperability research on an owned device.
The document reproduces paths, offsets, message formats, and field layouts. It contains **no key
material and no credential values** — the one place where credentials transit the response wire
(`SET_AUTH_INFO` echo, C.2) is described structurally only, and no device was powered on, connected
to, or exercised during this work; everything comes from static analysis of an offline copy.

---

## How this was checked

All analysis is static, on the user's own firmware copy, in one working session across two context
windows; every function marked VERIFIED below was returned by `mcp__ghidra_svc__decompile_function`
(binary `libInfraSSHManager.so`) during that session, and the functions carrying load-bearing quotes
in Parts B–C (start path, exec mechanism, key persistence, credentials, state accessors) were
**re-run in the final window** so their quoted lines are in evidence directly.

**Commands run (Bash):** `nm -D` (verb surface, exports, wrapper symbols, mangled enum types);
`strings -t x` (path/command strings, compiler tag, separator bytes; `grep -E 'TP_|STATE|…'`);
`ls`/`grep -l` for repo cross-reference. No disassembler other than Ghidra was used for AArch64.

**Ghidra calls:** `list_project_binaries` (confirmed binary indexed, start of session);
`search_symbols_by_name` (for every address used — no mangled names passed to `decompile_function`);
`read_bytes` (vtables: controller `_ZTV`@0x11dc40→vptr 0x11dc50 read 104B; MsgSender
vptr 0x11d9c0 read 72B; StateManager/PasswordManager/Wrapper vtable regions earlier in session);
`disassemble` (`initialize` 0x109970 ×70 instrs, to settle the jumptable warning);
`list_imports` (regex `^(system|popen|fork|execv|execl|execve|execvp|posix_spawn|clone)$` → none).

**Decompiled (VERIFIED; bodies quoted or reduced above):**
`doMsgReceiptProcess` 0x10a9b8 · `executeStartSshdCmd` 0x109e30 · `startSshd` 0x10908c ·
`executeIMSystem` 0x108ed8 · `createSshdDirectory` 0x108e38 · `makeDirectory` 0x108e14 ·
`createKey` 0x109004 · `initialize` 0x109970 · `finalize` 0x109cdc · `createKeyFromBackup` 0x10885c ·
`updateBackupKey` 0x1097e8 · `deleteBackupKey` 0x1089a4 · `readHostKeyData` 0x1096b4 ·
`deleteKey` 0x108d68 · `executeStopSshdCmd` 0x109f48 · `stopSshd` 0x1095d4 · `getSshdPid` 0x10949c ·
`isProcessAlive` 0x10954c · `executeDeleteHostKeyCmd` 0x10a03c · `executeSetAuthInfoCmd` 0x10a534 ·
`updateAuthInfo` 0x10845c · `updatePasswordFile` 0x108318 · `encryptPassword` 0x10820c ·
`makeSalt` 0x108178 · `getRandom` 0x108138 · `resetPamFailureCount` 0x109124 ·
`executeResetPamFailureCountCmd` 0x109bc0 · `executeNotifyCamRemoteCmd` 0x10a1e4 ·
`executeRegisterNotifyEventCmd` 0x10a144 · `executeUnregisterNotifyEventCmd` 0x10a104 ·
`sendFingerPrintEvt` 0x10a424 · `createFingerPrint` 0x1092bc · `isKeyValid` 0x107c28 ·
`isSshdStarted` 0x107c38 · `setSshdState` 0x107e60 · `setKeyGenerateState` 0x107e6c ·
state-change helper `FUN_00107cd8` · `MsgSenderImpl::sendAsyncMsg` 0x1076c8 ·
`MsgSenderImpl::sendAsyncMsgToId` 0x107508.

**Deliberately not decompiled (not described beyond name + call site):** `InfraSSHManager_Init`/`Exit`;
the OSAL receive-thread classes (`MsgReceiptProcessing` caller side); `MsgSenderImpl` register slots
0x10764c/0x107690; `isDirectoryExist`, `isFileExist`, `createSshSessionCountFile`,
`createSshAuthFailedCountFile`, `resetSshAuthFailedCountFile`, `extractFingerPrint`,
`isChangeCamRemoteEnableToDisable`, the `wrap*` libc shims, and the log/string helpers
(`FUN_00108720`, `FUN_00109a84`, `FUN_00107fe4`, `FUN_00108664`, `FUN_001099f0`); also out of
binary: `create_host_key.sh`, `get_finger_print.sh`, `libSTMcmdexecute.so`, sshd's own config.

**HYPOTHESIS index:** (1) endpoint `0x94020a` is owned by a task in `libSTMcmdexecute.so`, which
shells commands out — the NEEDED dependency plus the `executeIMSystem` protocol are suggestive, the
implementation was not opened. (2) Host key is ECDSA — inferred from path constants
(`ssh_host_ecdsa_key[.pub]`); the generator script was not read. (3) sshd authenticates against
`/tmp_network/ssh/ssh_name_password` via PAM — strongly supported by the `pam_tally2` and
auth-failure-counter machinery, but sshd's config lives outside this binary. (4) The consumer of the
`0x8f013a` telemetry messages (activity/watchdog vs. audit log) was not identified. (5)
Unescaped-username caveat in C.2 — exploitability depends on the executor's shell semantics
(unexamined).

**Known decompiler limitations noted in place:** sret (`std::string`) argument wiring partially lost
in `updateAuthInfo`/`encryptPassword`/`updateBackupKey` (mechanism reconstructed from clean callee
bodies); implicit `this` dropped in some `const` controller methods (slot arithmetic cross-checked
against the constructor-injected member layout and vtable reads); one spurious "unrecovered
jumptable" warning in `initialize` disproved by disassembly.
