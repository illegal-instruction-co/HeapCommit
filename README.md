# heapcommit

Heap CommitRoutine hijack PoC. Overwrites the XOR-encoded CommitRoutine pointer inside the 
Windows HEAP structure to intercept heap segment commit operations.

No IAT hooks. No inline hooks. No exceptions. No VirtualProtect.

## how it works

Every Windows HEAP struct has a `CommitRoutine` function pointer at offset `+0x168`.
This pointer is called when the heap manager needs to commit new memory for a growing segment.

The pointer is XOR-encoded with a cookie stored in ntdll's `.data` section:

```
HEAP[0x168] = CommitRoutine ^ cookie
```

When NULL: `HEAP[0x168] == cookie` (since `0 ^ cookie = cookie`).
When set:  `HEAP[0x168] != cookie` → CFG-guarded indirect call fires.

This PoC:
1. Reads the process heap from PEB
2. Resolves the XOR cookie by scanning ntdll `.data`
3. Encodes a trampoline function pointer
4. Writes it to `HEAP+0x168`
5. Triggers heap growth → trampoline fires on every segment commit

## build

```
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

## run

```
build\bin\Release\heapcommit.exe
```

## what you'll see

Before arming, `HEAP[0x168]` equals the cookie (CommitRoutine is NULL).
After arming, `HEAP[0x168]` changes to the XOR-encoded trampoline.
Large allocations trigger the CommitRoutine, firing the callback.
After disarming, `HEAP[0x168]` is restored to the original cookie value.

## offensive applications

- **Threadless injection**: WriteProcessMemory to target's `HEAP+0x168`, no CreateRemoteThread
- **Stage-0 loader**: CommitRoutine bootstraps payload, then restores original
- **EDR blind spot**: no known EDR monitors HEAP struct integrity at this offset
- **Universal**: every Windows process has a heap, PEB+0x30 is the address

## structure

```
heapcommit/
├── CMakeLists.txt
├── include/
│   ├── Types.h          # offset constants, function pointer typedefs
│   └── HeapCommit.h     # engine class
├── src/
│   ├── HeapCommit.cpp   # cookie resolution, arm/disarm, trampoline
│   └── Main.cpp         # demo
└── README.md
```

## related

- [vehbutnot](../vehbutnot) — WNF-Guard context-swap hooking
- Discovery documented in `../vehbutnot/heap_commitroutine_hijack.md`
