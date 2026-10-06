#include "HeapCommit.h"

#include <atomic>
#include <format>
#include <iostream>
#include <string>
#include <vector>

using namespace std;
using namespace machinetherapist;

static atomic<int32_t> callbackHits{0};

void OnCommitRoutineTriggered(PVOID heapBase, PVOID commitAddress, SIZE_T commitSize, PVOID)
{
	auto count = callbackHits.fetch_add(1) + 1;

	if (count <= 3) {
		cout << format("\n  [COMMIT] #{} heap=0x{:016X} addr=0x{:016X} size=0x{:X}",
		               count,
		               reinterpret_cast<uintptr_t>(heapBase),
		               reinterpret_cast<uintptr_t>(commitAddress),
		               commitSize);
	}
}

void TriggerHeapGrowth()
{
	vector<void*> blocks;
	blocks.reserve(64);

	for (int i = 0; i < 64; ++i) {
		auto* p = HeapAlloc(GetProcessHeap(), 0, 0x10000 + i * 0x1000);
		if (p)
			blocks.push_back(p);
	}

	for (auto* p : blocks)
		HeapFree(GetProcessHeap(), 0, p);
}

int main()
{
	cout << "============================================================\n"
	     << "  heapcommit \xe2\x80\x94 Heap CommitRoutine Hijack PoC\n"
	     << "============================================================\n\n";

	HeapCommitConfig config{
		.handler = OnCommitRoutineTriggered,
	};

	HeapCommit engine;

	cout << "[*] Initializing...\n";
	if (!engine.Initialize(config)) {
		cerr << "[!] Init failed\n";
		return 1;
	}
	cout << "[+] Initialized\n\n";

	cout << "[*] Heap state (before arm):\n";
	static_cast<void>(engine.DumpHeapInfo());

	cout << "\n[*] Arming CommitRoutine...\n";
	if (!engine.Arm()) {
		cerr << "[!] Arm failed\n";
		return 1;
	}
	cout << "[+] CommitRoutine hijacked\n\n";

	cout << "[*] Heap state (armed):\n";
	static_cast<void>(engine.DumpHeapInfo());

	cout << "\n[*] Triggering heap growth (64 large allocations)...\n";
	TriggerHeapGrowth();

	cout << format("\n\n[*] CommitRoutine fired {} time(s)\n", engine.GetTriggerCount());

	cout << "\n[*] Disarming...\n";
	static_cast<void>(engine.Disarm());
	cout << "[+] Original CommitRoutine restored\n\n";

	cout << "[*] Heap state (after disarm):\n";
	static_cast<void>(engine.DumpHeapInfo());

	cout << "\n============================================================\n"
	     << format("  Total triggers: {}\n", callbackHits.load())
	     << "============================================================\n";

	cout << "\n[*] Shutdown...\n";
	engine.Shutdown();
	cout << "[+] Clean.\n";

	return 0;
}
