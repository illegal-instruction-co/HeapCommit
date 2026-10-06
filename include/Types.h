#pragma once

#include <Windows.h>

#include <cstddef>
#include <cstdint>

extern "C" NTSTATUS NTAPI NtAllocateVirtualMemory(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);

namespace machinetherapist {

	inline constexpr size_t HeapCommitRoutineOffset = 0x168;
	inline constexpr size_t HeapFlagsOffset = 0x070;

	using HeapCommitRoutineFn = NTSTATUS(NTAPI*)(PVOID heapBase, PVOID* commitAddress, PSIZE_T commitSize);

}
