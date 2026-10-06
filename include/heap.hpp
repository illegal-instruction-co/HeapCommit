#pragma once

#include <cstdint>
#include <windows.h>
#include <array>

namespace heap {

struct ProcessBasicInfo final
{
	int32_t ExitStatus;
	uint8_t _pad[4];
	void *PebBaseAddress;
	uint64_t AffinityMask;
	int32_t BasePriority;
	uint8_t _pad2[4];
	uint64_t UniqueProcessId;
	uint64_t InheritedFromUniqueProcessId;
};

struct FindResult final
{
	uint32_t offset;
	uint64_t encoded;
	bool found;
};

template<typename T = uint32_t>
consteval std::array<T, 7> offsetCandidatesPrimary()
{
	return {0x148, 0x150, 0x158, 0x160, 0x168, 0x170, 0x140};
}

template<typename T = uint32_t>
consteval std::array<T, 7> offsetCandidatesFallback()
{
	return {0x168, 0x158, 0x148, 0x170, 0x160, 0x150, 0x140};
}

FindResult findCommitRoutine(
	HANDLE process,
	void *processHeap,
	uint32_t cookie
);

}
