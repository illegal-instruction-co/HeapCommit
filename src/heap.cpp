#include <heap.hpp>
#include <encoding.hpp>
#include <syscall.hpp>

#include <bit>

namespace heap {

FindResult findCommitRoutine(
	HANDLE process,
	void *processHeap,
	uint32_t cookie
)
{
	uint8_t heapBuf[0x200] = {};
	NTSTATUS status = NtReadVirtualMemory(process, processHeap, heapBuf, sizeof(heapBuf), nullptr);
	if (status != 0) {
		return {0, 0, false};
	}

	uint64_t encoded = 0;

	if (cookie != 0) {
		const uint64_t cookie64 = cookie;
		const uint32_t rotBits = cookie64 & 0x3F;
		const uint64_t encodedNull = std::rotr(cookie64, static_cast<int>(rotBits));

		const auto candidates = offsetCandidatesPrimary();
		for (const uint32_t off : candidates) {
			const uint64_t val = *reinterpret_cast<uint64_t *>(heapBuf + off);
			if (val == encodedNull) {
				return {off, val, true};
			}
		}

		for (const uint32_t off : candidates) {
			const uint64_t val = *reinterpret_cast<uint64_t *>(heapBuf + off);
			if (val == cookie64) {
				return {off, val, true};
			}
		}
	}

	const auto candidates = offsetCandidatesFallback();
	for (const uint32_t off : candidates) {
		const uint64_t val = *reinterpret_cast<uint64_t *>(heapBuf + off);
		if (val != 0 && (val >> 48) != 0 && (val >> 48) != 0x7FF && (val >> 48) != 0x000) {
			return {off, val, true};
		}
	}

	const uint32_t offset = 0x168;
	status = NtReadVirtualMemory(
		process,
		(uint8_t *)processHeap + offset,
		&encoded,
		sizeof(encoded),
		nullptr
	);
	if (status != 0) {
		return {0, 0, false};
	}

	return {offset, encoded, true};
}

}
