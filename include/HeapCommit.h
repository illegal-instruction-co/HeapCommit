#pragma once

#include "Types.h"

#include <atomic>
#include <cstdint>

namespace machinetherapist {

	using PayloadCallback = void (*)(PVOID heapBase, PVOID commitAddress, SIZE_T commitSize, PVOID userData);

	struct HeapCommitConfig final {
		PayloadCallback handler = nullptr;
		PVOID userData = nullptr;
	};

	class HeapCommit final {
	public:
		~HeapCommit();

		HeapCommit() = default;
		HeapCommit(const HeapCommit&) = delete;
		HeapCommit& operator=(const HeapCommit&) = delete;

		[[nodiscard]] inline int32_t GetTriggerCount() const noexcept { return _triggerCount.load(); }

		[[nodiscard]] bool Initialize(const HeapCommitConfig& config);
		[[nodiscard]] bool Arm();
		[[nodiscard]] bool Disarm();
		void Shutdown();

		[[nodiscard]] bool DumpHeapInfo();

	private:
		static HeapCommit* _instance;

		HeapCommitConfig _config{};
		PVOID _processHeap = nullptr;
		HMODULE _ntdll = nullptr;
		uint64_t _xorCookie = 0;
		uint64_t _originalEncoded = 0;
		std::atomic<int32_t> _triggerCount{0};
		std::atomic<bool> _armed{false};
		bool _initialized = false;

		[[nodiscard]] bool ResolveXorCookie();
		[[nodiscard]] bool ReadOriginalRoutine();
		[[nodiscard]] bool WriteCommitRoutine(uint64_t encodedValue);

		static NTSTATUS NTAPI TrampolineCommitRoutine(PVOID heapBase, PVOID* commitAddress, PSIZE_T commitSize);
	};

}
