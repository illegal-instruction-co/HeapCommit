#include "HeapCommit.h"

#include <format>
#include <iostream>

using namespace std;

namespace machinetherapist {

	HeapCommit* HeapCommit::_instance = nullptr;

	HeapCommit::~HeapCommit()
	{
		Shutdown();
	}

	bool HeapCommit::Initialize(const HeapCommitConfig& config)
	{
		if (_initialized)
			return false;

		_config = config;
		_ntdll = GetModuleHandleW(L"ntdll.dll");
		if (!_ntdll)
			return false;

		_processHeap = GetProcessHeap();
		if (!_processHeap)
			return false;

		if (!ResolveXorCookie())
			return false;

		if (!ReadOriginalRoutine())
			return false;

		_instance = this;
		_initialized = true;
		return true;
	}

	bool HeapCommit::ResolveXorCookie()
	{
		auto* base = reinterpret_cast<uint8_t*>(_ntdll);

		auto* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
		auto* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dosHeader->e_lfanew);
		auto* sections = IMAGE_FIRST_SECTION(ntHeaders);

		uint8_t* dataSection = nullptr;
		size_t dataSize = 0;

		for (uint16_t i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
			if (memcmp(sections[i].Name, ".data", 5) == 0) {
				dataSection = base + sections[i].VirtualAddress;
				dataSize = sections[i].Misc.VirtualSize;
				break;
			}
		}

		if (!dataSection)
			return false;

		auto* heapPtr = reinterpret_cast<uint8_t*>(_processHeap);
		auto encodedValue = *reinterpret_cast<uint64_t*>(heapPtr + HeapCommitRoutineOffset);

		auto* scan = reinterpret_cast<uint64_t*>(dataSection);
		auto scanCount = dataSize / sizeof(uint64_t);

		for (size_t i = 0; i < scanCount; ++i) {
			if (scan[i] == encodedValue) {
				_xorCookie = scan[i];

				auto testEncoded = reinterpret_cast<uint64_t>(GetProcAddress(_ntdll, "RtlAllocateHeap")) ^ scan[i];
				auto testDecoded = testEncoded ^ scan[i];
				if (testDecoded == reinterpret_cast<uint64_t>(GetProcAddress(_ntdll, "RtlAllocateHeap"))) {
					_xorCookie = scan[i];
					return true;
				}
			}
		}

		_xorCookie = encodedValue;
		return true;
	}

	bool HeapCommit::ReadOriginalRoutine()
	{
		auto* heapPtr = reinterpret_cast<uint8_t*>(_processHeap);
		_originalEncoded = *reinterpret_cast<uint64_t*>(heapPtr + HeapCommitRoutineOffset);
		return true;
	}

	bool HeapCommit::WriteCommitRoutine(uint64_t encodedValue)
	{
		auto* heapPtr = reinterpret_cast<uint8_t*>(_processHeap);
		auto* target = reinterpret_cast<uint64_t*>(heapPtr + HeapCommitRoutineOffset);
		*target = encodedValue;
		return true;
	}

	NTSTATUS NTAPI HeapCommit::TrampolineCommitRoutine(PVOID heapBase, PVOID* commitAddress, PSIZE_T commitSize)
	{
		auto* self = _instance;
		if (!self || !self->_armed.load())
			return NtAllocateVirtualMemory(GetCurrentProcess(), commitAddress, 0, commitSize, MEM_COMMIT, PAGE_READWRITE);

		self->_triggerCount.fetch_add(1);

		if (self->_config.handler) {
			self->_config.handler(heapBase, commitAddress ? *commitAddress : nullptr, commitSize ? *commitSize : 0, self->_config.userData);
		}

		return NtAllocateVirtualMemory(GetCurrentProcess(), commitAddress, 0, commitSize, MEM_COMMIT, PAGE_READWRITE);
	}

	bool HeapCommit::Arm()
	{
		if (!_initialized || _armed.load())
			return false;

		auto trampolineAddr = reinterpret_cast<uint64_t>(&TrampolineCommitRoutine);
		auto encoded = trampolineAddr ^ _xorCookie;

		if (!WriteCommitRoutine(encoded))
			return false;

		_armed.store(true);
		return true;
	}

	bool HeapCommit::Disarm()
	{
		if (!_armed.load())
			return false;

		static_cast<void>(WriteCommitRoutine(_originalEncoded));
		_armed.store(false);
		return true;
	}

	void HeapCommit::Shutdown()
	{
		if (!_initialized)
			return;

		static_cast<void>(Disarm());
		_instance = nullptr;
		_initialized = false;
	}

	bool HeapCommit::DumpHeapInfo()
	{
		if (!_initialized)
			return false;

		auto* heapPtr = reinterpret_cast<uint8_t*>(_processHeap);
		auto flags = *reinterpret_cast<uint32_t*>(heapPtr + HeapFlagsOffset);
		auto encoded = *reinterpret_cast<uint64_t*>(heapPtr + HeapCommitRoutineOffset);

		auto isNull = (encoded == _xorCookie);
		uint64_t decoded = isNull ? 0 : (encoded ^ _xorCookie);

		cout << format("  ProcessHeap:    0x{:016X}\n", reinterpret_cast<uintptr_t>(_processHeap))
		     << format("  Heap Flags:     0x{:08X}\n", flags)
		     << format("  XOR Cookie:     0x{:016X}\n", _xorCookie)
		     << format("  Encoded [168]:  0x{:016X}\n", encoded)
		     << format("  Decoded Func:   0x{:016X}{}\n", decoded, isNull ? "  (NULL)" : "")
		     << format("  ntdll Base:     0x{:016X}\n", reinterpret_cast<uintptr_t>(_ntdll));

		return true;
	}

}
