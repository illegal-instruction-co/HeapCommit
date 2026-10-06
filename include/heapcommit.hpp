#pragma once

#include <cstdint>
#include <windows.h>

namespace heapcommit {

enum class Status : uint32_t {
	OK = 0, INVALID_PROCESS = 1, READ_FAILED = 2,
	EXPORT_FAILED = 3, WRITE_FAILED = 4, NOT_FOUND = 5
};

constexpr bool isValid(Status s) noexcept {
	return s == Status::OK;
}

constexpr const char *toString(Status s) noexcept {
	using enum Status;
	switch (s) {
	case OK: return "OK";
	case INVALID_PROCESS: return "INVALID_PROCESS";
	case READ_FAILED: return "READ_FAILED";
	case EXPORT_FAILED: return "EXPORT_FAILED";
	case WRITE_FAILED: return "WRITE_FAILED";
	case NOT_FOUND: return "NOT_FOUND";
	}
	return "UNKNOWN";
}

struct Config final
{
	HANDLE process;
	void *processHeap;
	void *shellcode;
	uint32_t shellcodeSize;
	void *loaderAddr;
	void *dstData;
	uint32_t commitRoutineOffset;
};

Status inject(const Config &cfg);

}
