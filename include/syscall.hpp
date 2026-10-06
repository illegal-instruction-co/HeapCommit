#pragma once

#include <cstdint>
#include <windows.h>

extern "C" {
	NTSTATUS NTAPI NtReadVirtualMemory(
		HANDLE ProcessHandle,
		void *BaseAddress,
		void *Buffer,
		size_t BufferSize,
		size_t *NumberOfBytesRead
	);

	NTSTATUS NTAPI NtWriteVirtualMemory(
		HANDLE ProcessHandle,
		void *BaseAddress,
		void *Buffer,
		size_t BufferSize,
		size_t *NumberOfBytesWritten
	);

	NTSTATUS NTAPI NtQueryInformationProcess(
		HANDLE ProcessHandle,
		uint32_t ProcessInformationClass,
		void *ProcessInformation,
		uint32_t ProcessInformationLength,
		uint32_t *ReturnLength
	);

	NTSTATUS NTAPI NtClose(HANDLE Handle);
}
