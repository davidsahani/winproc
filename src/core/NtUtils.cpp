#include "NtUtils.hpp"

#include <string>
#include <format>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winternl.h>

#include "WinError.hpp"

// Only need these two from ntstatus.h — can't include the full header
// because NtUtils.hpp already pulled in Windows.h (which defines a
// conflicting subset of NTSTATUS codes).
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

// Info-class value: SystemProcessIdInformation == 0x58
#ifndef SystemProcessIdInformation
#define SystemProcessIdInformation static_cast<SYSTEM_INFORMATION_CLASS>(0x58)
#endif

// Struct layout used by SystemProcessIdInformation
typedef struct _SYSTEM_PROCESS_ID_INFORMATION {
	PVOID ProcessId;          // input only
	UNICODE_STRING ImageName; // in/out: caller supplies buffer; callee fills it
} SYSTEM_PROCESS_ID_INFORMATION, *PSYSTEM_PROCESS_ID_INFORMATION;

typedef NTSTATUS(WINAPI *PNtQueryInformationProcess)(HANDLE, UINT, PVOID, ULONG, PULONG);

static std::wstring DevicePathToDrivePath(const std::wstring &ntPath);

NtUtils::NtUtils() {
	m_hNtDll = GetModuleHandleW(L"ntdll.dll");
}

HMODULE NtUtils::GetNtdllModule() {
	static NtUtils instance;
	if (!instance.m_hNtDll) {
		instance.m_hNtDll = GetModuleHandleW(L"ntdll.dll");
	}
	return instance.m_hNtDll;
}

Result<bool, Error> NtUtils::IsProcessSuspended(DWORD pid) {
	HMODULE hNtDll = GetNtdllModule();
	if (!hNtDll) {
		return WinErr(GetLastError(), "Failed to load module ntdll.dll");
	}

	// Resolve NtQuerySystemInformation
	using NtQuerySystemInformationFn = NTSTATUS(NTAPI *)(
		ULONG SystemInformationClass,
		PVOID SystemInformation,
		ULONG SystemInformationLength,
		PULONG ReturnLength
	);

	auto NtQuerySystemInformation = reinterpret_cast<NtQuerySystemInformationFn>(
		GetProcAddress(hNtDll, "NtQuerySystemInformation")
	);

	if (!NtQuerySystemInformation) {
		return Error("Symbol not found: ntdll.dll!NtQuerySystemInformation");
	}

	constexpr ULONG SystemProcessInformation = 5;
	constexpr ULONG StateWaiting = 5;
	constexpr ULONG ReasonSuspended = 5;

	// Query system process information with dynamic buffer sizing
	ULONG bufferSize = 1024 * 1024; // Start with 1 MB
	auto buffer = std::make_unique<BYTE[]>(bufferSize);

	ULONG returnLength = 0;
	NTSTATUS status = NtQuerySystemInformation(
		SystemProcessInformation, buffer.get(), bufferSize, &returnLength
	);

	if (status == STATUS_INFO_LENGTH_MISMATCH) {
		bufferSize = returnLength;
		buffer = std::make_unique<BYTE[]>(bufferSize);
		status = NtQuerySystemInformation(
			SystemProcessInformation, buffer.get(), bufferSize, &returnLength
		);
	}

	if (!NT_SUCCESS(status)) {
		return NtStatusErr(
			status,
			std::format("Failed to query system process information for PID: {}", pid)
		);
	}

	// Walk the process list to find our target PID
	auto *procInfo = reinterpret_cast<SYSTEM_PROCESS_INFORMATION *>(buffer.get());

	while (true) {
		if (reinterpret_cast<ULONG_PTR>(procInfo->UniqueProcessId) ==
			static_cast<ULONG_PTR>(pid)) {
			ULONG threadCount = procInfo->NumberOfThreads;
			if (threadCount == 0) return false;

			// Thread array follows immediately after the SYSTEM_PROCESS_INFORMATION header
			auto *threads = reinterpret_cast<SYSTEM_THREAD_INFORMATION *>(
				reinterpret_cast<BYTE *>(procInfo) + sizeof(SYSTEM_PROCESS_INFORMATION)
			);

			for (ULONG i = 0; i < threadCount; ++i) {
				if (threads[i].ThreadState != StateWaiting ||
					threads[i].WaitReason != ReasonSuspended) {
					return false;
				}
			}
			return true;
		}

		if (procInfo->NextEntryOffset == 0) break;
		procInfo = reinterpret_cast<SYSTEM_PROCESS_INFORMATION *>(
			reinterpret_cast<BYTE *>(procInfo) + procInfo->NextEntryOffset
		);
	}

	return Error(std::format("No process found with PID: {}", pid));
}

Result<std::monostate, Error> NtUtils::SuspendProcess(DWORD pid) {
	HMODULE hNtDll = GetNtdllModule();
	if (!hNtDll) {
		return WinErr(GetLastError(), "Failed to load module ntdll.dll");
	}

	using NtSuspendProcessFn = NTSTATUS(NTAPI *)(HANDLE ProcessHandle);
	auto NtSuspendProcessPtr =
		reinterpret_cast<NtSuspendProcessFn>(GetProcAddress(hNtDll, "NtSuspendProcess"));

	if (!NtSuspendProcessPtr) {
		return Error("Symbol not found: ntdll.dll!NtSuspendProcess");
	}

	HANDLE hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
	if (!hProcess) {
		return WinErr(
			GetLastError(), std::format("Failed to open process with PID: {}", pid)
		);
	}

	NTSTATUS status = NtSuspendProcessPtr(hProcess);
	CloseHandle(hProcess);

	if (!NT_SUCCESS(status)) {
		return NtStatusErr(
			status, std::format("Failed to suspend process with PID: {}", pid)
		);
	}

	return std::monostate{};
}

Result<std::monostate, Error> NtUtils::ResumeProcess(DWORD pid) {
	HMODULE hNtDll = GetNtdllModule();
	if (!hNtDll) {
		return WinErr(GetLastError(), "Failed to load module ntdll.dll");
	}

	using NtResumeProcessFn = NTSTATUS(NTAPI *)(HANDLE ProcessHandle);
	auto NtResumeProcessPtr =
		reinterpret_cast<NtResumeProcessFn>(GetProcAddress(hNtDll, "NtResumeProcess"));

	if (!NtResumeProcessPtr) {
		return Error("Symbol not found: ntdll.dll!NtResumeProcess");
	}

	HANDLE hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
	if (!hProcess) {
		return WinErr(
			GetLastError(), std::format("Failed to open process with PID: {}", pid)
		);
	}

	NTSTATUS status = NtResumeProcessPtr(hProcess);
	CloseHandle(hProcess);

	if (!NT_SUCCESS(status)) {
		return NtStatusErr(
			status, std::format("Failed to resume process with PID: {}", pid)
		);
	}

	return std::monostate{};
}

Result<std::vector<ProcessInfo>, Error> NtUtils::GetProcessList() {
	HMODULE hNtDll = GetNtdllModule();
	if (!hNtDll) {
		return WinErr(GetLastError(), "Failed to load module ntdll.dll");
	}

	using NtQuerySystemInformationFn = NTSTATUS(NTAPI *)(
		ULONG SystemInformationClass,
		PVOID SystemInformation,
		ULONG SystemInformationLength,
		PULONG ReturnLength
	);

	auto NtQuerySystemInformation = reinterpret_cast<NtQuerySystemInformationFn>(
		GetProcAddress(hNtDll, "NtQuerySystemInformation")
	);

	if (!NtQuerySystemInformation) {
		return Error("Symbol not found: ntdll.dll!NtQuerySystemInformation");
	}

	constexpr ULONG SystemProcessInformation = 5;
	ULONG bufferSize = 1024 * 1024; // Start with 1 MB
	auto buffer = std::make_unique<BYTE[]>(bufferSize);

	ULONG returnLength = 0;
	NTSTATUS status = NtQuerySystemInformation(
		SystemProcessInformation, buffer.get(), bufferSize, &returnLength
	);

	if (status == STATUS_INFO_LENGTH_MISMATCH) {
		bufferSize = returnLength;
		buffer = std::make_unique<BYTE[]>(bufferSize);
		status = NtQuerySystemInformation(
			SystemProcessInformation, buffer.get(), bufferSize, &returnLength
		);
	}

	if (!NT_SUCCESS(status)) {
		return NtStatusErr(status, std::format("Failed to query system process list"));
	}

	auto *procInfo = reinterpret_cast<SYSTEM_PROCESS_INFORMATION *>(buffer.get());
	std::vector<ProcessInfo> processList;
	processList.reserve(bufferSize);

	while (true) {
		ProcessInfo info{};
		info.Pid =
			static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(procInfo->UniqueProcessId));
		info.ParentPid =
			static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(procInfo->Reserved2));
		info.SessionId = procInfo->SessionId;
		info.BasePriority = procInfo->BasePriority;
		info.Memory = procInfo->WorkingSetSize;

		if (procInfo->ImageName.Buffer) {
			info.Name = std::wstring(
				procInfo->ImageName.Buffer, procInfo->ImageName.Length / sizeof(WCHAR)
			);
		} else if (info.Pid == 0) {
			info.Name = L"Idle";
		} else {
			info.Name = L"System";
		}

		processList.push_back(info);

		if (procInfo->NextEntryOffset == 0) break;
		procInfo = reinterpret_cast<SYSTEM_PROCESS_INFORMATION *>(
			reinterpret_cast<BYTE *>(procInfo) + procInfo->NextEntryOffset
		);
	}

	return processList;
}

Result<std::vector<ThreadInfo>, Error> NtUtils::GetProcessThreads(DWORD pid) {
	HMODULE hNtDll = GetNtdllModule();
	if (!hNtDll) {
		return WinErr(GetLastError(), "Failed to load module ntdll.dll");
	}

	using NtQuerySystemInformationFn = NTSTATUS(NTAPI *)(
		ULONG SystemInformationClass,
		PVOID SystemInformation,
		ULONG SystemInformationLength,
		PULONG ReturnLength
	);

	auto NtQuerySystemInformation = reinterpret_cast<NtQuerySystemInformationFn>(
		GetProcAddress(hNtDll, "NtQuerySystemInformation")
	);

	if (!NtQuerySystemInformation) {
		return Error("Symbol not found: ntdll.dll!NtQuerySystemInformation");
	}

	using NtQueryInformationThreadFn = NTSTATUS(NTAPI *)(
		HANDLE ThreadHandle,
		ULONG ThreadInformationClass,
		PVOID ThreadInformation,
		ULONG ThreadInformationLength,
		PULONG ReturnLength
	);

	auto NtQueryInformationThread = reinterpret_cast<NtQueryInformationThreadFn>(
		GetProcAddress(hNtDll, "NtQueryInformationThread")
	);

	if (!NtQueryInformationThread) {
		return Error("Symbol not found: ntdll.dll!NtQueryInformationThread");
	}

	constexpr ULONG SystemProcessInformation = 5;
	constexpr ULONG ThreadQuerySetWin32StartAddress = 9;

	ULONG bufferSize = 1024 * 1024; // Start with 1 MB
	auto buffer = std::make_unique<BYTE[]>(bufferSize);

	ULONG returnLength = 0;
	NTSTATUS status = NtQuerySystemInformation(
		SystemProcessInformation, buffer.get(), bufferSize, &returnLength
	);

	if (status == STATUS_INFO_LENGTH_MISMATCH) {
		bufferSize = returnLength;
		buffer = std::make_unique<BYTE[]>(bufferSize);
		status = NtQuerySystemInformation(
			SystemProcessInformation, buffer.get(), bufferSize, &returnLength
		);
	}

	if (!NT_SUCCESS(status)) {
		return NtStatusErr(
			status,
			std::format("Failed to query system thread information for PID: {}", pid)
		);
	}

	auto *procInfo = reinterpret_cast<SYSTEM_PROCESS_INFORMATION *>(buffer.get());

	while (true) {
		if (reinterpret_cast<ULONG_PTR>(procInfo->UniqueProcessId) ==
			static_cast<ULONG_PTR>(pid)) {
			ULONG threadCount = procInfo->NumberOfThreads;

			auto *threads = reinterpret_cast<SYSTEM_THREAD_INFORMATION *>(
				reinterpret_cast<BYTE *>(procInfo) + sizeof(SYSTEM_PROCESS_INFORMATION)
			);

			std::vector<ThreadInfo> threadsList;
			threadsList.reserve(threadCount);

			for (ULONG i = 0; i < threadCount; ++i) {
				ThreadInfo info{};
				info.Tid = static_cast<DWORD>(
					reinterpret_cast<ULONG_PTR>(threads[i].ClientId.UniqueThread)
				);
				info.NativeStartAddress = threads[i].StartAddress;

				HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, info.Tid);
				if (hThread) {
					PVOID win32StartAddress = nullptr;
					status = NtQueryInformationThread(
						hThread,
						ThreadQuerySetWin32StartAddress,
						&win32StartAddress,
						sizeof(PVOID),
						nullptr
					);

					if (status == STATUS_SUCCESS) {
						info.Win32StartAddress = win32StartAddress;
					} else {
						info.Win32StartAddress = nullptr;
					}
					CloseHandle(hThread);
				} else {
					info.Win32StartAddress = nullptr;
				}

				info.BasePriority = threads[i].BasePriority;
				info.ThreadState = threads[i].ThreadState;
				info.WaitReason = threads[i].WaitReason;
				threadsList.push_back(info);
			}
			return threadsList;
		}

		if (procInfo->NextEntryOffset == 0) break;
		procInfo = reinterpret_cast<SYSTEM_PROCESS_INFORMATION *>(
			reinterpret_cast<BYTE *>(procInfo) + procInfo->NextEntryOffset
		);
	}

	return Error(std::format("No process found with PID: {}", pid));
}

Result<std::wstring, Error> NtUtils::GetProcessPath(DWORD pid) {
	HMODULE hNtDll = GetNtdllModule();
	if (!hNtDll) {
		return WinErr(GetLastError(), "Failed to load module ntdll.dll");
	}

	using pfnNtQuerySystemInformation =
		NTSTATUS(NTAPI *)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
	auto NtQuerySystemInformation =
		(pfnNtQuerySystemInformation)GetProcAddress(hNtDll, "NtQuerySystemInformation");

	if (!NtQuerySystemInformation) {
		return Error("Symbol not found: ntdll.dll!NtQuerySystemInformation");
	}

	// Allocate buffer
	constexpr USHORT kMaxBytes = 1024;
	PWSTR buf = (PWSTR)LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT, kMaxBytes);
	if (!buf) {
		return Error("Failed to allocate buffer");
	}

	SYSTEM_PROCESS_ID_INFORMATION info = {0};
	info.ProcessId = (PVOID)(ULONG_PTR)pid;
	info.ImageName.Buffer = buf;
	info.ImageName.Length = 0;
	info.ImageName.MaximumLength = kMaxBytes;

	NTSTATUS status = NtQuerySystemInformation(
		SystemProcessIdInformation, &info, sizeof(info), nullptr
	);

	std::wstring out;
	bool success = false;

	if (NT_SUCCESS(status) && info.ImageName.Buffer && info.ImageName.Length) {
		out =
			std::wstring(info.ImageName.Buffer, info.ImageName.Length / sizeof(wchar_t));
		success = true;
	}

	LocalFree(buf);

	if (success) {
		return DevicePathToDrivePath(out);
	} else {
		return NtStatusErr(
			status, std::format("Failed to query system process path for PID: {}", pid)
		);
	}
}

// Helper to convert NT internal path to Drive path
static std::wstring DevicePathToDrivePath(const std::wstring &ntPath) {
	if (ntPath.empty()) return ntPath;

	WCHAR drives[512]; // ample space
	if (!GetLogicalDriveStringsW(sizeof(drives) / sizeof(WCHAR), drives)) {
		return ntPath;
	}

	WCHAR deviceName[MAX_PATH];
	WCHAR driveName[3] = L" :";

	PWSTR pDrive = drives;
	while (*pDrive) {
		// pDrive is like "C:\"
		driveName[0] = pDrive[0]; // Copy drive letter "C"

		// QueryDosDevice requires "C:", not "C:\"
		if (QueryDosDeviceW(driveName, deviceName, MAX_PATH)) {
			size_t deviceNameLen = wcslen(deviceName);
			// Check if ntPath starts with deviceName
			// deviceName might be "\Device\HarddiskVolume3"
			// ntPath might be "\Device\HarddiskVolume3\Windows\..."
			if (ntPath.size() > deviceNameLen &&
				_wcsnicmp(ntPath.c_str(), deviceName, deviceNameLen) == 0 &&
				ntPath[deviceNameLen] == L'\\') {

				return std::wstring(driveName) + ntPath.substr(deviceNameLen);
			}
		}

		// Move to next drive string
		pDrive += wcslen(pDrive) + 1;
	}

	return ntPath;
}
