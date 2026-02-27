#include "NtUtils.hpp"
#include <string>
#include <format>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winternl.h>

// Only need these two from ntstatus.h — can't include the full header
// because NtUtils.hpp already pulled in Windows.h (which defines a
// conflicting subset of NTSTATUS codes).
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

#include "WinError.hpp"

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

NtUtils &NtUtils::Instance() {
	static NtUtils instance;
	return instance;
}

Result<bool, Error> NtUtils::IsProcessSuspended(DWORD pid) {
	HMODULE hNtDll = Instance().m_hNtDll;

	if (!hNtDll) {
		return Error("Failed to get module handle for ntdll.dll");
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
		return Error("Failed to resolve NtQuerySystemInformation");
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

	if (status != STATUS_SUCCESS) {
		return Error(
			std::format(
				"NtQuerySystemInformation failed with status 0x{:08X}",
				static_cast<unsigned long>(status)
			)
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

	return Error(std::format("Process with PID {} not found", pid));
}

Result<bool, Error> NtUtils::SuspendProcess(DWORD pid) {
	HMODULE hNtDll = Instance().m_hNtDll;
	if (!hNtDll) {
		return Error("Failed to get module handle for ntdll.dll");
	}

	using NtSuspendProcessFn = NTSTATUS(NTAPI *)(HANDLE ProcessHandle);
	auto NtSuspendProcessPtr =
		reinterpret_cast<NtSuspendProcessFn>(GetProcAddress(hNtDll, "NtSuspendProcess"));

	if (!NtSuspendProcessPtr) {
		return Error("Failed to resolve NtSuspendProcess");
	}

	HANDLE hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
	if (!hProcess) {
		return WinErr(GetLastError(), std::format("Failed to open process {}", pid));
	}

	NTSTATUS status = NtSuspendProcessPtr(hProcess);
	CloseHandle(hProcess);

	if (status != STATUS_SUCCESS) {
		return Error(
			std::format(
				"NtSuspendProcess failed with status 0x{:08X}",
				static_cast<unsigned long>(status)
			)
		);
	}

	return true;
}

Result<bool, Error> NtUtils::ResumeProcess(DWORD pid) {
	HMODULE hNtDll = Instance().m_hNtDll;
	if (!hNtDll) {
		return Error("Failed to get module handle for ntdll.dll");
	}

	using NtResumeProcessFn = NTSTATUS(NTAPI *)(HANDLE ProcessHandle);
	auto NtResumeProcessPtr =
		reinterpret_cast<NtResumeProcessFn>(GetProcAddress(hNtDll, "NtResumeProcess"));

	if (!NtResumeProcessPtr) {
		return Error("Failed to resolve NtResumeProcess");
	}

	HANDLE hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
	if (!hProcess) {
		return WinErr(GetLastError(), std::format("Failed to open process {}", pid));
	}

	NTSTATUS status = NtResumeProcessPtr(hProcess);
	CloseHandle(hProcess);

	if (status != STATUS_SUCCESS) {
		return Error(
			std::format(
				"NtResumeProcess failed with status 0x{:08X}",
				static_cast<unsigned long>(status)
			)
		);
	}

	return true;
}

Result<std::vector<ThreadInfo>, Error> NtUtils::GetProcessThreads(DWORD pid) {
	HMODULE hNtDll = Instance().m_hNtDll;

	if (!hNtDll) {
		return Error("Failed to get module handle for ntdll.dll");
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

	if (!NtQuerySystemInformation || !NtQueryInformationThread) {
		return Error("Failed to resolve NtQuery APIs");
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

	if (status != STATUS_SUCCESS) {
		return Error(
			std::format(
				"NtQuerySystemInformation failed with status 0x{:08X}",
				static_cast<unsigned long>(status)
			)
		);
	}

	auto *procInfo = reinterpret_cast<SYSTEM_PROCESS_INFORMATION *>(buffer.get());
	std::vector<ThreadInfo> threadsList;

	while (true) {
		if (reinterpret_cast<ULONG_PTR>(procInfo->UniqueProcessId) ==
			static_cast<ULONG_PTR>(pid)) {
			ULONG threadCount = procInfo->NumberOfThreads;

			auto *threads = reinterpret_cast<SYSTEM_THREAD_INFORMATION *>(
				reinterpret_cast<BYTE *>(procInfo) + sizeof(SYSTEM_PROCESS_INFORMATION)
			);

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

				threadsList.push_back(info);
			}
			return threadsList;
		}

		if (procInfo->NextEntryOffset == 0) break;
		procInfo = reinterpret_cast<SYSTEM_PROCESS_INFORMATION *>(
			reinterpret_cast<BYTE *>(procInfo) + procInfo->NextEntryOffset
		);
	}

	return Error(std::format("Process with PID {} not found", pid));
}

Result<std::vector<ProcessInfo>, Error> NtUtils::GetProcessList() {
	HMODULE hNtDll = Instance().m_hNtDll;

	if (!hNtDll) {
		return Error("Failed to get module handle for ntdll.dll");
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
		return Error("Failed to resolve NtQuerySystemInformation");
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

	if (status != STATUS_SUCCESS) {
		return Error(
			std::format(
				"NtQuerySystemInformation failed with status 0x{:08X}",
				static_cast<unsigned long>(status)
			)
		);
	}

	auto *procInfo = reinterpret_cast<SYSTEM_PROCESS_INFORMATION *>(buffer.get());
	std::vector<ProcessInfo> processList;

	constexpr ULONG StateWaiting = 5;
	constexpr ULONG ReasonSuspended = 5;

	while (true) {
		ProcessInfo info{};
		info.Pid =
			static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(procInfo->UniqueProcessId));

		if (procInfo->ImageName.Buffer) {
			info.Name = std::wstring(
				procInfo->ImageName.Buffer, procInfo->ImageName.Length / sizeof(WCHAR)
			);
		} else if (info.Pid == 0) {
			info.Name = L"Idle";
		} else {
			info.Name = L"System";
		}

		ULONG threadCount = procInfo->NumberOfThreads;
		info.Suspended = false;
		if (threadCount > 0) {
			auto *threads = reinterpret_cast<SYSTEM_THREAD_INFORMATION *>(
				reinterpret_cast<BYTE *>(procInfo) + sizeof(SYSTEM_PROCESS_INFORMATION)
			);
			bool allSuspended = true;
			for (ULONG i = 0; i < threadCount; ++i) {
				if (threads[i].ThreadState != StateWaiting ||
					threads[i].WaitReason != ReasonSuspended) {
					allSuspended = false;
					break;
				}
			}
			info.Suspended = allSuspended;
		}

		processList.push_back(info);

		if (procInfo->NextEntryOffset == 0) break;
		procInfo = reinterpret_cast<SYSTEM_PROCESS_INFORMATION *>(
			reinterpret_cast<BYTE *>(procInfo) + procInfo->NextEntryOffset
		);
	}

	return processList;
}

Result<std::wstring, Error> NtUtils::GetProcessPath(DWORD pid) {
	HMODULE hNtDll = Instance().m_hNtDll;
	if (!hNtDll) {
		return Error("Failed to get module handle for ntdll.dll");
	}

	using pfnNtQuerySystemInformation =
		NTSTATUS(NTAPI *)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
	auto NtQuerySystemInformation =
		(pfnNtQuerySystemInformation)GetProcAddress(hNtDll, "NtQuerySystemInformation");

	if (!NtQuerySystemInformation) {
		return Error("Failed to get address of NtQuerySystemInformation");
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
		return Error(
			std::format(
				"NtQuerySystemInformation (0x58) failed or empty. Status: {:x}",
				(unsigned int)status
			)
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
