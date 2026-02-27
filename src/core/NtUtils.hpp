#pragma once

#include <vector>
#include <Windows.h>

#include "Result.hpp"
#include "Error.hpp"

struct ThreadInfo {
	DWORD Tid;
	PVOID NativeStartAddress;
	PVOID Win32StartAddress;
};

struct ProcessInfo {
	DWORD Pid;
	std::wstring Name;
	bool Suspended;
};

class NtUtils {
public:
	/**
     * @brief Check if the specified process is suspended.
     */
	static Result<bool, Error> IsProcessSuspended(DWORD pid);

	/**
     * @brief Suspend the specified process.
     */
	static Result<bool, Error> SuspendProcess(DWORD pid);

	/**
     * @brief Resume the specified process.
     */
	static Result<bool, Error> ResumeProcess(DWORD pid);

	/**
     * @brief Get threads information for the specified process.
     */
	static Result<std::vector<ThreadInfo>, Error> GetProcessThreads(DWORD pid);

	/**
	 * @brief Get a list of all running processes.
	 */
	static Result<std::vector<ProcessInfo>, Error> GetProcessList();

	/**
     * @brief Get the image path of the specified process.
     */
	static Result<std::wstring, Error> GetProcessPath(DWORD pid);

private:
	NtUtils();
	~NtUtils() = default;
	static NtUtils &Instance();

	HMODULE m_hNtDll; /* Handle to the ntdll.dll module */
};
