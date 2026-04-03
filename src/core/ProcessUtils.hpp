#pragma once

#include <string>
#include <variant>
#include <vector>
#include <Windows.h>

#include "NtUtils.hpp"

// Define a struct to hold thread name info for output
struct ThreadNameInfo {
	ThreadInfo info;
	std::string Name;
};

// Define a struct to hold thread address info for output
struct ThreadAddrInfo {
	ThreadInfo info;
	std::string Name;
	std::string StartAddress;
};

namespace ProcessUtils {

	/**
	* @brief Enable SeDebugPrivilege for the current process.
	*/
	ResultVoid EnableDebugPrivilege(HANDLE hProcess);

	/**
	* @brief Gets names for all threads in a process (lightweight, no symbol resolution).
	*/
	Result<std::vector<ThreadNameInfo>, Error> GetThreadNames(DWORD pid);

	/**
	 * @brief Gets start addresses for all threads in a process.
	 */
	Result<std::vector<ThreadAddrInfo>, Error> GetThreadStartAddresses(DWORD pid);

	/**
	 * @brief Resolves a process name or PID string to a list of matching processes.
	 */
	Result<std::vector<ProcessInfo>, Error> GetTargetProcesses(std::string_view target);

	/**
	 * @brief Gets the file description for the process from its executable version info.
	 */
	Result<std::wstring, Error> GetFileDescriptionFromPath(const std::wstring &file);

	/**
	 * @brief Gets the file description for the process from its executable version info.
	 */
	Result<std::wstring, Error> GetProcessDescription(DWORD pid);

	/**
	 * @brief Suspend a single thread by its thread ID.
	 */
	Result<std::monostate, Error> SuspendThread(DWORD tid);

	/**
	 * @brief Resume a single thread by its thread ID.
	 */
	Result<std::monostate, Error> ResumeThread(DWORD tid);

	/**
	 * @brief Gets the priority class for the specified process.
	 */
	Result<DWORD, Error> GetProcessPriority(DWORD pid);

	/**
	 * @brief Gets the priority level for the specified thread.
	 */
	Result<int, Error> GetThreadPriorityLevel(DWORD tid);

	/**
	 * @brief Sets the priority class for the specified process.
	 */
	Result<std::monostate, Error> SetProcessPriority(DWORD pid, DWORD priorityClass);

	/**
	 * @brief Sets the priority level for the specified thread.
	 */
	Result<std::monostate, Error> SetThreadPriorityLevel(DWORD tid, int priorityLevel);

} // namespace ProcessUtils
