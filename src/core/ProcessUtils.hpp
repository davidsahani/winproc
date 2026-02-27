#pragma once

#include <string>
#include <vector>
#include <Windows.h>

#include "NtUtils.hpp"

// Define a struct to hold thread address info for output
struct ThreadAddrInfo {
	DWORD Tid;
	std::string StartAddress;
};

namespace ProcessUtils {

	/**
	* @brief Enable SeDebugPrivilege for the current process.
	*/
	bool EnableDebugPrivilege();

	/**
	 * @brief Gets start addresses for all threads in a process.
	 */
	Result<std::vector<ThreadAddrInfo>, Error> GetThreadStartAddresses(DWORD pid);

	/**
	 * @brief Resolves a process name or PID string to a list of matching processes.
	 */
	Result<std::vector<ProcessInfo>, Error> GetTargetProcesses(const std::string &input);

	/**
	 * @brief Gets the file description for the process from its executable version info.
	 */
	Result<std::wstring, Error> GetProcessDescription(DWORD pid);

	/**
	 * @brief Gets the priority class for the specified process.
	 */
	Result<DWORD, Error> GetProcessPriority(DWORD pid);

	/**
	 * @brief Gets the priority level for the specified thread.
	 */
	Result<int, Error> GetThreadPriorityLevel(DWORD tid);

	/**
	 * @brief Suspend a single thread by its thread ID.
	 */
	Result<bool, Error> SuspendThread(DWORD tid);

	/**
	 * @brief Resume a single thread by its thread ID.
	 */
	Result<bool, Error> ResumeThread(DWORD tid);

} // namespace ProcessUtils
