#pragma once

#include <vector>

#include "core/NtUtils.hpp"
#include "core/ProcessUtils.hpp"

enum class Action
{
	Terminate,
	Suspend,
	Resume,
	SetPriority,
};

namespace Formatter {
	void PrintProcessList(const std::vector<ProcessInfo> &processes);
	void PrintProcessDetails(const std::vector<ProcessInfo> &processes);
	void PrintThreads(
		DWORD pid,
		std::wstring_view processName,
		const std::vector<ThreadAddrInfo> &threads
	);
	void PrintCommandResult(
		const std::pair<ProcessInfo, ResultVoid> &result, Action action
	);
	void PrintThreadsResult(
		DWORD pid,
		std::wstring_view processName,
		Action action,
		const std::vector<std::pair<ThreadNameInfo, ResultVoid>> &results
	);
	void PrintThreadsResult(
		DWORD pid,
		std::wstring_view processName,
		Action action,
		const std::vector<std::pair<ThreadAddrInfo, ResultVoid>> &results
	);

	void PrintSuccess(std::string_view message);
	void PrintWarning(std::string_view message);
	void PrintError(std::string_view message);
	void PrintWarning(std::string_view message, std::string_view traceback);
	void PrintError(std::string_view message, std::string_view traceback);
} // namespace Formatter
