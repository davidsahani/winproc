#pragma once

#include <vector>

#include "core/NtUtils.hpp"
#include "core/ProcessUtils.hpp"

enum class Action
{
	Terminate,
	Suspend,
	Resume,
};

class Formatter {
public:
	explicit Formatter(bool useJson);

	void PrintProcessList(const std::vector<ProcessInfo> &processes);
	void PrintProcessDetails(const std::vector<ProcessInfo> &processes);
	void
	PrintCommandResult(const std::pair<ProcessInfo, ResultVoid> &result, Action action);
	void PrintThreadAction(
		DWORD pid,
		std::wstring_view processName,
		Action action,
		const std::vector<std::pair<ThreadAddrInfo, ResultVoid>> &results
	);
	void PrintThreadAction(
		DWORD pid,
		std::wstring_view processName,
		Action action,
		const std::vector<std::pair<ThreadNameInfo, ResultVoid>> &results
	);
	void PrintThreads(
		DWORD pid,
		std::wstring_view processName,
		const std::vector<ThreadAddrInfo> &threads
	);

	void PrintSuccess(std::string_view message);
	void PrintError(std::string_view message);
	void PrintError(std::string_view message, std::string_view traceback);

private:
	bool m_useJson;
};
