#pragma once

#include <string>
#include <vector>

#include "core/NtUtils.hpp"
#include "core/ProcessUtils.hpp"

class Formatter {
public:
	explicit Formatter(bool useJson);

	void PrintProcessList(const std::vector<ProcessInfo> &processes);
	void PrintProcessDetails(const std::vector<ProcessInfo> &processes);
	void PrintCommandResult(
		const std::vector<std::pair<ProcessInfo, std::string>> &results,
		const std::string &actionVerb
	);
	void PrintThreads(
		DWORD pid,
		const std::wstring &processName,
		const std::vector<ThreadAddrInfo> &threads
	);

	// Helper for errors that happen before command execution loop
	void PrintError(const std::string &message);
	void PrintError(const std::string &message, const std::string &traceback);

private:
	bool m_useJson;
};
