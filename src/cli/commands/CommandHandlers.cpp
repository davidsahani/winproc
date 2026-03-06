#include "CommandHandlers.hpp"
#include <Windows.h>
#include <DbgHelp.h>
#include <iostream>
#include <format>
#include <regex>

#include "WinError.hpp"
#include "StringUtils.hpp"
#include "core/NtUtils.hpp"
#include "core/ProcessUtils.hpp"

static std::vector<ThreadAddrInfo> GetMatchingThreads(
	const std::vector<ThreadAddrInfo> &addrInfoList, const std::string &pattern
) {
	std::vector<ThreadAddrInfo> matchedThreads;

	std::regex re;
	try {
		re = std::regex(pattern, std::regex_constants::icase);
	} catch (const std::regex_error &) {
		std::cerr << std::format("Invalid regex pattern: {}\n", pattern);
		return matchedThreads;
	}

	for (const auto &t : addrInfoList) {
		if (std::regex_search(t.StartAddress, re)) {
			matchedThreads.push_back(t);
		}
	}

	return matchedThreads;
}

int CommandHandlers::HandleList(Formatter &formatter) {
	auto listResult = NtUtils::GetProcessList();
	if (!listResult.has_value()) {
		formatter.PrintError(
			std::format(
				"Failed to retrieve process list"
				"\nReason: {}",
				listResult.error().message
			),
			listResult.error().traceback
		);
		return 1;
	}
	formatter.PrintProcessList(listResult.value());
	return 0;
}

int CommandHandlers::HandleKill(const std::string &target, Formatter &formatter) {
	auto procsResult = ProcessUtils::GetTargetProcesses(target);
	if (!procsResult.has_value()) {
		formatter.PrintError(
			std::format(
				"Failed to resolve target: \"{}\""
				"\nReason: {}",
				target,
				procsResult.error().message
			),
			procsResult.error().traceback
		);
		return 1;
	}

	bool anyError = false;

	for (const auto &proc : procsResult.value()) {
		HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, proc.Pid);
		if (!hProcess) {
			Error err = WinErr(
				GetLastError(),
				std::format(
					"Failed to open process \"{}\" with PID {}",
					StringUtils::WstrToString(proc.Name),
					proc.Pid
				)
			);
			formatter.PrintCommandResult({proc, err}, Action::Terminate);
			anyError = true;
			continue;
		}
		if (!TerminateProcess(hProcess, 0)) {
			Error err = WinErr(
				GetLastError(),
				std::format(
					"Failed to terminate process \"{}\" with PID {}",
					StringUtils::WstrToString(proc.Name),
					proc.Pid
				)
			);
			formatter.PrintCommandResult({proc, err}, Action::Terminate);
			anyError = true;
		} else {
			formatter.PrintCommandResult({proc, std::monostate{}}, Action::Terminate);
		}
		CloseHandle(hProcess);
	}
	return anyError ? 1 : 0;
}

int CommandHandlers::HandleSuspend(const std::string &target, Formatter &formatter) {
	auto procsResult = ProcessUtils::GetTargetProcesses(target);
	if (!procsResult.has_value()) {
		formatter.PrintError(
			std::format(
				"Failed to resolve target: \"{}\""
				"\nReason: {}",
				target,
				procsResult.error().message
			),
			procsResult.error().traceback
		);
		return 1;
	}

	std::vector<std::pair<ProcessInfo, ResultVoid>> results{};

	for (const auto &proc : procsResult.value()) {
		results.push_back({
			proc,
			NtUtils::SuspendProcess(proc.Pid),
		});
	}

	bool anyError = false;
	for (const auto &res : results) {
		if (!res.second.has_value()) {
			anyError = true;
		}
		formatter.PrintCommandResult(res, Action::Suspend);
	}
	return anyError ? 1 : 0;
}

int CommandHandlers::HandleResume(const std::string &target, Formatter &formatter) {
	auto procsResult = ProcessUtils::GetTargetProcesses(target);
	if (!procsResult.has_value()) {
		formatter.PrintError(
			std::format(
				"Failed to resolve target: \"{}\""
				"\nReason: {}",
				target,
				procsResult.error().message
			),
			procsResult.error().traceback
		);
		return 1;
	}

	std::vector<std::pair<ProcessInfo, ResultVoid>> results{};

	for (const auto &proc : procsResult.value()) {
		results.push_back({
			proc,
			NtUtils::ResumeProcess(proc.Pid),
		});
	}

	bool anyError = false;
	for (const auto &res : results) {
		if (!res.second.has_value()) {
			anyError = true;
		}
		formatter.PrintCommandResult(res, Action::Resume);
	}
	return anyError ? 1 : 0;
}

static bool SuspendThreadById(DWORD tid, const ProcessInfo &proc, Formatter &formatter) {
	ResultVoid result = ProcessUtils::SuspendThread(tid);

	if (result.has_value()) {
		formatter.PrintSuccess(
			std::format(
				"Thread {} of process \"{}\" with PID {} has been suspended.\n",
				tid,
				StringUtils::WstrToString(proc.Name),
				proc.Pid
			)
		);
	} else {
		const Error &error = result.error();
		formatter.PrintError(error.message, error.traceback);
	}
	return result.has_value();
}

static bool ResumeThreadById(DWORD tid, const ProcessInfo &proc, Formatter &formatter) {
	ResultVoid result = ProcessUtils::ResumeThread(tid);

	if (result.has_value()) {
		formatter.PrintSuccess(
			std::format(
				"Thread {} of process \"{}\" with PID {} has been resumed.\n",
				tid,
				StringUtils::WstrToString(proc.Name),
				proc.Pid
			)
		);
	} else {
		const Error &error = result.error();
		formatter.PrintError(error.message, error.traceback);
	}

	return result.has_value();
}

static bool inline SuspendThreadByName(
	const std::vector<ThreadNameInfo> &matchedThreads,
	const ProcessInfo &proc,
	Formatter &formatter
) {
	bool allOk = true;
	std::vector<std::pair<ThreadNameInfo, ResultVoid>> results;
	for (const auto &matchedInfo : matchedThreads) {
		auto result = ProcessUtils::SuspendThread(matchedInfo.Tid);
		if (!result.has_value()) allOk = false;
		results.push_back({matchedInfo, result});
	}

	formatter.PrintThreadAction(proc.Pid, proc.Name, Action::Suspend, results);
	return allOk;
}

static bool inline ResumeThreadByName(
	const std::vector<ThreadNameInfo> &matchedThreads,
	const ProcessInfo &proc,
	Formatter &formatter
) {
	bool allOk = true;
	std::vector<std::pair<ThreadNameInfo, ResultVoid>> results;
	for (const auto &matchedInfo : matchedThreads) {
		auto res = ProcessUtils::ResumeThread(matchedInfo.Tid);
		if (!res.has_value()) allOk = false;
		results.push_back({matchedInfo, res});
	}

	formatter.PrintThreadAction(proc.Pid, proc.Name, Action::Resume, results);
	return allOk;
}

int CommandHandlers::HandleSuspendThread(
	const std::string &target, const std::string &threadIdOrName, Formatter &formatter
) {
	auto procsResult = ProcessUtils::GetTargetProcesses(target);
	if (!procsResult.has_value()) {
		formatter.PrintError(
			std::format(
				"Failed to resolve target: \"{}\""
				"\nReason: {}",
				target,
				procsResult.error().message
			),
			procsResult.error().traceback
		);
		return 1;
	}

	DWORD tid = 0;
	bool isId = false;
	try {
		size_t pos;
		tid = static_cast<DWORD>(std::stoul(threadIdOrName, &pos));
		if (pos == threadIdOrName.length()) isId = true;
	} catch (...) {
	}

	if (isId && procsResult.value().size() == 1) {
		const auto &proc = procsResult.value().front();
		return SuspendThreadById(tid, proc, formatter) ? 0 : 1;
	}

	bool found = false;
	bool anyError = false;

	for (const auto &proc : procsResult.value()) {
		auto nameInfoResult = ProcessUtils::GetThreadNames(proc.Pid);
		if (!nameInfoResult.has_value()) {
			formatter.PrintError(
				std::format(
					"Failed to get thread names for process \"{}\" with PID {}"
					"\nReason: {}",
					StringUtils::WstrToString(proc.Name),
					proc.Pid,
					nameInfoResult.error().message
				),
				nameInfoResult.error().traceback
			);
			anyError = true;
			continue;
		}

		// Find and suspend thread by Id
		if (isId) {
			for (const ThreadNameInfo &threadInfo : nameInfoResult.value()) {
				if (threadInfo.Tid == tid) {
					bool success = SuspendThreadById(tid, proc, formatter);
					if (!success) anyError = true;
					found = true;
				}
			}
		} else {
			// Filter matching thread names
			std::vector<ThreadNameInfo> matchedThreads;
			for (const auto &threadInfo : nameInfoResult.value()) {
				if (threadInfo.Name == threadIdOrName) {
					matchedThreads.push_back(threadInfo);
					found = true;
				}
			}

			// Suspend thread by name
			if (!matchedThreads.empty()) {
				bool success = SuspendThreadByName(matchedThreads, proc, formatter);
				if (!success) anyError = true;
				continue;
			}
		}
	}

	if (!found) {
		ProcessInfo proc = procsResult.value().front();

		if (isId) {
			formatter.PrintError(
				std::format(
					"No threads matched TID '{}' of process \"{}\" with PID {}",
					threadIdOrName,
					StringUtils::WstrToString(proc.Name),
					proc.Pid
				)
			);
		} else {
			formatter.PrintError(
				std::format(
					"No threads matched name '{}' of process \"{}\" with PID {}",
					threadIdOrName,
					StringUtils::WstrToString(proc.Name),
					proc.Pid
				)
			);
		}
		return 1;
	}

	return anyError ? 1 : 0;
}

int CommandHandlers::HandleResumeThread(
	const std::string &target, const std::string &threadIdOrName, Formatter &formatter
) {
	auto procsResult = ProcessUtils::GetTargetProcesses(target);
	if (!procsResult.has_value()) {
		formatter.PrintError(
			std::format(
				"Failed to resolve target: \"{}\""
				"\nReason: {}",
				target,
				procsResult.error().message
			),
			procsResult.error().traceback
		);
		return 1;
	}

	DWORD tid = 0;
	bool isId = false;
	try {
		size_t pos;
		tid = static_cast<DWORD>(std::stoul(threadIdOrName, &pos));
		if (pos == threadIdOrName.length()) isId = true;
	} catch (...) {
	}

	if (isId && procsResult.value().size() == 1) {
		const auto &proc = procsResult.value().front();
		return ResumeThreadById(tid, proc, formatter) ? 0 : 1;
	}

	bool found = false;
	bool anyError = false;

	for (const auto &proc : procsResult.value()) {
		auto nameInfoResult = ProcessUtils::GetThreadNames(proc.Pid);
		if (!nameInfoResult.has_value()) {
			formatter.PrintError(
				std::format(
					"Failed to get thread names for process \"{}\" with PID {}"
					"\nReason: {}",
					StringUtils::WstrToString(proc.Name),
					proc.Pid,
					nameInfoResult.error().message
				),
				nameInfoResult.error().traceback
			);
			anyError = true;
			continue;
		}

		// Find and resume thread by Id
		if (isId) {
			for (const ThreadNameInfo &threadInfo : nameInfoResult.value()) {
				if (threadInfo.Tid == tid) {
					bool success = ResumeThreadById(tid, proc, formatter);
					if (!success) anyError = true;
					found = true;
				}
			}
		} else {
			// Filter matching thread names
			std::vector<ThreadNameInfo> matchedThreads;
			for (const auto &threadInfo : nameInfoResult.value()) {
				if (threadInfo.Name == threadIdOrName) {
					matchedThreads.push_back(threadInfo);
					found = true;
				}
			}

			// Resume thread by name
			if (!matchedThreads.empty()) {
				bool success = ResumeThreadByName(matchedThreads, proc, formatter);
				if (!success) anyError = true;
				continue;
			}
		}
	}

	if (!found) {
		ProcessInfo proc = procsResult.value().front();

		if (isId) {
			formatter.PrintError(
				std::format(
					"No threads matched TID '{}' of process \"{}\" with PID {}",
					threadIdOrName,
					StringUtils::WstrToString(proc.Name),
					proc.Pid
				)
			);
		} else {
			formatter.PrintError(
				std::format(
					"No threads matched name '{}' of process \"{}\" with PID {}",
					threadIdOrName,
					StringUtils::WstrToString(proc.Name),
					proc.Pid
				)
			);
		}
		return 1;
	}

	return anyError ? 1 : 0;
}

int CommandHandlers::HandleSuspendThreadByAddr(
	const std::string &target, const std::string &threadAddrRegex, Formatter &formatter
) {
	auto procsResult = ProcessUtils::GetTargetProcesses(target);
	if (!procsResult.has_value()) {
		formatter.PrintError(
			std::format(
				"Failed to resolve target: \"{}\""
				"\nReason: {}",
				target,
				procsResult.error().message
			),
			procsResult.error().traceback
		);
		return 1;
	}

	ProcessUtils::EnableDebugPrivilege();
	bool anyError = false;
	bool found = false;

	for (const auto &proc : procsResult.value()) {
		std::vector<std::pair<ThreadAddrInfo, ResultVoid>> results;

		auto addrInfoResult = ProcessUtils::GetThreadStartAddresses(proc.Pid);
		if (!addrInfoResult.has_value()) {
			formatter.PrintError(
				std::format(
					"Failed to get thread start addresses for process \"{}\" with PID {}."
					"\nReason: {}",
					StringUtils::WstrToString(proc.Name),
					proc.Pid,
					addrInfoResult.error().message
				),
				addrInfoResult.error().traceback
			);
			anyError = true;
			continue;
		}

		const std::vector<ThreadAddrInfo> matchedThreads =
			GetMatchingThreads(addrInfoResult.value(), threadAddrRegex);

		for (const auto &matchedInfo : matchedThreads) {
			auto res = ProcessUtils::SuspendThread(matchedInfo.Tid);
			if (!res.has_value()) anyError = true;
			results.push_back({matchedInfo, res});
		}

		if (!matchedThreads.empty()) {
			formatter.PrintThreadAction(proc.Pid, proc.Name, Action::Suspend, results);
			found = true;
		}
	}

	if (!found) {
		ProcessInfo proc = procsResult.value().front();

		formatter.PrintError(
			std::format(
				"No threads matched pattern '{}' "
				"for process \"{}\" with PID {}.",
				threadAddrRegex,
				StringUtils::WstrToString(proc.Name),
				proc.Pid
			)
		);
		return 1;
	}

	return anyError ? 1 : 0;
}

int CommandHandlers::HandleResumeThreadByAddr(
	const std::string &target, const std::string &threadAddrRegex, Formatter &formatter
) {
	auto procsResult = ProcessUtils::GetTargetProcesses(target);
	if (!procsResult.has_value()) {
		formatter.PrintError(
			std::format(
				"Failed to resolve target: \"{}\""
				"\nReason: {}",
				target,
				procsResult.error().message
			),
			procsResult.error().traceback
		);
		return 1;
	}

	ProcessUtils::EnableDebugPrivilege();
	bool anyError = false;
	bool found = false;

	for (const auto &proc : procsResult.value()) {
		std::vector<std::pair<ThreadAddrInfo, ResultVoid>> results;

		auto addrInfoResult = ProcessUtils::GetThreadStartAddresses(proc.Pid);
		if (!addrInfoResult.has_value()) {
			formatter.PrintError(
				std::format(
					"Failed to get thread start addresses for PID: {}"
					"\nReason: {}",
					proc.Pid,
					addrInfoResult.error().message
				),
				addrInfoResult.error().traceback
			);
			anyError = true;
			continue;
		}

		const std::vector<ThreadAddrInfo> matchedThreads =
			GetMatchingThreads(addrInfoResult.value(), threadAddrRegex);

		for (const auto &matchedInfo : matchedThreads) {
			auto res = ProcessUtils::ResumeThread(matchedInfo.Tid);
			if (!res.has_value()) anyError = true;
			results.push_back({matchedInfo, res});
		}

		if (!matchedThreads.empty()) {
			formatter.PrintThreadAction(proc.Pid, proc.Name, Action::Resume, results);
			found = true;
		}
	}

	if (!found) {
		ProcessInfo proc = procsResult.value().front();

		formatter.PrintError(
			std::format(
				"No threads matched pattern '{}' "
				"for process \"{}\" with PID {}.",
				threadAddrRegex,
				StringUtils::WstrToString(proc.Name),
				proc.Pid
			)
		);
		return 1;
	}

	return anyError ? 1 : 0;
}

int CommandHandlers::HandleQuery(const std::string &target, Formatter &formatter) {
	auto pidsResult = ProcessUtils::GetTargetProcesses(target);
	if (!pidsResult.has_value()) {
		formatter.PrintError(
			std::format(
				"Failed to resolve target: \"{}\""
				"\nReason: {}",
				target,
				pidsResult.error().message
			),
			pidsResult.error().traceback
		);
		return 1;
	}
	formatter.PrintProcessDetails(pidsResult.value());
	return 0;
}

int CommandHandlers::HandleQueryThread(
	const std::string &target,
	const std::string &threadIdOrName,
	bool queryAll,
	Formatter &formatter
) {
	auto procsResult = ProcessUtils::GetTargetProcesses(target);
	if (!procsResult.has_value()) {
		formatter.PrintError(
			std::format(
				"Failed to resolve target: \"{}\""
				"\nReason: {}",
				target,
				procsResult.error().message
			),
			procsResult.error().traceback
		);
		return 1;
	}

	ProcessUtils::EnableDebugPrivilege();
	bool anyError = false;
	bool foundAny = false;

	for (const auto &proc : procsResult.value()) {
		auto addrInfoResult = ProcessUtils::GetThreadStartAddresses(proc.Pid);
		if (!addrInfoResult.has_value()) {
			formatter.PrintError(
				std::format(
					"Failed to get thread start addresses for process \"{}\" with PID: {}"
					"\nCause: {}",
					StringUtils::WstrToString(proc.Name),
					proc.Pid,
					addrInfoResult.error().message
				),
				addrInfoResult.error().traceback
			);
			anyError = true;
			continue;
		}

		auto addrInfoList = addrInfoResult.value();
		std::vector<ThreadAddrInfo> matchedThreads;

		bool found = queryAll;

		if (queryAll) {
			matchedThreads = addrInfoList;
		} else if (!threadIdOrName.empty()) {
			DWORD tid = 0;
			bool isId = false;
			try {
				size_t pos;
				tid = static_cast<DWORD>(std::stoul(threadIdOrName, &pos));
				if (pos == threadIdOrName.length()) isId = true;
			} catch (...) {
			}

			for (const auto &a : addrInfoList) {
				if (isId && a.Tid == tid) {
					matchedThreads.push_back(a);
					found = true;
				} else if (!isId && a.Name == threadIdOrName) {
					matchedThreads.push_back(a);
					found = true;
				}
			}
		}

		if (found) formatter.PrintThreads(proc.Pid, proc.Name, matchedThreads);
		if (found) foundAny = true;
	}

	if (!foundAny) {
		ProcessInfo proc = procsResult.value().front();

		formatter.PrintError(
			std::format(
				"No threads matched id/name \"{}\" for process \"{}\" with PID {}.",
				threadIdOrName,
				StringUtils::WstrToString(proc.Name),
				proc.Pid
			)
		);

		return 1;
	}

	return anyError ? 1 : 0;
}
