#include "CommandHandlers.hpp"
#include <Windows.h>
#include <DbgHelp.h>
#include <iostream>
#include <format>
#include <regex>

#include "core/NtUtils.hpp"
#include "core/ProcessUtils.hpp"

static std::vector<DWORD> GetMatchingThreads(
	const std::vector<ThreadAddrInfo> &addrInfoList, const std::string &pattern
) {
	std::vector<DWORD> matchedTids;

	std::regex re;
	try {
		re = std::regex(pattern, std::regex_constants::icase);
	} catch (const std::regex_error &) {
		std::cerr << std::format("Invalid regex pattern: {}\n", pattern);
		return matchedTids;
	}

	for (const auto &t : addrInfoList) {
		if (std::regex_search(t.StartAddress, re)) {
			matchedTids.push_back(t.Tid);
		}
	}

	return matchedTids;
}

int CommandHandlers::HandleList(Formatter &formatter) {
	auto listResult = NtUtils::GetProcessList();
	if (!listResult.has_value()) {
		formatter.PrintError(
			std::format("Error getting process list: {}", listResult.error().message),
			listResult.error().traceback
		);
		return 1;
	}
	formatter.PrintProcessList(listResult.value());
	return 0;
}

int CommandHandlers::HandleKill(const std::string &target, Formatter &formatter) {
	auto pidsResult = ProcessUtils::GetTargetProcesses(target);
	if (!pidsResult.has_value()) {
		formatter.PrintError(
			std::format("Error resolving target: {}", pidsResult.error().message),
			pidsResult.error().traceback
		);
		return 1;
	}

	bool anyError = false;
	std::vector<std::pair<ProcessInfo, std::string>> results;

	for (const auto &proc : pidsResult.value()) {
		HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, proc.Pid);
		if (!hProcess) {
			results.push_back({proc, std::to_string(GetLastError())});
			anyError = true;
			continue;
		}
		if (!TerminateProcess(hProcess, 0)) {
			results.push_back({proc, std::to_string(GetLastError())});
			anyError = true;
		} else {
			results.push_back({proc, ""});
		}
		CloseHandle(hProcess);
	}
	formatter.PrintCommandResult(results, "killed");
	return anyError ? 1 : 0;
}

int CommandHandlers::HandleSuspend(const std::string &target, Formatter &formatter) {
	auto pidsResult = ProcessUtils::GetTargetProcesses(target);
	if (!pidsResult.has_value()) {
		formatter.PrintError(
			std::format("Error resolving target: {}", pidsResult.error().message),
			pidsResult.error().traceback
		);
		return 1;
	}

	bool anyError = false;
	std::vector<std::pair<ProcessInfo, std::string>> results;

	for (const auto &proc : pidsResult.value()) {
		auto res = NtUtils::SuspendProcess(proc.Pid);
		if (!res.has_value()) {
			results.push_back({proc, res.error().str()});
			anyError = true;
		} else {
			results.push_back({proc, ""});
		}
	}
	formatter.PrintCommandResult(results, "suspended");
	return anyError ? 1 : 0;
}

int CommandHandlers::HandleResume(const std::string &target, Formatter &formatter) {
	auto pidsResult = ProcessUtils::GetTargetProcesses(target);
	if (!pidsResult.has_value()) {
		formatter.PrintError(
			std::format("Error resolving target: {}", pidsResult.error().message),
			pidsResult.error().traceback
		);
		return 1;
	}

	bool anyError = false;
	std::vector<std::pair<ProcessInfo, std::string>> results;

	for (const auto &proc : pidsResult.value()) {
		auto res = NtUtils::ResumeProcess(proc.Pid);
		if (!res.has_value()) {
			results.push_back({proc, res.error().str()});
			anyError = true;
		} else {
			results.push_back({proc, ""});
		}
	}
	formatter.PrintCommandResult(results, "resumed");
	return anyError ? 1 : 0;
}

int CommandHandlers::HandleSuspendThread(
	const std::string &target, const std::string &thread, Formatter &formatter
) {
	auto pidsResult = ProcessUtils::GetTargetProcesses(target);
	if (!pidsResult.has_value()) {
		formatter.PrintError(
			std::format("Error resolving target: {}", pidsResult.error().message),
			pidsResult.error().traceback
		);
		return 1;
	}

	DWORD tid = 0;
	bool isRegex = false;
	try {
		size_t pos;
		tid = static_cast<DWORD>(std::stoul(thread, &pos));
		if (pos != thread.length()) { // Not a full number match
			isRegex = true;
		}
	} catch (...) {
		isRegex = true;
	}

	const auto &proc = pidsResult.value().front();
	bool anyError = false;

	if (isRegex) {
		ProcessUtils::EnableDebugPrivilege();
		auto addrInfoResult = ProcessUtils::GetThreadStartAddresses(proc.Pid);
		if (!addrInfoResult.has_value()) {
			formatter.PrintError(
				std::format(
					"Failed to get thread start addresses for PID {}"
					"\nReason: {}",
					proc.Pid,
					addrInfoResult.error().message
				),
				addrInfoResult.error().traceback
			);
			return 1;
		}
		auto matchedTids = GetMatchingThreads(addrInfoResult.value(), thread);
		if (matchedTids.empty()) {
			formatter.PrintError(std::format("No threads matched pattern: '{}'", thread));
			return 1;
		}

		for (DWORD matchedTid : matchedTids) {
			auto res = ProcessUtils::SuspendThread(matchedTid);
			if (!res.has_value()) {
				formatter.PrintError(
					std::format(
						"Failed to suspend thread {}: {}", matchedTid, res.error().message
					),
					res.error().traceback
				);
				anyError = true;
			} else {
				formatter.PrintCommandResult(
					{{proc, ""}},
					std::format("thread {} suspended (matched '{}')", matchedTid, thread)
				);
			}
		}
	} else {
		auto res = ProcessUtils::SuspendThread(tid);
		if (!res.has_value()) {
			formatter.PrintError(
				std::format("Failed to suspend thread {}: {}", tid, res.error().message),
				res.error().traceback
			);
			return 1;
		}

		formatter.PrintCommandResult(
			{{proc, ""}}, std::format("thread {} suspended", tid)
		);
	}

	return anyError ? 1 : 0;
}

int CommandHandlers::HandleResumeThread(
	const std::string &target, const std::string &thread, Formatter &formatter
) {
	auto pidsResult = ProcessUtils::GetTargetProcesses(target);
	if (!pidsResult.has_value()) {
		formatter.PrintError(
			std::format("Error resolving target: {}", pidsResult.error().message),
			pidsResult.error().traceback
		);
		return 1;
	}

	DWORD tid = 0;
	bool isRegex = false;
	try {
		size_t pos;
		tid = static_cast<DWORD>(std::stoul(thread, &pos));
		if (pos != thread.length()) { // Not a full number match
			isRegex = true;
		}
	} catch (...) {
		isRegex = true;
	}

	const auto &proc = pidsResult.value().front();
	bool anyError = false;

	if (isRegex) {
		ProcessUtils::EnableDebugPrivilege();
		auto addrInfoResult = ProcessUtils::GetThreadStartAddresses(proc.Pid);
		if (!addrInfoResult.has_value()) {
			formatter.PrintError(
				std::format(
					"Failed to get thread start addresses for PID {}"
					"\nReason: {}",
					proc.Pid,
					addrInfoResult.error().message
				),
				addrInfoResult.error().traceback
			);
			return 1;
		}
		auto matchedTids = GetMatchingThreads(addrInfoResult.value(), thread);
		if (matchedTids.empty()) {
			formatter.PrintError(std::format("No threads matched pattern: '{}'", thread));
			return 1;
		}

		for (DWORD matchedTid : matchedTids) {
			auto res = ProcessUtils::ResumeThread(matchedTid);
			if (!res.has_value()) {
				formatter.PrintError(
					std::format(
						"Failed to resume thread {}"
						"\nReason: {}",
						matchedTid,
						res.error().message
					),
					res.error().traceback
				);
				anyError = true;
			} else {
				formatter.PrintCommandResult(
					{{proc, ""}},
					std::format("thread {} resumed (matched '{}')", matchedTid, thread)
				);
			}
		}
	} else {
		auto res = ProcessUtils::ResumeThread(tid);
		if (!res.has_value()) {
			formatter.PrintError(
				std::format(
					"Failed to resume thread {}"
					"\nReason: {}",
					tid,
					res.error().message
				),
				res.error().traceback
			);
			return 1;
		}

		formatter.PrintCommandResult({{proc, ""}}, std::format("thread {} resumed", tid));
	}

	return anyError ? 1 : 0;
}

int CommandHandlers::HandleQuery(const std::string &target, Formatter &formatter) {
	auto pidsResult = ProcessUtils::GetTargetProcesses(target);
	if (!pidsResult.has_value()) {
		formatter.PrintError(
			std::format("Error resolving target: {}", pidsResult.error().message),
			pidsResult.error().traceback
		);
		return 1;
	}
	formatter.PrintProcessDetails(pidsResult.value());
	return 0;
}

int CommandHandlers::HandleQueryThread(
	const std::string &target, const std::string &thread, Formatter &formatter
) {
	auto pidsResult = ProcessUtils::GetTargetProcesses(target);
	if (!pidsResult.has_value()) {
		formatter.PrintError(
			std::format(
				"Error resolving target: {}"
				"\nReason: {}",
				target,
				pidsResult.error().message
			),
			pidsResult.error().traceback
		);
		return 1;
	}

	DWORD tid = 0;
	bool isRegex = false;
	try {
		size_t pos;
		tid = static_cast<DWORD>(std::stoul(thread, &pos));
		if (pos != thread.length()) { // Not a full number match
			isRegex = true;
		}
	} catch (...) {
		isRegex = true;
	}

	ProcessUtils::EnableDebugPrivilege();
	bool anyError = false;

	for (const auto &proc : pidsResult.value()) {
		std::vector<DWORD> matchedTids;
		auto addrInfoResult = ProcessUtils::GetThreadStartAddresses(proc.Pid);
		if (!addrInfoResult.has_value()) {
			formatter.PrintError(
				std::format(
					"Failed to get thread start addresses for PID {}"
					"\nReason: {}",
					proc.Pid,
					addrInfoResult.error().message
				),
				addrInfoResult.error().traceback
			);
			anyError = true;
			continue;
		}
		auto addrInfoList = addrInfoResult.value();
		if (isRegex) {
			matchedTids = GetMatchingThreads(addrInfoList, thread);
		} else {
			// Just verifying if the requested TID actually belongs to this process
			auto threadsResult = NtUtils::GetProcessThreads(proc.Pid);
			if (threadsResult.has_value()) {
				for (const auto &t : threadsResult.value()) {
					if (t.Tid == tid) {
						matchedTids.push_back(tid);
						break;
					}
				}
			}
		}

		if (matchedTids.empty()) {
			if (isRegex) {
				formatter.PrintError(
					std::format(
						"No threads matched pattern '{}' for PID {}.", thread, proc.Pid
					)
				);
			} else {
				formatter.PrintError(
					std::format("Thread {} not found in PID {}.", tid, proc.Pid)
				);
			}
			anyError = true;
			continue;
		}

		std::vector<ThreadAddrInfo> filteredList;
		for (const auto &t : addrInfoList) {
			if (std::find(matchedTids.begin(), matchedTids.end(), t.Tid) !=
				matchedTids.end()) {
				filteredList.push_back(t);
			}
		}

		if (!filteredList.empty()) {
			formatter.PrintThreads(proc.Pid, proc.Name, filteredList);
		}
	}

	return anyError ? 1 : 0;
}
