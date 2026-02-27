#include "CommandHandlers.hpp"
#include <Windows.h>
#include <DbgHelp.h>
#include <iostream>
#include <format>
#include <regex>

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
		auto matchedThreads = GetMatchingThreads(addrInfoResult.value(), thread);
		if (matchedThreads.empty()) {
			formatter.PrintError(std::format("No threads matched pattern: '{}'", thread));
			return 1;
		}

		std::vector<ThreadAddrInfo> successfulThreads;
		std::vector<std::pair<ThreadAddrInfo, std::string>> failedThreads;

		for (const auto &matchedInfo : matchedThreads) {
			auto res = ProcessUtils::SuspendThread(matchedInfo.Tid);
			if (!res.has_value()) {
				failedThreads.push_back({matchedInfo, res.error().message});
				anyError = true;
			} else {
				successfulThreads.push_back(matchedInfo);
			}
		}

		formatter.PrintThreadAction(
			proc.Pid, proc.Name, "Suspended", successfulThreads, failedThreads
		);
	} else {
		ProcessUtils::EnableDebugPrivilege();
		auto addrInfoResult = ProcessUtils::GetThreadStartAddresses(proc.Pid);
		std::string startAddress = "Unknown";
		if (addrInfoResult.has_value()) {
			for (const auto &a : addrInfoResult.value()) {
				if (a.Tid == tid) {
					startAddress = a.StartAddress;
					break;
				}
			}
		}

		std::vector<ThreadAddrInfo> successfulThreads;
		std::vector<std::pair<ThreadAddrInfo, std::string>> failedThreads;
		ThreadAddrInfo tInfo = {tid, startAddress};

		auto res = ProcessUtils::SuspendThread(tid);
		if (!res.has_value()) {
			failedThreads.push_back({tInfo, res.error().message});
		} else {
			successfulThreads.push_back(tInfo);
		}

		formatter.PrintThreadAction(
			proc.Pid, proc.Name, "Suspended", successfulThreads, failedThreads
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
		auto matchedThreads = GetMatchingThreads(addrInfoResult.value(), thread);
		if (matchedThreads.empty()) {
			formatter.PrintError(std::format("No threads matched pattern: '{}'", thread));
			return 1;
		}

		std::vector<ThreadAddrInfo> successfulThreads;
		std::vector<std::pair<ThreadAddrInfo, std::string>> failedThreads;

		for (const auto &matchedInfo : matchedThreads) {
			auto res = ProcessUtils::ResumeThread(matchedInfo.Tid);
			if (!res.has_value()) {
				failedThreads.push_back({matchedInfo, res.error().message});
				anyError = true;
			} else {
				successfulThreads.push_back(matchedInfo);
			}
		}

		formatter.PrintThreadAction(
			proc.Pid, proc.Name, "Resumed", successfulThreads, failedThreads
		);
	} else {
		ProcessUtils::EnableDebugPrivilege();
		auto addrInfoResult = ProcessUtils::GetThreadStartAddresses(proc.Pid);
		std::string startAddress = "Unknown";
		if (addrInfoResult.has_value()) {
			for (const auto &a : addrInfoResult.value()) {
				if (a.Tid == tid) {
					startAddress = a.StartAddress;
					break;
				}
			}
		}

		std::vector<ThreadAddrInfo> successfulThreads;
		std::vector<std::pair<ThreadAddrInfo, std::string>> failedThreads;
		ThreadAddrInfo tInfo = {tid, startAddress};

		auto res = ProcessUtils::ResumeThread(tid);
		if (!res.has_value()) {
			failedThreads.push_back({tInfo, res.error().message});
		} else {
			successfulThreads.push_back(tInfo);
		}

		formatter.PrintThreadAction(
			proc.Pid, proc.Name, "Resumed", successfulThreads, failedThreads
		);
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
		std::vector<ThreadAddrInfo> matchedThreads;
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
			matchedThreads = GetMatchingThreads(addrInfoList, thread);
		} else {
			// Just verifying if the requested TID actually belongs to this process
			auto threadsResult = NtUtils::GetProcessThreads(proc.Pid);
			if (threadsResult.has_value()) {
				for (const auto &t : threadsResult.value()) {
					if (t.Tid == tid) {
						for (const auto &a : addrInfoList) {
							if (a.Tid == tid) {
								matchedThreads.push_back(a);
								break;
							}
						}
						break;
					}
				}
			}
		}

		if (matchedThreads.empty()) {
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

		formatter.PrintThreads(proc.Pid, proc.Name, matchedThreads);
	}

	return anyError ? 1 : 0;
}
