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

int CommandHandlers::HandleSuspendThread(
	const std::string &target, const std::string &thread, Formatter &formatter
) {
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
	std::vector<std::pair<ThreadAddrInfo, ResultVoid>> results;

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

		for (const auto &matchedInfo : matchedThreads) {
			auto result = ProcessUtils::SuspendThread(matchedInfo.Tid);
			if (!result.has_value()) {
				anyError = true;
			}
			results.push_back({matchedInfo, result});
		}
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

		ThreadAddrInfo tInfo = {tid, startAddress};
		auto result = ProcessUtils::SuspendThread(tid);
		if (!result.has_value()) {
			anyError = true;
		}
		results.push_back({tInfo, result});
	}

	formatter.PrintThreadAction(proc.Pid, proc.Name, Action::Suspend, results);
	return anyError ? 1 : 0;
}

int CommandHandlers::HandleResumeThread(
	const std::string &target, const std::string &thread, Formatter &formatter
) {
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
	std::vector<std::pair<ThreadAddrInfo, ResultVoid>> results;

	if (isRegex) {
		ProcessUtils::EnableDebugPrivilege();
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
			return 1;
		}
		auto matchedThreads = GetMatchingThreads(addrInfoResult.value(), thread);
		if (matchedThreads.empty()) {
			formatter.PrintError(std::format("No threads matched pattern: '{}'", thread));
			return 1;
		}

		for (const auto &matchedInfo : matchedThreads) {
			auto res = ProcessUtils::ResumeThread(matchedInfo.Tid);
			if (!res.has_value()) {
				results.push_back({matchedInfo, res.error()});
				anyError = true;
			} else {
				results.push_back({matchedInfo, std::monostate{}});
			}
		}
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

		ThreadAddrInfo tInfo = {tid, startAddress};
		auto res = ProcessUtils::ResumeThread(tid);
		if (!res.has_value()) {
			results.push_back({tInfo, res.error()});
		} else {
			results.push_back({tInfo, std::monostate{}});
		}
	}

	formatter.PrintThreadAction(proc.Pid, proc.Name, Action::Resume, results);
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
	const std::string &target, const std::string &thread, Formatter &formatter
) {
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
