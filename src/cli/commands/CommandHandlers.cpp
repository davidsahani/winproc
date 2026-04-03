#include "CommandHandlers.hpp"

#include <format>
#include <regex>
#include <Windows.h>
#include <DbgHelp.h>

#include "WinError.hpp"
#include "StringUtils.hpp"
#include "core/Convert.hpp"
#include "core/NtUtils.hpp"
#include "core/ProcessUtils.hpp"
#include "cli/Formatter.hpp"

static Result<std::vector<ThreadAddrInfo>, Error> GetMatchingThreads(
	const std::vector<ThreadAddrInfo> &addrInfoList, std::string_view pattern
) {
	std::vector<ThreadAddrInfo> matchedThreads;

	std::regex re;
	try {
		re = std::regex(pattern.begin(), pattern.end(), std::regex_constants::icase);
	} catch (const std::regex_error &) {
		return Error(std::format("Invalid regex pattern: {}", pattern));
	}

	for (const auto &t : addrInfoList) {
		if (std::regex_search(t.StartAddress, re)) {
			matchedThreads.push_back(t);
		}
	}

	return matchedThreads;
}

int CommandHandlers::HandleList() {
	auto listResult = NtUtils::GetProcessList();
	if (!listResult.has_value()) {
		Formatter::PrintError(
			std::format(
				"Failed to retrieve process list"
				"\nCause: {}",
				listResult.error().message
			),
			listResult.error().traceback
		);
		return 1;
	}
	Formatter::PrintProcessList(listResult.value());
	return 0;
}

int CommandHandlers::HandleKill(std::string_view target) {
	auto procsResult = ProcessUtils::GetTargetProcesses(target);
	if (!procsResult.has_value()) {
		Formatter::PrintError(
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
			Formatter::PrintCommandResult({proc, err}, Action::Terminate);
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
			Formatter::PrintCommandResult({proc, err}, Action::Terminate);
			anyError = true;
		} else {
			Formatter::PrintCommandResult({proc, std::monostate{}}, Action::Terminate);
		}
		CloseHandle(hProcess);
	}
	return anyError ? 1 : 0;
}

int CommandHandlers::HandleQuery(std::string_view target) {
	auto procsResult = ProcessUtils::GetTargetProcesses(target);
	if (!procsResult.has_value()) {
		Formatter::PrintError(
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
	Formatter::PrintProcessDetails(procsResult.value());
	return 0;
}

int CommandHandlers::HandleQueryThread(
	std::string_view target, std::string_view threadIdOrName, bool queryAll
) {
	auto procsResult = ProcessUtils::GetTargetProcesses(target);
	if (!procsResult.has_value()) {
		Formatter::PrintError(
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

	auto result = ProcessUtils::EnableDebugPrivilege(GetCurrentProcess());
	if (!result.has_value()) {
		const Error &err = result.error();
		Formatter::PrintWarning(err.message, err.traceback + "\n");
	}

	const auto threadIdOpt = StringUtils::TryParseInt(threadIdOrName);
	bool anyError = false;
	bool foundAny = false;

	for (const auto &proc : procsResult.value()) {
		auto addrInfoResult = ProcessUtils::GetThreadStartAddresses(proc.Pid);
		if (!addrInfoResult.has_value()) {
			Formatter::PrintError(
				std::format(
					"Failed to get thread start addresses for {} (PID: {})"
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
			for (const auto &t : addrInfoList) {
				if (threadIdOpt ? t.info.Tid == static_cast<DWORD>(threadIdOpt.value())
								: t.Name == threadIdOrName) {
					found = true;
					matchedThreads.push_back(t);
					if (!threadIdOpt) break;
				}
			}
		}

		if (found) Formatter::PrintThreads(proc.Pid, proc.Name, matchedThreads);
		if (found) foundAny = true;
	}

	if (!foundAny) {
		ProcessInfo proc = procsResult.value().front();

		Formatter::PrintError(
			std::format(
				"No threads matched {} \"{}\" for {} (PID: {}).",
				threadIdOpt ? "TID" : "name",
				threadIdOrName,
				StringUtils::WstrToString(proc.Name),
				proc.Pid
			)
		);

		return 1;
	}

	return anyError ? 1 : 0;
}

int CommandHandlers::HandleSuspend(std::string_view target) {
	auto procsResult = ProcessUtils::GetTargetProcesses(target);
	if (!procsResult.has_value()) {
		Formatter::PrintError(
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
		auto res = NtUtils::SuspendProcess(proc.Pid);
		results.push_back({proc, res});
	}

	bool anyError = false;
	for (const auto &res : results) {
		if (!res.second.has_value()) anyError = true;
		Formatter::PrintCommandResult(res, Action::Suspend);
	}
	return anyError ? 1 : 0;
}

int CommandHandlers::HandleResume(std::string_view target) {
	auto procsResult = ProcessUtils::GetTargetProcesses(target);
	if (!procsResult.has_value()) {
		Formatter::PrintError(
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
		auto res = NtUtils::ResumeProcess(proc.Pid);
		results.push_back({proc, res});
	}

	bool anyError = false;
	for (const auto &res : results) {
		if (!res.second.has_value()) anyError = true;
		Formatter::PrintCommandResult(res, Action::Resume);
	}
	return anyError ? 1 : 0;
}

static bool SuspendThreadById(DWORD tid, const ProcessInfo &proc) {
	ResultVoid result = ProcessUtils::SuspendThread(tid);

	if (result.has_value()) {
		Formatter::PrintSuccess(
			std::format(
				"Suspended thread {} in process {} (PID {}).",
				tid,
				StringUtils::WstrToString(proc.Name),
				proc.Pid
			)
		);
	} else {
		const Error &error = result.error();
		Formatter::PrintError(error.message, error.traceback);
	}
	return result.has_value();
}

static bool ResumeThreadById(DWORD tid, const ProcessInfo &proc) {
	ResultVoid result = ProcessUtils::ResumeThread(tid);

	if (result.has_value()) {
		Formatter::PrintSuccess(
			std::format(
				"Resumed thread {} in process {} (PID {}).",
				tid,
				StringUtils::WstrToString(proc.Name),
				proc.Pid
			)
		);
	} else {
		const Error &error = result.error();
		Formatter::PrintError(error.message, error.traceback);
	}

	return result.has_value();
}

static bool inline SuspendThreadsByName(
	const std::vector<ThreadNameInfo> &matchedThreads, const ProcessInfo &proc
) {
	bool allOk = true;
	std::vector<std::pair<ThreadNameInfo, ResultVoid>> results;
	for (const auto &matchedInfo : matchedThreads) {
		auto result = ProcessUtils::SuspendThread(matchedInfo.info.Tid);
		if (!result.has_value()) allOk = false;
		results.push_back({matchedInfo, result});
	}

	Formatter::PrintThreadsResult(proc.Pid, proc.Name, Action::Suspend, results);
	return allOk;
}

static bool inline ResumeThreadsByName(
	const std::vector<ThreadNameInfo> &matchedThreads, const ProcessInfo &proc
) {
	bool allOk = true;
	std::vector<std::pair<ThreadNameInfo, ResultVoid>> results;
	for (const auto &matchedInfo : matchedThreads) {
		auto res = ProcessUtils::ResumeThread(matchedInfo.info.Tid);
		if (!res.has_value()) allOk = false;
		results.push_back({matchedInfo, res});
	}

	Formatter::PrintThreadsResult(proc.Pid, proc.Name, Action::Resume, results);
	return allOk;
}

int CommandHandlers::HandleSuspendThread(
	std::string_view target,
	std::string_view threadIdOrName,
	std::string_view filterPriority
) {
	auto procsResult = ProcessUtils::GetTargetProcesses(target);
	if (!procsResult.has_value()) {
		Formatter::PrintError(
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

	const auto threadIdOpt = StringUtils::TryParseInt(threadIdOrName);
	const auto filterPrioOpt = StringUtils::TryParseInt(filterPriority);
	const std::string filterPrioNorm = StringUtils::Normalize(filterPriority);

	// Validate priority value is valid string or parsable number.
	if (!filterPriority.empty() && !filterPrioOpt.has_value()) {
		auto pRes = Convert::ParseThreadPriority(filterPriority);
		if (!pRes.has_value()) {
			Formatter::PrintError(
				std::format("Invalid priority value: {}", filterPriority)
			);
			return 1;
		}
	}

	if (threadIdOpt && procsResult.value().size() == 1 && filterPriority.empty()) {
		const auto &proc = procsResult.value().front();
		const DWORD tid = static_cast<DWORD>(threadIdOpt.value());
		return SuspendThreadById(tid, proc) ? 0 : 1;
	}

	bool foundAny = false;
	bool anyError = false;
	bool threadFound = false;

	for (const auto &proc : procsResult.value()) {
		auto nameInfoResult = ProcessUtils::GetThreadNames(proc.Pid);
		if (!nameInfoResult.has_value()) {
			Formatter::PrintError(
				std::format(
					"Failed to get thread names for {} (PID: {})"
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

		// Find threads by thread Id or thread name
		std::vector<ThreadNameInfo> matchedThreads;
		for (const auto &threadInfo : nameInfoResult.value()) {
			if (
				threadIdOpt
					? threadInfo.info.Tid == static_cast<DWORD>(threadIdOpt.value())
					: threadInfo.Name == threadIdOrName
				//
			) {
				threadFound = true;
				// Filter by priority if specified
				if (!filterPriority.empty()) {
					if (filterPrioOpt.has_value()) {
						if (threadInfo.info.BasePriority !=
							static_cast<LONG>(filterPrioOpt.value())) {
							continue;
						}
					} else {
						const std::string basePriority = StringUtils::Normalize(
							Convert::ThreadPriorityToString(threadInfo.info.BasePriority)
						);
						if (basePriority != filterPrioNorm) continue;
					}
				}

				matchedThreads.push_back(threadInfo);
				// Thread Id is unique, so we can break after finding it.
				if (threadIdOpt.has_value()) break;
			}
		}

		if (!matchedThreads.empty()) {
			bool ok;
			if (threadIdOpt) {
				const DWORD tid = static_cast<DWORD>(threadIdOpt.value());
				ok = SuspendThreadById(tid, proc);
			} else {
				ok = SuspendThreadsByName(matchedThreads, proc);
			}
			if (!ok) anyError = true;
			foundAny = true;
		}
	}

	if (!foundAny) {
		ProcessInfo proc = procsResult.value().front();

		if (threadFound && !filterPriority.empty()) {
			Formatter::PrintError(
				std::format(
					"No threads matched {} '{}' with priority '{}' for {} (PID: {})",
					threadIdOpt.has_value() ? "TID" : "name",
					threadIdOrName,
					filterPriority,
					StringUtils::WstrToString(proc.Name),
					proc.Pid
				)
			);
		} else {
			Formatter::PrintError(
				std::format(
					"No threads matched {} '{}' for {} (PID: {})",
					threadIdOpt.has_value() ? "TID" : "name",
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
	std::string_view target,
	std::string_view threadIdOrName,
	std::string_view filterPriority
) {
	auto procsResult = ProcessUtils::GetTargetProcesses(target);
	if (!procsResult.has_value()) {
		Formatter::PrintError(
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

	const auto threadIdOpt = StringUtils::TryParseInt(threadIdOrName);
	const auto filterPrioOpt = StringUtils::TryParseInt(filterPriority);
	const std::string filterPrioNorm = StringUtils::Normalize(filterPriority);

	// Validate priority value is valid string or parsable number.
	if (!filterPriority.empty() && !filterPrioOpt.has_value()) {
		auto pRes = Convert::ParseThreadPriority(filterPriority);
		if (!pRes.has_value()) {
			Formatter::PrintError(
				std::format("Invalid priority value: {}", filterPriority)
			);
			return 1;
		}
	}

	if (threadIdOpt && procsResult.value().size() == 1 && filterPriority.empty()) {
		const auto &proc = procsResult.value().front();
		const DWORD tid = static_cast<DWORD>(threadIdOpt.value());
		return ResumeThreadById(tid, proc) ? 0 : 1;
	}

	bool foundAny = false;
	bool anyError = false;
	bool threadFound = false;

	for (const auto &proc : procsResult.value()) {
		auto nameInfoResult = ProcessUtils::GetThreadNames(proc.Pid);
		if (!nameInfoResult.has_value()) {
			Formatter::PrintError(
				std::format(
					"Failed to get thread names for {} (PID: {})"
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

		// Find thread by Id or thread Name
		std::vector<ThreadNameInfo> matchedThreads;
		for (const ThreadNameInfo &threadInfo : nameInfoResult.value()) {
			if (
				threadIdOpt
					? threadInfo.info.Tid == static_cast<DWORD>(threadIdOpt.value())
					: threadInfo.Name == threadIdOrName
				//
			) {
				threadFound = true;
				// Filter by priority if specified
				if (!filterPriority.empty()) {
					if (filterPrioOpt.has_value()) {
						if (threadInfo.info.BasePriority !=
							static_cast<LONG>(filterPrioOpt.value())) {
							continue;
						}
					} else {
						const std::string basePriority = StringUtils::Normalize(
							Convert::ThreadPriorityToString(threadInfo.info.BasePriority)
						);
						if (basePriority != filterPrioNorm) continue;
					}
				}

				matchedThreads.push_back(threadInfo);
				if (threadIdOpt.has_value()) break;
			}
		}

		if (!matchedThreads.empty()) {
			bool ok;
			if (threadIdOpt) {
				const DWORD tid = static_cast<DWORD>(threadIdOpt.value());
				ok = ResumeThreadById(tid, proc);
			} else {
				ok = ResumeThreadsByName(matchedThreads, proc);
			}
			if (!ok) anyError = true;
			foundAny = true;
		}
	}

	if (!foundAny) {
		ProcessInfo proc = procsResult.value().front();

		if (threadFound && !filterPriority.empty()) {
			Formatter::PrintError(
				std::format(
					"No threads matched {} '{}' with priority '{}' for {} (PID: {})",
					threadIdOpt.has_value() ? "TID" : "name",
					threadIdOrName,
					filterPriority,
					StringUtils::WstrToString(proc.Name),
					proc.Pid
				)
			);
		} else {
			Formatter::PrintError(
				std::format(
					"No threads matched {} '{}' for {} (PID: {})",
					threadIdOpt ? "TID" : "name",
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
	std::string_view target,
	std::string_view threadAddrRegex,
	std::string_view filterPriority
) {
	auto procsResult = ProcessUtils::GetTargetProcesses(target);
	if (!procsResult.has_value()) {
		Formatter::PrintError(
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

	const auto filterPrioOpt = StringUtils::TryParseInt(filterPriority);
	const std::string filterPrioNorm = StringUtils::Normalize(filterPriority);

	// Validate priority value is valid string or parsable number.
	if (!filterPriority.empty() && !filterPrioOpt.has_value()) {
		auto pRes = Convert::ParseThreadPriority(filterPriority);
		if (!pRes.has_value()) {
			Formatter::PrintError(
				std::format("Invalid priority value: {}", filterPriority)
			);
			return 1;
		}
	}

	ResultVoid result = ProcessUtils::EnableDebugPrivilege(GetCurrentProcess());
	if (!result.has_value()) {
		Formatter::PrintError(
			std::format(
				"Failed to enable debug privilege for current process"
				"\nCause: {}",
				result.error().message
			),
			result.error().traceback
		);
		return 1;
	}

	bool foundAny = false;
	bool anyError = false;
	bool patternMatched = false;

	for (const auto &proc : procsResult.value()) {
		auto addrInfoResult = ProcessUtils::GetThreadStartAddresses(proc.Pid);
		if (!addrInfoResult.has_value()) {
			Formatter::PrintError(
				std::format(
					"Failed to get thread start addresses for {} (PID: {})"
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

		auto matchedResult = GetMatchingThreads(addrInfoResult.value(), threadAddrRegex);
		if (!matchedResult.has_value()) {
			Formatter::PrintError(
				std::format(
					"Failed to get thread start addresses for {} (PID: {})"
					"\nReason: {}",
					StringUtils::WstrToString(proc.Name),
					proc.Pid,
					matchedResult.error().message
				),
				matchedResult.error().traceback
			);
			anyError = true;
			continue;
		}

		const std::vector<ThreadAddrInfo> matchedThreads = matchedResult.value();
		if (!matchedThreads.empty()) patternMatched = true;

		std::vector<ThreadAddrInfo> filteredThreads;
		if (filterPriority.empty()) {
			filteredThreads = matchedThreads;
		} else {
			// Filter threads by priority when specified
			for (const auto &matchedInfo : matchedThreads) {
				if (filterPrioOpt.has_value()) {
					if (matchedInfo.info.BasePriority !=
						static_cast<LONG>(filterPrioOpt.value())) {
						continue;
					}
				} else {
					const std::string basePriority = StringUtils::Normalize(
						Convert::ThreadPriorityToString(matchedInfo.info.BasePriority)
					);
					if (basePriority != filterPrioNorm) continue;
				}
				filteredThreads.push_back(matchedInfo);
			}
		}

		std::vector<std::pair<ThreadAddrInfo, ResultVoid>> results;

		for (const auto &matchedInfo : filteredThreads) {
			auto res = ProcessUtils::SuspendThread(matchedInfo.info.Tid);
			if (!res.has_value()) anyError = true;
			results.push_back({matchedInfo, res});
		}

		if (!filteredThreads.empty()) {
			Formatter::PrintThreadsResult(proc.Pid, proc.Name, Action::Suspend, results);
			foundAny = true;
		}
	}

	if (!foundAny) {
		ProcessInfo proc = procsResult.value().front();

		if (patternMatched && !filterPriority.empty()) {
			Formatter::PrintError(
				std::format(
					"No threads matched pattern '{}' with priority '{}' "
					"for {} (PID: {}).",
					threadAddrRegex,
					filterPriority,
					StringUtils::WstrToString(proc.Name),
					proc.Pid
				)
			);
		} else {
			Formatter::PrintError(
				std::format(
					"No threads matched pattern '{}' for {} (PID: {}).",
					threadAddrRegex,
					StringUtils::WstrToString(proc.Name),
					proc.Pid
				)
			);
		}
		return 1;
	}

	return anyError ? 1 : 0;
}

int CommandHandlers::HandleResumeThreadByAddr(
	std::string_view target,
	std::string_view threadAddrRegex,
	std::string_view filterPriority
) {
	auto procsResult = ProcessUtils::GetTargetProcesses(target);
	if (!procsResult.has_value()) {
		Formatter::PrintError(
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

	const auto filterPrioOpt = StringUtils::TryParseInt(filterPriority);
	const std::string filterPrioNorm = StringUtils::Normalize(filterPriority);

	// Validate priority value is valid string or parsable number.
	if (!filterPriority.empty() && !filterPrioOpt.has_value()) {
		auto pRes = Convert::ParseThreadPriority(filterPriority);
		if (!pRes.has_value()) {
			Formatter::PrintError(
				std::format("Invalid priority value: {}", filterPriority)
			);
			return 1;
		}
	}

	ResultVoid result = ProcessUtils::EnableDebugPrivilege(GetCurrentProcess());
	if (!result.has_value()) {
		Formatter::PrintError(
			std::format(
				"Failed to enable debug privilege for current process"
				"\nCause: {}",
				result.error().message
			),
			result.error().traceback
		);
		return 1;
	}

	bool anyError = false;
	bool foundAny = false;
	bool patternMatched = false;

	for (const auto &proc : procsResult.value()) {
		auto addrInfoResult = ProcessUtils::GetThreadStartAddresses(proc.Pid);
		if (!addrInfoResult.has_value()) {
			Formatter::PrintError(
				std::format(
					"Failed to get thread start addresses for {} (PID: {})"
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

		auto matchedResult = GetMatchingThreads(addrInfoResult.value(), threadAddrRegex);
		if (!matchedResult.has_value()) {
			Formatter::PrintError(
				std::format(
					"Failed to get thread start addresses for {} (PID: {})"
					"\nReason: {}",
					StringUtils::WstrToString(proc.Name),
					proc.Pid,
					matchedResult.error().message
				),
				matchedResult.error().traceback
			);
			anyError = true;
			continue;
		}

		const std::vector<ThreadAddrInfo> matchedThreads = matchedResult.value();
		if (!matchedThreads.empty()) patternMatched = true;

		std::vector<ThreadAddrInfo> filteredThreads;

		if (filterPriority.empty()) {
			filteredThreads = matchedThreads;
		} else {
			// Filter threads by priority when specified
			for (const auto &matchedInfo : matchedThreads) {
				if (filterPrioOpt.has_value()) {
					if (matchedInfo.info.BasePriority !=
						static_cast<LONG>(filterPrioOpt.value())) {
						continue;
					}
				} else {
					const std::string basePriority = StringUtils::Normalize(
						Convert::ThreadPriorityToString(matchedInfo.info.BasePriority)
					);
					if (basePriority != filterPrioNorm) continue;
				}
				filteredThreads.push_back(matchedInfo);
			}
		}

		std::vector<std::pair<ThreadAddrInfo, ResultVoid>> results;

		for (const auto &matchedInfo : filteredThreads) {
			auto res = ProcessUtils::ResumeThread(matchedInfo.info.Tid);
			if (!res.has_value()) anyError = true;
			results.push_back({matchedInfo, res});
		}

		if (!filteredThreads.empty()) {
			Formatter::PrintThreadsResult(proc.Pid, proc.Name, Action::Resume, results);
			foundAny = true;
		}
	}

	if (!foundAny) {
		ProcessInfo proc = procsResult.value().front();

		if (patternMatched && !filterPriority.empty()) {
			Formatter::PrintError(
				std::format(
					"No threads matched pattern '{}' with priority '{}' "
					"for {} (PID: {}).",
					threadAddrRegex,
					filterPriority,
					StringUtils::WstrToString(proc.Name),
					proc.Pid
				)
			);
		} else {
			Formatter::PrintError(
				std::format(
					"No threads matched pattern '{}' for {} (PID: {}).",
					threadAddrRegex,
					StringUtils::WstrToString(proc.Name),
					proc.Pid
				)
			);
		}
		return 1;
	}

	return anyError ? 1 : 0;
}

int CommandHandlers::HandleSetPriority(std::string_view target, std::string_view value) {
	auto procsResult = ProcessUtils::GetTargetProcesses(target);
	if (!procsResult.has_value()) {
		Formatter::PrintError(
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

	auto prioResult = Convert::ParseProcessPriority(value);
	if (!prioResult.has_value()) {
		Formatter::PrintError(std::format("Invalid process priority value: {}", value));
		return 1;
	}
	DWORD priorityClass = prioResult.value();

	bool anyError = false;
	std::vector<std::pair<ProcessInfo, ResultVoid>> results;

	for (const auto &proc : procsResult.value()) {
		auto result = ProcessUtils::SetProcessPriority(proc.Pid, priorityClass);
		results.push_back({proc, result});
	}

	for (const auto &res : results) {
		Formatter::PrintCommandResult(res, Action::SetPriority);
		if (!res.second.has_value()) anyError = true;
	}
	return anyError ? 1 : 0;
}

static bool SetPriorityThreadById(DWORD tid, int priorityLevel, const ProcessInfo &proc) {
	ResultVoid result = ProcessUtils::SetThreadPriorityLevel(tid, priorityLevel);

	if (result.has_value()) {
		Formatter::PrintSuccess(
			std::format(
				"Priority of thread {} in process {} (PID {}) set to {}.",
				tid,
				StringUtils::WstrToString(proc.Name),
				proc.Pid,
				priorityLevel
			)
		);
	} else {
		const Error &error = result.error();
		Formatter::PrintError(error.message, error.traceback);
	}
	return result.has_value();
}

static bool SetPriorityThreadsByName(
	const std::vector<ThreadNameInfo> &matchedThreads,
	int priorityLevel,
	const ProcessInfo &proc
) {
	bool allOk = true;
	std::vector<std::pair<ThreadNameInfo, ResultVoid>> results;
	for (const auto &matchedInfo : matchedThreads) {
		auto result =
			ProcessUtils::SetThreadPriorityLevel(matchedInfo.info.Tid, priorityLevel);
		if (!result.has_value()) allOk = false;
		results.push_back({matchedInfo, result});
	}

	Formatter::PrintThreadsResult(proc.Pid, proc.Name, Action::SetPriority, results);
	return allOk;
}

int CommandHandlers::HandleSetPriorityThread(
	std::string_view target,
	std::string_view priority,
	std::string_view threadIdOrName,
	std::string_view filterPriority
) {
	auto procsResult = ProcessUtils::GetTargetProcesses(target);
	if (!procsResult.has_value()) {
		Formatter::PrintError(
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

	auto prioResult = Convert::ParseThreadPriority(priority);
	if (!prioResult.has_value()) {
		Formatter::PrintError(std::format("Invalid thread priority value: {}", priority));
		return 1;
	}

	const int priorityLevel = prioResult.value();
	const auto threadIdOpt = StringUtils::TryParseInt(threadIdOrName);
	const auto filterPrioOpt = StringUtils::TryParseInt(filterPriority);
	const std::string filterPrioNorm = StringUtils::Normalize(filterPriority);

	// Validate priority value is valid string or parsable number.
	if (!filterPriority.empty() && !filterPrioOpt.has_value()) {
		auto pRes = Convert::ParseThreadPriority(filterPriority);
		if (!pRes.has_value()) {
			Formatter::PrintError(
				std::format("Invalid priority value: {}", filterPriority)
			);
			return 1;
		}
	}

	if (threadIdOpt && procsResult.value().size() == 1 && filterPriority.empty()) {
		const auto &proc = procsResult.value().front();
		const DWORD tid = static_cast<DWORD>(threadIdOpt.value());
		return SetPriorityThreadById(tid, priorityLevel, proc) ? 0 : 1;
	}

	bool foundAny = false;
	bool anyError = false;
	bool threadFound = false;

	for (const auto &proc : procsResult.value()) {
		auto nameInfoResult = ProcessUtils::GetThreadNames(proc.Pid);
		if (!nameInfoResult.has_value()) {
			Formatter::PrintError(
				std::format(
					"Failed to get thread names for {} (PID: {})"
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

		// Find threads by thread Id or thread name
		std::vector<ThreadNameInfo> matchedThreads;
		for (const auto &threadInfo : nameInfoResult.value()) {
			if (
				threadIdOpt
					? threadInfo.info.Tid == static_cast<DWORD>(threadIdOpt.value())
					: threadInfo.Name == threadIdOrName
				//
			) {
				threadFound = true;
				// Filter threads by priority when specified
				if (!filterPriority.empty()) {
					if (filterPrioOpt.has_value()) {
						if (threadInfo.info.BasePriority !=
							static_cast<LONG>(filterPrioOpt.value())) {
							continue;
						}
					} else {
						const std::string basePriority = StringUtils::Normalize(
							Convert::ThreadPriorityToString(threadInfo.info.BasePriority)
						);
						if (basePriority != filterPrioNorm) continue;
					}
				}

				matchedThreads.push_back(threadInfo);
				if (threadIdOpt.has_value()) break;
			}
		}

		if (!matchedThreads.empty()) {
			bool ok;
			if (threadIdOpt) {
				const DWORD tid = static_cast<DWORD>(threadIdOpt.value());
				ok = SetPriorityThreadById(tid, priorityLevel, proc);
			} else {
				ok = SetPriorityThreadsByName(matchedThreads, priorityLevel, proc);
			}
			if (!ok) anyError = true;
			foundAny = true;
		}
	}

	if (!foundAny) {
		ProcessInfo proc = procsResult.value().front();

		if (threadFound && !filterPriority.empty()) {
			Formatter::PrintError(
				std::format(
					"No threads matched {} '{}' with priority '{}' for {} (PID: {})",
					threadIdOpt.has_value() ? "TID" : "name",
					threadIdOrName,
					filterPriority,
					StringUtils::WstrToString(proc.Name),
					proc.Pid
				)
			);
		} else {
			Formatter::PrintError(
				std::format(
					"No threads matched {} '{}' for {} (PID: {})",
					threadIdOpt ? "TID" : "name",
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

int CommandHandlers::HandleSetPriorityThreadByAddr(
	std::string_view target,
	std::string_view priority,
	std::string_view threadAddrRegex,
	std::string_view filterPriority
) {
	auto procsResult = ProcessUtils::GetTargetProcesses(target);
	if (!procsResult.has_value()) {
		Formatter::PrintError(
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

	auto prioResult = Convert::ParseThreadPriority(priority);
	if (!prioResult.has_value()) {
		Formatter::PrintError(std::format("Invalid thread priority value: {}", priority));
		return 1;
	}

	const int priorityLevel = prioResult.value();
	const auto filterPrioOpt = StringUtils::TryParseInt(filterPriority);

	// Validate priority value is valid string or parsable number.
	if (!filterPriority.empty() && !filterPrioOpt.has_value()) {
		auto pRes = Convert::ParseThreadPriority(filterPriority);
		if (!pRes.has_value()) {
			Formatter::PrintError(
				std::format("Invalid priority value: {}", filterPriority)
			);
			return 1;
		}
	}

	const std::string filterPrioNorm = StringUtils::Normalize(filterPriority);

	ResultVoid result = ProcessUtils::EnableDebugPrivilege(GetCurrentProcess());
	if (!result.has_value()) {
		Formatter::PrintError(
			std::format(
				"Failed to enable debug privilege for current process"
				"\nCause: {}",
				result.error().message
			),
			result.error().traceback
		);
		return 1;
	}

	bool foundAny = false;
	bool anyError = false;
	bool patternMatched = false;

	for (const auto &proc : procsResult.value()) {
		std::vector<std::pair<ThreadAddrInfo, ResultVoid>> results;

		auto addrInfoResult = ProcessUtils::GetThreadStartAddresses(proc.Pid);
		if (!addrInfoResult.has_value()) {
			Formatter::PrintError(
				std::format(
					"Failed to get thread start addresses for {} (PID: {})"
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

		auto matchedResult = GetMatchingThreads(addrInfoResult.value(), threadAddrRegex);
		if (!matchedResult.has_value()) {
			Formatter::PrintError(
				std::format(
					"Failed matching thread addresses for {} (PID: {})"
					"\nReason: {}",
					StringUtils::WstrToString(proc.Name),
					proc.Pid,
					matchedResult.error().message
				),
				matchedResult.error().traceback
			);
			anyError = true;
			continue;
		}

		const std::vector<ThreadAddrInfo> matchedThreads = matchedResult.value();
		if (!matchedThreads.empty()) patternMatched = true;

		std::vector<ThreadAddrInfo> filteredThreads;
		if (filterPriority.empty()) {
			filteredThreads = matchedThreads;
		} else {
			// Filter threads by priority when specified
			for (const auto &matchedInfo : matchedThreads) {
				if (filterPrioOpt.has_value()) {
					if (matchedInfo.info.BasePriority !=
						static_cast<LONG>(filterPrioOpt.value())) {
						continue;
					}
				} else {
					const std::string basePriority = StringUtils::Normalize(
						Convert::ThreadPriorityToString(matchedInfo.info.BasePriority)
					);
					if (basePriority != filterPrioNorm) continue;
				}
				filteredThreads.push_back(matchedInfo);
			}
		}

		for (const auto &matchedInfo : filteredThreads) {
			auto res =
				ProcessUtils::SetThreadPriorityLevel(matchedInfo.info.Tid, priorityLevel);
			if (!res.has_value()) anyError = true;
			results.push_back({matchedInfo, res});
		}

		if (!filteredThreads.empty()) {
			Formatter::PrintThreadsResult(
				proc.Pid, proc.Name, Action::SetPriority, results
			);
			foundAny = true;
		}
	}

	if (!foundAny) {
		ProcessInfo proc = procsResult.value().front();

		if (patternMatched && !filterPriority.empty()) {
			Formatter::PrintError(
				std::format(
					"No threads matched pattern '{}' with priority '{}' "
					"for {} (PID: {}).",
					threadAddrRegex,
					filterPriority,
					StringUtils::WstrToString(proc.Name),
					proc.Pid
				)
			);
		} else {
			Formatter::PrintError(
				std::format(
					"No threads matched pattern '{}' for {} (PID: {}).",
					threadAddrRegex,
					StringUtils::WstrToString(proc.Name),
					proc.Pid
				)
			);
		}
		return 1;
	}

	return anyError ? 1 : 0;
}
