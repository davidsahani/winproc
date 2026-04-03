#include "Formatter.hpp"

#include <iostream>
#include <format>
#include <map>
#include <tuple>
#include <regex>

#include "utils/StringUtils.hpp"
#include "core/ProcessUtils.hpp"
#include "core/Convert.hpp"

void Formatter::PrintSuccess(std::string_view message) {
	std::cout << "SUCCESS: " << message << "\n";
}

void Formatter::PrintWarning(std::string_view message) {
	std::cerr << "WARNING: " << message << "\n";
}

void Formatter::PrintError(std::string_view message) {
	std::cerr << "ERROR: " << message << "\n";
}

void Formatter::PrintWarning(std::string_view message, std::string_view traceback) {
	std::cerr << "WARNING: " << message << "\n";
	std::cerr << "TRACEBACK: " << traceback << "\n";
}

void Formatter::PrintError(std::string_view message, std::string_view traceback) {
	std::cerr << "ERROR: " << message << "\n";
	std::cerr << "TRACEBACK: " << traceback << "\n";
}

void Formatter::PrintProcessList(const std::vector<ProcessInfo> &processes) {
	std::wcout << std::format(
		L"{:<30} {:>8} {:<9} {:<14} {:>12}  {:<50}\n",
		L"Image Name",
		L"PID",
		L"Session",
		L"Priority",
		L"Memory",
		L"Description"
	);
	std::wcout << std::format(
		L"{:=<30} {:=<8} {:=<9} {:=<14} {:=<12}  {:=<50}\n", L"", L"", L"", L"", L"", L""
	);
	for (const auto &p : processes) {
		std::wstring desc = ProcessUtils::GetProcessDescription(p.Pid).value_or(L"");
		std::wstring nameStr = p.Name;

		if (nameStr.length() > 30) nameStr = nameStr.substr(0, 27) + L"...";
		if (desc.length() > 50) desc = desc.substr(0, 47) + L"...";

		std::wstring session = Convert::SessionIdToString(p.SessionId);
		std::string memory = Convert::MemoryToMB(p.Memory);
		std::string priority = Convert::ProcessPriorityToString(p.BasePriority);

		std::wstring memStr(memory.begin(), memory.end());
		std::wstring prioStr(priority.begin(), priority.end());

		std::wcout << std::format(
			L"{:<30} {:>8} {:<9} {:<14} {:>12}  {:<50}\n",
			nameStr,
			p.Pid,
			session,
			prioStr,
			memStr,
			desc
		);
	}
}

void Formatter::PrintProcessDetails(const std::vector<ProcessInfo> &processes) {
	std::map<
		std::tuple<std::wstring, std::wstring, std::wstring>,
		std::vector<const ProcessInfo *>>
		groupedProcesses;

	for (const auto &p : processes) {
		std::wstring exePath = NtUtils::GetProcessPath(p.Pid).value_or(L"");
		std::wstring desc =
			ProcessUtils::GetFileDescriptionFromPath(exePath).value_or(L"");

		groupedProcesses[std::make_tuple(p.Name, desc, exePath)].emplace_back(&p);
	}

	bool first = true;
	for (const auto &[key, procs] : groupedProcesses) {
		if (!first) std::wcout << L"\n";
		first = false;

		const auto &[name, desc, exePath] = key;

		std::wcout << std::format(L"PROCESS_NAME: {}\n", name);
		std::wcout << std::format(L"DESCRIPTION : {}\n", desc);
		std::wcout << std::format(L"EXECUTABLE  : {}\n", exePath);
		std::wcout << L"INSTANCES   :\n";

		// Calculate dynamic widths for all columns
		size_t pidWidth = 3;      // "PID"
		size_t ppidWidth = 4;     // "PPID"
		size_t sessionWidth = 7;  // "Session"
		size_t priorityWidth = 8; // "Priority"
		size_t memWidth = 6;      // "Memory"

		struct InstanceData {
			std::wstring pidStr;
			std::wstring ppidStr;
			std::wstring session;
			std::wstring prioStr;
			std::wstring memStr;
		};

		std::vector<InstanceData> instances;
		for (const auto &p : procs) {
			std::wstring pidStr = std::to_wstring(p->Pid);
			std::wstring ppidStr = std::to_wstring(p->ParentPid);
			std::wstring session = Convert::SessionIdToString(p->SessionId);
			std::string memory = Convert::MemoryToMB(p->Memory);
			std::string priority = Convert::ProcessPriorityToString(p->BasePriority);

			std::wstring memStr(memory.begin(), memory.end());
			std::wstring prioStr(priority.begin(), priority.end());

			pidWidth = (std::max)(pidWidth, pidStr.length());
			ppidWidth = (std::max)(ppidWidth, ppidStr.length());
			sessionWidth = (std::max)(sessionWidth, session.length());
			priorityWidth = (std::max)(priorityWidth, prioStr.length());
			memWidth = (std::max)(memWidth, memStr.length());

			instances.push_back({pidStr, ppidStr, session, prioStr, memStr});
		}

		// Header (Right-align header for right-aligned data: PID, PPID, Memory)
		std::wcout << L"    "
				   << std::format(
						  L"{:>{}}  {:>{}}  {:<{}}  {:<{}}  {:>{}}\n",
						  L"PID",
						  pidWidth,
						  L"PPID",
						  ppidWidth,
						  L"Session",
						  sessionWidth,
						  L"Priority",
						  priorityWidth,
						  L"Memory",
						  memWidth
					  );

		// Separator
		std::wcout << L"    "
				   << std::format(
						  L"{:-<{}}  {:-<{}}  {:-<{}}  {:-<{}}  {:-<{}}\n",
						  L"",
						  pidWidth,
						  L"",
						  ppidWidth,
						  L"",
						  sessionWidth,
						  L"",
						  priorityWidth,
						  L"",
						  memWidth
					  );

		for (const auto &inst : instances) {
			std::wcout << std::format(
				L"    {:>{}}  {:>{}}  {:<{}}  {:<{}}  {:>{}}\n",
				inst.pidStr,
				pidWidth,
				inst.ppidStr,
				ppidWidth,
				inst.session,
				sessionWidth,
				inst.prioStr,
				priorityWidth,
				inst.memStr,
				memWidth
			);
		}
	}
}

struct ThreadRow {
	std::string tid, priority, state, reason, name, address;
};

static void PrintTable(std::ostream &os, const std::vector<ThreadRow> &rows);

void Formatter::PrintThreads(
	DWORD pid, std::wstring_view processName, const std::vector<ThreadAddrInfo> &threads
) {
	std::vector<ThreadRow> rows;
	for (const auto &t : threads) {
		std::string tid = std::to_string(t.info.Tid);
		std::string priority = Convert::ThreadPriorityToString(t.info.BasePriority);
		std::string state = Convert::ThreadStateToString(t.info.ThreadState);
		// State 5 is "Waiting" according to Convert.cpp
		std::string reason = (t.info.ThreadState == 5)
								 ? Convert::WaitReasonToString(t.info.WaitReason)
								 : "";
		std::string name = t.Name;
		std::string startAddr = t.StartAddress;

		rows.push_back({tid, priority, state, reason, name, startAddr});
	}

	std::cout << std::format(
		"--- Threads for {} (PID: {}) ---\n", StringUtils::WstrToString(processName), pid
	);

	PrintTable(std::cout, rows);
}

static void PrintTable(std::ostream &os, const std::vector<ThreadRow> &rows) {
	size_t tidW = 3, priW = 8, staW = 5, reaW = 6, namW = 4, adrW = 12;
	bool showName = false, showAddr = false;

	for (const auto &r : rows) {
		tidW = (std::max)(tidW, r.tid.length());
		priW = (std::max)(priW, r.priority.length());
		staW = (std::max)(staW, r.state.length());
		reaW = (std::max)(reaW, r.reason.length());
		if (!r.name.empty()) {
			showName = true;
			namW = (std::max)(namW, r.name.length());
		}
		if (!r.address.empty()) {
			showAddr = true;
			adrW = (std::max)(adrW, r.address.length());
		}
	}

	// Header
	os << std::format(
		"{:<{}} | {:<{}} | {:<{}} | {:<{}}",
		"TID",
		tidW,
		"Priority",
		priW,
		"State",
		staW,
		"Reason",
		reaW
	);
	if (showName) os << std::format(" | {:<{}}", "Name", namW);
	if (showAddr) os << std::format(" | {:<{}}", "StartAddress", adrW);
	os << "\n";

	// Separator
	os << std::format(
		"{:-<{}}+{:-<{}}+{:-<{}}+{:-<{}}",
		"",
		tidW + 1,
		"",
		priW + 2,
		"",
		staW + 2,
		"",
		reaW + 2
	);
	if (showName) os << std::format("+{:-<{}}", "", namW + 2);
	if (showAddr) os << std::format("+{:-<{}}", "", adrW + 2);
	os << "\n";

	// Rows
	for (const auto &r : rows) {
		os << std::format(
			"{:<{}} | {:<{}} | {:<{}} | {:<{}}",
			r.tid,
			tidW,
			r.priority,
			priW,
			r.state,
			staW,
			r.reason,
			reaW
		);
		if (showName) os << std::format(" | {:<{}}", r.name, namW);
		if (showAddr) os << std::format(" | {:<{}}", r.address, adrW);
		os << "\n";
	}
	os << "\n";
}

namespace {
	template <typename T> static ThreadRow MakeThreadRow(const T &t) {
		ThreadRow r = {
			std::to_string(t.info.Tid),
			Convert::ThreadPriorityToString(t.info.BasePriority),
			Convert::ThreadStateToString(t.info.ThreadState),
			(t.info.ThreadState == 5) ? Convert::WaitReasonToString(t.info.WaitReason)
									  : "",
			t.Name,
			"" /*StartAddress*/
		};
		if constexpr (std::is_same_v<T, ThreadAddrInfo>) {
			r.address = t.StartAddress;
		}
		return r;
	}

	static std::string GetGroupKey(const std::string &err) {
		static const std::regex idRegex(R"( for (TID|PID) \d+)");
		return std::regex_replace(err, idRegex, "");
	}

	template <typename T>
	static void PrintFailures(
		const std::vector<std::pair<const T *, std::string>> &failures,
		std::string_view verb,
		std::string_view processName,
		DWORD pid
	) {
		if (failures.empty()) return;

		std::map<std::string, std::vector<std::pair<const T *, std::string>>> groups;
		std::vector<std::string> groupKeys;
		for (const auto &fail : failures) {
			std::string key = GetGroupKey(fail.second);
			if (groups.find(key) == groups.end()) {
				groupKeys.push_back(key);
			}
			groups[key].push_back(fail);
		}

		if (groups.size() == 1) {
			std::cerr << std::format(
				"[FAILED] Could not {} {} threads in {} (PID: {}):\n\n",
				verb,
				failures.size(),
				processName,
				pid
			);
			std::cerr
				<< std::format("Error: {}\n\n", GetGroupKey(failures.front().second));
			std::vector<ThreadRow> rows;
			for (const auto &[t, err] : failures) {
				rows.push_back(MakeThreadRow(*t));
			}
			PrintTable(std::cerr, rows);

		} else {
			std::cerr << std::format(
				"[FAILED] Could not {} threads in {} (PID: {})\n\n", verb, processName, pid
			);

			int groupIdx = 1;
			for (const auto &key : groupKeys) {
				const auto &groupFailures = groups[key];
				std::cerr << std::format(
					"Error Group {} ({} threads)\n", groupIdx++, groupFailures.size()
				);
				std::cerr << "──────────────────────────────────────────────\n";
				std::cerr << std::format("Error: {}\n\n", key);

				std::vector<ThreadRow> rows;
				for (const auto &[t, err] : groupFailures) {
					rows.push_back(MakeThreadRow(*t));
				}
				PrintTable(std::cerr, rows);
			}
		}
	}
} // namespace

void Formatter::PrintCommandResult(
	const std::pair<ProcessInfo, ResultVoid> &result, Action action
) {
	static const std::map<Action, std::pair<std::string, std::string>> actionMap = {
		{Action::Terminate, {"Terminated", "terminate"}},
		{Action::Suspend, {"Suspended", "suspend"}},
		{Action::Resume, {"Resumed", "resume"}},
		{Action::SetPriority, {"Set priority for", "set priority of"}},
	};

	const auto &[pastVerb, verb] = actionMap.at(action);
	const auto &[proc, res] = result;

	if (res.has_value()) {
		std::cout << std::format(
			"SUCCESS: {} process \"{}\" with PID {}",
			pastVerb,
			StringUtils::WstrToString(proc.Name),
			proc.Pid
		);
	} else {
		std::cerr << std::format(
			"ERROR: Failed to {} process \"{}\" with PID {}"
			"\nCause: {}",
			verb,
			StringUtils::WstrToString(proc.Name),
			proc.Pid,
			res.error().message
		);
	}
}

void Formatter::PrintThreadsResult(
	DWORD pid,
	std::wstring_view procName,
	Action action,
	const std::vector<std::pair<ThreadNameInfo, ResultVoid>> &results
) {
	static const std::map<Action, std::pair<std::string, std::string>> actionMap = {
		{Action::Suspend, {"Suspended", "suspend"}},
		{Action::Resume, {"Resumed", "resume"}},
		{Action::SetPriority, {"Set priority for", "set priority for"}},
	};

	if (results.empty()) return; // Nothing to print

	// Re-query fresh thread info to get updated priority/state/reason
	auto updatedResults = results;
	auto freshThreads = NtUtils::GetProcessThreads(pid);
	if (freshThreads.has_value()) {
		std::map<DWORD, ThreadInfo> freshMap;
		for (const auto &ti : freshThreads.value()) {
			freshMap[ti.Tid] = ti;
		}
		for (auto &[t, res] : updatedResults) {
			auto it = freshMap.find(t.info.Tid);
			if (it != freshMap.end()) t.info = it->second;
		}
	}

	const auto &[pastVerb, verb] = actionMap.at(action);
	std::string processName = StringUtils::WstrToString(procName);

	// Partition into successes and failures for grouped display
	std::vector<const ThreadNameInfo *> successes;
	std::vector<std::pair<const ThreadNameInfo *, std::string>> failures;

	for (const auto &[t, res] : updatedResults) {
		if (res.has_value()) {
			successes.push_back(&t);
		} else {
			failures.push_back({&t, res.error().message});
		}
	}

	if (!successes.empty()) {
		std::cout << std::format(
			"[SUCCESS] {} {} threads in {} (PID: {}):\n",
			pastVerb,
			successes.size(),
			processName,
			pid
		);

		std::vector<ThreadRow> rows;
		for (const auto *t : successes) {
			rows.push_back(MakeThreadRow(*t));
		}
		PrintTable(std::cout, rows);
	}

	if (!failures.empty()) {
		PrintFailures(failures, verb, processName, pid);
	}
}

void Formatter::PrintThreadsResult(
	DWORD pid,
	std::wstring_view procName,
	Action action,
	const std::vector<std::pair<ThreadAddrInfo, ResultVoid>> &results
) {
	static const std::map<Action, std::pair<std::string, std::string>> actionMap = {
		{Action::Suspend, {"Suspended", "suspend"}},
		{Action::Resume, {"Resumed", "resume"}},
		{Action::SetPriority, {"Set priority for", "set priority for"}},
	};

	if (results.empty()) return; // Nothing to print

	// Re-query fresh thread info to get updated priority/state/reason
	auto updatedResults = results;
	auto freshThreads = NtUtils::GetProcessThreads(pid);
	if (freshThreads.has_value()) {
		std::map<DWORD, ThreadInfo> freshMap;
		for (const auto &ti : freshThreads.value()) {
			freshMap[ti.Tid] = ti;
		}
		for (auto &[t, res] : updatedResults) {
			auto it = freshMap.find(t.info.Tid);
			if (it != freshMap.end()) t.info = it->second;
		}
	}

	const auto &[pastVerb, verb] = actionMap.at(action);
	std::string processName = StringUtils::WstrToString(procName);

	// Partition into successes and failures for grouped display
	std::vector<const ThreadAddrInfo *> successes;
	std::vector<std::pair<const ThreadAddrInfo *, std::string>> failures;

	for (const auto &[t, res] : updatedResults) {
		if (res.has_value()) {
			successes.push_back(&t);
		} else {
			failures.push_back({&t, res.error().message});
		}
	}

	if (!successes.empty()) {
		std::cout << std::format(
			"[SUCCESS] {} {} threads in {} (PID: {}):\n",
			pastVerb,
			successes.size(),
			processName,
			pid
		);

		std::vector<ThreadRow> rows;
		for (const auto *t : successes) {
			rows.push_back(MakeThreadRow(*t));
		}
		PrintTable(std::cout, rows);
	}

	if (!failures.empty()) {
		PrintFailures(failures, verb, processName, pid);
	}
}
