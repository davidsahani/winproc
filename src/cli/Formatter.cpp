#include "Formatter.hpp"
#include <iostream>
#include <format>
#include <map>
#include <tuple>

#include "external/json.hpp"
#include "utils/StringUtils.hpp"
#include "core/ProcessUtils.hpp"

Formatter::Formatter(bool useJson) : m_useJson(useJson) {}

static std::wstring PriorityClassToWString(DWORD priorityClass) {
	switch (priorityClass) {
		case IDLE_PRIORITY_CLASS:
			return L"Idle";
		case BELOW_NORMAL_PRIORITY_CLASS:
			return L"Below Normal";
		case NORMAL_PRIORITY_CLASS:
			return L"Normal";
		case ABOVE_NORMAL_PRIORITY_CLASS:
			return L"Above Normal";
		case HIGH_PRIORITY_CLASS:
			return L"High";
		case REALTIME_PRIORITY_CLASS:
			return L"Realtime";
		case PROCESS_MODE_BACKGROUND_BEGIN:
			return L"Background Begin";
		case PROCESS_MODE_BACKGROUND_END:
			return L"Background End";
		default:
			return std::to_wstring(priorityClass);
	}
}

static std::string ThreadPriorityToString(int priority) {
	switch (priority) {
		case THREAD_PRIORITY_IDLE:
			return "Idle";
		case THREAD_PRIORITY_LOWEST:
			return "Lowest";
		case THREAD_PRIORITY_BELOW_NORMAL:
			return "Below Normal";
		case THREAD_PRIORITY_NORMAL:
			return "Normal";
		case THREAD_PRIORITY_ABOVE_NORMAL:
			return "Above Normal";
		case THREAD_PRIORITY_HIGHEST:
			return "Highest";
		case THREAD_PRIORITY_TIME_CRITICAL:
			return "Time Critical";
		default:
			return std::to_string(priority);
	}
}

void Formatter::PrintError(const std::string &message) {
	if (m_useJson) {
		nlohmann::json j = {{"error", message}};
		std::cout << j.dump(4) << "\n";
	} else {
		std::cerr << message << "\n";
	}
}

void Formatter::PrintError(const std::string &message, const std::string &traceback) {
	if (m_useJson) {
		nlohmann::json j = {
			{"error", message},
			{"traceback", traceback},
		};
		std::cout << j.dump(4) << "\n";
	} else {
		std::cerr << "ERROR: " << message << "\n";
		std::cerr << "TRACEBACK: " << traceback << "\n";
	}
}

void Formatter::PrintProcessList(const std::vector<ProcessInfo> &processes) {
	if (m_useJson) {
		nlohmann::json j = nlohmann::json::array();
		for (const auto &p : processes) {
			std::string desc = StringUtils::WstrToString(
				ProcessUtils::GetProcessDescription(p.Pid).value_or(L"")
			);
			nlohmann::json item;
			item["pid"] = p.Pid;
			item["name"] = StringUtils::WstrToString(p.Name);
			item["description"] = desc;
			item["suspended"] = p.Suspended;
			j.push_back(item);
		}
		std::cout << j.dump(4) << "\n";
	} else {
		std::wcout << std::format(
			L"{:<30} {:>8} {:<50} {:<9}\n",
			L"Image Name",
			L"PID",
			L"Description",
			L"Suspended"
		);
		std::wcout << std::format(L"{:=<30} {:=<8} {:=<50} {:=<9}\n", L"", L"", L"", L"");
		for (const auto &p : processes) {
			std::wstring desc = ProcessUtils::GetProcessDescription(p.Pid).value_or(L"");
			std::wstring nameStr = p.Name;

			if (nameStr.length() > 30) nameStr = nameStr.substr(0, 27) + L"...";
			if (desc.length() > 50) desc = desc.substr(0, 47) + L"...";

			std::wcout << std::format(
				L"{:<30} {:>8} {:<50} {:<9}\n",
				nameStr,
				p.Pid,
				desc,
				p.Suspended ? L"True" : L"False"
			);
		}
	}
}

void Formatter::PrintProcessDetails(const std::vector<ProcessInfo> &processes) {
	if (m_useJson) {
		nlohmann::json j = nlohmann::json::array();
		for (const auto &p : processes) {
			std::string desc = StringUtils::WstrToString(
				ProcessUtils::GetProcessDescription(p.Pid).value_or(L"")
			);
			std::string exePath =
				StringUtils::WstrToString(NtUtils::GetProcessPath(p.Pid).value_or(L""));
			auto prioRes = ProcessUtils::GetProcessPriority(p.Pid);

			nlohmann::json item;
			item["pid"] = p.Pid;
			item["name"] = StringUtils::WstrToString(p.Name);
			item["description"] = desc;
			item["suspended"] = p.Suspended;
			if (prioRes.has_value()) {
				item["priority_class"] = prioRes.value();
				item["priority"] =
					StringUtils::WstrToString(PriorityClassToWString(prioRes.value()));
			}
			item["executable"] = exePath;
			j.push_back(item);
		}
		std::cout << j.dump(4) << "\n";
	} else {
		std::map<
			std::tuple<std::wstring, std::wstring, std::wstring>,
			std::vector<std::tuple<DWORD, bool, std::wstring>>>
			groupedProcesses;

		for (const auto &p : processes) {
			std::wstring desc = ProcessUtils::GetProcessDescription(p.Pid).value_or(L"");
			std::wstring exePath = NtUtils::GetProcessPath(p.Pid).value_or(L"");
			auto prioRes = ProcessUtils::GetProcessPriority(p.Pid);
			std::wstring priorityStr = prioRes.has_value()
										   ? PriorityClassToWString(prioRes.value())
										   : L"Unknown";

			groupedProcesses[std::make_tuple(p.Name, desc, exePath)].emplace_back(
				p.Pid, p.Suspended, priorityStr
			);
		}

		bool first = true;
		for (const auto &[key, instances] : groupedProcesses) {
			if (!first) std::wcout << L"\n";
			first = false;

			const auto &[name, desc, exePath] = key;

			std::wcout << std::format(L"PROCESS_NAME: {}\n", name);
			std::wcout << std::format(L"        DESCRIPTION        : {}\n", desc);
			std::wcout << std::format(L"        EXECUTABLE         : {}\n", exePath);
			std::wcout << L"        INSTANCES          :\n";

			for (const auto &[pid, suspended, priorityStr] : instances) {
				std::wcout << std::format(
					L"            PID: {:<8} | Priority: {:<14} | Suspended: {}\n",
					pid,
					priorityStr,
					suspended ? L"True" : L"False"
				);
			}
		}
	}
}

void Formatter::PrintCommandResult(
	const std::vector<std::pair<ProcessInfo, std::string>> &results,
	const std::string &actionVerb
) {
	if (m_useJson) {
		nlohmann::json jOutputs = nlohmann::json::array();
		for (const auto &[proc, errorMsg] : results) {
			bool success = errorMsg.empty();
			nlohmann::json item;
			item["success"] = success;
			item["pid"] = proc.Pid;
			item["name"] = StringUtils::WstrToString(proc.Name);
			if (!success) {
				item["error"] = errorMsg;
			}
			jOutputs.push_back(item);
		}
		std::cout << jOutputs.dump(4) << "\n";
	} else {
		for (const auto &[proc, errorMsg] : results) {
			if (errorMsg.empty()) {
				std::cout << std::format(
					"SUCCESS: The process \"{}\" with PID {} has been {}.\n",
					StringUtils::WstrToString(proc.Name),
					proc.Pid,
					actionVerb
				);
			} else {
				std::cerr << std::format(
					"ERROR: Failed to {} process \"{}\" with PID {}: {}\n",
					actionVerb,
					StringUtils::WstrToString(proc.Name),
					proc.Pid,
					errorMsg
				);
			}
		}
	}
}

void Formatter::PrintThreadAction(
	DWORD pid,
	const std::wstring &processName,
	const std::string &actionVerb, // "Suspended" or "Resumed"
	const std::vector<ThreadAddrInfo> &successfulThreads,
	const std::vector<std::pair<ThreadAddrInfo, std::string>> &failedThreads
) {
	if (m_useJson) {
		nlohmann::json jOutputs = nlohmann::json::array();

		for (const auto &t : successfulThreads) {
			nlohmann::json item;
			item["success"] = true;
			item["pid"] = pid;
			item["name"] = StringUtils::WstrToString(processName);
			item["tid"] = t.Tid;
			item["start_address"] = t.StartAddress;
			item["action"] = actionVerb;
			jOutputs.push_back(item);
		}

		for (const auto &[t, err] : failedThreads) {
			nlohmann::json item;
			item["success"] = false;
			item["pid"] = pid;
			item["name"] = StringUtils::WstrToString(processName);
			item["tid"] = t.Tid;
			item["start_address"] = t.StartAddress;
			item["action"] = actionVerb;
			item["error"] = err;
			jOutputs.push_back(item);
		}

		std::cout << jOutputs.dump(4) << "\n";
	} else {
		if (successfulThreads.empty() && failedThreads.empty()) {
			return; // Nothing to print
		}

		size_t total = successfulThreads.size() + failedThreads.size();

		if (total == 1) {
			if (!successfulThreads.empty()) {
				const auto &t = successfulThreads.front();
				std::cout << std::format(
					"{} thread {} of PID {} with StartAddress {}\n",
					actionVerb,
					t.Tid,
					pid,
					t.StartAddress
				);
			} else {
				const auto &[t, err] = failedThreads.front();
				std::cerr << std::format(
					"ERROR: Failed to {} thread {} of PID {}: {}\n",
					StringUtils::ToLower(actionVerb),
					t.Tid,
					pid,
					err
				);
			}
		} else {
			if (!successfulThreads.empty()) {
				std::cout << std::format(
					"[SUCCESS] {} {} threads in {} (PID: {}):\n",
					actionVerb,
					successfulThreads.size(),
					StringUtils::WstrToString(processName),
					pid
				);

				for (const auto &t : successfulThreads) {
					std::cout << std::format(
						"  TID: {:<4} | StartAddress: {}\n", t.Tid, t.StartAddress
					);
				}
				std::cout << "\n";
			}

			if (!failedThreads.empty()) {
				std::cerr << std::format(
					"[FAILED] Could not {} {} threads in {} (PID: {}):\n",
					StringUtils::ToLower(actionVerb),
					failedThreads.size(),
					StringUtils::WstrToString(processName),
					pid
				);

				for (const auto &[t, err] : failedThreads) {
					std::cerr << std::format(
						"  TID: {:<4} | StartAddress: {:<40} | Error: {}\n",
						t.Tid,
						t.StartAddress,
						err
					);
				}
				std::cerr << "\n";
			}
		}
	}
}

void Formatter::PrintThreads(
	DWORD pid, const std::wstring &processName, const std::vector<ThreadAddrInfo> &threads
) {
	if (m_useJson) {
		nlohmann::json jArr = nlohmann::json::array();
		for (const auto &t : threads) {
			auto prioRes = ProcessUtils::GetThreadPriorityLevel(t.Tid);
			nlohmann::json threadObj = {{"TID", t.Tid}};
			if (prioRes.has_value()) {
				threadObj["PriorityLevel"] = prioRes.value();
				threadObj["Priority"] = ThreadPriorityToString(prioRes.value());
			}
			threadObj["StartAddress"] = t.StartAddress;
			jArr.push_back(threadObj);
		}
		std::cout << jArr.dump(4) << "\n";
	} else {
		std::cout << std::format(
			"--- Threads for {} (PID: {}) ---\n",
			StringUtils::WstrToString(processName),
			pid
		);
		std::cout
			<< std::format("{:<7}| {:<16}| {}\n", "TID", "Priority", "StartAddress");
		std::cout << std::string(67, '-') << "\n";
		for (const auto &t : threads) {
			auto prioRes = ProcessUtils::GetThreadPriorityLevel(t.Tid);
			std::string prioStr =
				prioRes.has_value() ? ThreadPriorityToString(prioRes.value()) : "Unknown";
			std::cout << std::format("{:<9}  {:<18}{}\n", t.Tid, prioStr, t.StartAddress);
		}
		std::cout << "\n";
	}
}
