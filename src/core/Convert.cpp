#include "Convert.hpp"

#include <sstream>
#include <iomanip>
#include <Wtsapi32.h>

#include "utils/StringUtils.hpp"

std::string Convert::ProcessPriorityToString(LONG priority) {
	switch (priority) {
		case 4:
			return "Idle";
		case 6:
			return "Below normal";
		case 8:
			return "Normal";
		case 10:
			return "Above normal";
		case 13:
			return "High";
		case 24:
			return "Realtime";
		default:
			return std::to_string(priority);
	}
}

std::string Convert::ThreadPriorityToString(LONG priority) {
	switch (priority) {
		case 1:
		case 16:
			return "Idle";
		case 6:
			return "Lowest";
		case 7:
			return "Below normal";
		case 8:
		case 24:
			return "Normal";
		case 9:
			return "Above Normal";
		case 10:
			return "Highest";
		case 15:
		case 31:
			return "Time critical";
		default:
			return std::to_string(priority);
	}
}

std::optional<DWORD> Convert::ParseProcessPriority(std::string_view value) {
	std::string normalized = StringUtils::Normalize(value);

	if (normalized == "idle") return IDLE_PRIORITY_CLASS;
	if (normalized == "below_normal") return BELOW_NORMAL_PRIORITY_CLASS;
	if (normalized == "normal") return NORMAL_PRIORITY_CLASS;
	if (normalized == "above_normal") return ABOVE_NORMAL_PRIORITY_CLASS;
	if (normalized == "high") return HIGH_PRIORITY_CLASS;
	if (normalized == "realtime") return REALTIME_PRIORITY_CLASS;

	auto parsed = StringUtils::TryParseInt(value);
	if (parsed.has_value()) {
		return static_cast<DWORD>(parsed.value());
	}

	return std::nullopt;
}

std::optional<int> Convert::ParseThreadPriority(std::string_view value) {
	std::string normalized = StringUtils::Normalize(value);

	if (normalized == "idle") return THREAD_PRIORITY_IDLE;
	if (normalized == "lowest") return THREAD_PRIORITY_LOWEST;
	if (normalized == "below_normal") return THREAD_PRIORITY_BELOW_NORMAL;
	if (normalized == "normal") return THREAD_PRIORITY_NORMAL;
	if (normalized == "above_normal") return THREAD_PRIORITY_ABOVE_NORMAL;
	if (normalized == "highest") return THREAD_PRIORITY_HIGHEST;
	if (normalized == "time_critical") return THREAD_PRIORITY_TIME_CRITICAL;

	auto parsed = StringUtils::TryParseInt(value);
	if (parsed.has_value()) {
		return static_cast<int>(parsed.value());
	}

	return std::nullopt;
}

std::string Convert::ThreadStateToString(ULONG threadState) {
	// Matches KTHREAD_STATE enum from the NT kernel / WinInternals
	switch (threadState) {
		case 0:
			return "Initialized";
		case 1:
			return "Ready";
		case 2:
			return "Running";
		case 3:
			return "Standby";
		case 4:
			return "Terminated";
		case 5:
			return "Waiting";
		case 6:
			return "Transition";
		case 7:
			return "DeferredReady";
		case 8:
			return "GateWaitObsolete";
		case 9:
			return "WaitingForProcessInSwap";
		default:
			return "Unknown (" + std::to_string(threadState) + ")";
	}
}

std::string Convert::WaitReasonToString(ULONG waitReason) {
	// Matches KWAIT_REASON enum from the NT kernel / WinInternals
	switch (waitReason) {
		case 0:
			return "Executive";
		case 1:
			return "FreePage";
		case 2:
			return "PageIn";
		case 3:
			return "PoolAllocation";
		case 4:
			return "DelayExecution";
		case 5:
			return "Suspended";
		case 6:
			return "UserRequest";
		case 7:
			return "WrExecutive";
		case 8:
			return "WrFreePage";
		case 9:
			return "WrPageIn";
		case 10:
			return "WrPoolAllocation";
		case 11:
			return "WrDelayExecution";
		case 12:
			return "WrSuspended";
		case 13:
			return "WrUserRequest";
		case 14:
			return "WrEventPair";
		case 15:
			return "WrQueue";
		case 16:
			return "WrLpcReceive";
		case 17:
			return "WrLpcReply";
		case 18:
			return "WrVirtualMemory";
		case 19:
			return "WrPageOut";
		case 20:
			return "WrRendezvous";
		case 21:
			return "WrKeyedEvent";
		case 22:
			return "WrTerminated";
		case 23:
			return "WrProcessInSwap";
		case 24:
			return "WrCpuRateControl";
		case 25:
			return "WrCalloutStack";
		case 26:
			return "WrKernel";
		case 27:
			return "WrResource";
		case 28:
			return "WrPushLock";
		case 29:
			return "WrMutex";
		case 30:
			return "WrQuantumEnd";
		case 31:
			return "WrDispatchInt";
		case 32:
			return "WrPreempted";
		case 33:
			return "WrYieldExecution";
		case 34:
			return "WrFastMutex";
		case 35:
			return "WrGuardedMutex";
		case 36:
			return "WrRundown";
		case 37:
			return "WrAlertByThreadId";
		case 38:
			return "WrDeferredPreempt";
		case 39:
			return "WrPhysicalFault";
		case 40:
			return "WrIoRing";
		case 41:
			return "WrMdlCache";
		case 42:
			return "WrRcu";
		default:
			return "Unknown (" + std::to_string(waitReason) + ")";
	}
}

std::string Convert::MemoryToMB(SIZE_T bytes) {
	double mb = static_cast<double>(bytes) / (1024.0 * 1024.0);
	std::ostringstream oss;
	oss << std::fixed << std::setprecision(2) << mb << " MB";
	return oss.str();
}

std::wstring Convert::SessionIdToString(ULONG sessionId) {
	LPWSTR buffer = nullptr;
	DWORD bytesReturned = 0;

	if (WTSQuerySessionInformationW(
			WTS_CURRENT_SERVER_HANDLE, sessionId, WTSWinStationName, &buffer, &bytesReturned
		)) {
		std::wstring name(buffer);
		WTSFreeMemory(buffer);
		if (!name.empty()) {
			return name;
		}
	}

	if (sessionId == 0) return L"Services";
	return std::to_wstring(sessionId);
}
