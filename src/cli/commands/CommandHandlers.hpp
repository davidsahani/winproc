#pragma once

#include <string_view>

namespace CommandHandlers {
	int HandleList();
	int HandleKill(std::string_view target);
	int HandleQuery(std::string_view target);
	int HandleQueryThread(
		std::string_view target, std::string_view threadIdOrName, bool queryAll
	);
	int HandleSuspend(std::string_view target);
	int HandleResume(std::string_view target);
	int HandleSuspendThread(
		std::string_view target,
		std::string_view threadIdOrName,
		std::string_view filterPriority
	);
	int HandleResumeThread(
		std::string_view target,
		std::string_view threadIdOrName,
		std::string_view filterPriority
	);
	int HandleSuspendThreadByAddr(
		std::string_view target,
		std::string_view threadAddrRegex,
		std::string_view filterPriority
	);
	int HandleResumeThreadByAddr(
		std::string_view target,
		std::string_view threadAddrRegex,
		std::string_view filterPriority
	);
	int HandleSetPriority(std::string_view target, std::string_view value);
	int HandleSetPriorityThread(
		std::string_view target,
		std::string_view priority,
		std::string_view threadIdOrName,
		std::string_view filterPriority
	);
	int HandleSetPriorityThreadByAddr(
		std::string_view target,
		std::string_view priority,
		std::string_view threadAddrRegex,
		std::string_view filterPriority
	);
} // namespace CommandHandlers
