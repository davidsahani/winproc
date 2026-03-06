#pragma once

#include <string>
#include "cli/Formatter.hpp"

namespace CommandHandlers {

	int HandleList(Formatter &formatter);
	int HandleKill(const std::string &target, Formatter &formatter);
	int HandleSuspend(const std::string &target, Formatter &formatter);
	int HandleResume(const std::string &target, Formatter &formatter);
	int HandleSuspendThread(
		const std::string &target, const std::string &threadIdOrName, Formatter &formatter
	);
	int HandleResumeThread(
		const std::string &target, const std::string &threadIdOrName, Formatter &formatter
	);
	int HandleSuspendThreadByAddr(
		const std::string &target,
		const std::string &threadAddrRegex,
		Formatter &formatter
	);
	int HandleResumeThreadByAddr(
		const std::string &target,
		const std::string &threadAddrRegex,
		Formatter &formatter
	);
	int HandleQuery(const std::string &target, Formatter &formatter);
	int HandleQueryThread(
		const std::string &target,
		const std::string &threadIdOrName,
		bool queryAll,
		Formatter &formatter
	);
} // namespace CommandHandlers
