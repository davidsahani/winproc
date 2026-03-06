#include "CliApp.hpp"

#include <iostream>
#include <string>

#include "cli/Formatter.hpp"
#include "cli/commands/CommandHandlers.hpp"
#include "commands/CommandHandlers.hpp"
#include "external/argparse.hpp"

int CliApp::Run(int argc, char *argv[]) {
	argparse::ArgumentParser parser("winproc");

	parser.add_argument("-list")
		.help("List all processes")
		.default_value(false)
		.implicit_value(true);

	parser.add_argument("-kill")
		.help("Kill process by name or PID")
		.default_value(std::string{});

	parser.add_argument("-suspend")
		.help("Suspend process by name or PID")
		.default_value(std::string{});

	parser.add_argument("-resume")
		.help("Resume process by name or PID")
		.default_value(std::string{});

	parser.add_argument("-query")
		.help("Query process details by name or PID")
		.default_value(std::string{});

	parser.add_argument("-thread")
		.help(
			"Target a specific thread ID or Name (only valid with -suspend, -resume, or "
			"-query)\n"
			"  Usage: winproc -suspend/-resume/-query <PID> -thread <TID/Name>"
		)
		.default_value(std::string{});

	parser.add_argument("-threads")
		.help("List all threads for a process (only valid with -query)")
		.default_value(false)
		.implicit_value(true);

	parser.add_argument("-thread_addrs")
		.help(
			"Target threads by start address regex (only valid with -suspend or -resume)"
		)
		.default_value(std::string{});

	parser.add_argument("--json")
		.help("Output to JSON")
		.default_value(false)
		.implicit_value(true);

	try {
		parser.parse_args(argc, argv);
	} catch (const std::exception &err) {
		std::cerr << err.what() << std::endl;
		std::cerr << parser;
		return -1;
	}

	bool outputJson = parser.get<bool>("--json");
	Formatter formatter(outputJson);

	if (parser.get<bool>("-list")) {
		return CommandHandlers::HandleList(formatter);
	}

	std::string targetKill = parser.get<std::string>("-kill");
	if (!targetKill.empty()) {
		return CommandHandlers::HandleKill(targetKill, formatter);
	}

	std::string threadIdOrName = parser.get<std::string>("-thread");
	bool queryAllThreads = parser.get<bool>("-threads");
	std::string threadAddrRegex = parser.get<std::string>("-thread_addrs");

	std::string targetSuspend = parser.get<std::string>("-suspend");
	std::string targetResume = parser.get<std::string>("-resume");
	std::string targetQuery = parser.get<std::string>("-query");

	bool threadUsed = parser.is_used("-thread");
	bool threadsUsed = parser.is_used("-threads");
	bool threadAddrsUsed = parser.is_used("-thread_addrs");

	if ((threadUsed || threadsUsed || threadAddrsUsed) && targetSuspend.empty() &&
		targetResume.empty() && targetQuery.empty()) {
		std::cerr << "Error: thread arguments can only be used with -suspend, -resume, "
					 "or -query.\n";
		return -1;
	}

	if (threadsUsed && targetQuery.empty()) {
		std::cerr << "Error: -threads can only be used with -query.\n";
		return -1;
	}

	if (threadAddrsUsed && !targetQuery.empty()) {
		std::cerr << "Error: -thread_addrs cannot be used with -query.\n";
		return -1;
	}

	int threadFlagsUsed =
		(threadUsed ? 1 : 0) + (threadsUsed ? 1 : 0) + (threadAddrsUsed ? 1 : 0);
	if (threadFlagsUsed > 1) {
		std::cerr << "Error: Only one of -thread, -threads, or -thread_addrs can be used "
					 "at a time.\n";
		return -1;
	}

	if (!targetSuspend.empty()) {
		if (threadAddrsUsed) {
			return CommandHandlers::HandleSuspendThreadByAddr(
				targetSuspend, threadAddrRegex, formatter
			);
		} else if (threadUsed) {
			return CommandHandlers::HandleSuspendThread(
				targetSuspend, threadIdOrName, formatter
			);
		}
		return CommandHandlers::HandleSuspend(targetSuspend, formatter);
	}

	if (!targetResume.empty()) {
		if (threadAddrsUsed) {
			return CommandHandlers::HandleResumeThreadByAddr(
				targetResume, threadAddrRegex, formatter
			);
		} else if (threadUsed) {
			return CommandHandlers::HandleResumeThread(
				targetResume, threadIdOrName, formatter
			);
		}
		return CommandHandlers::HandleResume(targetResume, formatter);
	}

	if (!targetQuery.empty()) {
		if (threadUsed || threadsUsed) {
			return CommandHandlers::HandleQueryThread(
				targetQuery, threadIdOrName, queryAllThreads, formatter
			);
		}
		return CommandHandlers::HandleQuery(targetQuery, formatter);
	}

	std::cerr << "No valid command provided.\n";
	std::cerr << parser;
	return -1;
}
