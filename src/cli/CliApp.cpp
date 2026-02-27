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
			"Target a specific thread ID (only valid with -suspend, -resume, or "
			"-query)\n"
			"  Usage: winproc -suspend/-resume/-query <PID> -thread [<TID>/<Regex>]"
		)
		.default_value(std::string{".*"})
		.hidden();

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

	std::string threadId = parser.get<std::string>("-thread");

	std::string targetSuspend = parser.get<std::string>("-suspend");
	std::string targetResume = parser.get<std::string>("-resume");
	std::string targetQuery = parser.get<std::string>("-query");

	bool threadUsed = parser.is_used("-thread");

	if (threadUsed && targetSuspend.empty() && targetResume.empty() &&
		targetQuery.empty()) {
		std::cerr << "Error: -thread can only be used with -suspend, -resume, or "
					 "-query.\n";
		std::cerr << "  Usage: winproc -suspend/-resume/-query <PID> -thread <TID>\n";
		return -1;
	}

	if (!targetSuspend.empty()) {
		if (threadUsed) {
			return CommandHandlers::HandleSuspendThread(
				targetSuspend, threadId, formatter
			);
		}
		return CommandHandlers::HandleSuspend(targetSuspend, formatter);
	}

	if (!targetResume.empty()) {
		if (threadUsed) {
			return CommandHandlers::HandleResumeThread(targetResume, threadId, formatter);
		}
		return CommandHandlers::HandleResume(targetResume, formatter);
	}

	if (!targetQuery.empty()) {
		if (threadUsed) {
			return CommandHandlers::HandleQueryThread(targetQuery, threadId, formatter);
		}
		return CommandHandlers::HandleQuery(targetQuery, formatter);
	}

	std::cerr << "No valid command provided.\n";
	std::cerr << parser;
	return -1;
}
