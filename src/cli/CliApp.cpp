#include "CliApp.hpp"

#include <iostream>
#include <string>

#include "commands/CommandHandlers.hpp"
#include "external/argparse.hpp"

int CliApp::Run(int argc, char *argv[]) {
	argparse::ArgumentParser parser("winproc");
	constexpr const char version[] = "1.0";

	// --- list ---
	argparse::ArgumentParser listCmd("list", version, argparse::default_arguments::help);
	listCmd.add_description("List all processes");

	// --- kill ---
	argparse::ArgumentParser killCmd("kill", version, argparse::default_arguments::help);
	killCmd.add_description("Terminate process by <PID/Name>");
	killCmd.add_argument("target").help("Process PID or name");

	// --- query ---
	argparse::ArgumentParser queryCmd("query", version, argparse::default_arguments::help);
	queryCmd.add_description("Query process details by <PID/Name>");
	queryCmd.add_argument("target").help("Process PID or name");

	auto &queryMutex = queryCmd.add_mutually_exclusive_group();
	queryMutex.add_argument("-thread")
		.help("Target a specific thread by ID or name")
		.default_value(std::string{});
	queryMutex.add_argument("-threads")
		.help("List all threads for the process")
		.default_value(false)
		.implicit_value(true);

	// --- suspend ---
	argparse::ArgumentParser suspendCmd(
		"suspend", version, argparse::default_arguments::help
	);
	suspendCmd.add_description("Suspend process by <PID/Name>");
	suspendCmd.add_argument("target").help("Process PID or name");

	auto &suspendMutex = suspendCmd.add_mutually_exclusive_group();
	suspendMutex.add_argument("-thread")
		.help("Target a specific thread by ID or name")
		.default_value(std::string{});
	suspendMutex.add_argument("-thread_addr")
		.help("Target threads by start address regex")
		.default_value(std::string{});

	suspendCmd.add_argument("-withpriority")
		.help("Filter target threads by priority level")
		.default_value(std::string{});

	// --- resume ---
	argparse::ArgumentParser resumeCmd(
		"resume", version, argparse::default_arguments::help
	);
	resumeCmd.add_description("Resume process by <PID/Name>");
	resumeCmd.add_argument("target").help("Process PID or name");

	auto &resumeMutex = resumeCmd.add_mutually_exclusive_group();
	resumeMutex.add_argument("-thread")
		.help("Target a specific thread by ID or name")
		.default_value(std::string{});
	resumeMutex.add_argument("-thread_addr")
		.help("Target threads by start address regex")
		.default_value(std::string{});

	resumeCmd.add_argument("-withpriority")
		.help("Filter target threads by priority level")
		.default_value(std::string{});

	// --- setpriority ---
	argparse::ArgumentParser setpriorityCmd(
		"setpriority", version, argparse::default_arguments::help
	);
	setpriorityCmd.add_description("Set priority for process or thread by <PID/Name>");
	setpriorityCmd.add_argument("target").help("Process PID or name");
	setpriorityCmd.add_argument("value").help(
		"Priority value (e.g., normal, high, real-time, etc. or integer)"
	);

	auto &setpriorityMutex = setpriorityCmd.add_mutually_exclusive_group();
	setpriorityMutex.add_argument("-thread")
		.help("Target a specific thread by ID or name")
		.default_value(std::string{});
	setpriorityMutex.add_argument("-thread_addr")
		.help("Target threads by start address regex")
		.default_value(std::string{});

	setpriorityCmd.add_argument("-withpriority")
		.help("Filter target threads by priority level")
		.default_value(std::string{});

	// --- register subparsers ---
	parser.add_subparser(listCmd);
	parser.add_subparser(killCmd);
	parser.add_subparser(queryCmd);
	parser.add_subparser(suspendCmd);
	parser.add_subparser(resumeCmd);
	parser.add_subparser(setpriorityCmd);

	try {
		parser.parse_args(argc, argv);
	} catch (const std::exception &err) {
		std::cerr << err.what() << std::endl;
		std::cerr << parser;
		return -1;
	}

	if (parser.is_subcommand_used("list")) {
		return CommandHandlers::HandleList();
	}

	if (parser.is_subcommand_used("kill")) {
		auto target = killCmd.get<std::string>("target");
		return CommandHandlers::HandleKill(target);
	}

	if (parser.is_subcommand_used("query")) {
		auto target = queryCmd.get<std::string>("target");

		if (queryCmd.is_used("-thread") || queryCmd.is_used("-threads")) {
			auto threadIdOrName = queryCmd.get<std::string>("-thread");
			bool queryAll = queryCmd.get<bool>("-threads");
			return CommandHandlers::HandleQueryThread(target, threadIdOrName, queryAll);
		}
		return CommandHandlers::HandleQuery(target);
	}

	if (parser.is_subcommand_used("suspend")) {
		auto target = suspendCmd.get<std::string>("target");

		std::string withPriority = "";
		if (suspendCmd.is_used("-withpriority")) {
			withPriority = suspendCmd.get<std::string>("-withpriority");
		}
		if (suspendCmd.is_used("-thread")) {
			auto tid = suspendCmd.get<std::string>("-thread");
			return CommandHandlers::HandleSuspendThread(target, tid, withPriority);
		}
		if (suspendCmd.is_used("-thread_addr")) {
			auto regex = suspendCmd.get<std::string>("-thread_addr");
			return CommandHandlers::HandleSuspendThreadByAddr(target, regex, withPriority);
		}
		return CommandHandlers::HandleSuspend(target);
	}

	if (parser.is_subcommand_used("resume")) {
		auto target = resumeCmd.get<std::string>("target");

		std::string withPriority = "";
		if (resumeCmd.is_used("-withpriority")) {
			withPriority = resumeCmd.get<std::string>("-withpriority");
		}
		if (resumeCmd.is_used("-thread")) {
			auto tid = resumeCmd.get<std::string>("-thread");
			return CommandHandlers::HandleResumeThread(target, tid, withPriority);
		}
		if (resumeCmd.is_used("-thread_addr")) {
			auto regex = resumeCmd.get<std::string>("-thread_addr");
			return CommandHandlers::HandleResumeThreadByAddr(target, regex, withPriority);
		}
		return CommandHandlers::HandleResume(target);
	}

	if (parser.is_subcommand_used("setpriority")) {
		auto target = setpriorityCmd.get<std::string>("target");
		auto priority = setpriorityCmd.get<std::string>("value");

		std::string withPriority = "";
		if (setpriorityCmd.is_used("-withpriority")) {
			withPriority = setpriorityCmd.get<std::string>("-withpriority");
		}
		if (setpriorityCmd.is_used("-thread")) {
			auto tid = setpriorityCmd.get<std::string>("-thread");
			return CommandHandlers::HandleSetPriorityThread(
				target, priority, tid, withPriority
			);
		}
		if (setpriorityCmd.is_used("-thread_addr")) {
			auto regex = setpriorityCmd.get<std::string>("-thread_addr");
			return CommandHandlers::HandleSetPriorityThreadByAddr(
				target, priority, regex, withPriority
			);
		}
		return CommandHandlers::HandleSetPriority(target, priority);
	}

	std::cerr << "Error: No command provided.\n";
	std::cerr << parser;
	return -1;
}
