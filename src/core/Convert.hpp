#pragma once

#include <optional>
#include <string>
#include <Windows.h>

namespace Convert {

	/**
	 * @brief Convert base priority (typically 4, 6, 8, 10, 13, 24) to a human-readable string.
	 */
	std::string ProcessPriorityToString(LONG priority);

	/**
	 * @brief Convert thread dynamic or base priority to a human-readable string.
	 */
	std::string ThreadPriorityToString(LONG priority);

	/**
	 * @brief Parse a process priority class string or numeric value.
	 */
	std::optional<DWORD> ParseProcessPriority(std::string_view value);

	/**
	 * @brief Parse a thread priority level string or numeric value.
	 */
	std::optional<int> ParseThreadPriority(std::string_view value);

	/**
	 * @brief Convert session ID to a human-readable string.
	 *        Session 0 is the Services session; others are numbered user sessions.
	 */
	std::wstring SessionIdToString(ULONG sessionId);

	/**
	 * @brief Convert memory size (in bytes) to a megabytes string, e.g. "12.34 MB".
	 */
	std::string MemoryToMB(SIZE_T bytes);

	/**
	 * @brief Convert KTHREAD_STATE value to a human-readable string.
	 *        Values match the KTHREAD_STATE enum (0=Initialized, 1=Ready, 2=Running, ...).
	 */
	std::string ThreadStateToString(ULONG threadState);

	/**
	 * @brief Convert KWAIT_REASON value to a human-readable string.
	 */
	std::string WaitReasonToString(ULONG waitReason);
} // namespace Convert
