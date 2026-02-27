#pragma once

#include <string>

namespace StringUtils {
	/**
	 * @brief Convert UTF-16 wstring to UTF-8 std::string.
	 */
	std::string WstrToString(const std::wstring &wstr);
} // namespace StringUtils
