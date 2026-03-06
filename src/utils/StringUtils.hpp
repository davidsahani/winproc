#pragma once

#include <string>

namespace StringUtils {
	/**
	 * @brief Convert UTF-16 wstring to UTF-8 std::string.
	 */
	std::string WstrToString(std::wstring_view wstr);

	/**
	 * @brief Converts a std::string to lowercase.
	 */
	std::string ToLower(std::string_view str);
} // namespace StringUtils
