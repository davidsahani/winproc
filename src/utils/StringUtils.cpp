#include "StringUtils.hpp"

#include <windows.h>
#include <algorithm>
#include <cctype>

std::string StringUtils::WstrToString(std::wstring_view wstr) {
	std::string result = {};

	if (!wstr.empty()) {
		int sizeNeeded = WideCharToMultiByte(
			CP_UTF8,
			0,
			wstr.data(),
			static_cast<int>(wstr.size()),
			nullptr,
			0,
			nullptr,
			nullptr
		);
		if (sizeNeeded > 0) {
			result.resize(sizeNeeded);
			WideCharToMultiByte(
				CP_UTF8,
				0,
				wstr.data(),
				static_cast<int>(wstr.size()),
				result.data(),
				sizeNeeded,
				nullptr,
				nullptr
			);
		}
	}

	return result;
}

std::string StringUtils::ToLower(std::string_view str) {
	std::string result(str);
	std::transform(result.begin(), result.end(), result.begin(), [](unsigned char c) {
		return std::tolower(c);
	});
	return result;
}

std::string StringUtils::Normalize(std::string_view str) {
	std::string result = ToLower(str);
	std::replace_if(
		result.begin(),
		result.end(),
		[](unsigned char c) {
			return std::isspace(c);
		},
		'_'
	);
	return result;
}

std::optional<long> StringUtils::TryParseInt(std::string_view str) {
	errno = 0;

	char *end = nullptr;
	long result = std::strtol(str.data(), &end, 10);

	if (end == str.data()) return std::nullopt;              // nothing parsed
	if (end != str.data() + str.size()) return std::nullopt; // not fully consumed
	if (errno == ERANGE) return std::nullopt;                // overflow
	if (result < INT_MIN || result > INT_MAX) return std::nullopt;

	return result;
}
