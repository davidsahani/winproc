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
