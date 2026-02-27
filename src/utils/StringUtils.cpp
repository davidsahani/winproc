#include "StringUtils.hpp"

#include <windows.h>

namespace StringUtils {

	std::string WstrToString(const std::wstring &wstr) {
		std::string result = {};

		if (!wstr.empty()) {
			int sizeNeeded = WideCharToMultiByte(
				CP_UTF8,
				0,
				wstr.c_str(),
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
					wstr.c_str(),
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

} // namespace StringUtils
