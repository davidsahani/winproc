#pragma once
#include "Error.hpp"

#include <format>
#include "Format.hpp"

namespace error::private_ {
	static inline Error add_error(DWORD winError, Error error) {
		error.message += std::format("\nReason: {}", format_win32(winError));
		return error;
	}

	static inline Error add_error(HRESULT hr, Error error) {
		error.message += std::format("\nReason: {}", format_hresult(hr));
		return error;
	}
}; // namespace error::private_

#define WinErr(hr, ...) error::private_::add_error(hr, Error(__VA_ARGS__))
