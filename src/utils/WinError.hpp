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

	static inline Error add_ntstatus(NTSTATUS status, Error error) {
		error.message += std::format("\nReason: {}", format_ntstatus(status));
		return error;
	}
}; // namespace error::private_

#define WinErr(code, ...) error::private_::add_error(code, Error(__VA_ARGS__))
#define NtStatusErr(status, ...) error::private_::add_ntstatus(status, Error(__VA_ARGS__))
