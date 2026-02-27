#include "Format.hpp"

#include <string>
#include <format>
#include <comdef.h> // _com_error, _bstr_t

static inline std::string wide_to_utf8(std::wstring_view ws) {
	if (ws.empty()) return {};
	int bytes = ::WideCharToMultiByte(CP_UTF8, 0, ws.data(), static_cast<int>(ws.size()), nullptr, 0, nullptr, nullptr);
	if (bytes <= 0) return {};
	std::string out(static_cast<size_t>(bytes), '\0');
	::WideCharToMultiByte(CP_UTF8, 0, ws.data(), static_cast<int>(ws.size()), out.data(), bytes, nullptr, nullptr);
	return out;
}

static inline std::string tchar_to_utf8(const TCHAR *s) {
	if (!s || !*s) return {};
#ifdef UNICODE
	return wide_to_utf8(s);
#else
	// In non-Unicode builds, ErrorMessage() is already multibyte (ACP).
	return std::string(s);
#endif
}

static inline void rtrim_inplace(std::string &s) {
	while (!s.empty()) {
		const char c = s.back();
		if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
			s.pop_back();
		else
			break;
	}
}

std::string format_hresult(HRESULT hr) {
	_com_error ce(hr);

	// Prefer IErrorInfo description when present (often more specific than system text).
	_bstr_t desc = ce.Description();
	if (desc.length() != 0) {
		// _bstr_t is wide on Windows.
		return wide_to_utf8(std::wstring_view(static_cast<const wchar_t *>(desc), desc.length()));
	}

	std::string msg = tchar_to_utf8(ce.ErrorMessage());
	rtrim_inplace(msg); // Remove trailing whitespaces

	if (msg.empty()) {
		return std::format("Unknown Error code: 0x{:X}", hr);
	}
	return msg;
}

std::string format_win32(DWORD winError) {
	// Let _com_error do the FormatMessage
	// work via a Win32-mapped HRESULT.
	return format_hresult(HRESULT_FROM_WIN32(winError));
}
