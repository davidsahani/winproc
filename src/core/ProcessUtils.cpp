#include "ProcessUtils.hpp"

#include <errhandlingapi.h>
#include <iostream>
#include <format>
#include <algorithm>
#include <cctype>
#include <cwctype>
#include <memory>
#include <DbgHelp.h>

#pragma comment(lib, "version.lib")

#include "WinError.hpp"
#include "utils/StringUtils.hpp"

bool ProcessUtils::EnableDebugPrivilege() {
	HANDLE hToken;
	LUID luid;
	TOKEN_PRIVILEGES tkp;

	if (!OpenProcessToken(
			GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken
		)) {
		std::cerr << WinErr(GetLastError(), "Failed to open process token: ").message
				  << "\n";
		return false;
	}

	std::unique_ptr<void, decltype(&CloseHandle)> hTokenDtor(hToken, CloseHandle);

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
		std::cerr << WinErr(GetLastError(), "Failed to lookup privilege value: ").message
				  << "\n";
		return false;
	}

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = luid;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(
			hToken, FALSE, &tkp, sizeof(TOKEN_PRIVILEGES), NULL, NULL
		)) {
		std::cerr << WinErr(GetLastError(), "Failed to adjust token privileges").message
				  << "\n";
		return false;
	}

	return true;
}

// Format a thread or function address into a readable string (e.g. module!function).
static inline std::string FormatAddress(HANDLE hProcess, PVOID address) {
	if (!address) return "";

	DWORD64 addr64 = reinterpret_cast<DWORD64>(address);
	char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(CHAR)];
	PSYMBOL_INFO pSymbol = reinterpret_cast<PSYMBOL_INFO>(buffer);
	pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
	pSymbol->MaxNameLen = MAX_SYM_NAME;

	DWORD64 displacement = 0;

	IMAGEHLP_MODULE64 moduleInfo{};
	moduleInfo.SizeOfStruct = sizeof(IMAGEHLP_MODULE64);
	std::string baseName = "Unknown";
	bool hasModule = SymGetModuleInfo64(hProcess, addr64, &moduleInfo);

	if (hasModule) {
		std::string imageName = moduleInfo.ImageName;
		size_t slashPos = imageName.find_last_of("\\/");
		if (slashPos != std::string::npos) {
			baseName = imageName.substr(slashPos + 1);
		} else {
			baseName = imageName;
		}
	}

	if (SymFromAddr(hProcess, addr64, &displacement, pSymbol)) {
		if (hasModule) {
			if (displacement > 0) {
				return std::format("{}!{}+0x{:x}", baseName, pSymbol->Name, displacement);
			} else {
				return std::format("{}!{}", baseName, pSymbol->Name);
			}
		} else {
			if (displacement > 0) {
				return std::format("{}+0x{:x}", pSymbol->Name, displacement);
			} else {
				return std::format("{}", pSymbol->Name);
			}
		}
	} else {
		if (hasModule) {
			return std::format("{}+0x{:x}", baseName, addr64 - moduleInfo.BaseOfImage);
		} else {
			return std::format("0x{:x}", addr64);
		}
	}
}

Result<std::vector<ThreadAddrInfo>, Error>
ProcessUtils::GetThreadStartAddresses(DWORD pid) {
	std::vector<ThreadAddrInfo> addrInfoList;
	auto threadsResult = NtUtils::GetProcessThreads(pid);
	if (!threadsResult.has_value()) {
		return threadsResult.error();
	}

	HANDLE hProcess =
		OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (hProcess) {
		SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);
		char symbolPath[MAX_PATH];
		if (GetEnvironmentVariableA("_NT_SYMBOL_PATH", symbolPath, MAX_PATH) == 0) {
			SymInitialize(
				hProcess,
				"srv*C:\\Symbols*https://msdl.microsoft.com/download/symbols",
				TRUE
			);
		} else {
			SymInitialize(hProcess, NULL, TRUE);
		}
	}

	for (const auto &t : threadsResult.value()) {
		PVOID bestAddress = t.Win32StartAddress ? t.Win32StartAddress
												: t.NativeStartAddress;
		std::string formattedAddr = FormatAddress(hProcess, bestAddress);
		addrInfoList.push_back({t.Tid, formattedAddr});
	}

	if (hProcess) {
		SymCleanup(hProcess);
		CloseHandle(hProcess);
	}

	return addrInfoList;
}

Result<std::vector<ProcessInfo>, Error>
ProcessUtils::GetTargetProcesses(const std::string &input) {
	if (input.empty()) {
		return Error("Input is empty.");
	}

	bool isNumeric = std::all_of(input.begin(), input.end(), [](unsigned char c) {
		return std::isdigit(c);
	});
	DWORD targetPid = 0;
	if (isNumeric) {
		try {
			targetPid = static_cast<DWORD>(std::stoul(input));
		} catch (...) {
			isNumeric = false;
		}
	}

	auto listResult = NtUtils::GetProcessList();
	if (!listResult.has_value()) {
		return Error(listResult.error().str());
	}

	std::vector<ProcessInfo> targets;
	std::wstring wideInput;
	if (!isNumeric) {
		wideInput = std::wstring(input.begin(), input.end());
		std::transform(wideInput.begin(), wideInput.end(), wideInput.begin(), ::towlower);
	}

	for (const auto &proc : listResult.value()) {
		if (isNumeric) {
			if (proc.Pid == targetPid) {
				targets.push_back(proc);
			}
		} else {
			std::wstring name = proc.Name;
			std::transform(name.begin(), name.end(), name.begin(), ::towlower);
			if (name == wideInput) {
				targets.push_back(proc);
			}
		}
	}

	if (targets.empty()) {
		return Error(std::format("Process '{}' not found", input));
	}

	return targets;
}

static inline void TrimInPlace(std::wstring &s) {
	auto notSpace = [](wchar_t ch) {
		return ch != L' ' && ch != L'\t' && ch != L'\r' && ch != L'\n';
	};
	auto beginIt = std::find_if(s.begin(), s.end(), notSpace);
	if (beginIt == s.end()) {
		s.clear();
		return;
	}
	auto endIt = std::find_if(s.rbegin(), s.rend(), notSpace).base();
	s.assign(beginIt, endIt);
}

static std::wstring
QueryVersionString(const BYTE *verInfo, WORD lang, WORD codepage, const wchar_t *keyName) {
	wchar_t subBlock[256]{};
	swprintf_s(subBlock, L"\\StringFileInfo\\%04x%04x\\%s", lang, codepage, keyName);

	void *p = nullptr;
	UINT cch = 0;
	if (!VerQueryValueW(verInfo, subBlock, &p, &cch) || !p || cch == 0) return L"";

	std::wstring out(static_cast<const wchar_t *>(p));
	TrimInPlace(out);
	return out;
}

static Result<std::wstring, Error>
GetFileDescriptionFromFileVersionInfo(const std::wstring &file) {
	DWORD dummy = 0;
	DWORD size = GetFileVersionInfoSizeW(file.c_str(), &dummy); // call Size* first
	if (size == 0) {
		return WinErr(
			GetLastError(),
			std::format(
				"GetFileVersionInfoSizeW failed "
				"while probing VERSIONINFO resource "
				"for file: {}",
				StringUtils::WstrToString(file)
			)
		);
	}

	std::vector<BYTE> buf(size);
	if (!GetFileVersionInfoW(
			file.c_str(), 0, size, buf.data()
		)) // then GetFileVersionInfoW
	{
		return WinErr(
			GetLastError(),
			std::format(
				"GetFileVersionInfoW failed "
				"while loading VERSIONINFO resource "
				"for file: {}",
				StringUtils::WstrToString(file)
			)
		);
	}

	struct LANGANDCODEPAGE {
		WORD wLanguage;
		WORD wCodePage;
	};

	LANGANDCODEPAGE *trans = nullptr;
	UINT cbTrans = 0;
	constexpr const wchar_t key[] = L"FileDescription";

	if (!VerQueryValueW(
			buf.data(), L"\\VarFileInfo\\Translation", (LPVOID *)&trans, &cbTrans
		) ||
		!trans) {
		// fallback list: try common lang/codepage guesses
		constexpr std::pair<WORD, WORD> fallbacks[] = {
			{0x0409, 0x04B0}, // en-US / typical codepage
			{0x0409, 1252},   // en-US / CP1252
			{0x0000, 1200}    // neutral / UTF-16
		};

		for (auto fb : fallbacks) {
			auto s = QueryVersionString(buf.data(), fb.first, fb.second, key);
			if (!s.empty()) return s;
		}

		return Error(
			std::format(
				"VERSIONINFO resource is missing a Translation table "
				"for file: {}",
				StringUtils::WstrToString(file)
			)
		);
	}

	const UINT n = cbTrans / sizeof(LANGANDCODEPAGE);
	if (n == 0) {
		return Error(
			std::format(
				"VERSIONINFO Translation table is present but empty; "
				"no localized strings are available "
				"for file: {}",
				StringUtils::WstrToString(file)
			)
		);
	}

	for (UINT i = 0; i < n; ++i) {
		auto s =
			QueryVersionString(buf.data(), trans[i].wLanguage, trans[i].wCodePage, key);
		if (!s.empty()) return s;
	}

	return Error(
		std::format(
			"VERSIONINFO resource is present, but {} is empty "
			"for file: {}",
			StringUtils::WstrToString(key),
			StringUtils::WstrToString(file)
		)
	);
}

Result<std::wstring, Error> ProcessUtils::GetProcessDescription(DWORD pid) {
	auto pathRes = NtUtils::GetProcessPath(pid);
	if (!pathRes.has_value()) {
		return Error(pathRes.error().str());
	}
	return GetFileDescriptionFromFileVersionInfo(pathRes.value());
}

Result<DWORD, Error> ProcessUtils::GetProcessPriority(DWORD pid) {
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	if (!hProcess) {
		return WinErr(GetLastError(), std::format("OpenProcess failed for PID {}", pid));
	}
	DWORD priority = GetPriorityClass(hProcess);
	DWORD err = GetLastError();
	CloseHandle(hProcess);
	if (priority == 0) {
		return WinErr(err, std::format("GetPriorityClass failed for PID {}", pid));
	}
	return priority;
}

Result<int, Error> ProcessUtils::GetThreadPriorityLevel(DWORD tid) {
	HANDLE hThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
	if (!hThread) {
		return WinErr(GetLastError(), std::format("OpenThread failed for TID {}", tid));
	}
	int priority = GetThreadPriority(hThread);
	DWORD err = GetLastError();
	CloseHandle(hThread);
	if (priority == THREAD_PRIORITY_ERROR_RETURN) {
		return WinErr(err, std::format("GetThreadPriority failed for TID {}", tid));
	}
	return priority;
}

Result<bool, Error> ProcessUtils::SuspendThread(DWORD tid) {
	HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
	if (!hThread) {
		return WinErr(GetLastError(), std::format("OpenThread failed for TID {}", tid));
	}
	DWORD prevCount = ::SuspendThread(hThread);
	DWORD err = GetLastError();
	CloseHandle(hThread);
	if (prevCount == static_cast<DWORD>(-1)) {
		return WinErr(err, std::format("SuspendThread failed for TID {}", tid));
	}
	return true;
}

Result<bool, Error> ProcessUtils::ResumeThread(DWORD tid) {
	HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
	if (!hThread) {
		return WinErr(GetLastError(), std::format("OpenThread failed for TID {}", tid));
	}
	DWORD prevCount = ::ResumeThread(hThread);
	DWORD err = GetLastError();
	CloseHandle(hThread);
	if (prevCount == static_cast<DWORD>(-1)) {
		return WinErr(err, std::format("ResumeThread failed for TID {}", tid));
	}
	return true;
}
