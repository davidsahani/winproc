#include "ProcessUtils.hpp"

#include <format>
#include <algorithm>
#include <cwctype>
#include <DbgHelp.h>

#pragma comment(lib, "version.lib")

#include "WinError.hpp"
#include "utils/ScopeExit.hpp"
#include "utils/StringUtils.hpp"

ResultVoid ProcessUtils::EnableDebugPrivilege(HANDLE hProcess) {
	HANDLE hToken;
	LUID luid;
	TOKEN_PRIVILEGES tkp;

	if (!OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		const DWORD pid = GetProcessId(hProcess);
		return WinErr(
			GetLastError(), std::format("Failed to open process token for PID {}", pid)
		);
	}

	SCOPE_EXIT(CloseHandle(hToken));

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
		const DWORD pid = GetProcessId(hProcess);
		return WinErr(
			GetLastError(),
			std::format("Failed to lookup privilege value for PID {}", pid)
		);
	}

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = luid;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(
			hToken, FALSE, &tkp, sizeof(TOKEN_PRIVILEGES), NULL, NULL
		)) {
		const DWORD pid = GetProcessId(hProcess);
		return WinErr(
			GetLastError(),
			std::format("Failed to adjust token privileges for PID {}", pid)
		);
	}

	return std::monostate{};
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

typedef HRESULT(WINAPI *GetThreadDescription_t)(
	HANDLE hThread, PWSTR *ppszThreadDescription
);

static Result<std::string, Error> GetThreadName(DWORD tid) {
	static auto pGetThreadDescription = reinterpret_cast<GetThreadDescription_t>(
		GetProcAddress(GetModuleHandleW(L"kernelbase.dll"), "GetThreadDescription")
	);

	if (!pGetThreadDescription) {
		pGetThreadDescription = reinterpret_cast<GetThreadDescription_t>(
			GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetThreadDescription")
		);
	}

	if (!pGetThreadDescription) {
		return Error(
			"GetThreadDescription symbol not found in kernelbase.dll or "
			"kernel32.dll"
		);
	}

	HANDLE hThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
	if (!hThread) {
		return WinErr(GetLastError(), std::format("OpenThread failed for TID {}", tid));
	}

	SCOPE_EXIT(CloseHandle(hThread));

	PWSTR pszDesc = nullptr;
	HRESULT hr = pGetThreadDescription(hThread, &pszDesc);
	std::string name = "";
	if (SUCCEEDED(hr)) {
		if (pszDesc) {
			name = StringUtils::WstrToString(pszDesc);
			LocalFree(pszDesc);
		}
	} else {
		return WinErr(hr, std::format("GetThreadDescription failed for TID {}", tid));
	}
	return name;
}

Result<std::vector<ThreadNameInfo>, Error> ProcessUtils::GetThreadNames(DWORD pid) {
	std::vector<ThreadNameInfo> nameInfoList;
	auto threadsResult = NtUtils::GetProcessThreads(pid);
	if (!threadsResult.has_value()) {
		return threadsResult.error();
	}

	for (const auto thread : threadsResult.value()) {
		nameInfoList.push_back({thread, GetThreadName(thread.Tid).value_or("")});
	}

	return nameInfoList;
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

	for (const auto t : threadsResult.value()) {
		PVOID bestAddress = t.Win32StartAddress ? t.Win32StartAddress
												: t.NativeStartAddress;
		std::string formattedAddr = FormatAddress(hProcess, bestAddress);

		std::string threadName = GetThreadName(t.Tid).value_or("");
		addrInfoList.push_back({t, threadName, formattedAddr});
	}

	if (hProcess) {
		SymCleanup(hProcess);
		CloseHandle(hProcess);
	}

	return addrInfoList;
}

Result<std::vector<ProcessInfo>, Error>
ProcessUtils::GetTargetProcesses(std::string_view target) {
	if (target.empty()) {
		return Error("Process name or PID cannot be empty.");
	}

	auto targetPidOpt = StringUtils::TryParseInt(target);

	auto listResult = NtUtils::GetProcessList();
	if (!listResult) return listResult;

	std::vector<ProcessInfo> targets;
	std::wstring procName;
	if (!targetPidOpt) {
		procName = std::wstring(target.begin(), target.end());
		std::transform(procName.begin(), procName.end(), procName.begin(), ::towlower);
	}

	for (const auto &proc : listResult.value()) {
		if (targetPidOpt) {
			if (proc.Pid == static_cast<DWORD>(targetPidOpt.value())) {
				targets.push_back(proc);
			}
		} else {
			std::wstring name = proc.Name;
			std::transform(name.begin(), name.end(), name.begin(), ::towlower);
			if (name == procName) targets.push_back(proc);
		}
	}

	if (targets.empty()) {
		return Error(std::format("Process '{}' not found", target));
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

Result<std::wstring, Error>
ProcessUtils::GetFileDescriptionFromPath(const std::wstring &file) {
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
	if (!pathRes) return pathRes.error();
	return GetFileDescriptionFromPath(pathRes.value());
}

Result<std::monostate, Error> ProcessUtils::SuspendThread(DWORD tid) {
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
	return std::monostate{};
}

Result<std::monostate, Error> ProcessUtils::ResumeThread(DWORD tid) {
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
	return std::monostate{};
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

Result<std::monostate, Error>
ProcessUtils::SetProcessPriority(DWORD pid, DWORD priorityClass) {
	HANDLE hProcess = OpenProcess(PROCESS_SET_INFORMATION, FALSE, pid);
	if (!hProcess) {
		return WinErr(GetLastError(), std::format("OpenProcess failed for PID {}", pid));
	}
	BOOL success = SetPriorityClass(hProcess, priorityClass);
	DWORD err = GetLastError();
	CloseHandle(hProcess);
	if (!success) {
		return WinErr(err, std::format("SetPriorityClass failed for PID {}", pid));
	}
	return std::monostate{};
}

Result<std::monostate, Error>
ProcessUtils::SetThreadPriorityLevel(DWORD tid, int priorityLevel) {
	HANDLE hThread = OpenThread(THREAD_SET_INFORMATION, FALSE, tid);
	if (!hThread) {
		return WinErr(GetLastError(), std::format("OpenThread failed for TID {}", tid));
	}
	BOOL success = SetThreadPriority(hThread, priorityLevel);
	DWORD err = GetLastError();
	CloseHandle(hThread);
	if (!success) {
		return WinErr(err, std::format("SetThreadPriority failed for TID {}", tid));
	}
	return std::monostate{};
}
