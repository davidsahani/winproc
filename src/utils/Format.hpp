#pragma once
#include <string>
#include <Windows.h>

std::string format_hresult(HRESULT hr);
std::string format_win32(DWORD winError);
std::string format_ntstatus(LONG status);
