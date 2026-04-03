#pragma once
#include <string>
#include <Windows.h>

#ifndef _NTDEF_
typedef _Return_type_success_(return >= 0) LONG NTSTATUS;
#endif

std::string format_hresult(HRESULT hr);
std::string format_win32(DWORD winError);
std::string format_ntstatus(NTSTATUS status);
