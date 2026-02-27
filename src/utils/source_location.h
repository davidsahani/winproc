// source_location standard header (core)

// Copyright (c) Microsoft Corporation.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#ifndef _SOURCE_LOCATION_H_
#define _SOURCE_LOCATION_H_
#include <yvals_core.h>
#if _STL_COMPILER_PREPROCESSOR

#include <cstdint>

#pragma pack(push, _CRT_PACKING)
#pragma warning(push, _STL_WARNING_LEVEL)
#pragma warning(disable : _STL_DISABLED_WARNINGS)
_STL_DISABLE_CLANG_WARNINGS
#pragma push_macro("new")
#undef new

#ifndef _SHOULD_USE_DETAILED_FUNCTION_NAME_IN_SOURCE_LOCATION
#define _SHOULD_USE_DETAILED_FUNCTION_NAME_IN_SOURCE_LOCATION 1
#endif // ^^^ !defined(_SHOULD_USE_DETAILED_FUNCTION_NAME_IN_SOURCE_LOCATION) ^^^

_EXPORT_STD struct source_location {
    _NODISCARD static constexpr source_location current(const uint_least32_t _Line_ = __builtin_LINE(),
        const uint_least32_t _Column_ = __builtin_COLUMN(), const char* const _File_ = __builtin_FILE(),
#if _SHOULD_USE_DETAILED_FUNCTION_NAME_IN_SOURCE_LOCATION
        const char* const _Function_ = __builtin_FUNCSIG()
#else // ^^^ detailed / basic vvv
        const char* const _Function_ = __builtin_FUNCTION()
#endif // ^^^ basic ^^^
            ) noexcept {
        source_location _Result{};
        _Result._Line     = _Line_;
        _Result._Column   = _Column_;
        _Result._File     = _File_;
        _Result._Function = _Function_;
        return _Result;
    }

    _NODISCARD_CTOR constexpr source_location() noexcept = default;

    _NODISCARD constexpr uint_least32_t line() const noexcept {
        return _Line;
    }
    _NODISCARD constexpr uint_least32_t column() const noexcept {
        return _Column;
    }
    _NODISCARD constexpr const char* file_name() const noexcept {
        return _File;
    }
    _NODISCARD constexpr const char* function_name() const noexcept {
        return _Function;
    }

private:
    uint_least32_t _Line{};
    uint_least32_t _Column{};
    const char* _File     = "";
    const char* _Function = "";
};

#pragma pop_macro("new")
_STL_RESTORE_CLANG_WARNINGS
#pragma warning(pop)
#pragma pack(pop)

#endif // _STL_COMPILER_PREPROCESSOR
#endif // _SOURCE_LOCATION_H_
