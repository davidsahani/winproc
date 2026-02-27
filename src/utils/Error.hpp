#pragma once
#include <string>
#include "Result.hpp"

#define _SHOULD_USE_DETAILED_FUNCTION_NAME_IN_SOURCE_LOCATION 0
#include "source_location.h"

struct Error {
	std::string message;
	std::string traceback;

	Error(const std::string &msg, const std::string &traceback);

	Error(const std::string &msg, source_location loc = source_location::current());

	const std::string str() const;
};

using ResultVoid = Result<std::monostate, Error>;
