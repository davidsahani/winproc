#include "Error.hpp"
#include <filesystem>
#include <sstream>

Error::Error(const std::string &msg, const std::string &traceback)
    : message(msg), traceback(traceback) {}

Error::Error(const std::string &msg, source_location loc)
    : message(msg)
{
    std::ostringstream oss;
#ifndef NDEBUG
    oss << loc.file_name();
#else
    oss << std::filesystem::path(loc.file_name()).filename().string();
#endif
    oss << ":" << loc.line() << " in function: " << loc.function_name();
    traceback = oss.str();
}

const std::string Error::str() const {
    std::ostringstream oss;
    oss << message;
    oss << "\nTraceback: " << traceback;
    return oss.str();
}
