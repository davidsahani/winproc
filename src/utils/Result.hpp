#pragma once
#include <type_traits>
#include <utility>
#include <variant>
#include <stdexcept>

template <typename T, typename E>
class Result {
    static_assert(!std::is_same_v<T, E>,
        "Result<T, E> requires T != E because holds_alternative/get<T> "
        "need a unique T in the variant."
    );

public:
    // OK constructor: constructible as T, not constructible as E
    template <class U>
    requires (
        std::is_constructible_v<T, U&&> &&
        !std::is_same_v<std::remove_cvref_t<U>, Result> &&
        !std::is_same_v<std::remove_cvref_t<U>, E>
    )
    Result(U &&value) : _data(std::in_place_type<T>, std::forward<U>(value)) {}

    // ERR constructor: constructible as E, not constructible as T
    template <class U>
    requires (
        std::is_same_v<std::remove_cvref_t<U>, E> &&
        !std::is_same_v<std::remove_cvref_t<U>, Result>
    )
    Result(U &&error) : _data(std::in_place_type<E>, std::forward<U>(error)) {}

    // Check if result is success
	bool has_value() const {
		return std::holds_alternative<T>(_data);
	}

	explicit operator bool() const {
		return has_value();
	}

	// Access the value (throws if it's an error)
	T &value() noexcept(false) {
		if (!has_value()) throw std::logic_error("Called value() on an Err");
		return std::get<T>(_data);
	}

	const T &value() const noexcept(false) {
		if (!has_value()) throw std::logic_error("Called value() on an Err");
		return std::get<T>(_data);
	}

	// Access the error (throws if it's a value)
	E &error() noexcept(false) {
		if (has_value()) throw std::logic_error("Called error() on an Ok");
		return std::get<E>(_data);
	}

	const E &error() const noexcept(false) {
		if (has_value()) throw std::logic_error("Called error() on an Ok");
		return std::get<E>(_data);
	}

	// Returns the value if successful, otherwise returns the default value
    template <class U>
    constexpr T value_or(U&& default_value) const& {
        return has_value() ? std::get<T>(_data) : static_cast<T>(std::forward<U>(default_value));
    }

    template <class U>
    constexpr T value_or(U&& default_value) && {
        return has_value() ? std::move(std::get<T>(_data)) : static_cast<T>(std::forward<U>(default_value));
    }

    // Pattern matching-like API
	template <typename OkFn, typename ErrFn>
	auto match(OkFn okFn, ErrFn errFn) const {
		if (has_value())
			return okFn(std::get<T>(_data));
		else
			return errFn(std::get<E>(_data));
	}

private:
    std::variant<T, E> _data;
};
