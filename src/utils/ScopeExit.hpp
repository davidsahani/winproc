#pragma once

#include <type_traits>
#include <utility>

namespace scope {

	template <typename F> class [[nodiscard]] ScopeExit {
	public:
		explicit ScopeExit(F f) noexcept(std::is_nothrow_move_constructible_v<F>)
			: func(std::move(f)), active(true) {}

		ScopeExit(ScopeExit &&other) noexcept(std::is_nothrow_move_constructible_v<F>)
			: func(std::move(other.func)), active(other.active) {
			other.active = false;
		}

		~ScopeExit() noexcept(noexcept(std::declval<F &>()())) {
			if (active) func();
		}

		ScopeExit(const ScopeExit &) = delete;
		ScopeExit &operator=(const ScopeExit &) = delete;
		void *operator new(std::size_t) noexcept = delete;
		void *operator new[](std::size_t) noexcept = delete;

		constexpr void release() noexcept { active = false; }

	private:
		F func;
		bool active;
	};

	template <class F> ScopeExit(F) -> ScopeExit<std::decay_t<F>>;
} // namespace scope

#define CONCAT_IMPL(x, y) x##y
#define CONCAT(x, y) CONCAT_IMPL(x,y)
#ifdef __COUNTER__
#define UNIQUE_NAME(base) CONCAT(base, __COUNTER__)
#else
#define UNIQUE_NAME(base) CONCAT(base, __LINE__)
#endif

#define SCOPE_EXIT(...) \
[[maybe_unused]] auto UNIQUE_NAME(_scope_exit_) = scope::ScopeExit([&](){ __VA_ARGS__; });
