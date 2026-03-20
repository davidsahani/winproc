#pragma once
#include "ScopeExit.hpp"

namespace scope {

	struct ScopeExitHelper {
		template <class F>
		constexpr auto operator+(F &&f) const noexcept(
			std::is_nothrow_constructible_v<ScopeExit<std::decay_t<F>>, F &&>
		) -> ScopeExit<std::decay_t<F>> {
			using Decayed = std::decay_t<F>;
			return ScopeExit<Decayed>(Decayed(std::forward<F>(f)));
		}
	};

	inline constexpr ScopeExitHelper scope_exit_helper{};

} // namespace scope

#define DEFER \
[[maybe_unused]] auto SCOPE_PP_UNIQUE_NAME(_defer_) = scope::scope_exit_helper + [&]()
