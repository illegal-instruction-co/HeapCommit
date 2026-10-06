#pragma once

#include <bit>
#include <cstdint>
#include <type_traits>

namespace encoding {

[[nodiscard]] constexpr std::uint64_t encodePointer(std::uint64_t ptr, std::uint64_t cookie) noexcept
{
	return std::rotr(ptr ^ cookie, static_cast<int>(cookie & 0x3F));
}

[[nodiscard]] constexpr std::uint64_t decodePointer(std::uint64_t encoded, std::uint64_t cookie) noexcept
{
	return std::rotl(encoded, static_cast<int>(cookie & 0x3F)) ^ cookie;
}

template<typename T>
concept PointerLike = std::is_pointer_v<T> || std::is_same_v<T, std::uintptr_t>;

template<PointerLike T>
[[nodiscard]] std::uint64_t encodeTypedPointer(T ptr, std::uint64_t cookie) noexcept
{
	return encodePointer(reinterpret_cast<std::uintptr_t>(ptr), cookie);
}

template<PointerLike T>
[[nodiscard]] T decodeTypedPointer(std::uint64_t encoded, std::uint64_t cookie) noexcept
{
	return reinterpret_cast<T>(static_cast<std::uintptr_t>(decodePointer(encoded, cookie)));
}

static_assert(decodePointer(encodePointer(0xDEADBEEFCAFEBABE, 0x1234'5678'9ABC'DEC0),
                            0x1234'5678'9ABC'DEC0) == 0xDEADBEEFCAFEBABE);
static_assert(decodePointer(encodePointer(0xDEADBEEFCAFEBABE, 0x0F0F'F0F0'1234'567F),
                            0x0F0F'F0F0'1234'567F) == 0xDEADBEEFCAFEBABE);

}