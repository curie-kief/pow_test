#pragma once

#include <inttypes.h>
#include <stddef.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

// Note HAS_INTEL_HW and future HAS_ARM_HW only mean we can emit the AES instructions
// check CPU support for the hardware AES encryption has to be done at runtime
#if defined(__x86_64__) || defined(__i386__) || defined(_M_X86) || defined(_M_X64)
#ifdef __GNUC__
#include <x86intrin.h>
#include <cpuid.h>
#pragma GCC target ("aes")
#define HAS_INTEL_HW
#endif
#ifdef _MSC_VER 
#include <intrin.h>
#define HAS_INTEL_HW
#endif
#endif

#if defined(_WIN32) || defined(_WIN64)
#include <malloc.h>
#define WIN_MEM_ALIGN
#endif

#ifdef HAS_INTEL_HW
inline void cpuid(uint32_t eax, int32_t ecx, int32_t val[4])
{
	val[0] = 0;
	val[1] = 0;
	val[2] = 0;
	val[3] = 0;

#ifdef _MSC_VER
	__cpuidex(val, eax, ecx);
#else
	__cpuid_count(eax, ecx, val[0], val[1], val[2], val[3]);
#endif
}

inline bool hw_check_aes()
{
	int32_t cpu_info[4];
	cpuid(1, 0, cpu_info);
	return (cpu_info[2] & (1 << 25)) != 0;
}
#endif

#ifdef HAS_ARM_HW
inline bool hw_check_aes()
{
	return false;
}
#endif

#if !defined(HAS_INTEL_HW) && !defined(HAS_ARM_HW)
inline bool hw_check_aes()
{
	return false;
}
#endif

// This cruft avoids casting-galore and allows us not to worry about sizeof(void*)
union cn_sptr
{
	cn_sptr() : as_void(nullptr) {}
	cn_sptr(uint64_t* ptr) { as_uqword = ptr; }
	cn_sptr(uint32_t* ptr) { as_udword = ptr; }
	cn_sptr(uint8_t* ptr) { as_byte = ptr; }
#ifdef HAS_INTEL_HW
	cn_sptr(__m128i* ptr) { as_xmm = ptr; }
#endif

	void* as_void;
	uint8_t* as_byte;
	uint64_t* as_uqword;
	int32_t* as_dword;
	uint32_t* as_udword;
#ifdef HAS_INTEL_HW
	__m128i* as_xmm;
#endif
};

template<size_t MEMORY, size_t ITER>
class cn_slow_hash
{
public:
	cn_slow_hash()
	{
#if !defined(WIN_MEM_ALIGN)
		lpad.as_void = aligned_alloc(4096, MEMORY);
		spad.as_void = aligned_alloc(4096, 4096);
#else
		lpad.as_void = _aligned_malloc(MEMORY, 4096);
		spad.as_void = _aligned_malloc(4096, 4096);
#endif
	}

	~cn_slow_hash()
	{
#if !defined(WIN_MEM_ALIGN)
		free(lpad.as_void);
		free(spad.as_void);
#else
		_aligned_free(lpad.as_void);
		_aligned_free(spad.as_void);
#endif		
	}

	void hash(const void* in, size_t len, void* out)
	{
		if(hw_check_aes() && !check_override())
			hardware_hash(in, len, out);
		else
			software_hash(in, len, out);
	}

	void software_hash(const void* in, size_t len, void* out);
	
#if !defined(HAS_INTEL_HW) && !defined(HAS_ARM_HW)
	inline void hardware_hash(const void* in, size_t len, void* out) { assert(false); }
#else
	void hardware_hash(const void* in, size_t len, void* out);
#endif

private:
	static constexpr size_t MASK = ((MEMORY-1) >> 4) << 4;

	inline bool check_override()
	{
		const char *env = getenv("SUMO_USE_SOFTWARE_AES");
		if (!env) {
			return false;
		}
		else if (!strcmp(env, "0") || !strcmp(env, "no")) {
			return false;
		}
		else {
			return true;
		}
	}

	inline cn_sptr scratchpad_ptr(uint32_t idx) { return lpad.as_byte + (idx & MASK); }

#if !defined(HAS_INTEL_HW) && !defined(HAS_ARM_HW)
	inline void explode_scratchpad_hard() { assert(false); }
	inline void implode_scratchpad_hard() { assert(false); }
#else
	void explode_scratchpad_hard();
	void implode_scratchpad_hard();
#endif

	void explode_scratchpad_soft();
	void implode_scratchpad_soft();

	cn_sptr lpad;
	cn_sptr spad;
};
