#pragma once
#include <cstddef>
#include <string_view>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
using module_t = HMODULE;
#else
using module_t = void*;
#endif

module_t get_idaexe_handle();
module_t get_libida_handle();
bool get_module_data(module_t handle, unsigned char*& data, size_t& size);
module_t get_module_handle(std::string_view name);
bool write_memory(unsigned char* baseaddr, const unsigned char* buffer, size_t buffersize);
