#include "module.h"

#ifdef _WIN32
#include <psapi.h>
#else
#include <cstring>
#include <fstream>
#include <link.h>
#include <sys/mman.h>
#include <unistd.h>
#endif

inline module_t handle_or(std::initializer_list<std::string_view> candidates) {
    for (const auto& candidate : candidates) {
        if (module_t handle = get_module_handle(candidate)) {
            return handle;
        }
    }
    return module_t{};
}

module_t get_idaexe_handle() {
#ifdef _WIN32
    return handle_or({"ida.exe", "ida64.exe"});
#else
    return handle_or({"ida", "ida64"});
#endif
}

module_t get_libida_handle() {
#ifdef _WIN32
    return handle_or({"ida.dll", "ida64.dll", "ida32.dll"});
#elif defined(__APPLE__)
    return handle_or({"libida.dylib", "libida64.dylib", "libida32.dylib"});
#else
    return handle_or({"libida.so", "libida64.so", "libida32.so"});
#endif
}

bool get_module_data(module_t handle, unsigned char*& data, size_t& size) {
#ifdef _WIN32
    MODULEINFO modinfo;
    if (!GetModuleInformation(GetCurrentProcess(), handle, &modinfo, sizeof(modinfo)))
        return false;

    data = reinterpret_cast<unsigned char*>(modinfo.lpBaseOfDll);
    size = modinfo.SizeOfImage;
#else
    link_map* map;
    if (dlinfo(handle, RTLD_DI_LINKMAP, &map) != 0)
        return false;

    std::ifstream maps("/proc/self/maps");
    std::string line;
    uintptr_t base_addr = reinterpret_cast<uintptr_t>(map->l_addr);
    uintptr_t module_end{};

    while (std::getline(maps, line)) {
        if (line.find(map->l_name) != std::string::npos) {
            std::string range = line.substr(0, line.find(' '));
            if (size_t dash = range.find('-'); dash != std::string::npos) {
                uintptr_t start = std::stoul(range.substr(0, dash), nullptr, 16);
                uintptr_t end = std::stoul(range.substr(dash + 1), nullptr, 16);
                if (start == base_addr && end > module_end)
                    module_end = end;
            }
        }
    }

    data = reinterpret_cast<unsigned char*>(map->l_addr);
    size = module_end - base_addr;
#endif
    return true;
}

module_t get_module_handle(std::string_view name) {
#ifdef _WIN32
    return GetModuleHandleA(name.data());
#else
    return dlopen(name.data(), RTLD_LAZY);
#endif
}

bool write_memory(unsigned char* baseaddr, const unsigned char* buffer, size_t buffersize) {
#ifdef _WIN32
    SIZE_T written;
    DWORD oldprotect;

    VirtualProtectEx(GetCurrentProcess(), baseaddr, buffersize, PAGE_EXECUTE_READWRITE, &oldprotect);
    bool success = WriteProcessMemory(GetCurrentProcess(), baseaddr, buffer, buffersize, &written);
    VirtualProtectEx(GetCurrentProcess(), baseaddr, buffersize, oldprotect, &oldprotect);

    return success;
#else
    bool success{};

    unsigned char* pagestart = reinterpret_cast<unsigned char*>(
        reinterpret_cast<uintptr_t>(baseaddr) & ~(sysconf(_SC_PAGESIZE) - 1));

    if (mprotect(pagestart, buffersize + (baseaddr - pagestart), PROT_READ | PROT_WRITE | PROT_EXEC) != -1) {
        success = true;
        memcpy(baseaddr, buffer, buffersize);
        mprotect(baseaddr, buffersize, PROT_READ | PROT_EXEC);
    }

    return success;
#endif
}
