#include <windows.h>
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <psapi.h>

#include "Utf8Ini.h"
#include "patternfind.h"

struct Patch {
    std::string name;
    std::string module;
    std::vector<PatternByte> search;
    std::vector<PatternByte> replaceTr;
    std::string replace;
};

static void dprintf(const char* format, ...) {
    static char dprintf_msg[2048];
    va_list args;
    va_start(args, format);
    *dprintf_msg = 0;
    vsnprintf_s(dprintf_msg, sizeof(dprintf_msg), format, args);
#ifdef DEBUG
    static auto hasConsole = false;
    if (!hasConsole) {
        hasConsole = true;
        AllocConsole();
    }
    DWORD written = 0;
    WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), dprintf_msg, lstrlenA(dprintf_msg), &written, nullptr);
#else
    OutputDebugStringA(dprintf_msg);
#endif //DEBUG
}

static void dputs(const char* text) {
    dprintf("%s\n", text);
}

static void do_patching(const wchar_t* ini_file) {
    Utf8Ini ini;
    auto hFile = CreateFileW(ini_file, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile != INVALID_HANDLE_VALUE) {
        auto fileSize = GetFileSize(hFile, nullptr);
        if (fileSize) {
            auto iniData = new char[fileSize + 1];
            iniData[fileSize] = '\0';
            DWORD read;
            if (ReadFile(hFile, iniData, fileSize, &read, nullptr)) {
                int errorLine;
                if (!ini.Deserialize(iniData, errorLine)) {
                    dprintf("Deserialize failed (line %d)...\n", errorLine);
                    ini.Clear();
                }
            } else {
                dputs("ReadFile failed...");
            }
            delete[] iniData;
        } else {
            dputs("GetFileSize failed...");
        }

        CloseHandle(hFile);
    } else {
        dputs("CreateFileW failed...");
    }

    std::vector<Patch> patches;
    auto sections = ini.Sections();
    patches.reserve(sections.size());
    for (const auto& section : sections) {
        Patch patch;
        patch.name = section;
        auto searchData = ini.GetValue(section, "search");
        patch.replace = ini.GetValue(section, "replace");
        auto enabled = ini.GetValue(section, "enabled");
        patch.module = ini.GetValue(section, "module");
        if (!patch.module.length())
            patch.module = "dll";
        if (enabled == "0") {
            dprintf("%s disabled...\n", patch.name.c_str());
            continue;
        }
        if (!patterntransform(searchData, patch.search) || !patterntransform(patch.replace, patch.replaceTr)) {
            dprintf("Invalid data in %s...\n", section.c_str());
            continue;
        }
        dprintf("%s loaded!\n", patch.name.c_str());
        patches.push_back(patch);
    }

    auto patched = 0;
    for (const auto& patch : patches) {
        HMODULE hModule;
        if (patch.module == "dll") {
            hModule = GetModuleHandleA("ida.dll");
            if (!hModule)
                hModule = GetModuleHandleA("ida64.dll");
        } else if (patch.module == "exe") {
            hModule = GetModuleHandleA("ida.exe");
            if (!hModule)
                hModule = GetModuleHandleA("ida64.exe");
        } else {
            hModule = GetModuleHandleA(patch.module.c_str());
        }

        if (!hModule) {
            dprintf("Failed to find module %s for patch %s...\n", patch.module.c_str(), patch.name.c_str());
            continue;
        }
        MODULEINFO modinfo;
        if (!GetModuleInformation(GetCurrentProcess(), hModule, &modinfo, sizeof(modinfo))) {
            dprintf("GetModuleInformation failed for module %s (%p)...\n", patch.module.c_str(), hModule);
            continue;
        }
        auto data = (unsigned char*)modinfo.lpBaseOfDll;
        auto datasize = size_t(modinfo.SizeOfImage);
        auto found = patternfind(data, datasize, patch.search);
        if (found == -1) {
            dprintf("Failed to find pattern for %s...\n", patch.name.c_str());
            continue;
        }
        auto buffersize = patch.replaceTr.size();
        auto buffer = new unsigned char[buffersize];
        memcpy(buffer, data + found, buffersize);
        patternwrite(buffer, buffersize, patch.replace.c_str());
        SIZE_T written;

        DWORD oldprotect;
        VirtualProtectEx(GetCurrentProcess(), data + found, buffersize, PAGE_EXECUTE_READWRITE, &oldprotect);
        if (WriteProcessMemory(GetCurrentProcess(), data + found, buffer, buffersize, &written)) {
            patched++;
        } else {
            dprintf("WriteProcessMemory failed...");
            dprintf("%d", GetLastError());
        }
        VirtualProtectEx(GetCurrentProcess(), data + found, buffersize, oldprotect, &oldprotect);

        delete[] buffer;
    }

    dprintf("%d/%d patches successful!\n", patched, int(patches.size()));
}

struct plugin_ctx_t : public plugmod_t {
    virtual bool idaapi run(size_t) override;
};

bool idaapi plugin_ctx_t::run(size_t) {
    // no-op
    return true;
}

static plugmod_t* idaapi init() {
    return new plugin_ctx_t;
}

BOOL WINAPI DllMain(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD     fdwReason,
    _In_ LPVOID    lpvReserved
) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        char mutexName[32] = "";
        sprintf_s(mutexName, "idapatch%X", GetCurrentProcessId());
        if (CreateMutexA(nullptr, FALSE, mutexName) && GetLastError() != ERROR_ALREADY_EXISTS) {
            wchar_t patchIni[MAX_PATH] = L"";
            if (GetModuleFileNameW(hinstDLL, patchIni, _countof(patchIni))) {
                *wcsrchr(patchIni, L'\\') = L'\0';
                wcscat_s(patchIni, L"\\idapatch.ini");
                do_patching(patchIni);
            }
        }
    }
    return true;
}

plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_FIX			// Load the plugin on startup instead of on file load
  | PLUGIN_HIDE			// Hide the plugin from the Edit->Plugins menu
  | PLUGIN_MULTI,       // The plugin can work with multiple idbs in parallel
  init,                 // initialize
  nullptr,
  nullptr,
  nullptr,              // long comment about the plugin
  nullptr,              // multiline help about the plugin
  "idapatch",           // the preferred short name of the plugin
  nullptr,              // the preferred hotkey to run the plugin
};
