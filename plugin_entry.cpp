#include <fstream>

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

#include "module.h"
#include "patternfind.h"
#include "Utf8Ini.h"

#ifndef _WIN32
#include <dlfcn.h>
#include <semaphore.h>
#endif

struct Patch {
    std::string name;
    std::string module;
    std::vector<PatternByte> search;
    std::vector<PatternByte> replaceTr;
    std::string replace;
};

void logmsg(const char* fmt, ...) {
    va_list arglist;
    va_start(arglist, fmt);
    vmsg(fmt, arglist);
    va_end(arglist);
}

#ifdef _WIN32
constexpr std::string_view PlatformString = "windows";
#elif defined(__APPLE__)
constexpr std::string_view PlatformString = "macos";
#else
constexpr std::string_view PlatformString = "linux";
#endif

static void do_patching(std::string_view ini_file) {
    Utf8Ini ini;

    if (std::ifstream file(ini_file.data()); !file.fail()) {
        std::string iniData((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        int errorLine;
        if (!ini.Deserialize(iniData, errorLine)) {
            logmsg("Deserialize failed (line %d)...\n", errorLine);
            ini.Clear();
        }
    } else {
        logmsg("Creating stream for INI file (%s) failed...\n", ini_file.data());
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
        auto platform = ini.GetValue(section, "platform");
        if (enabled == "0" || (!platform.empty() && platform != PlatformString)) {
            logmsg("%s disabled...\n", patch.name.c_str());
            continue;
        }
        if (!patterntransform(searchData, patch.search) || !patterntransform(patch.replace, patch.replaceTr)) {
            logmsg("Invalid data in %s...\n", section.c_str());
            continue;
        }
        logmsg("%s loaded!\n", patch.name.c_str());
        patches.push_back(patch);
    }

    auto patched = 0;
    for (const auto& patch : patches) {
        module_t module;
        if (patch.module == "dll")
            module = get_libida_handle();
        else if (patch.module == "exe")
            module = get_idaexe_handle();
        else
            module = get_module_handle(patch.module);

        if (!module) {
            logmsg("Failed to find module %s for patch %s...\n", patch.module.c_str(), patch.name.c_str());
            continue;
        }
        unsigned char* data;
        size_t datasize;
        if (!get_module_data(module, data, datasize)) {
            logmsg("Failed to get data of module %s (%p)...\n", patch.module.c_str(), module);
            continue;
        }
        auto found = patternfind(data, datasize, patch.search);
        if (found == -1) {
            logmsg("Failed to find pattern for %s...\n", patch.name.c_str());
            continue;
        }
        auto buffersize = patch.replaceTr.size();
        auto buffer = new unsigned char[buffersize];
        memcpy(buffer, data + found, buffersize);
        patternwrite(buffer, buffersize, patch.replace.c_str());

        if (write_memory(data + found, buffer, buffersize)) {
            patched++;
        } else {
        #ifdef _WIN32
            logmsg("Writing memory failed (%d)...\n", GetLastError());
        #else
            logmsg("Writing memory failed (%d)...\n", errno);
        #endif
        }

        delete[] buffer;
    }

    logmsg("%d/%d patches successful!\n", patched, int(patches.size()));
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

#ifdef _WIN32
BOOL WINAPI DllMain(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD     fdwReason,
    _In_ LPVOID    lpvReserved
) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        char mutexName[32] = "";
        sprintf_s(mutexName, "idapatch%X", GetCurrentProcessId());
        if (CreateMutexA(nullptr, FALSE, mutexName) && GetLastError() != ERROR_ALREADY_EXISTS) {
            char patchIni[MAX_PATH];
            if (GetModuleFileNameA(hinstDLL, patchIni, sizeof(patchIni))) {
                *strrchr(patchIni, '\\') = '\0';
                strcat_s(patchIni, "\\idapatch.ini");
                do_patching(patchIni);
            }
        }
    }
    return true;
}
#else
__attribute__((constructor)) static void on_load() {
    char semName[32];
    snprintf(semName, sizeof(semName), "/idapatch%d", getpid());

    sem_t* sem = sem_open(semName, O_CREAT | O_EXCL, 0644, 1);
    if (sem == SEM_FAILED)
        return;

    Dl_info dl_info;
    if (dladdr(reinterpret_cast<void*>(on_load), &dl_info) && dl_info.dli_fname) {
        char* patchIni = strdup(dl_info.dli_fname);
        if (patchIni) {
            *strrchr(patchIni, '/') = '\0';
            strncat(patchIni, "/idapatch.ini", 14);
            do_patching(patchIni);
            free(patchIni);
        }
    }

    sem_close(sem);
    sem_unlink(semName);
}
#endif

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
