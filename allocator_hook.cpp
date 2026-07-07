#include "allocator_hook.h"
#include "utils.h"
#include "config/config_paths.h"
#include <windows.h>
#include <Shlobj.h> //shlob on me obj ladidadida
#include <mimalloc.h>
#pragma comment(lib, "mimalloc.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "bcrypt.lib")
#include <detours/detours.h>
#include <string>
#include <vector>
#include <fstream>
#include <algorithm>
#include <direct.h>
#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "dbghelp.lib")
#include "logger.h"
#include <toml++/toml.hpp>
#include <filesystem>
//https://www.youtube.com/watch?v=M7g8YY0FZfU
bool g_mimallocActive = false;

// Function pointers for original functions
typedef void*(__cdecl* MallocFunc)(size_t);
typedef void(__cdecl* FreeFunc)(void*);
typedef void*(__cdecl* CallocFunc)(size_t, size_t);
typedef void*(__cdecl* ReallocFunc)(void*, size_t);
typedef void*(__cdecl* AlignedMallocFunc)(size_t, size_t);
typedef void(__cdecl* AlignedFreeFunc)(void*);
typedef void*(__cdecl* AlignedReallocFunc)(void*, size_t, size_t);
typedef size_t(__cdecl* MsizeFunc)(void*);
typedef void*(__cdecl* ExpandFunc)(void*, size_t);
typedef void*(__cdecl* RecallocFunc)(void*, size_t, size_t);
typedef void*(__cdecl* AlignedOffsetMallocFunc)(size_t, size_t, size_t);
typedef void*(__cdecl* AlignedOffsetReallocFunc)(void*, size_t, size_t, size_t);
typedef void*(__cdecl* AlignedRecallocFunc)(void*, size_t, size_t, size_t);
typedef void*(__cdecl* AlignedOffsetRecallocFunc)(void*, size_t, size_t, size_t, size_t);
typedef size_t(__cdecl* AlignedMsizeFunc)(void*, size_t, size_t);

static MallocFunc original_malloc = nullptr;
static FreeFunc original_free = nullptr;
static CallocFunc original_calloc = nullptr;
static ReallocFunc original_realloc = nullptr;
static AlignedMallocFunc original_aligned_malloc = nullptr;
static AlignedFreeFunc original_aligned_free = nullptr;
static AlignedReallocFunc original_aligned_realloc = nullptr;
static MsizeFunc original_msize = nullptr;
static ExpandFunc original_expand = nullptr;
static RecallocFunc original_recalloc = nullptr;
static AlignedOffsetMallocFunc original_aligned_offset_malloc = nullptr;
static AlignedOffsetReallocFunc original_aligned_offset_realloc = nullptr;
static AlignedRecallocFunc original_aligned_recalloc = nullptr;
static AlignedOffsetRecallocFunc original_aligned_offset_recalloc = nullptr;
static AlignedMsizeFunc original_aligned_msize = nullptr;

// Safe wrappers
void* __cdecl HookedMalloc(size_t size) {
    return mi_malloc(size);
}

void __cdecl SafeFree(void* p) {
    if (!p) return;
    if (mi_is_in_heap_region(p)) {
        mi_free(p);
    } else {
        if (original_free) original_free(p);
    }
}

void* __cdecl HookedCalloc(size_t count, size_t size) {
    return mi_calloc(count, size);
}

void* __cdecl SafeRealloc(void* p, size_t newsize) {
    if (!p) return mi_realloc(p, newsize);
    if (mi_is_in_heap_region(p)) {
        return mi_realloc(p, newsize);
    } else {
        // We don't attempt to migrate the block to mimalloc (e.g. via malloc + memcpy + free)
        // because we don't know the size without calling _msize (overhead) and it's risky.
        // Since we hook early, these are rare and will likely be freed... Hopefully....
        if (original_realloc) return original_realloc(p, newsize);
        return nullptr;
    }
}

void* __cdecl HookedAlignedMalloc(size_t size, size_t alignment) {
    return mi_malloc_aligned(size, alignment);
}

void __cdecl SafeAlignedFree(void* p) {
    if (!p) return;
    if (mi_is_in_heap_region(p)) {
        mi_free(p);
    } else {
        if (original_aligned_free) original_aligned_free(p);
    }
}

void* __cdecl SafeAlignedRealloc(void* p, size_t size, size_t alignment) {
    if (!p) return mi_malloc_aligned(size, alignment);
    if (mi_is_in_heap_region(p)) {
        return mi_realloc_aligned(p, size, alignment);
    } else {
        if (original_aligned_realloc) return original_aligned_realloc(p, size, alignment);
        return nullptr;
    }
}

size_t __cdecl SafeMsize(void* p) {
    if (!p) return 0;
    if (mi_is_in_heap_region(p)) {
        return mi_usable_size(p);
    } else {
        if (original_msize) return original_msize(p);
        return 0;
    }
}

void* __cdecl SafeExpand(void* p, size_t size) {
    if (!p) return nullptr;
    if (mi_is_in_heap_region(p)) {
        return mi_expand(p, size);
    } else {
        if (original_expand) return original_expand(p, size);
        return nullptr;
    }
}

void* __cdecl SafeRecalloc(void* p, size_t count, size_t size) {
    if (!p) return mi_calloc(count, size);
    if (mi_is_in_heap_region(p)) {
        return mi_recalloc(p, count, size);
    } else {
        if (original_recalloc) return original_recalloc(p, count, size);
        return nullptr;
    }
}

void* __cdecl HookedAlignedOffsetMalloc(size_t size, size_t alignment, size_t offset) {
    return mi_malloc_aligned_at(size, alignment, offset);
}

void* __cdecl SafeAlignedOffsetRealloc(void* p, size_t size, size_t alignment, size_t offset) {
    if (!p) return mi_malloc_aligned_at(size, alignment, offset);
    if (mi_is_in_heap_region(p)) {
        return mi_realloc_aligned_at(p, size, alignment, offset);
    } else {
        if (original_aligned_offset_realloc) return original_aligned_offset_realloc(p, size, alignment, offset);
        return nullptr;
    }
}

void* __cdecl SafeAlignedRecalloc(void* p, size_t count, size_t size, size_t alignment) {
    if (!p || mi_is_in_heap_region(p)) {
        return mi_recalloc_aligned(p, count, size, alignment);
    } else {
        if (original_aligned_recalloc) return original_aligned_recalloc(p, count, size, alignment);
        return nullptr;
    }
}

void* __cdecl SafeAlignedOffsetRecalloc(void* p, size_t count, size_t size, size_t alignment, size_t offset) {
    if (!p || mi_is_in_heap_region(p)) {
        return mi_recalloc_aligned_at(p, count, size, alignment, offset);
    } else {
        if (original_aligned_offset_recalloc) return original_aligned_offset_recalloc(p, count, size, alignment, offset);
        return nullptr;
    }
}

size_t __cdecl SafeAlignedMsize(void* p, size_t alignment, size_t offset) {
    if (!p) return 0;
    if (mi_is_in_heap_region(p)) {
        return mi_usable_size(p);
    } else {
        if (original_aligned_msize) return original_aligned_msize(p, alignment, offset);
        return 0;
    }
}

// Helper to check if hooks should be enabled from config.
// Runs at DLL_PROCESS_ATTACH, before HookThread, so we parse the TOML/INI directly without going through ConfigStore or other singletons.
bool ShouldEnableAllocatorHooks() {
    // Try new TOML path first
    std::string tomlPath = ConfigPaths::GetConfigPath();
    if (!tomlPath.empty() && std::filesystem::exists(Utils::ToPath(tomlPath))) {
        try {
            toml::table root = toml::parse_file(Utils::Utf8ToWide(tomlPath));
            auto enabled = root["patches"]["Mimalloc"]["enabled"].value<bool>();
            if (enabled.has_value()) { return enabled.value(); }
        } catch (...) {
            // Parse error - fall through to INI fallback
        }
    }

    // Fall back to old INI path (first-run-after-update, before migration runs)
    std::string iniPath = Utils::GetDefaultINIPath();
    std::ifstream file(Utils::ToPath(iniPath));
    if (!file.is_open()) { return false; }

    std::string line;
    bool inMimallocSection = false;

    while (std::getline(file, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ' || line.back() == '\t')) { line.pop_back(); }
        size_t start = line.find_first_not_of(" \t");
        if (start != std::string::npos && start > 0) { line = line.substr(start); }

        if (line.empty() || line[0] == ';') continue;

        if (!line.empty() && line[0] == '[' && line.back() == ']') {
            inMimallocSection = (_stricmp(line.c_str(), "[Optimization_Mimalloc]") == 0);
            continue;
        }

        if (inMimallocSection) {
            size_t equalPos = line.find('=');
            if (equalPos != std::string::npos) {
                std::string key = line.substr(0, equalPos);
                std::string value = line.substr(equalPos + 1);

                while (!key.empty() && (key.back() == ' ' || key.back() == '\t')) key.pop_back();
                while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) value.erase(0, 1);
                while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) value.pop_back();

                if (_stricmp(key.c_str(), "Enabled") == 0) { return _stricmp(value.c_str(), "true") == 0; }
            }
        }
    }

    return false;
}

void InitializeAllocatorHooks() {
    if (!ShouldEnableAllocatorHooks()) {
        LOG_INFO("Allocator hooks disabled via config.");
        return;
    }

    LOG_INFO("Initializing Allocator Hooks (mimalloc via Detours)...");

    // Use LoadLibrary instead of GetModuleHandle - at DLL_PROCESS_ATTACH time, MSVCR80.dll may not be loaded yet...
    // MSVCR80 is the only CRT worth hooking: it's the game's (VC8) runtime and MSVCP80/operator new funnel into it, while the other loaded CRTs (msvcrt/ucrtbase/msvcp_win) are OS-side only. x
    HMODULE hMsvcr80 = LoadLibraryA("MSVCR80.dll");
    if (!hMsvcr80) {
        LOG_ERROR("Failed to load MSVCR80.dll! Cannot install hooks.");
        return;
    }

    // Helper to get address and log
    auto GetProc = [&](const char* name) -> void* {
        void* addr = (void*)GetProcAddress(hMsvcr80, name);
        if (!addr) LOG_WARNING(std::string("Could not find export: ") + name);
        return addr;
    };

    // init original pointers
    original_malloc = (MallocFunc)GetProc("malloc");
    original_free = (FreeFunc)GetProc("free");
    original_calloc = (CallocFunc)GetProc("calloc");
    original_realloc = (ReallocFunc)GetProc("realloc");
    original_aligned_malloc = (AlignedMallocFunc)GetProc("_aligned_malloc");
    original_aligned_free = (AlignedFreeFunc)GetProc("_aligned_free");
    original_aligned_realloc = (AlignedReallocFunc)GetProc("_aligned_realloc");
    original_msize = (MsizeFunc)GetProc("_msize");
    original_expand = (ExpandFunc)GetProc("_expand");
    original_recalloc = (RecallocFunc)GetProc("_recalloc");
    original_aligned_offset_malloc = (AlignedOffsetMallocFunc)GetProc("_aligned_offset_malloc");
    original_aligned_offset_realloc = (AlignedOffsetReallocFunc)GetProc("_aligned_offset_realloc");
    original_aligned_recalloc = (AlignedRecallocFunc)GetProc("_aligned_recalloc");
    original_aligned_offset_recalloc = (AlignedOffsetRecallocFunc)GetProc("_aligned_offset_recalloc");
    original_aligned_msize = (AlignedMsizeFunc)GetProc("_aligned_msize");

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    int hookCount = 0;

    if (original_malloc) {
        DetourAttach(&(PVOID&)original_malloc, HookedMalloc);
        hookCount++;
    }
    if (original_free) {
        DetourAttach(&(PVOID&)original_free, SafeFree);
        hookCount++;
    }
    if (original_calloc) {
        DetourAttach(&(PVOID&)original_calloc, HookedCalloc);
        hookCount++;
    }
    if (original_realloc) {
        DetourAttach(&(PVOID&)original_realloc, SafeRealloc);
        hookCount++;
    }
    if (original_aligned_malloc) {
        DetourAttach(&(PVOID&)original_aligned_malloc, HookedAlignedMalloc);
        hookCount++;
    }
    if (original_aligned_free) {
        DetourAttach(&(PVOID&)original_aligned_free, SafeAlignedFree);
        hookCount++;
    }
    if (original_aligned_realloc) {
        DetourAttach(&(PVOID&)original_aligned_realloc, SafeAlignedRealloc);
        hookCount++;
    }
    if (original_msize) {
        DetourAttach(&(PVOID&)original_msize, SafeMsize);
        hookCount++;
    }
    if (original_expand) {
        DetourAttach(&(PVOID&)original_expand, SafeExpand);
        hookCount++;
    }
    if (original_recalloc) {
        DetourAttach(&(PVOID&)original_recalloc, SafeRecalloc);
        hookCount++;
    }
    if (original_aligned_offset_malloc) {
        DetourAttach(&(PVOID&)original_aligned_offset_malloc, HookedAlignedOffsetMalloc);
        hookCount++;
    }
    if (original_aligned_offset_realloc) {
        DetourAttach(&(PVOID&)original_aligned_offset_realloc, SafeAlignedOffsetRealloc);
        hookCount++;
    }
    if (original_aligned_recalloc) {
        DetourAttach(&(PVOID&)original_aligned_recalloc, SafeAlignedRecalloc);
        hookCount++;
    }
    if (original_aligned_offset_recalloc) {
        DetourAttach(&(PVOID&)original_aligned_offset_recalloc, SafeAlignedOffsetRecalloc);
        hookCount++;
    }
    if (original_aligned_msize) {
        DetourAttach(&(PVOID&)original_aligned_msize, SafeAlignedMsize);
        hookCount++;
    }

    LONG error = DetourTransactionCommit();
    if (error == NO_ERROR) {
        LOG_INFO("Successfully hooked " + std::to_string(hookCount) + " allocator functions.");
        g_mimallocActive = true;
    } else {
        LOG_ERROR("Failed to commit Detours transaction: " + std::to_string(error));
    }
}
