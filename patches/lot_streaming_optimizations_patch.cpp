#include "../patch_system.h"
#include "../patch_helpers.h"
#include "../logger.h"
#include "../settings.h"
#include "../utils.h"
#include <cstdint>
#include <format>
#include <mutex>
#include <unordered_map>
#include <vector>

// Consolidates (gone now) the four lot-streaming patches into one, each an independently toggleable sub-patch with a few values exposed for some
// The object streaming throttle spreads a lot's per-object scene-node build over time so a lot loading / popping into detailed view doesn't build every object in one frame
// The map view blocker pauses lot streaming while in map view
// The lot visibility override disables the camera-view distance bias in the lot visibility metric so lots don't load/unload purely on view
// The optimized streaming settings enables "Throttle Lot LoD Transitions", sets its Max Active Lot Threshold to 12 (big = good), and applies the configurable Camera speed threshold value, defaulting lower (makes lots only load if the camera has been still for a period lower = longer)

namespace {

// Shared engine signatures (all resolved by unique pattern, no version addresses)

// Object throttle
// Lot::AddLotObjectsToScene (patch target). SUB ESP,8; PUSH EDI; MOV EDI,ECX; CMP [EDI+0xC9],0; ...
const AddressInfo sigAddLotEntry = {
    .name = "Lot::AddLotObjectsToScene",
    .pattern = "83 EC 08 57 8B F9 80 BF C9 00 00 00 00 74 0E C6 87 C1 00 00 00 00 5F 83 C4 08 C2 08",
    .expectedBytes = {0x83, 0xEC, 0x08, 0x57, 0x8B, 0xF9},
};
// Lot::UpdateObjectSceneNode (called per object). __thiscall(lot, obj, char, char)
const AddressInfo sigUpdateObjectSceneNode = {
    .name = "Lot::UpdateObjectSceneNode",
    .pattern = "83 EC 0C 83 B9 64 03 00 00 00 89 4C 24 04 0F 84 ?? ?? ?? ?? 83 B9 08 04 00 00 01",
    .expectedBytes = {0x83, 0xEC, 0x0C, 0x83, 0xB9, 0x64},
};
// ScriptMessageScope ctor. __thiscall(scope, int beginMsg, int endMsg, lot)
const AddressInfo sigScopeCtor = {
    .name = "ScriptMessageScope::ctor",
    .pattern = "8B 44 24 08 56 8B F1 8B 4C 24 10 57 8B 7C 24 0C 85 FF 89 06 89 4E 04 74 19",
    .expectedBytes = {0x8B, 0x44, 0x24, 0x08, 0x56},
};
// ScriptMessageScope dtor. __fastcall(scope)
const AddressInfo sigScopeDtor = {
    .name = "ScriptMessageScope::dtor",
    .pattern = "56 8B F1 83 3E 00 74 1B E8 ?? ?? ?? ?? 85 C0 74 12 8B 4E 04 8B 10 8B 52 18 6A 00 51",
    .expectedBytes = {0x56, 0x8B, 0xF1, 0x83, 0x3E, 0x00},
};
// RemoteMethodCall poster (re-marshal). __cdecl(thread, lot, func, a4, char, char)
const AddressInfo sigReMarshal = {
    .name = "Services::PostRemoteMethodCall",
    .pattern = "53 56 6A 00 6A 00 6A 00 6A 00 68 ?? ?? ?? ?? 6A 20 E8 ?? ?? ?? ?? 83 C4 18 85 C0 74 ?? C7 00 ?? ?? ?? ?? 33 C9 8D 50 04 87 0A 8B 4C 24 10 8B 54 24 14 89 48 0C 8B 4C 24 18 89 48 14 8A 4C 24 20",
    .expectedBytes = {0x53, 0x56, 0x6A, 0x00, 0x6A, 0x00},
};

// Map view blocker
// Sims3::World::WorldManager::Update (hook target). __thiscall(worldMgr, param2, float param3)
const AddressInfo sigWorldManagerUpdate = {
    .name = "World::WorldManager::Update",
    .addresses = {{GameVersion::Retail, 0x00c6d3b0}, {GameVersion::Steam, 0x00c6d570}, {GameVersion::EA, 0x00c6c8f0}},
    .pattern = "55 8B EC 83 E4 F0 83 EC 64 53 56 8B F1 83 BE B4 01 00 00 00 57 75",
    .expectedBytes = {0x55, 0x8B, 0xEC, 0x83, 0xE4, 0xF0},
};
// ScriptCore.CameraController::Camera_IsMapViewModeEnabled. __cdecl() -> char (reads camera+0x8B9)
const AddressInfo sigCameraIsMapView = {
    .name = "Camera_IsMapViewModeEnabled",
    .addresses = {{GameVersion::Steam, 0x0073e060}},
    .pattern = "E8 ?? ?? ?? ?? 85 C0 74 2F 8B C8 E8 ?? ?? ?? ?? 85 C0 74 24 8B C8 E8 ?? ?? ?? ?? 85 C0 74 19 8B 10 8B C8 8B 42 0C 68 89 DD 0F 11 FF D0 85 C0 74 ?? 8A 80 B9 08 00 00",
};

// Visibility override
// JZ in the lot visibility/distance metric (FUN_00c62d80). Patched JZ(0x74) -> JMP(0xEB).
const AddressInfo sigVisibilityCondition = {
    .name = "LotVisibility::cameraBias JZ",
    .addresses = {{GameVersion::Retail, 0x00c62ae5}, {GameVersion::Steam, 0x00c63015}, {GameVersion::EA, 0x00c623a5}},
    .pattern = "74 ?? F3 0F 10 44 24 08 F3 0F 5C 87 E0 00 00 00 F3 0F 11 44 24 08 D9 44 24 08 5F 5E 8B E5 5D C2 0C 00",
    .expectedBytes = {0x74},
};

// Object Streaming Throttle internals
// in short, the engine marshal runs inline when posted from its own service thread, so we process x objects then let the DLL hook thread post the continuation cross-thread, which actually enqueues = real per-frame spread.
constexpr size_t kOffObjBegin = 0x14;
constexpr size_t kOffObjEnd = 0x18;
constexpr size_t kOffDetailedViewRequested = 0xC1;
constexpr size_t kOffBulldozing = 0xC9;
constexpr int kScopeMsgBegin = 0x4c55e8c;
constexpr int kScopeMsgEnd = 0x4c55efa;

using UpdateObjectSceneNode_t = void(__thiscall*)(void* lot, void* obj, char initialLoad, char alwaysVisibleOnly);
using ScopeCtor_t = void*(__thiscall*)(void* scope, int beginMsg, int endMsg, void* lot);
using ScopeDtor_t = void(__fastcall*)(void* scope);
using ReMarshal_t = char(__cdecl*)(int thread, void* lot, void* func, int a4, char initialLoad, char alwaysVisibleOnly);

// Settings (bound directly so GUI edits are live in the detour).
int g_objectsPerLot = 2;
int g_delayMs = 16;

// Resolved engine pointers (set when the throttle sub-feature installs).
uintptr_t g_addLotEntry = 0;
ReMarshal_t g_reMarshal = nullptr;
UpdateObjectSceneNode_t g_updateNode = nullptr;
ScopeCtor_t g_scopeCtor = nullptr;
ScopeDtor_t g_scopeDtor = nullptr;
bool g_throttleActive = false; // gates DrainPending

int ClampPerLot(int k) {
    return k < 1 ? 1 : (k > 256 ? 256 : k);
}

struct LotState {
    size_t next = 0;
    char startedDetailed = 0;
    char initialLoad = 0;
    char alwaysVisibleOnly = 0;
    bool needsPost = false;
    uint64_t lastWorkTick = 0;
    void* objBegin = nullptr;
};
std::unordered_map<void*, LotState> g_state;
std::mutex g_stateMtx;

void EraseState(void* lot) {
    std::lock_guard<std::mutex> lk(g_stateMtx);
    g_state.erase(lot);
}

#pragma warning(push)
#pragma warning(disable : 4733)
bool ProbeLot(void* lot) {
    if (!lot) return false;
    __try {
        volatile uint8_t a = *(reinterpret_cast<volatile uint8_t*>(lot) + kOffBulldozing);
        volatile uint8_t b = *(reinterpret_cast<volatile uint8_t*>(lot) + kOffDetailedViewRequested);
        (void)a;
        (void)b;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
#pragma warning(pop)

// __fastcall(lot, edx, char, char) is ABI-identical to the original __thiscall(lot,char,char) RET 8.
void __fastcall Detour_AddLotObjectsToScene(void* lot, void* /*edx*/, char initialLoad, char alwaysVisibleOnly) {
    uint8_t* L = static_cast<uint8_t*>(lot);

    if (L[kOffBulldozing] != 0) { // bulldozing early-out, matches original
        L[kOffDetailedViewRequested] = 0;
        EraseState(lot);
        return;
    }

    void** begin = *reinterpret_cast<void***>(L + kOffObjBegin);
    void** end = *reinterpret_cast<void***>(L + kOffObjEnd);
    size_t count = (begin && end && end >= begin) ? static_cast<size_t>(end - begin) : 0;

    char detailed = static_cast<char>(L[kOffDetailedViewRequested]);

    size_t idx = 0;
    char startedDetailed = detailed;
    {
        std::lock_guard<std::mutex> lk(g_stateMtx);
        auto it = g_state.find(lot);
        // Resume only on the same object list; a changed mObjects begin means reload/reuse -> restart.
        if (it != g_state.end() && it->second.objBegin == reinterpret_cast<void*>(begin)) {
            idx = it->second.next;
            startedDetailed = it->second.startedDetailed;
        }
    }

    if (idx != 0 && detailed != startedDetailed) { // demoted/promoted mid-stream -> stop
        EraseState(lot);
        return;
    }
    if (idx >= count) {
        EraseState(lot);
        return;
    }

    size_t windowEnd = idx + static_cast<size_t>(ClampPerLot(g_objectsPerLot));
    if (windowEnd > count) windowEnd = count;

    void* scope[2] = {nullptr, nullptr};
    g_scopeCtor(scope, kScopeMsgBegin, kScopeMsgEnd, lot);
    for (size_t i = idx; i < windowEnd; ++i) { g_updateNode(lot, begin[i], initialLoad, alwaysVisibleOnly); }
    g_scopeDtor(scope);

    if (windowEnd < count) {
        std::lock_guard<std::mutex> lk(g_stateMtx);
        auto& st = g_state[lot];
        st.next = windowEnd;
        st.startedDetailed = startedDetailed;
        st.initialLoad = initialLoad;
        st.alwaysVisibleOnly = alwaysVisibleOnly;
        st.needsPost = true;
        st.lastWorkTick = GetTickCount64();
        st.objBegin = reinterpret_cast<void*>(begin);
    } else {
        EraseState(lot);
    }
}

// Hook-thread pump: posts one continuation per pending lot whose delay has elapsed, cross-thread.
void DrainPending() {
    if (!g_throttleActive || !g_addLotEntry || !g_reMarshal) return;

    struct Post {
        void* lot;
        char il;
        char av;
    };
    std::vector<Post> posts;
    {
        const uint64_t now = GetTickCount64();
        const uint64_t delay = (g_delayMs < 0) ? 0 : static_cast<uint64_t>(g_delayMs);
        std::lock_guard<std::mutex> lk(g_stateMtx);
        posts.reserve(g_state.size());
        for (auto& [lot, st] : g_state) {
            if (st.needsPost && (now - st.lastWorkTick) >= delay) {
                st.needsPost = false;
                posts.push_back({lot, st.initialLoad, st.alwaysVisibleOnly});
            }
        }
    }
    for (const auto& p : posts) {
        if (!ProbeLot(p.lot)) {
            EraseState(p.lot);
            continue;
        }
        g_reMarshal(1, p.lot, reinterpret_cast<void*>(g_addLotEntry), 0, p.il, p.av);
    }
}

// Map View Lot Blocker
constexpr size_t kWorldMgrSkipOffset = 0x258; // "skip lot streaming" gate in WorldManager::Update
constexpr uint64_t kMapViewGraceMs = 1000;    // keep blocking briefly after exit (zoom-out anim)

using WorldManagerUpdate_t = int(__thiscall*)(void* worldMgr, unsigned param2, float param3);
using IsMapView_t = char(__cdecl*)();

WorldManagerUpdate_t g_worldUpdateOrig = nullptr; // Detours trampoline
IsMapView_t g_isMapView = nullptr;
uint64_t g_lastMapViewTick = 0;

bool QueryMapView() {
    if (!g_isMapView) return false;
    __try {
        return g_isMapView() != 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// __fastcall(self, edx, ...) emulates __thiscall(self, param2, param3) RET 8.
int __fastcall Hooked_WorldManagerUpdate(void* worldMgr, void* /*edx*/, unsigned param2, float param3) {
    if (!g_worldUpdateOrig) return 0;

    bool inMap = QueryMapView();
    uint64_t now = GetTickCount64();
    if (inMap) g_lastMapViewTick = now;

    // Block while in map view, plus a bounded grace window after exit. Can never stick: blocking dies at most kMapViewGraceMs after the last frame map view was actually active.
    bool block = inMap || (g_lastMapViewTick != 0 && (now - g_lastMapViewTick) < kMapViewGraceMs);

    if (block) {
        char* skip = reinterpret_cast<char*>(worldMgr) + kWorldMgrSkipOffset;
        char old = *skip;
        *skip = 1;
        int r = g_worldUpdateOrig(worldMgr, param2, param3);
        *skip = old;
        return r;
    }
    return g_worldUpdateOrig(worldMgr, param2, param3);
}

} // namespace

// Patch
class LotStreamingOptimizationsPatch : public OptimizationPatch {
  private:
    // Sub-feature toggles
    bool subThrottle = true;
    bool subMapView = true;
    bool subVisibility = true;
    bool subStreamingSettings = true;

    // Exposed value (the LoD-transition Max Active Lot Threshold is fixed at 12, not exposed).
    float cameraSpeedThreshold = 5.0f;

    // Tracked patches (throttle JMP, visibility byte, live-setting writes) + the map-view detour.
    std::vector<PatchHelper::PatchLocation> patchedLocations;
    std::vector<DetourHelper::Hook> mapViewHooks;

    bool throttleInstalled = false;
    bool mapViewInstalled = false;

    // Live-setting application progress (settings may not exist until the game is further along).
    bool lsThrottleLodDone = false;
    bool lsThresholdDone = false;
    bool lsCameraDone = false;

    bool InstallThrottle() {
        auto entry = sigAddLotEntry.Resolve();
        auto node = sigUpdateObjectSceneNode.Resolve();
        auto ctor = sigScopeCtor.Resolve();
        auto dtor = sigScopeDtor.Resolve();
        auto post = sigReMarshal.Resolve();
        if (!entry || !node || !ctor || !dtor || !post) {
            LOG_WARNING("[LotStreamingOpt] Object throttle: could not resolve all signatures");
            return false;
        }

        g_addLotEntry = *entry;
        g_updateNode = reinterpret_cast<UpdateObjectSceneNode_t>(*node);
        g_scopeCtor = reinterpret_cast<ScopeCtor_t>(*ctor);
        g_scopeDtor = reinterpret_cast<ScopeDtor_t>(*dtor);
        g_reMarshal = reinterpret_cast<ReMarshal_t>(*post);
        {
            std::lock_guard<std::mutex> lk(g_stateMtx);
            g_state.clear();
        }

        if (!PatchHelper::WriteRelativeJump(*entry, reinterpret_cast<uintptr_t>(&Detour_AddLotObjectsToScene), &patchedLocations)) {
            LOG_WARNING("[LotStreamingOpt] Object throttle: failed to write entry hook");
            return false;
        }
        g_throttleActive = true;
        LOG_INFO(std::format("[LotStreamingOpt] Object throttle installed (entry @ {:#010x})", *entry));
        return true;
    }

    bool InstallMapView() {
        auto wm = sigWorldManagerUpdate.Resolve();
        auto isMap = sigCameraIsMapView.Resolve();
        if (!wm || !isMap) {
            LOG_WARNING("[LotStreamingOpt] Map view blocker: could not resolve signatures (skipping)");
            return false;
        }
        g_worldUpdateOrig = reinterpret_cast<WorldManagerUpdate_t>(*wm);
        g_isMapView = reinterpret_cast<IsMapView_t>(*isMap);
        g_lastMapViewTick = 0;

        mapViewHooks = {{reinterpret_cast<void**>(&g_worldUpdateOrig), reinterpret_cast<void*>(&Hooked_WorldManagerUpdate)}};
        if (!DetourHelper::InstallHooks(mapViewHooks)) {
            LOG_WARNING("[LotStreamingOpt] Map view blocker: failed to install hook");
            mapViewHooks.clear();
            return false;
        }
        LOG_INFO(std::format("[LotStreamingOpt] Map view blocker installed (WorldManager::Update @ {:#010x})", *wm));
        return true;
    }

    bool InstallVisibility() {
        auto addr = sigVisibilityCondition.Resolve();
        if (!addr) {
            LOG_WARNING("[LotStreamingOpt] Visibility override: could not resolve condition (skipping)");
            return false;
        }
        BYTE expectedOld = 0x74;
        if (!PatchHelper::WriteByte(*addr, 0xEB, &patchedLocations, &expectedOld)) { // JZ -> JMP
            LOG_WARNING("[LotStreamingOpt] Visibility override: failed to patch");
            return false;
        }
        LOG_INFO(std::format("[LotStreamingOpt] Visibility override installed (JZ->JMP @ {:#010x})", *addr));
        return true;
    }

    // Apply the streaming live settings; safe to call repeatedly (per-setting done-flags). Settings that don't exist yet are retried from Update() until they register.
    void TryApplyStreamingSettings() {
        if (!subStreamingSettings) return;

        if (!lsThrottleLodDone && LiveSetting::Exists(L"Throttle Lot LoD Transitions")) {
            lsThrottleLodDone = LiveSetting::Patch<bool>(L"Throttle Lot LoD Transitions", true, &patchedLocations);
            if (lsThrottleLodDone) LOG_INFO("[LotStreamingOpt] Enabled 'Throttle Lot LoD Transitions'");
        }
        if (!lsThresholdDone && LiveSetting::Exists(L"Throttle Lot LoD Transitions Max Active Lot Threshold")) {
            // Counts register as int; fall back to unsigned if the registry typed it that way.
            lsThresholdDone = LiveSetting::Patch<int>(L"Throttle Lot LoD Transitions Max Active Lot Threshold", 12, &patchedLocations) ||
                              LiveSetting::Patch<unsigned int>(L"Throttle Lot LoD Transitions Max Active Lot Threshold", 12u, &patchedLocations);
            if (lsThresholdDone) LOG_INFO("[LotStreamingOpt] Set 'Max Active Lot Threshold' = 12");
        }
        if (!lsCameraDone && LiveSetting::Exists(L"Camera speed threshold")) {
            lsCameraDone = LiveSetting::Patch<float>(L"Camera speed threshold", cameraSpeedThreshold, &patchedLocations);
            if (lsCameraDone) LOG_INFO(std::format("[LotStreamingOpt] Set 'Camera speed threshold' = {:.2f}", cameraSpeedThreshold));
        }
    }

  public:
    LotStreamingOptimizationsPatch() : OptimizationPatch("LotStreamingOptimizations", nullptr) {
        RegisterBoolSetting(&subThrottle, "objectThrottle", true, "Spread each lot's object/scene-node building across frames instead of one burst.\n");
        RegisterBoolSetting(&subMapView, "mapViewBlocker", true, "Pause lot streaming while in map view, so entering/leaving map view doesn't hitch.");
        RegisterBoolSetting(&subVisibility, "visibilityOverride", true, "Disable the camera-view distance bias so lots don't load/unload purely on view angle.");
        RegisterBoolSetting(&subStreamingSettings, "streamingSettings", true,
            "Enable 'Throttle Lot LoD Transitions' (+ Max Active Lot Threshold 12) and apply the\n"
            "camera speed threshold below.");

        RegisterIntSetting(&g_objectsPerLot, "objectsPerLot", 2, 1, 64, "Object throttle: Objects built per window. Lower = smoother", {}, SettingUIType::Slider);
        RegisterIntSetting(&g_delayMs, "delayMs", 16, 0, 500, "Object throttle: Minimum ms between a lot's windows. Higher = more spread / smoother.", {}, SettingUIType::Slider);
        RegisterFloatSetting(&cameraSpeedThreshold, "cameraSpeedThreshold", SettingUIType::InputBox, 5.0f, 0.0f, 50.0f,
            "Streaming settings: Camera speed threshold the engine uses decide how soon after camera movement stops to start loading lots");
    }

    bool Install() override {
        if (isEnabled) return true;
        lastError.clear();
        LOG_INFO("[LotStreamingOpt] Installing...");

        // Each sub-feature is independent: a resolve/install failure logs and is skipped rather than failing the whole patch.
        throttleInstalled = subThrottle && InstallThrottle();
        mapViewInstalled = subMapView && InstallMapView();
        if (subVisibility) InstallVisibility();

        lsThrottleLodDone = lsThresholdDone = lsCameraDone = false;
        TryApplyStreamingSettings();

        isEnabled = true;
        LOG_INFO("[LotStreamingOpt] Installed");
        return true;
    }

    bool Uninstall() override {
        if (!isEnabled) return true;
        lastError.clear();
        LOG_INFO("[LotStreamingOpt] Uninstalling...");

        if (!mapViewHooks.empty()) {
            DetourHelper::RemoveHooks(mapViewHooks);
            mapViewHooks.clear();
        }
        mapViewInstalled = false;

        // Restores throttle JMP, visibility byte, and live-setting writes (all tracked).
        if (!PatchHelper::RestoreAll(patchedLocations)) { LOG_WARNING("[LotStreamingOpt] Some tracked locations failed to restore"); }
        patchedLocations.clear();

        g_throttleActive = false;
        throttleInstalled = false;
        {
            std::lock_guard<std::mutex> lk(g_stateMtx);
            g_state.clear();
        }

        isEnabled = false;
        LOG_INFO("[LotStreamingOpt] Uninstalled");
        return true;
    }

    void Update() override {
        // Base handles debounced reinstall when any setting/toggle changes (which re-applies the camera threshold and re-evaluates sub-toggles).
        OptimizationPatch::Update();
        if (!isEnabled.load()) return;

        if (throttleInstalled) DrainPending();

        // Keep retrying live settings that weren't registered yet at install time.
        if (subStreamingSettings && (!lsThrottleLodDone || !lsThresholdDone || !lsCameraDone)) { TryApplyStreamingSettings(); }
    }
};

REGISTER_PATCH(LotStreamingOptimizationsPatch,
    {.displayName = "Lot Streaming Optimizations",
        .description =
            "Reduces stutter from lot streaming: throttles per-object loading, pauses streaming in map view, overrides view-based lot visibility, and applies optimized streaming settings. Each part toggleable below.",
        .category = "Performance",
        .experimental = true,
        .supportedVersions = VERSION_ALL,
        .technicalDetails = {"Object throttle: replaces Lot::AddLotObjectsToScene, building x objects/window and re-posting the rest cross-thread",
            "Map view blocker: hooks WorldManager::Update and gates the +0x258 skip flag on the live Camera_IsMapViewModeEnabled state.",
            "Visibility override: JZ->JMP on the camera-view distance bias in the lot visibility metric.",
            "Streaming settings: 'Throttle Lot LoD Transitions' on, its Max Active Lot Threshold = 12, configurable Camera speed threshold."}})
