do
--[[
    ADVANCED BYPASS ANTI-CHEAT SYSTEM v2.0
    
    Features:
    - Breaks the game's security system
    - Bypasses almost all types of anti-cheat systems
    - Prevents being kicked/banned
    - Modifies settings without being caught
    - Blocks suspicious data transmission to server
    - Property emulation for stealth
    
    Executor Support: Works best with Synapse X, Script-Ware, Fluxus, etc.
    Gracefully degrades on basic executors.
]]

-- Set to true to enable debug messages for anti-ban system
local ANTIBAN_DEBUG = false

local Players = game:GetService("Players")
local LocalPlayer = Players.LocalPlayer
local StarterGui = game:GetService("StarterGui")
local RunService = game:GetService("RunService")
local ReplicatedStorage = game:GetService("ReplicatedStorage")

-- ===== EXECUTOR CAPABILITY DETECTION =====
local ExecutorCapabilities = {
    hasHookMetamethod = hookmetamethod ~= nil,
    hasHookFunction = hookfunction ~= nil,
    hasNewCClosure = newcclosure ~= nil,
    hasCheckCaller = checkcaller ~= nil,
    hasGetHui = gethui ~= nil,
    hasSynProtect = syn and syn.protect_gui ~= nil,
    hasGetNamecallMethod = getnamecallmethod ~= nil,
    hasSetNamecallMethod = setnamecallmethod ~= nil,
    hasGetRawMetatable = getrawmetatable ~= nil,
    hasSetReadOnly = setreadonly ~= nil,
    hasFireSignal = firesignal ~= nil,
    hasGetConnections = getconnections ~= nil,
    hasGetGc = getgc ~= nil,
    hasGetUpvalue = debug and debug.getupvalue ~= nil,
    hasSetUpvalue = debug and debug.setupvalue ~= nil,
    -- Advanced hooks (executor-specific)
    hasAddGetHook = false, -- Will check below
    hasAddSetHook = false,
    hasAddPropertyEmulator = false,
}

-- Check for advanced hook functions (these vary by executor)
pcall(function()
    ExecutorCapabilities.hasAddGetHook = type(AddGetHook) == "function"
end)
pcall(function()
    ExecutorCapabilities.hasAddSetHook = type(AddSetHook) == "function"
end)
pcall(function()
    ExecutorCapabilities.hasAddPropertyEmulator = type(AddPropertyEmulator) == "function"
end)

-- Alternative names for these functions in some executors
if not ExecutorCapabilities.hasAddGetHook then
    pcall(function()
        if type(sethook) == "function" or type(gethook) == "function" then
            ExecutorCapabilities.hasAdvancedHooks = true
        end
    end)
end

local function getExecutorName()
    local name = "Unknown"
    pcall(function()
        if identifyexecutor then
            name = identifyexecutor()
        elseif getexecutorname then
            name = getexecutorname()
        end
    end)
    return name
end

if ANTIBAN_DEBUG then
    warn("[ANTI-BAN] Executor: " .. getExecutorName())
    warn("[ANTI-BAN] Advanced Hooks Available: " .. tostring(ExecutorCapabilities.hasAddGetHook or ExecutorCapabilities.hasAddSetHook))
end

-- ===== 1. ADVANCED STEALTH GUI PROTECTION (Enhanced v3) =====
-- Multi-layer protection system with instance cloaking, hook-based hiding, and deep protection

-- Comprehensive list of names that look like legitimate Roblox/CoreGui elements
local STEALTH_GUI_NAMES = {
    -- Core Roblox GUI names (high priority - these are actual Roblox GUIs)
    "RobloxGui", "CoreGui", "SystemGui", "PlayerListGui", "ChatWindow",
    "BackpackGui", "HealthGui", "TopBarApp", "SettingsHub", "InspectMenu",
    -- Internal Roblox service names
    "RbxAnalyticsService", "RbxEventHandler", "RbxReplicatedFirst",
    "CoreScript_Internal", "PlayerDisplay_Handler", "SystemOverlay",
    "UIService_Manager", "CorePackages_Root", "VoiceChatShield",
    "BubbleChat_Container", "EmoteMenu_Core", "GameMenu_Handler",
    "NotificationFrame", "ControllerMenu", "TouchControlFrame",
    "VRService_Overlay", "StarterGui_Clone", "LoadingGui_Core",
    "AvatarContextMenu", "RobloxNetworkStats", "PerformanceStats",
    "TenFootInterface", "VirtualCursor", "InGameMenuCore",
    -- Additional stealth names
    "RbxLocalization", "RbxThumbnail", "RbxAssetService", "RbxTextFilter",
    "PolicyService_Internal", "SocialService_Handler", "VoiceChat_Internal",
    "ExperienceChat", "UnibarV2", "Chrome", "SelfView", "Unibar"
}

-- Stealth names for non-GUI instances (Parts, Highlights, BillboardGuis)
local STEALTH_INSTANCE_NAMES = {
    "RbxMeshPart", "CorePart_Internal", "SystemPart", "RbxBasePart",
    "PhysicsHandler", "CollisionPart", "RenderPart", "NetworkPart",
    "ReplicatorPart", "DataModelPart", "AnimationPart", "SoundPart",
    "LightingPart", "EffectPart", "StreamingPart", "TerrainPart",
    "RbxCharacterPart", "RbxAccessory", "RbxJoint", "RbxMotor",
    "CollisionGroup", "PhysicsGroup", "NetworkGroup", "ReplicaGroup"
}

-- Track all protected GUIs with weak references (auto-cleanup when destroyed)
local ProtectedGUIs = setmetatable({}, { __mode = "v" })
local ProtectedInstances = setmetatable({}, { __mode = "v" })
local CloakedInstances = setmetatable({}, { __mode = "k" }) -- Instances hidden from GetChildren/GetDescendants

-- PERFORMANCE: Track GUIs we've already protected to prevent double-protection
local AlreadyProtectedGUIs = setmetatable({}, { __mode = "k" })
-- PERFORMANCE: Track OUR script-created GUIs (only protect these, not game GUIs)
local OurScriptGUIs = setmetatable({}, { __mode = "k" })

-- Generate unique stealth name with timestamp and random components
local function getRandomStealthName()
    local base = STEALTH_GUI_NAMES[math.random(1, #STEALTH_GUI_NAMES)]
    local rand1 = math.random(10000, 99999)
    local rand2 = string.format("%x", math.random(0, 0xFFFF))
    return base .. "_" .. rand1 .. "_" .. rand2
end

local function getRandomInstanceName()
    local base = STEALTH_INSTANCE_NAMES[math.random(1, #STEALTH_INSTANCE_NAMES)]
    local rand1 = math.random(10000, 99999)
    return base .. "_" .. rand1
end

-- Generate random child element names (frames, labels, buttons)
local function getRandomChildName(className)
    local prefixes = {
        Frame = {"Container", "Holder", "Panel", "Box", "Region", "Area"},
        TextLabel = {"Label", "Text", "Display", "Info", "Title", "Desc"},
        TextButton = {"Button", "Btn", "Action", "Control", "Trigger"},
        ImageLabel = {"Icon", "Image", "Graphic", "Visual", "Sprite"},
        ImageButton = {"IconBtn", "ImgButton", "Visual", "Sprite"},
        ScrollingFrame = {"Scroll", "List", "Content", "Items"},
        TextBox = {"Input", "Field", "Entry", "TextInput"},
    }
    local options = prefixes[className] or {"Element", "Child", "Item", "Node"}
    return options[math.random(1, #options)] .. "_" .. math.random(1000, 9999)
end

-- ===== INSTANCE CLOAKING SYSTEM =====
-- Hooks GetChildren, GetDescendants, FindFirstChild to hide protected instances

local CloakingEnabled = false
local oldGetChildren, oldGetDescendants, oldFindFirstChild, oldFindFirstChildOfClass, oldFindFirstChildWhichIsA

local function setupInstanceCloaking()
    if CloakingEnabled then return end
    if not hookfunction or not newcclosure then return end
    
    pcall(function()
        local folder = Instance.new("Folder")
        
        -- Hook GetChildren
        oldGetChildren = hookfunction(folder.GetChildren, newcclosure(function(self)
            local children = oldGetChildren(self)
            local filtered = {}
            for _, child in ipairs(children) do
                if not CloakedInstances[child] then
                    table.insert(filtered, child)
                end
            end
            return filtered
        end))
        
        -- Hook GetDescendants
        oldGetDescendants = hookfunction(folder.GetDescendants, newcclosure(function(self)
            local descendants = oldGetDescendants(self)
            local filtered = {}
            for _, desc in ipairs(descendants) do
                if not CloakedInstances[desc] then
                    table.insert(filtered, desc)
                end
            end
            return filtered
        end))
        
        -- Hook FindFirstChild
        oldFindFirstChild = hookfunction(folder.FindFirstChild, newcclosure(function(self, name, recursive)
            local result
            if recursive then
                result = oldFindFirstChild(self, name, true)
            else
                result = oldFindFirstChild(self, name)
            end
            if result and CloakedInstances[result] then
                return nil
            end
            return result
        end))
        
        -- Hook FindFirstChildOfClass
        oldFindFirstChildOfClass = hookfunction(folder.FindFirstChildOfClass, newcclosure(function(self, className)
            local result = oldFindFirstChildOfClass(self, className)
            if result and CloakedInstances[result] then
                return nil
            end
            return result
        end))
        
        -- Hook FindFirstChildWhichIsA
        oldFindFirstChildWhichIsA = hookfunction(folder.FindFirstChildWhichIsA, newcclosure(function(self, className)
            local result = oldFindFirstChildWhichIsA(self, className)
            if result and CloakedInstances[result] then
                return nil
            end
            return result
        end))
        
        folder:Destroy()
        CloakingEnabled = true
        
        if ANTIBAN_DEBUG then
            warn("[ANTI-BAN] Instance cloaking system active")
        end
    end)
end

-- Cloak an instance (hide from GetChildren/GetDescendants/FindFirstChild)
local function cloakInstance(instance)
    if not instance then return end
    CloakedInstances[instance] = true
    -- Also cloak all descendants
    pcall(function()
        for _, desc in ipairs(instance:GetDescendants()) do
            CloakedInstances[desc] = true
        end
    end)
end

-- Uncloak an instance
local function uncloakInstance(instance)
    if not instance then return end
    CloakedInstances[instance] = nil
    pcall(function()
        for _, desc in ipairs(instance:GetDescendants()) do
            CloakedInstances[desc] = nil
        end
    end)
end

-- ===== DEEP PROTECTION SYSTEM =====
-- Protects all child elements with stealth names

local function protectAllChildren(parent)
    if not parent then return end
    pcall(function()
        for _, child in ipairs(parent:GetDescendants()) do
            if child:IsA("GuiObject") or child:IsA("GuiBase") then
                child.Name = getRandomChildName(child.ClassName)
                ProtectedInstances[child] = true
            end
        end
    end)
end

-- Watch for new children and protect them
local function watchAndProtectChildren(parent)
    if not parent then return end
    pcall(function()
        parent.DescendantAdded:Connect(function(desc)
            if desc:IsA("GuiObject") or desc:IsA("GuiBase") then
                task.defer(function()
                    desc.Name = getRandomChildName(desc.ClassName)
                    ProtectedInstances[desc] = true
                    CloakedInstances[desc] = true
                end)
            end
        end)
    end)
end

-- ===== MAIN GUI PROTECTION FUNCTION =====
-- Enhanced GUI protection with multiple fallback methods and deep protection
-- PERFORMANCE: Only protects OUR script-created GUIs, not game GUIs

local function protectGUI(gui)
    if not gui then return end
    
    -- PERFORMANCE: Skip if already protected (prevents memory leak from repeated protection)
    if AlreadyProtectedGUIs[gui] then return end
    AlreadyProtectedGUIs[gui] = true
    
    -- PERFORMANCE: Mark as our GUI so we only rotate/protect our own GUIs
    OurScriptGUIs[gui] = true
    
    pcall(function()
        -- Step 1: Assign random stealth name
        gui.Name = getRandomStealthName()
        
        -- Step 2: Try multiple protection methods in order of preference
        local parented = false
        
        -- Method 1: gethui (most hidden - executor's hidden UI container)
        if not parented and gethui then
            pcall(function()
                gui.Parent = gethui()
                parented = true
            end)
        end
        
        -- Method 2: syn.protect_gui (Synapse X specific protection)
        if not parented and syn and syn.protect_gui then
            pcall(function()
                syn.protect_gui(gui)
                gui.Parent = LocalPlayer:WaitForChild("PlayerGui")
                parented = true
            end)
        end
        
        -- Method 3: Try CoreGui (more hidden than PlayerGui)
        if not parented then
            pcall(function()
                local core = game:GetService("CoreGui")
                gui.Parent = core
                parented = true
            end)
        end
        
        -- Method 4: Fallback to PlayerGui
        if not parented then
            pcall(function()
                gui.Parent = LocalPlayer:WaitForChild("PlayerGui")
                parented = true
            end)
        end
        
        -- Step 3: Set stealth properties
        pcall(function() gui.ResetOnSpawn = false end)
        pcall(function() gui.ZIndexBehavior = Enum.ZIndexBehavior.Sibling end)
        
        -- Step 4: Track for protection
        ProtectedGUIs[gui] = true
        
        -- Step 5: Cloak the GUI from GetChildren/FindFirstChild
        cloakInstance(gui)
        
        -- PERFORMANCE: Skip deep child protection (causes overhead)
        -- protectAllChildren(gui) -- DISABLED for performance
        
        -- PERFORMANCE: Skip child watching (causes memory leak from connections)
        -- watchAndProtectChildren(gui) -- DISABLED for performance
    end)
end

-- Protect non-GUI instances (Highlights, Parts, BillboardGuis on models)
local function protectInstance(instance)
    if not instance then return end
    pcall(function()
        instance.Name = getRandomInstanceName()
        ProtectedInstances[instance] = true
        CloakedInstances[instance] = true
    end)
end

-- Create protected ScreenGui with automatic stealth
local function createProtectedScreenGui(name)
    local gui = Instance.new("ScreenGui")
    gui.Name = getRandomStealthName()
    gui.ResetOnSpawn = false
    protectGUI(gui)
    return gui
end

-- Check if a name looks like a protected/stealth name
local function isStealthName(name)
    if not name or type(name) ~= "string" then return false end
    for _, stealthBase in ipairs(STEALTH_GUI_NAMES) do
        if name:find(stealthBase) then return true end
    end
    for _, stealthBase in ipairs(STEALTH_INSTANCE_NAMES) do
        if name:find(stealthBase) then return true end
    end
    return false
end

-- ===== PERIODIC NAME ROTATION =====
-- Rotates GUI names periodically to prevent pattern detection
-- PERFORMANCE: Reduced frequency and only rotates OUR GUIs

local function startNameRotation()
    task.defer(function()
        while true do
            task.wait(180) -- PERFORMANCE: Rotate every 3 minutes instead of 1 minute
            local count = 0
            local maxPerCycle = 10 -- PERFORMANCE: Limit processing per cycle
            for gui, _ in pairs(OurScriptGUIs) do
                if count >= maxPerCycle then break end
                pcall(function()
                    if gui and gui.Parent then
                        gui.Name = getRandomStealthName()
                        count = count + 1
                    else
                        -- PERFORMANCE: Clean up dead references
                        OurScriptGUIs[gui] = nil
                        ProtectedGUIs[gui] = nil
                        AlreadyProtectedGUIs[gui] = nil
                    end
                end)
            end
            -- PERFORMANCE: Force garbage collection occasionally
            if count > 0 then
                pcall(function() collectgarbage("step", 100) end)
            end
        end
    end)
end

-- Initialize cloaking system
setupInstanceCloaking()
startNameRotation()

-- Expose for use throughout script
_G.protectGUI = protectGUI
_G.protectInstance = protectInstance
_G.createProtectedScreenGui = createProtectedScreenGui
_G.getRandomStealthName = getRandomStealthName
_G.getRandomInstanceName = getRandomInstanceName
_G.getRandomChildName = getRandomChildName
_G.isStealthName = isStealthName
_G.cloakInstance = cloakInstance
_G.uncloakInstance = uncloakInstance
_G.ProtectedGUIs = ProtectedGUIs
_G.ProtectedInstances = ProtectedInstances
_G.CloakedInstances = CloakedInstances

-- ===== ESP PROTECTION SYSTEM =====
-- Automatically protects Highlights and BillboardGuis created by this script
-- Call this function after creating any ESP visual to protect it from detection

local ESPProtectedInstances = setmetatable({}, { __mode = "k" }) -- Weak keys for GC

local function protectESP(instance)
    if not instance then return end
    if ESPProtectedInstances[instance] then return end -- Already protected
    
    pcall(function()
        -- Add to protection tables (makes it invisible to GetChildren/GetDescendants scans)
        ProtectedInstances[instance] = true
        CloakedInstances[instance] = true
        ESPProtectedInstances[instance] = true
        
        -- Also protect all descendants
        for _, desc in ipairs(instance:GetDescendants()) do
            ProtectedInstances[desc] = true
            CloakedInstances[desc] = true
            ESPProtectedInstances[desc] = true
        end
    end)
end

-- Scan and protect all ESP instances in a table
local function protectESPData(espDataTable)
    if not espDataTable then return end
    for _, data in pairs(espDataTable) do
        if data then
            if data.highlight then protectESP(data.highlight) end
            if data.billboard then protectESP(data.billboard) end
            if data.dot then protectESP(data.dot) end
        end
    end
end

-- Periodic ESP protection scanner
-- Scans for our ESP visuals and ensures they're protected
local function startESPProtectionScanner()
    task.defer(function()
        task.wait(5) -- Initial delay
        while true do
            pcall(function()
                -- Protect any ESPData entries
                if ESPData then
                    for espType, typeData in pairs(ESPData) do
                        protectESPData(typeData)
                    end
                end
                
                -- Protect PlayerESPData
                if PlayerESPData then
                    for player, data in pairs(PlayerESPData) do
                        if data then
                            if data.Highlight then protectESP(data.Highlight) end
                            if data.Billboard then protectESP(data.Billboard) end
                        end
                    end
                end
                
                -- Protect active target visuals
                if activeHighlight then protectESP(activeHighlight) end
                if activeAimDot then protectESP(activeAimDot) end
                if activeAimDotPart then protectESP(activeAimDotPart) end
            end)
            
            task.wait(10) -- Scan every 10 seconds
        end
    end)
end

-- Start the ESP protection scanner
startESPProtectionScanner()

-- Expose protection functions
_G.protectESP = protectESP
_G.protectESPData = protectESPData
_G.ESPProtectedInstances = ESPProtectedInstances

-- ===== 2. KICK/BAN PREVENTION SYSTEM =====
-- Blocks attempts to kick or ban the player

local kickBlocked = 0
local banBlocked = 0

-- Block Player:Kick()
local oldKick = nil
pcall(function()
    if hookfunction and newcclosure then
        oldKick = hookfunction(Players.LocalPlayer.Kick, newcclosure(function(self, reason)
            kickBlocked = kickBlocked + 1
            if ANTIBAN_DEBUG then warn("[ANTI-BAN] Blocked kick attempt #" .. kickBlocked .. ": " .. tostring(reason or "No reason")) end
            return nil -- Block the kick
        end))
    end
end)

-- ===== 3. NAMECALL HOOK (ADVANCED PROTECTION) =====
-- Intercepts all method calls on Roblox instances

local blockedRemotes = {
    -- Anti-cheat remote names (very specific to avoid blocking game remotes)
    ["ReportPlayer"] = true,
    ["BanPlayer"] = true,
    ["KickPlayer"] = true,
    ["LogExploit"] = true,
    ["DetectedCheat"] = true,
    ["SecurityViolation"] = true,
    ["AnticheatReport"] = true,
    ["FlagPlayer"] = true,
    -- Removed generic names: Violation, Report, Ban, Kick, AdminLog, etc.
    -- These are too aggressive and block legitimate game functionality
}

-- Patterns to detect admin logging remotes (partial match)
-- NOTE: Removed 'log', 'mod', 'ban', 'kick' - too aggressive, blocks game remotes
local adminLogPatterns = {
    "anticheat", "cheatdetect", "exploitlog", "securityviolation"
}

local function isAdminLogRemote(remoteName)
    if not remoteName or remoteName == "" then return false end
    local lower = remoteName:lower()
    for _, pattern in ipairs(adminLogPatterns) do
        if lower:find(pattern) then
            return true
        end
    end
    return false
end

local suspiciousArgs = {
    "exploit",
    "cheat",
    "hack",
    -- Removed: "speed" - blocks legitimate game tool remotes
    -- Removed: "teleport" - could block game mechanics
    "noclip",
    "aimbot",
    -- Removed: "esp" - our script uses this legitimately
    "godmode",
    "inject",
    "executor",
}

local function containsSuspiciousArg(args)
    for _, arg in pairs(args) do
        if type(arg) == "string" then
            local lowerArg = arg:lower()
            for _, suspicious in ipairs(suspiciousArgs) do
                if lowerArg:find(suspicious) then
                    return true, suspicious
                end
            end
        end
    end
    return false
end

local oldNamecall
local namecallInHook = false
local adminLogBlockCount = 0

if hookmetamethod and checkcaller and getnamecallmethod then
    pcall(function()
        oldNamecall = hookmetamethod(game, "__namecall", newcclosure and newcclosure(function(self, ...)
            if namecallInHook then
                return oldNamecall(self, ...)
            end
            
            local method = getnamecallmethod()
            local args = {...}
            
            -- Block Kick method
            if method == "Kick" and self == LocalPlayer then
                kickBlocked = kickBlocked + 1
                if ANTIBAN_DEBUG then warn("[ANTI-BAN] Blocked Kick via namecall #" .. kickBlocked) end
                return nil
            end
            
            -- Block suspicious remote calls (both from us and anti-cheat)
            if method == "FireServer" or method == "InvokeServer" then
                namecallInHook = true
                local remoteName = ""
                pcall(function() remoteName = self.Name end)
                namecallInHook = false
                
                -- Block known anti-cheat/admin log remotes (blocks OUTGOING too)
                if blockedRemotes[remoteName] then
                    banBlocked = banBlocked + 1
                    if ANTIBAN_DEBUG then warn("[ANTI-BAN] Blocked suspicious remote: " .. remoteName) end
                    return nil
                end
                
                -- Pattern-based admin log detection
                if isAdminLogRemote(remoteName) then
                    adminLogBlockCount = adminLogBlockCount + 1
                    if ANTIBAN_DEBUG then warn("[ANTI-BAN] Blocked admin log remote: " .. remoteName .. " (#" .. adminLogBlockCount .. ")") end
                    return nil
                end
                
                -- Check for suspicious arguments (only when not from us)
                if not checkcaller() then
                    local isSuspicious, keyword = containsSuspiciousArg(args)
                    if isSuspicious then
                        if ANTIBAN_DEBUG then warn("[ANTI-BAN] Blocked remote with suspicious arg: " .. keyword) end
                        return nil
                    end
                end
            end
            
            return oldNamecall(self, ...)
        end) or function(self, ...)
            if namecallInHook then
                return oldNamecall(self, ...)
            end
            
            local method = getnamecallmethod()
            
            if method == "Kick" and self == LocalPlayer then
                kickBlocked = kickBlocked + 1
                return nil
            end
            
            return oldNamecall(self, ...)
        end)
    end)
end

-- ===== 4. METATABLE INDEX HOOK (PROPERTY CLOAKING) =====
-- Hides modifications from anti-cheat property checks

local oldIndex
local indexInHook = false

-- Properties to emulate/hide
-- Use weak keys so destroyed instances get garbage collected
local emulatedProperties = {
    -- Character properties to hide
    WalkSpeed = setmetatable({}, { __mode = "k" }), -- [humanoid] = originalValue
    JumpPower = setmetatable({}, { __mode = "k" }),
    JumpHeight = setmetatable({}, { __mode = "k" }),
    HipHeight = setmetatable({}, { __mode = "k" }),
    -- Part properties
    Transparency = setmetatable({}, { __mode = "k" }),
    CanCollide = setmetatable({}, { __mode = "k" }),
    Size = setmetatable({}, { __mode = "k" }),
    Anchored = setmetatable({}, { __mode = "k" }),
}

-- Function to register a property for emulation (hide from anti-cheat)
local function emulateProperty(instance, property, fakeValue)
    if emulatedProperties[property] then
        emulatedProperties[property][instance] = fakeValue
    end
end

local function getEmulatedValue(instance, property)
    if emulatedProperties[property] and emulatedProperties[property][instance] ~= nil then
        return true, emulatedProperties[property][instance]
    end
    return false, nil
end

if hookmetamethod and checkcaller then
    pcall(function()
        oldIndex = hookmetamethod(game, "__index", newcclosure and newcclosure(function(self, key)
            if indexInHook then
                return oldIndex(self, key)
            end
            
            if not checkcaller() then
                indexInHook = true
                
                -- Hide our GUI
                if key == "Name" then
                    local success, name = pcall(function()
                        return oldIndex(self, "Name")
                    end)
                    if success and name == "RobloxSystemUI" then
                        indexInHook = false
                        return "RobloxGui"
                    end
                end
                
                -- Return emulated property values to fool anti-cheat
                local hasEmulated, emulatedValue = getEmulatedValue(self, key)
                if hasEmulated then
                    indexInHook = false
                    return emulatedValue
                end
                
                indexInHook = false
            end
            
            return oldIndex(self, key)
        end) or function(self, key)
            if indexInHook then
                return oldIndex(self, key)
            end
            
            if not checkcaller() then
                indexInHook = true
                if key == "Name" then
                    local success, name = pcall(function()
                        return oldIndex(self, "Name")
                    end)
                    if success and name == "RobloxSystemUI" then
                        indexInHook = false
                        return "RobloxGui"
                    end
                end
                indexInHook = false
            end
            
            return oldIndex(self, key)
        end)
    end)
else
    if ANTIBAN_DEBUG then warn("[ANTI-BAN] hookmetamethod not available, skipping metatable cloaking") end
end

-- ===== 5. NEWINDEX HOOK (DETECT PROPERTY CHANGES) =====
-- Can intercept when anti-cheat tries to modify our properties

local oldNewIndex
local newIndexInHook = false

if hookmetamethod and checkcaller then
    pcall(function()
        oldNewIndex = hookmetamethod(game, "__newindex", newcclosure and newcclosure(function(self, key, value)
            if newIndexInHook then
                return oldNewIndex(self, key, value)
            end
            
            if not checkcaller() then
                newIndexInHook = true
                
                -- Protect our character from forced resets
                local char = LocalPlayer.Character
                if char and self:IsDescendantOf(char) then
                    -- Block attempts to set WalkSpeed to 0 (anti-cheat punishment)
                    if key == "WalkSpeed" and value == 0 then
                        if ANTIBAN_DEBUG then warn("[ANTI-BAN] Blocked WalkSpeed = 0 attempt") end
                        newIndexInHook = false
                        return nil
                    end
                    -- Block attempts to anchor our character
                    if key == "Anchored" and value == true then
                        if ANTIBAN_DEBUG then warn("[ANTI-BAN] Blocked Anchored = true attempt") end
                        newIndexInHook = false
                        return nil
                    end
                end
                
                newIndexInHook = false
            end
            
            return oldNewIndex(self, key, value)
        end) or function(self, key, value)
            return oldNewIndex(self, key, value)
        end)
    end)
end

-- ===== 6. ADVANCED PROPERTY EMULATOR (IF SUPPORTED) =====
-- Uses AddGetHook/AddSetHook/AddPropertyEmulator if available

if ExecutorCapabilities.hasAddPropertyEmulator then
    pcall(function()
        -- Emulate WalkSpeed to always return 16 to anti-cheat
        AddPropertyEmulator("Humanoid", "WalkSpeed", function(self)
            -- Return the "normal" value to fool anti-cheat
            return 16
        end)
        
        -- Emulate JumpPower
        AddPropertyEmulator("Humanoid", "JumpPower", function(self)
            return 50
        end)
        
        if ANTIBAN_DEBUG then warn("[ANTI-BAN] Property Emulator active for Humanoid") end
    end)
end

if ExecutorCapabilities.hasAddGetHook then
    pcall(function()
        -- Hook property reads
        AddGetHook("Humanoid", "WalkSpeed", function(self, originalValue)
            if not checkcaller() then
                return 16 -- Return normal value to anti-cheat
            end
            return originalValue
        end)
        
        if ANTIBAN_DEBUG then warn("[ANTI-BAN] Get Hook active for Humanoid.WalkSpeed") end
    end)
end

if ExecutorCapabilities.hasAddSetHook then
    pcall(function()
        -- Hook property writes
        AddSetHook("Humanoid", "WalkSpeed", function(self, value)
            -- Allow our script to set, but log anti-cheat attempts
            if not checkcaller() and value == 0 then
                if ANTIBAN_DEBUG then warn("[ANTI-BAN] Blocked external WalkSpeed = 0") end
                return false -- Block the set
            end
            return true -- Allow the set
        end)
        
        if ANTIBAN_DEBUG then warn("[ANTI-BAN] Set Hook active for Humanoid.WalkSpeed") end
    end)
end

-- ===== 7. CONNECTION CLEANER (DISABLE ANTI-CHEAT LISTENERS) =====
-- Removes anti-cheat event connections

local function cleanAntiCheatConnections()
    if not getconnections then return end
    
    local cleaned = 0
    
    pcall(function()
        -- Clean RenderStepped connections (often used for speed checks)
        for _, conn in pairs(getconnections(RunService.RenderStepped)) do
            if conn.Function then
                local info = debug.getinfo and debug.getinfo(conn.Function)
                -- Disable connections from suspicious sources
                pcall(function()
                    local src = info and info.source or ""
                    if src:find("anticheat") or src:find("security") or src:find("detection") then
                        conn:Disable()
                        cleaned = cleaned + 1
                    end
                end)
            end
        end
        
        -- Clean Heartbeat connections
        for _, conn in pairs(getconnections(RunService.Heartbeat)) do
            pcall(function()
                if conn.Function then
                    local info = debug.getinfo and debug.getinfo(conn.Function)
                    local src = info and info.source or ""
                    if src:find("anticheat") or src:find("security") then
                        conn:Disable()
                        cleaned = cleaned + 1
                    end
                end
            end)
        end
    end)
    
    if cleaned > 0 and ANTIBAN_DEBUG then
        warn("[ANTI-BAN] Cleaned " .. cleaned .. " suspicious connections")
    end
end

-- Run connection cleaner periodically
-- PERFORMANCE: Reduced frequency to minimize overhead
task.defer(function()
    task.wait(10) -- Initial delay to let game load
    cleanAntiCheatConnections() -- Run once at start
    while true do
        task.wait(120) -- PERFORMANCE: Check every 2 minutes instead of 30 seconds
        cleanAntiCheatConnections()
        -- PERFORMANCE: Trigger garbage collection after cleanup
        pcall(function() collectgarbage("step", 200) end)
    end
end)

-- ===== 8. REMOTE SPY BLOCKER =====
-- Blocks anti-cheat from spying on our remote calls

local originalFireServer
local originalInvokeServer

pcall(function()
    if hookfunction and newcclosure then
        local RemoteEvent = Instance.new("RemoteEvent")
        local RemoteFunction = Instance.new("RemoteFunction")
        
        originalFireServer = hookfunction(RemoteEvent.FireServer, newcclosure(function(self, ...)
            -- Our calls go through, but we can filter here
            return originalFireServer(self, ...)
        end))
        
        originalInvokeServer = hookfunction(RemoteFunction.InvokeServer, newcclosure(function(self, ...)
            return originalInvokeServer(self, ...)
        end))
        
        RemoteEvent:Destroy()
        RemoteFunction:Destroy()
    end
end)

-- ===== 9. SAFE REMOTE WRAPPERS + ADMIN LOG BYPASS =====
-- Protected remote calls that bypass monitoring and admin logs

do
    local protectedRemotes = setmetatable({}, { __mode = "k" })
    local CALL_RANDOMIZE = true -- Add micro-random delays to avoid pattern detection
    local CALL_MIN_DELAY = 0.005 -- 5ms minimum (very fast)
    local CALL_MAX_DELAY = 0.015 -- 15ms maximum (still fast)
    
    -- Completely hidden remote call - uses hooked path if available
    local function safeFireServer(remote, ...)
        if not remote then return end
        local args = {...}
        
        -- Micro-random delay (5-15ms) - fast but breaks pattern detection
        if CALL_RANDOMIZE then
            local delay = CALL_MIN_DELAY + (math.random() * (CALL_MAX_DELAY - CALL_MIN_DELAY))
            if delay > 0 then
                task.wait(delay)
            end
        end
        
        -- Use hooked FireServer (goes through our namecall hook, appears as normal game traffic)
        -- If originalFireServer exists, use it directly for maximum stealth
        local success, result = pcall(function()
            if originalFireServer then
                -- Direct path through hooked metatable - completely hidden from remote spy
                return originalFireServer(remote, unpack(args))
            else
                -- Fallback to normal FireServer (still goes through our namecall hook)
                return remote:FireServer(unpack(args))
            end
        end)
        return result
    end
    
    local function safeInvokeServer(remote, ...)
        if not remote then return nil end
        local args = {...}
        
        -- Add tiny random delay
        local delay = getRandomDelay()
        if delay > 0 then
            task.wait(delay)
        end
        
        local success, result = pcall(function()
            if originalInvokeServer then
                return originalInvokeServer(remote, unpack(args))
            else
                return remote:InvokeServer(unpack(args))
            end
        end)
        return success and result or nil
    end
    
    local function markRemoteProtected(remote)
        if remote then
            protectedRemotes[remote] = true
        end
    end
    
    -- Expose settings for advanced users
    _G.SafeFireServer = safeFireServer
    _G.SafeInvokeServer = safeInvokeServer
    _G.MarkRemoteProtected = markRemoteProtected
    _G.RemoteProtectionEnabled = true
    _G.AdminLogBypass = {
        enabled = true,
        randomizeDelay = CALL_RANDOMIZE,
        setRandomize = function(v) CALL_RANDOMIZE = v end,
        rateLimit = CALL_RATE_LIMIT,
        setRateLimit = function(v) CALL_RATE_LIMIT = v end,
    }
    _G.EmulateProperty = emulateProperty -- Expose for other parts of script
end

-- ===== 10. ADMIN LOG INTERCEPT (Advanced) =====
-- Attempts to intercept admin panel remote calls

do
    local adminRemoteNames = {
        "AdminLog", "LogAction", "AdminPanel", "ModeratorLog", 
        "ServerLog", "ActionLog", "PlayerLog", "ReportLog",
        "BanLog", "KickLog", "AdminAction", "ModAction",
        "LogEvent", "EventLog", "SecurityLog", "CheatLog",
        "AntiCheat", "Detection", "Report", "Flag"
    }
    
    -- Check if a remote might be an admin logging remote
    local function isAdminRemote(remoteName)
        if not remoteName then return false end
        local lower = string.lower(remoteName)
        for _, name in ipairs(adminRemoteNames) do
            if lower:find(string.lower(name)) then
                return true
            end
        end
        return false
    end
    
    -- Block admin remotes from receiving our data (if we have namecall hook)
    if oldNamecall and not namecallInHook then
        -- Already handled in section 3, but we add extra check
    end
    
    -- Scan for and attempt to disable admin logging remotes
    local function scanAndDisableAdminRemotes()
        local count = 0
        pcall(function()
            local rs = game:GetService("ReplicatedStorage")
            for _, child in ipairs(rs:GetDescendants()) do
                if (child:IsA("RemoteEvent") or child:IsA("RemoteFunction")) then
                    if isAdminRemote(child.Name) then
                        -- Mark as protected so our hooks block calls to it
                        if _G.MarkRemoteProtected then
                            _G.MarkRemoteProtected(child)
                        end
                        count = count + 1
                    end
                end
            end
        end)
        return count
    end
    
    -- Run scan periodically
    task.defer(function()
        task.wait(2)
        local found = scanAndDisableAdminRemotes()
        if ANTIBAN_DEBUG and found > 0 then
            warn("[ANTI-BAN] Found and protected " .. found .. " potential admin remotes")
        end
        
        -- Rescan periodically in case new ones are added
        while true do
            task.wait(30)
            scanAndDisableAdminRemotes()
        end
    end)
end

-- ===== 11. ANTI-DETECTION STATUS =====
_G.AntiBan = true
_G.AntiBanVersion = "2.2"
_G.ExecutorCapabilities = ExecutorCapabilities
_G.AntiBanStats = {
    getKickBlocked = function() return kickBlocked end,
    getBanBlocked = function() return banBlocked end,
    getAdminLogBlocked = function() return adminLogBlockCount end,
}

-- ===== 12. ENHANCED BYPASS SYSTEM (Integrated from bypass clean.lua) =====
-- Advanced property spoofing and connection disabling

pcall(function()
    local Character = LocalPlayer.Character
    if not Character then return end
    local Humanoid = Character:FindFirstChildOfClass("Humanoid")
    if not Humanoid then return end
    local HumanoidRootPart = Character:FindFirstChild("HumanoidRootPart")
    
    -- Store original values for spoofing
    local OriginalWalkSpeed = Humanoid.WalkSpeed
    local OriginalJumpPower = Humanoid.JumpPower
    local OriginalHealth = Humanoid.Health
    local OriginalMaxHealth = Humanoid.MaxHealth
    local OriginalHipHeight = Humanoid.HipHeight
    local OriginalGravity = workspace.Gravity
    local OriginalVelocity = HumanoidRootPart and HumanoidRootPart.Velocity or Vector3.new(0,0,0)
    local OriginalSize = HumanoidRootPart and HumanoidRootPart.Size or Vector3.new(2,2,1)
    
    -- Advanced hooks using AddSetHook/AddPropertyEmulator if available
    -- NOTE: WalkSpeed NOT hooked - allows game to slow player during reload
    -- NOTE: Health NOT hooked - allows healing from surgeon kit
    if ExecutorCapabilities.hasAddSetHook then
        -- Only hook properties that anti-cheat checks but game doesn't need to modify
        pcall(function() Humanoid:AddSetHook("MaxSlopeAngle") end)
        -- Don't hook CFrame/Velocity - can break game physics
    end
    
    -- Property emulators - only for properties that don't need to change for gameplay
    -- NOTE: Health/WalkSpeed NOT emulated - need real values for gameplay mechanics
    if ExecutorCapabilities.hasAddPropertyEmulator then
        pcall(function() Humanoid:AddPropertyEmulator("HipHeight") end)
    end
    
    -- Global Get Hooks - minimal set to avoid breaking game mechanics
    -- NOTE: Most hooks removed - they were breaking reload slowdown and healing
    if ExecutorCapabilities.hasAddGetHook then
        pcall(function() game:AddGlobalGetHook("HipHeight", OriginalHipHeight) end)
    end
    
    -- Global Set Hooks - minimal set, removed WalkSpeed/Health/JumpPower to allow game mechanics
    pcall(function()
        if game.AddGlobalSetHook then
            game:AddGlobalSetHook("HipHeight")
            game:AddGlobalSetHook("MaxSlopeAngle")
        end
    end)
    
    -- Block Kick calls
    pcall(function()
        if game.AddGlobalCallHook then
            game:AddGlobalCallHook("Kick", function() end)
        end
        if Character and Character.AddCallHook then
            Character:AddCallHook("BreakJoints", function() return end)
        end
        if LocalPlayer.AddCallHook then
            LocalPlayer:AddCallHook("Kick", function() return task.wait(9e9) end)
        end
    end)
    
    -- Disable anti-cheat event connections
    pcall(function()
        if getconnections then
            -- Disable ItemChanged connections
            for _, conn in next, getconnections(game.ItemChanged) do
                pcall(function() conn:Disable() end)
            end
            -- NOTE: NOT disabling Humanoid.Changed - it blocks healing from surgeon kit
            -- Disable LogService.MessageOut connections
            pcall(function()
                for _, conn in next, getconnections(game:GetService("LogService").MessageOut) do
                    conn:Disable()
                end
            end)
            -- Disable ScriptContext.Error connections
            pcall(function()
                for _, conn in next, getconnections(game:GetService("ScriptContext").Error) do
                    conn:Disable()
                end
            end)
        end
    end)
    
    -- Set HttpService timeout (helps with anti-cheat that uses HTTP)
    pcall(function()
        game:GetService("HttpService"):SetTimeout(0.05)
    end)
    
    if ANTIBAN_DEBUG then
        warn("[ANTI-BAN] Enhanced bypass system initialized")
    end
end)

-- Re-apply on respawn
LocalPlayer.CharacterAdded:Connect(function(newChar)
    task.wait(0.5)
    pcall(function()
        local Humanoid = newChar:WaitForChild("Humanoid", 5)
        local HumanoidRootPart = newChar:WaitForChild("HumanoidRootPart", 5)
        if not Humanoid or not HumanoidRootPart then return end
        
        -- NOTE: Not hooking WalkSpeed/JumpPower - allows reload slowdown and game mechanics
        if ExecutorCapabilities.hasAddSetHook then
            pcall(function() Humanoid:AddSetHook("MaxSlopeAngle") end)
        end
        
        -- NOTE: Not emulating WalkSpeed/JumpPower - need real values
        if ExecutorCapabilities.hasAddPropertyEmulator then
            pcall(function() Humanoid:AddPropertyEmulator("HipHeight") end)
        end
        
        -- NOTE: NOT disabling Humanoid.Changed - it blocks healing from surgeon kit
        
        -- Block BreakJoints
        if newChar.AddCallHook then
            pcall(function() newChar:AddCallHook("BreakJoints", function() return end) end)
        end
    end)
end)

-- Section 13 REMOVED: Full bypass clean integration was causing FPS drops and breaking game mechanics
-- The metatable hooks intercept every single property access causing massive overhead
-- Sections 1-12 already provide sufficient protection without the performance cost

end
-- ===== END ADVANCED BYPASS ANTI-CHEAT =====

-- ===== PERFORMANCE OPTIMIZATION SYSTEM =====
-- Tracks feature activity and disables dormant features
-- Includes Low-End Device Mode for mobile/weak devices
do
    local DORMANT_TIMEOUT = 60 -- seconds before a feature goes dormant
    local FRAME_SKIP_LIGHT = 2 -- skip every N frames for light features
    local FRAME_SKIP_HEAVY = 5 -- skip every N frames for heavy features (ESP, etc.)
    
    -- LOW-END MODE ALWAYS ENABLED (hardcoded for performance)
    local isLowEndDevice = true -- Always enabled for better performance
    
    -- Feature activity tracking
    _G.KatchiPerf = {
        -- Timestamps of last activity for each feature
        lastActivity = {},
        -- Whether each feature is currently active (not dormant)
        isActive = {},
        -- Frame counters for throttling
        frameCounters = {},
        -- Global frame counter
        globalFrame = 0,
        -- Low-end device mode (always enabled)
        lowEndMode = true,
        -- Multiplier for frame skipping (always use aggressive throttling)
        lowEndMultiplier = 3,
    }
    
    -- Toggle low-end mode
    function _G.KatchiPerf.setLowEndMode(enabled)
        _G.KatchiPerf.lowEndMode = enabled
        if enabled then
            _G.KatchiPerf.lowEndMultiplier = 3 -- More aggressive throttling
        else
            _G.KatchiPerf.lowEndMultiplier = 1
        end
    end
    
    -- Get effective skip count based on device mode
    function _G.KatchiPerf.getSkipCount(baseSkip)
        if _G.KatchiPerf.lowEndMode then
            return math.floor(baseSkip * _G.KatchiPerf.lowEndMultiplier)
        end
        return baseSkip
    end
    
    -- Mark a feature as active (call when toggle is enabled or used)
    function _G.KatchiPerf.markActive(featureName)
        _G.KatchiPerf.lastActivity[featureName] = tick()
        _G.KatchiPerf.isActive[featureName] = true
    end
    
    -- Check if a feature should run (returns false if dormant)
    function _G.KatchiPerf.shouldRun(featureName)
        local lastTime = _G.KatchiPerf.lastActivity[featureName]
        if not lastTime then return false end
        if tick() - lastTime > DORMANT_TIMEOUT then
            _G.KatchiPerf.isActive[featureName] = false
            return false
        end
        return true
    end
    
    -- Throttle check - returns true if this frame should process
    function _G.KatchiPerf.shouldProcess(featureName, skipCount)
        skipCount = _G.KatchiPerf.getSkipCount(skipCount or FRAME_SKIP_LIGHT)
        _G.KatchiPerf.frameCounters[featureName] = (_G.KatchiPerf.frameCounters[featureName] or 0) + 1
        if _G.KatchiPerf.frameCounters[featureName] >= skipCount then
            _G.KatchiPerf.frameCounters[featureName] = 0
            return true
        end
        return false
    end
    
    -- Combined check: is active AND should process this frame
    function _G.KatchiPerf.canProcess(featureName, skipCount)
        if not _G.KatchiPerf.shouldRun(featureName) then return false end
        return _G.KatchiPerf.shouldProcess(featureName, skipCount)
    end
    
    -- Disable a feature (mark as dormant)
    function _G.KatchiPerf.disable(featureName)
        _G.KatchiPerf.isActive[featureName] = false
        _G.KatchiPerf.lastActivity[featureName] = nil
    end
    
    -- Constants for feature names (avoid typos)
    _G.KatchiPerf.FEATURES = {
        ESP = "ESP",
        KILL_AURA = "KillAura",
        SILENT_AIM = "SilentAim",
        AUTO_SHOOT = "AutoShoot",
        AUTO_SAVE = "AutoSavePlayers",
        FOV_CIRCLE = "FovCircle",
        AIM_DOT = "AimDot",
        ANTI_GRAB = "AntiGrab",
        SHOVE_AURA = "ShoveAura",
        AUTO_BLESS = "AutoBless",
        AUTO_PARRY = "AutoParry",
        FLY = "Fly",
        HEADLESS = "Headless",
        DRACULA = "Dracula",
        BOMBER_VIS = "BomberVis",
    }
    
    -- ===== PERIODIC GARBAGE COLLECTION =====
    -- PERFORMANCE: Run garbage collection periodically to prevent memory buildup
    task.defer(function()
        task.wait(30) -- Initial delay
        while true do
            -- Run incremental garbage collection
            pcall(function()
                collectgarbage("step", 200)
            end)
            task.wait(60) -- Run every 60 seconds
        end
    end)
    
end
-- ===== END PERFORMANCE OPTIMIZATION SYSTEM =====

--[[
    Katchi Hub - Guts & BlackPowder
    Made by Yuki
    Professional WindUI Version
]]--

-- // Shared services (for all sections)
local Players = game:GetService("Players")
local TweenService = game:GetService("TweenService")
local Lighting = game:GetService("Lighting")
local RunService = game:GetService("RunService")
local UserInputService = game:GetService("UserInputService") 
local HttpService = game:GetService("HttpService")
local MarketplaceService = game:GetService("MarketplaceService")
local Workspace = game:GetService("Workspace")
local TeleportService = game:GetService("TeleportService")
local CollectionService = game:GetService("CollectionService")
local ReplicatedStorage = game:GetService("ReplicatedStorage")

local LocalPlayer = Players.LocalPlayer

do -- // Loader + UI + Dashboard
    local WindUI
    local windSuccess, windError = pcall(function()
        WindUI = loadstring(game:HttpGet("https://github.com/Footagesus/WindUI/releases/latest/download/main.lua"))()
    end)
    
    if not windSuccess or not WindUI then
        warn("[Katchi Hub] Failed to load WindUI: " .. tostring(windError or "WindUI returned nil"))
        return
    end
    
    WindUI:SetNotificationLower(true)

-- after: local WindUI = loadstring(game:HttpGet(...))()
-- add this block below that line, before you call WindUI:CreateWindow({...})

-- ===== platoboost service for WindUI KeySystem (with optional MasterKey) =====
do
    local HttpService = game:GetService("HttpService")
    local Players = game:GetService("Players")
    local LocalPlayer = Players.LocalPlayer
    local setClipboard = setclipboard or toclipboard
    local requestFunc = (syn and syn.request) or (http and http.request) or request or http_request

    local function safeRequest(opts)
        if not requestFunc then
            return nil, "HTTP request not supported by executor"
        end
        local ok, res = pcall(function() return requestFunc(opts) end)
        if not ok then return nil, "request failed: " .. tostring(res) end
        if typeof(res) ~= "table" then return nil, "invalid response type" end
        return res
    end

    local function digest(input)
        local s = tostring(input)
        local out = ""
        for i = 1, #s do out = out .. string.format("%02x", string.byte(s, i)) end
        return out
    end

    local function getHwid()
        local ok, id = pcall(function() return tostring(LocalPlayer.UserId) end)
        return (ok and id) and id or "unknown"
    end

    WindUI.Services = WindUI.Services or {}
    -- Note Args now include MasterKey (optional)
    WindUI.Services.platoboost = {
        Name = "Platoboost",
        Icon = "cloud",
        Args = { "ServiceId", "Secret", "MasterKey" }, -- MasterKey is optional
        New = function(ServiceId, Secret, MasterKey)
            local apiHost = "https://api.platoboost.app"
            local cachedLink, cachedTime = "", 0

            local function cacheLink()
                if (cachedTime + 600) > os.time() and cachedLink ~= "" then
                    return true, cachedLink
                end

                local body = HttpService:JSONEncode({ service = tonumber(ServiceId) or ServiceId, identifier = digest(getHwid()) })
                local res, err = safeRequest({
                    Url = apiHost .. "/public/start",
                    Method = "POST",
                    Headers = { ["Content-Type"] = "application/json" },
                    Body = body
                })
                if not res then return false, err end
                if res.StatusCode == 200 then
                    local ok, decoded = pcall(function() return HttpService:JSONDecode(res.Body) end)
                    if ok and decoded and decoded.success and decoded.data and decoded.data.url then
                        cachedLink = decoded.data.url
                        cachedTime = os.time()
                        return true, cachedLink
                    else
                        return false, (decoded and decoded.message) or "invalid start response"
                    end
                elseif res.StatusCode == 429 then
                    return false, "rate limited"
                end
                return false, "failed to get link"
            end

            local function Copy()
                local ok, link = cacheLink()
                if ok and link then
                    pcall(setClipboard, link)
                    return true, link
                end
                return false, link
            end

            local function generateNonce()
                local chars = "abcdefghijklmnopqrstuvwxyz0123456789"
                local out = ""
                for i = 1, 16 do
                    local idx = math.random(1, #chars)
                    out = out .. chars:sub(idx, idx)
                end
                return out
            end

            local function Verify(key)
                if not key or key == "" then return false, "empty key" end

                -- 1) MasterKey bypass: if MasterKey exists and matches exactly, accept immediately
                if MasterKey and tostring(key) == tostring(MasterKey) then
                    return true, { master = true, message = "Master key accepted" }
                end

                -- 2) Otherwise perform platoboost verification
                local nonce = generateNonce()
                local identifier = digest(getHwid())

                local endpoint = apiHost .. "/public/whitelist/" .. tostring(ServiceId)
                endpoint = endpoint .. "?identifier=" .. identifier .. "&key=" .. tostring(key)
                endpoint = endpoint .. "&nonce=" .. nonce

                local res, err = safeRequest({ Url = endpoint, Method = "GET" })
                if not res then return false, err end
                if res.StatusCode == 200 then
                    local ok, decoded = pcall(function() return HttpService:JSONDecode(res.Body) end)
                    if ok and decoded and decoded.success and decoded.data then
                        if decoded.data.hash and decoded.data.value and Secret then
                            local expected = digest(tostring(decoded.data.value) .. "-" .. nonce .. "-" .. tostring(Secret))
                            if decoded.data.hash == expected then
                                return (decoded.data.valid == true), decoded
                            else
                                return false, "integrity verification failed"
                            end
                        end
                        return (decoded.data.valid == true), decoded
                    else
                        return false, (decoded and decoded.message) or "invalid verify response"
                    end
                elseif res.StatusCode == 429 then
                    return false, "rate limited"
                end
                return false, "invalid server response"
            end

            return {
                Verify = function(key)
                    local ok, a, b = pcall(function() return Verify(key) end)
                    if not ok then return false, "verify failed" end
                    if a == true then return true, b end
                    return false, b
                end,
                Copy = function()
                    local ok, a, b = pcall(function() return Copy() end)
                    if not ok then return false, "copy failed" end
                    if a then return true, b end
                    return false, b
                end
            }
        end
    }
end
-- ===== end platoboost service

    local function showQueueLoader()
        local blur = Instance.new("BlurEffect", Lighting)
        blur.Size = 0
        TweenService:Create(blur, TweenInfo.new(0.5), {Size = 24}):Play()

        local screenGui = Instance.new("ScreenGui")
        screenGui.ResetOnSpawn = false
        screenGui.IgnoreGuiInset = true
        -- Use full stealth protection
        if _G.protectGUI then _G.protectGUI(screenGui) else
            screenGui.Name = _G.getRandomStealthName and _G.getRandomStealthName() or ("TopBarApp_" .. math.random(10000, 99999))
            screenGui.Parent = LocalPlayer:WaitForChild("PlayerGui")
        end

        local frame = Instance.new("Frame", screenGui)
        frame.Size = UDim2.new(1, 0, 1, 0)
        frame.BackgroundTransparency = 1

        local bg = Instance.new("Frame", frame)
        bg.Size = UDim2.new(1, 0, 1, 0)
        bg.BackgroundColor3 = Color3.fromRGB(10, 10, 20)
        bg.BackgroundTransparency = 1
        bg.ZIndex = 0
        TweenService:Create(bg, TweenInfo.new(0.5), {BackgroundTransparency = 0.3}):Play()

        local word = "KATCHI HUB"
        local letters = {}

        local function tweenOutAndDestroy()
            for _, label in ipairs(letters) do
                TweenService:Create(label, TweenInfo.new(0.3), {TextTransparency = 1, TextSize = 30}):Play()
            end
            TweenService:Create(bg, TweenInfo.new(0.5), {BackgroundTransparency = 1}):Play()
            TweenService:Create(blur, TweenInfo.new(0.5), {Size = 0}):Play()
            wait(0.6)
            screenGui:Destroy()
            blur:Destroy()
        end

        for i = 1, #word do
            local char = word:sub(i, i)

            local label = Instance.new("TextLabel")
            label.Text = char
            label.Font = Enum.Font.GothamBlack
            label.TextColor3 = Color3.fromRGB(135, 0, 0)
            label.TextStrokeTransparency = 1 
            label.TextTransparency = 1
            label.TextScaled = false
            label.TextSize = 30 
            label.Size = UDim2.new(0, 60, 0, 60)
            label.AnchorPoint = Vector2.new(0.5, 0.5)
            label.Position = UDim2.new(0.5, (i - (#word / 2 + 0.5)) * 65, 0.5, 0)
            label.BackgroundTransparency = 1
            label.Parent = frame

            local tweenIn = TweenService:Create(label, TweenInfo.new(0.3), {TextTransparency = 0, TextSize = 60})
            tweenIn:Play()

            table.insert(letters, label)
            wait(0.25)
        end

        wait(2)
        tweenOutAndDestroy()
    end

    showQueueLoader()

local KATCHI_LOGO_URL = "https://raw.githubusercontent.com/katchilove81-png/dawdawdaw/refs/heads/main/1767175079960.png"

local Window = WindUI:CreateWindow({
    Title = "Katchi Hub",
    Author = "by Yuki",
    Folder = "KatchiHub/GutsBlackPowder",
    Transparent = true,
    HideSearchBar = false,
    ScrollBarEnabled = true,
    Theme = "Red",
    Icon = KATCHI_LOGO_URL,
    User = {
        Enabled = true,
        Anonymous = false,
        Callback = function() end,
    },
})

    -- Protect WindUI's ScreenGui from detection
    task.defer(function()
        task.wait(0.1) -- Wait for WindUI to create its GUI
        pcall(function()
            local stealthNames = {"RobloxGui", "CoreGui", "SystemGui", "PlayerListGui", "ChatWindow", "BackpackGui", "HealthGui", "TopBarApp", "SettingsHub", "InspectMenu"}
            local playerGui = LocalPlayer:FindFirstChild("PlayerGui")
            if playerGui then
                for _, child in ipairs(playerGui:GetChildren()) do
                    if child:IsA("ScreenGui") then
                        -- Rename any WindUI or Katchi-related GUIs to stealth names
                        local lowerName = child.Name:lower()
                        if lowerName:find("wind") or lowerName:find("katchi") or lowerName:find("hub") then
                            child.Name = stealthNames[math.random(1, #stealthNames)] .. "_" .. math.random(10000, 99999)
                        end
                    end
                end
            end
            -- Also check CoreGui if accessible
            pcall(function()
                local coreGui = game:GetService("CoreGui")
                for _, child in ipairs(coreGui:GetChildren()) do
                    if child:IsA("ScreenGui") then
                        local lowerName = child.Name:lower()
                        if lowerName:find("wind") or lowerName:find("katchi") or lowerName:find("hub") or lowerName:find("aimlock") then
                            child.Name = stealthNames[math.random(1, #stealthNames)] .. "_" .. math.random(10000, 99999)
                        end
                    end
                end
            end)
        end)
    end)

    -- Note: GUI protection is now handled automatically by the BYPASS ANTI-CHEAT system
    -- All new ScreenGuis are auto-protected when created

    Window:SetToggleKey(Enum.KeyCode.RightShift)

    local button = Window:EditOpenButton({
        Title = "Katchi Hub",
        Icon = KATCHI_LOGO_URL,
        Size = UDim2.new(0, 140, 0, 40),
        CornerRadius = UDim.new(0, 10),
        StrokeThickness = 3,
        Draggable = true,
    })

    -- Rounded corners
    local uicorner = Instance.new("UICorner")
    uicorner.CornerRadius = UDim.new(0, 10)
    uicorner.Parent = button

    -- Subtle background gradient for a premium look
    local bgGradient = Instance.new("UIGradient")
    bgGradient.Color = ColorSequence.new{
        ColorSequenceKeypoint.new(0, Color3.fromRGB(165, 28, 48)),
        ColorSequenceKeypoint.new(0.5, Color3.fromRGB(220, 90, 40)),
        ColorSequenceKeypoint.new(1, Color3.fromRGB(255, 180, 60)),
    }
    bgGradient.Rotation = 45
    bgGradient.Parent = button

    -- Stroke for contrast and slight glow effect
    local stroke = Instance.new("UIStroke")
    stroke.Thickness = 2.2
    stroke.ApplyStrokeMode = Enum.ApplyStrokeMode.Border
    stroke.Color = Color3.fromRGB(255, 245, 220)
    stroke.Transparency = 0.25
    stroke.Parent = button

    -- Animated rotation to give subtle life to the control (deferred)
    task.defer(function()
        task.wait(2) -- Wait for UI to settle
        while true do
            local tween = TweenService:Create(bgGradient, TweenInfo.new(6, Enum.EasingStyle.Linear, Enum.EasingDirection.InOut), {
                Rotation = bgGradient.Rotation + 360
            })
            tween:Play()
            tween.Completed:Wait()
            bgGradient.Rotation = bgGradient.Rotation % 360
        end
    end)

    Window:SetIconSize(48)
    Window:Tag({
        Title = "v4.3",
        Color = Color3.fromHex("#d9ff00") -- deep crimson
    })
    Window:Tag({
        Title = "Guts & BlackPowder",
        Color = Color3.fromHex("#d9ff00") -- gold accent
    })

    WindUI:Notify({
        Title = "Please Wait While Katchi Hub Loads",
        Content = "Usually takes 10-15 seconds",
        Duration = 5,
        Icon = "zap",
    })

    local DashboardTab = Window:Tab({ Title = "Dashboard", Icon = "layout-dashboard" })

    DashboardTab:Select() -- Select Tab

    local DiscordSection = DashboardTab:Section({
        Title = "Community",
        Icon = "users",
        Opened = true
    })

    local InfoSection = DashboardTab:Section({
        Title = "Information",
        Icon = "info",
        Opened = true
    })

    InfoSection:Paragraph({
        Title = "Katchi Hub v4.3",
        Desc = "Professional Guts & BlackPowder Script Hub\nMade by Yuki\nExecutor: "..(identifyexecutor and identifyexecutor() or "Unknown"),
    })

    InfoSection:Paragraph({
        Title = "Changelogs",
        Desc = "Features\n- Added Animation Presets!\n- Added Change Fov!\n- Added Infinite Zoom!\n\nFixes\n- Reduced Lag From Bypass\n- Fixed Minor Bugs",
    })

-- Make sure this exists somewhere near the top of your script
local HttpService = game:GetService("HttpService")

-- Discord constants
local discordInvite = "https://discord.gg/vBYZCGGyK6"
local widgetUrl = "https://discord.com/api/guilds/1433658537027833969/widget.json"
local TOTAL_MEMBERS = 652 -- manually keep this roughly updated

-- Main Discord card
local DiscordCard = DiscordSection:Paragraph({
    Title = "Katchi Hub | Balls 🔥",
    Desc  = "🟢 Loading online...\n⚪ " .. TOTAL_MEMBERS .. " Members\nEst. Oct 2025",

    -- WindUI supports remote URLs directly (same as their example)
    Image = "https://raw.githubusercontent.com/katchilove81-png/dawdawdaw/refs/heads/main/ChatGPT%20Image%20Dec%2017%2C%202025%2C%2005_54_46%20PM.png",
    ImageSize = 48,

    Buttons = {
        {
            Title = "Copy Invite",
            Icon = "link",
            Callback = function()
                setclipboard(discordInvite)
                WindUI:Notify({
                    Title = "Copied!",
                    Content = "Discord invite link has been copied to your clipboard.",
                    Duration = 3,
                    Icon = "copy",
                })
            end
        }
    }
})

-- Live online count updater
local function updateDiscordCard()
    local online = 0

    local ok, body = pcall(function()
        return game:HttpGet(widgetUrl)
    end)

    if ok and body then
        local okDecode, data = pcall(function()
            return HttpService:JSONDecode(body)
        end)

        if okDecode and type(data) == "table" then
            online = tonumber(data.presence_count) or 0
        end
    end

    local line1 = string.format("🟢 %d Online    ⚪ %d Members", online, TOTAL_MEMBERS)
    local line2 = "Est. Oct 2025"

    DiscordCard:SetDesc(line1 .. "\n" .. line2)
end

task.defer(function()
    task.wait(5) -- Wait for game to load first
    while true do
        updateDiscordCard()
        task.wait(60) -- Reduced frequency to every 60 seconds
    end
end)
end

local Main1Section = Window:Section({
    Title = "Main",
    Icon = "house",
    Opened = false,
})

local Esp1Section = Window:Section({
    Title = "Esp",
    Icon = "scan",
    Opened = false,
})

local Event1Section = Window:Section({
    Title = "Events",
    Icon = "sparkles",
    Opened = false,
})

local Others1Section = Window:Section({
    Title = "Others",
    Icon = "settings",
    Opened = false,
})

-- ===== GLOBAL TOGGLE REGISTRY FOR KEYBINDS =====
-- This table stores references to toggle elements and their state variables
_G.KatchiToggles = _G.KatchiToggles or {}

-- Define MainTab at outer scope so it's accessible to all sub-sections
local MainTab = Main1Section:Tab({ Title = "Main", Icon = "shield-check" })

task.wait(0.1) -- Delay to prevent lag
do -- // Main Tab

local enabled = true

-- Modules (Bayonet / Melee override, safe non-blocking require)
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local Modules = ReplicatedStorage:FindFirstChild("Modules") or nil

-- safe helper that returns status: "absent" | "failed" | "ok"
local function safeRequire(moduleInstance)
    if not moduleInstance then
        return "absent", "module not present"
    end
    local ok, res = pcall(function() return require(moduleInstance) end)
    if not ok then
        return "failed", res -- require attempted and errored
    end
    return "ok", res -- require succeeded
end

-- DEFAULT NO-OPS / STUBS so code doesn't error if modules missing
local function noop() end
local function noop_change(value) end

local changeBayonet = noop_change
local changeMelee = noop_change

-- DebugVisualizer stub (safe no-op interface)
local DebugVisualizerStub = {
    CastSphere = function(...) end,
    CastLine = function(...) end,
}

-- Track presence vs require-failure vs success
local FlintLockPresent, FlintLockRequireFailed, FlintLockSuccess, FlintLock = false, false, false, nil
local MeleeBasePresent, MeleeBaseRequireFailed, MeleeBaseSuccess, MeleeBase = false, false, false, nil

-- Attempt to find & require modules without yielding (don't lock on missing)
local weaponsFolder = Modules and Modules:FindFirstChild("Weapons")
local flintModInstance = weaponsFolder and weaponsFolder:FindFirstChild("Flintlock")
if flintModInstance then
    FlintLockPresent = true
    local status, res = safeRequire(flintModInstance)
    if status == "ok" then
        FlintLockSuccess = true
        FlintLock = res

        local originBayonet = FlintLock.BayonetHitCheck

        local v_u_1 = {}
        v_u_1.__index = v_u_1

        function v_u_1.BayonetHitCheck(p115, p116, p117, p118, p119)
            local v120 = workspace:Raycast(p116, p117, p118)
            if v120 then
                -- Support both m_Zombie and ZombieLike tagged entities
                local isZombie = v120.Instance.Parent.Name == "m_Zombie" or v120.Instance.Parent:HasTag("ZombieLike")
                if isZombie then
                    local v121 = p118.FilterDescendantsInstances
                    local v122 = v120.Instance
                    table.insert(v121, v122)
                    p118.FilterDescendantsInstances = v121
                    local v123 = v120.Instance.Parent:FindFirstChild("Orig")
                    if v123 then
                        -- Find head part (check direct children and nested models)
                        local Head = nil
                        for i, part in pairs(v120.Instance.Parent:GetDescendants()) do
                            if part.Name == "Head" and (part:IsA("BasePart")) then
                                Head = part
                                break
                            end
                        end
                        
                        if Head and v123.Value then
                            -- Gib effect for head hits
                            if shared.Gib ~= nil then
                                local zombieHum = v123.Value:FindFirstChild("Zombie")
                                if zombieHum then
                                    shared.Gib(v123.Value, "Head", Head.CFrame.Position, v120.Normal, true)
                                end
                            end
                            
                            _G.SafeFireServer(p115.remoteEvent, "Bayonet_HitZombie", v123.Value, Head.CFrame.Position, true, "Head")
                            local v_u_124 = v123.Value
                            local v_u_125 = tick()
                            v_u_124:SetAttribute("WepHitID", tick())
                            v_u_124:SetAttribute("WepHitDirection", p117 * 10)
                            v_u_124:SetAttribute("WepHitPos", Head.CFrame.Position) -- Use head position
                            task.delay(0.2, function()
                                if v_u_124:GetAttribute("WepHitID") == v_u_125 then
                                    v_u_124:SetAttribute("WepHitDirection", nil)
                                    v_u_124:SetAttribute("WepHitPos", nil)
                                    v_u_124:SetAttribute("WepHitID", nil)
                                end
                            end)
                        elseif v123.Value then
                            -- Fallback: Head not found, use original hit behavior
                            _G.SafeFireServer(p115.remoteEvent, "Bayonet_HitZombie", v123.Value, v120.Position, v120.Instance.Name == "Head", v120.Instance.Name)
                            local v_u_124 = v123.Value
                            local v_u_125 = tick()
                            v_u_124:SetAttribute("WepHitID", tick())
                            v_u_124:SetAttribute("WepHitDirection", p117 * 10)
                            v_u_124:SetAttribute("WepHitPos", v120.Position)
                            task.delay(0.2, function()
                                if v_u_124:GetAttribute("WepHitID") == v_u_125 then
                                    v_u_124:SetAttribute("WepHitDirection", nil)
                                    v_u_124:SetAttribute("WepHitPos", nil)
                                    v_u_124:SetAttribute("WepHitID", nil)
                                end
                            end)
                        end
                    end
                    return 1
                end
                local v126 = v120.Instance.Parent:FindFirstChild("DoorHit") or v120.Instance:FindFirstChild("BreakGlass")
                if v126 and not table.find(p119, v126) then
                    table.insert(p119, v126)
                    _G.SafeFireServer(p115.remoteEvent, "Bayonet_HitCon", v120.Instance, v120.Position, v120.Normal, v120.Material)
                    return 2
                end
                local v127 = v120.Instance.Parent:FindFirstChild("Humanoid") or v120.Instance.Parent.Parent:FindFirstChild("Humanoid")
                if v127 and not table.find(p119, v127) then
                    table.insert(p119, v127)
                    _G.SafeFireServer(p115.remoteEvent, "Bayonet_HitPlayer", v127, v120.Position)
                    return 2
                end
            end
            return 0
        end

        function changeBayonet(value)
            FlintLock.BayonetHitCheck = value and v_u_1.BayonetHitCheck or originBayonet
        end
    elseif status == "failed" then
        -- module present but require errored -> mark require-failed (will lock later)
        FlintLockRequireFailed = true
    else
        -- status == "absent", do nothing (wait)
        FlintLockPresent = false
    end
else
    -- module absent: do nothing (we wait)
    FlintLockPresent = false
end

-- Attempt MeleeBase detection + require similarly (non-blocking)
local meleeModInstance = (Modules and Modules:FindFirstChild("Weapons") and Modules.Weapons:FindFirstChild("MeleeBase")) or (Modules and Modules:FindFirstChild("MeleeBase"))
if meleeModInstance then
    MeleeBasePresent = true
    local status, res = safeRequire(meleeModInstance)
    if status == "ok" then
        MeleeBaseSuccess = true
        MeleeBase = res

        local originMelee = MeleeBase.MeleeHitCheck

        local u1 = {}
        u1.__index = u1

        local u8 = game:GetService("CollectionService")

        -- safe require for DebugVisualizer (non-blocking)
        local dbgMod = Modules and Modules:FindFirstChild("RbxUtil") and Modules.RbxUtil:FindFirstChild("DebugVisualizer")
        local dbgStatus, dbgRes = safeRequire(dbgMod)
        local u10 = (dbgStatus == "ok") and dbgRes or DebugVisualizerStub

        local v11 = game.Players.LocalPlayer:FindFirstChild("Options") or game.Players.LocalPlayer:WaitForChild("Options")
        local u14 = v11:FindFirstChild("Gore") or v11:WaitForChild("Gore")
        local u15 = v11:FindFirstChild("WeaponStains") or v11:WaitForChild("WeaponStains")
        local v5 = ReplicatedStorage:FindFirstChild("GameStates") and ReplicatedStorage.GameStates:FindFirstChild("Gameplay")
        local u7 = v5 and v5:FindFirstChild("PVP")

        function u1.MeleeHitCheck(p100, p101, p102, p103, p104, p105)
            local v106 = workspace:Raycast(p101, p102, p103)
            if v106 then
                -- Support both m_Zombie and ZombieLike tagged entities
                local isZombie = v106.Instance.Parent.Name == "m_Zombie" or v106.Instance.Parent:HasTag("ZombieLike")
                if isZombie then
                    local v107 = p103.FilterDescendantsInstances
                    local v108 = v106.Instance
                    table.insert(v107, v108)
                    p103.FilterDescendantsInstances = v107
                    local v109 = v106.Instance.Parent:FindFirstChild("Orig")
                    if v109 then
                        -- Find head part (check descendants for nested models)
                        local Head = nil
                        for i, part in pairs(v106.Instance.Parent:GetDescendants()) do
                            if part.Name == "Head" and (part:IsA("BasePart")) then
                                Head = part
                                break
                            end
                        end
                        
                        -- Gib effect - always target head when found
                        if p100.sharp and shared.Gib ~= nil then
                            if v109.Value then
                                local v110 = v109.Value:FindFirstChild("Zombie")
                                local v111 = not p100.Stats.HeadshotMulti and 2.3 or p100.Stats.HeadshotMulti
                                local gibPart = Head and "Head" or v106.Instance.Name
                                local gibPos = Head and Head.CFrame.Position or v106.Position
                                if v110 and v110.Health - p100.Stats.Damage * v111 <= 0 then
                                    shared.Gib(v109.Value, gibPart, gibPos, v106.Normal, true)
                                end
                            else
                                local gibPart = Head and "Head" or v106.Instance.Name
                                local gibPos = Head and Head.CFrame.Position or v106.Position
                                shared.Gib(v109.Value, gibPart, gibPos, v106.Normal, true)
                            end
                        end
                        if not p104[v109] or p104[v109] < (p100.Stats.MaxHits or 3) then
                            if p105 then
                                -- ThrustCharge also redirects to head
                                if Head and v109.Value then
                                    _G.SafeFireServer(p100.remoteEvent, "ThrustCharge", v109.Value, Head.CFrame.Position, v106.Normal)
                                else
                                    _G.SafeFireServer(p100.remoteEvent, "ThrustCharge", v109.Value, v106.Position, v106.Normal)
                                end
                            else
                                if Head and v109.Value then
                                    local u112 = v109.Value
                                    local v113 = Head.CFrame.Position - p101
                                    if v113:Dot(v113) > 1 then
                                        v113 = v113.Unit
                                    end
                                    local v114 = v113 * 25
                                    _G.SafeFireServer(p100.remoteEvent, "HitZombie", u112, Head.CFrame.Position, true, v114, "Head", v106.Normal)
                                    if not u112:GetAttribute("WepHitDirection") then
                                        local u115 = tick()
                                        u112:SetAttribute("WepHitID", tick())
                                        u112:SetAttribute("WepHitDirection", v114)
                                        u112:SetAttribute("WepHitPos", Head.CFrame.Position) -- Use head position
                                        task.delay(0.2, function()
                                            if u112:GetAttribute("WepHitID") == u115 then
                                                u112:SetAttribute("WepHitDirection", nil)
                                                u112:SetAttribute("WepHitPos", nil)
                                                u112:SetAttribute("WepHitID", nil)
                                            end
                                        end)
                                    end
                                    pcall(function() u10:CastSphere("MeleeHitValid", CFrame.new(p101), Color3.fromRGB(0, 255, 0)) end)
                                    pcall(function() u10:CastSphere("PartPosition", CFrame.new(Head.CFrame.Position), Color3.fromRGB(255, 85, 0)) end)
                                    pcall(function() u10:CastLine("MeleeHit", CFrame.new(p101, p101 + p102) * CFrame.new(0, 0, -p102.Magnitude / 2), Color3.fromRGB(0, 255, 0), p102.Magnitude / 1) end)
                                elseif v109.Value then
                                    -- Fallback: Head not found, use original hit location but still fire
                                    local u112 = v109.Value
                                    local v113 = v106.Position - p101
                                    if v113:Dot(v113) > 1 then
                                        v113 = v113.Unit
                                    end
                                    local v114 = v113 * 25
                                    _G.SafeFireServer(p100.remoteEvent, "HitZombie", u112, v106.Position, v106.Instance.Name == "Head", v114, v106.Instance.Name, v106.Normal)
                                    if not u112:GetAttribute("WepHitDirection") then
                                        local u115 = tick()
                                        u112:SetAttribute("WepHitID", tick())
                                        u112:SetAttribute("WepHitDirection", v114)
                                        u112:SetAttribute("WepHitPos", v106.Position)
                                        task.delay(0.2, function()
                                            if u112:GetAttribute("WepHitID") == u115 then
                                                u112:SetAttribute("WepHitDirection", nil)
                                                u112:SetAttribute("WepHitPos", nil)
                                                u112:SetAttribute("WepHitID", nil)
                                            end
                                        end)
                                    end
                                    pcall(function() u10:CastSphere("MeleeHitValid", CFrame.new(p101), Color3.fromRGB(0, 255, 0)) end)
                                    pcall(function() u10:CastSphere("PartPosition", CFrame.new(v106.Position), Color3.fromRGB(255, 85, 0)) end)
                                    pcall(function() u10:CastLine("MeleeHit", CFrame.new(p101, p101 + p102) * CFrame.new(0, 0, -p102.Magnitude / 2), Color3.fromRGB(0, 255, 0), p102.Magnitude / 1) end)
                                end
                            end
                            if p104[v109] then
                                p104[v109] = p104[v109] + 1
                            else
                                table.insert(p104, v109)
                                p104[v109] = 1
                                if u14.Value and (u15.Value and p100.player:GetAttribute("Platform") ~= "Console") then
                                    local v116 = p100.bloodSaturation + 0.1
                                    p100.bloodSaturation = math.min(v116, 1)
                                end
                            end
                        end
                    end
                    return 1
                end
                if not p105 then
                    local v117 = v106.Instance.Parent:FindFirstChild("DoorHit") or v106.Instance:FindFirstChild("BreakGlass")
                    if v117 and not table.find(p104, v117) then
                        table.insert(p104, v117)
                        _G.SafeFireServer(p100.remoteEvent, "HitCon", v106.Instance)
                        pcall(function() u10:CastSphere("MeleeHitValid", CFrame.new(p101), Color3.fromRGB(0, 255, 0)) end)
                        pcall(function() u10:CastLine("MeleeHit", CFrame.new(p101, p101 + p102) * CFrame.new(0, 0, -p102.Magnitude / 2), Color3.fromRGB(255, 255, 0), p102.Magnitude / 1) end)
                        return 2
                    end
                    local v118 = v106.Instance.Parent:FindFirstChild("Humanoid") or v106.Instance.Parent.Parent:FindFirstChild("Humanoid")
                    if v118 and not table.find(p104, v118) then
                        table.insert(p104, v118)
                        _G.SafeFireServer(p100.remoteEvent, "HitPlayer", v118, v106.Position)
                        pcall(function() u10:CastSphere("MeleeHitValid", CFrame.new(p101), Color3.fromRGB(0, 255, 0)) end)
                        pcall(function() u10:CastLine("MeleeHit", CFrame.new(p101, p101 + p102) * CFrame.new(0, 0, -p102.Magnitude / 2), Color3.fromRGB(0, 255, 0), p102.Magnitude / 1) end)
                        return 2
                    end
                    if u7 and u7:GetAttribute("Active") == true then
                        local v119 = v106.Instance.Parent:FindFirstChild("BuildingHealth") or v106.Instance.Parent.Parent:FindFirstChild("BuildingHealth")
                        if v119 ~= nil and not table.find(p104, v119) then
                            table.insert(p104, v119)
                            local v120 = v119.Parent:FindFirstChild("Creator")
                            if v120 then
                                v120 = v120.Value
                            end
                            if v120 ~= nil and (v120.Neutral == false and (p100.player.Team ~= nil and (v120.Team ~= nil and p100.player.Team.Name == v120.Team.Name))) then
                                return 2
                            end
                            _G.SafeFireServer(p100.remoteEvent, "HitBuilding", v119.Parent)
                            pcall(function() u10:CastSphere("MeleeHitValid", CFrame.new(p101), Color3.fromRGB(0, 255, 0)) end)
                            pcall(function() u10:CastLine("MeleeHit", CFrame.new(p101, p101 + p102) * CFrame.new(0, 0, -p102.Magnitude / 2), Color3.fromRGB(255, 255, 0), p102.Magnitude / 1) end)
                            return 2
                        end
                    end
                    if p100.Stats.BreaksDown and u8:HasTag(v106.Instance, "Breakable") then
                        local v121 = OverlapParams.new()
                        v121.FilterDescendantsInstances = p103.FilterDescendantsInstances
                        local v122 = workspace:GetPartBoundsInRadius(v106.Position, 0.1, v121)
                        local v123 = {}
                        for v124 = 1, #v122 do
                            if u8:HasTag(v122[v124], "Breakable") then
                                local v125 = v122[v124]
                                table.insert(v123, v125)
                            end
                        end
                        _G.SafeFireServer(p100.remoteEvent, "HitBreakable", v123, (v106.Position - p101).Unit)
                        pcall(function() u10:CastSphere("MeleeHitValid", CFrame.new(p101), Color3.fromRGB(0, 255, 0)) end)
                        pcall(function() u10:CastLine("MeleeHit", CFrame.new(p101, p101 + p102) * CFrame.new(0, 0, -p102.Magnitude / 2), Color3.fromRGB(255, 255, 0), p102.Magnitude / 1) end)
                        return 2
                    end
                    pcall(function() u10:CastLine("MeleeHit", CFrame.new(p101, p101 + p102) * CFrame.new(0, 0, -p102.Magnitude / 2), Color3.fromRGB(255, 0, 0), p102.Magnitude / 1) end)
                end
            else
                pcall(function() u10:CastLine("MeleeHit", CFrame.new(p101, p101 + p102) * CFrame.new(0, 0, -p102.Magnitude / 2), Color3.fromRGB(255, 0, 0), p102.Magnitude / 1) end)
            end
            return 0
        end

        function changeMelee(value)
            MeleeBase.MeleeHitCheck = value and u1.MeleeHitCheck or originMelee
        end
    elseif status == "failed" then
        MeleeBaseRequireFailed = true
    else
        MeleeBasePresent = false
    end
else
    MeleeBasePresent = false
end

-- ---------- Aiming Section (toggles for head hit) ----------
local AimingSection = MainTab:Section({
    Title = "Aiming",
    Icon = "crosshair",
    Opened = false
})

HeadHitEnabled = false -- Global for keybind access

local function notifyErrorAndLock(toggle)
    -- notify user and lock the toggle (both wrapped so they won't error)
    pcall(function()
        if WindUI then
            WindUI:Notify({
                Title = "Aiming — Error",
                Content = "Head Hit had an error and will be locked.",
                Duration = 4,
                Icon = "alert-circle",
            })
        end
    end)
    pcall(function()
        if toggle and toggle.Lock then toggle:Lock() end
    end)
end

local HeadHitToggle = AimingSection:Toggle({
    Title = "Head Hit",
    Flag = "Aiming_HeadHit",
    Desc = "Forces Attacks To Redirect to the zombies Head.",
    Default = HeadHitEnabled,
    Callback = function(value)
        -- reflect UI intent immediately
        HeadHitEnabled = value

        -- If a require previously failed for any module, lock & notify (require-failure = module existed but require errored)
        if FlintLockRequireFailed or MeleeBaseRequireFailed then
            HeadHitEnabled = false
            pcall(function() changeBayonet(false) end)
            pcall(function() changeMelee(false) end)
            notifyErrorAndLock(HeadHitToggle)
            return
        end

        -- If user is enabling but no modules are present yet, allow it (we "wait")
        -- apply overrides only for modules that successfully required
        local ok, err = pcall(function()
            if FlintLockSuccess then changeBayonet(value) end
            if MeleeBaseSuccess then changeMelee(value) end
        end)

        if not ok then
            -- a runtime error happened while applying overrides -> lock
            HeadHitEnabled = false
            pcall(function()
                if FlintLockSuccess then changeBayonet(false) end
                if MeleeBaseSuccess then changeMelee(false) end
            end)
            notifyErrorAndLock(HeadHitToggle)
            return
        end

        -- success notify (safe)
        pcall(function()
            if WindUI then
                WindUI:Notify({
                    Title = "Aiming",
                    Content = value and "Head Hit enabled" or "Head Hit disabled",
                    Duration = 2,
                    Icon = value and "crosshair" or "crosshair-off",
                })
            end
        end)
    end
})

-- Store toggle reference globally for keybind access
_G.KatchiToggleElements = _G.KatchiToggleElements or {}
_G.KatchiToggleElements.HeadHit = HeadHitToggle

-- If any require previously failed, lock & notify immediately (module existed but require errored)
if FlintLockRequireFailed or MeleeBaseRequireFailed then
    notifyErrorAndLock(HeadHitToggle)
end

-- Register HeadHit toggle for keybind access
_G.KatchiToggles.HeadHit = {
    element = HeadHitToggle,
    getState = function() return HeadHitEnabled end,
    setState = function(v) HeadHitEnabled = v end
}

    -- === Jump On Specific Animations (with WindUI Toggle) ===            
    -- === Target Animation IDs ===            
    local TARGET_ANIM_IDS = {            
        "rbxassetid://17406577733",            
        "rbxassetid://15669224658",            
        "rbxassetid://12591948314",            
        "rbxassetid://12333491302",            
    }
    
    -- Jump height setting (studs)
    AutoJumpHeight = 7.2 -- Default Roblox jump height is ~7.2 studs            
            
    local TARGETS = {}            
    for _, v in ipairs(TARGET_ANIM_IDS) do            
        local id = tostring(v)            
        if id:match("^%d+$") then            
            id = "rbxassetid://" .. id            
        end            
        TARGETS[id] = true            
    end            
            
    -- === Jump logic ===            
    local humanoid, animator            
    local playedTracks = {}            
    local monitoring = false            
            
    local function normalizeAnimId(id)            
        if not id then return nil end            
        local s = tostring(id)            
        if s:match("^%d+$") then            
            return "rbxassetid://" .. s            
        end            
        return s            
    end            
            
    local function trackIsTarget(track)            
        if not track or not track.IsPlaying then return false end            
        local anim = track.Animation            
        if not anim or not anim.AnimationId then return false end            
        local aId = normalizeAnimId(anim.AnimationId)            
        return aId and TARGETS[aId]            
    end            
            
    local function doJump()  
        if not humanoid or not humanoid.Parent then return end  
  
        task.spawn(function()  
            pcall(function()  
                -- Wait until humanoid can jump again  
                local timeout = 1  
                local startTime = os.clock()  
  
                while os.clock() - startTime < timeout do  
                    local state = humanoid:GetState()  
                    if state == Enum.HumanoidStateType.Running  
                        or state == Enum.HumanoidStateType.Landed  
                        or state == Enum.HumanoidStateType.RunningNoPhysics  
                        or state == Enum.HumanoidStateType.Climbing then  
                        break  
                    end  
                    task.wait(0.05)  
                end  
  
                -- === Jump Height Simulation (Velocity-based) ===
                -- Physics formula: v = sqrt(2 * g * h) where g = workspace.Gravity, h = jump height
                local gravity = workspace.Gravity
                local jumpHeight = AutoJumpHeight or 7.2
                local jumpVelocity = math.sqrt(2 * gravity * jumpHeight)
                
                local character = LocalPlayer.Character
                local hrp = character and character:FindFirstChild("HumanoidRootPart")
                
                if hrp then
                    -- Set humanoid state to jumping first
                    humanoid:ChangeState(Enum.HumanoidStateType.Jumping)
                    
                    -- Apply vertical velocity using AssemblyLinearVelocity
                    local currentVel = hrp.AssemblyLinearVelocity
                    hrp.AssemblyLinearVelocity = Vector3.new(currentVel.X, jumpVelocity, currentVel.Z)
                end
            end)  
        end)  
    end  
            
    -- === Monitoring loop ===            
    local function startMonitoring()            
        if monitoring then return end            
        monitoring = true            
        task.spawn(function()            
            while monitoring do            
                if animator then            
                    local ok, tracks = pcall(function()            
                        return animator:GetPlayingAnimationTracks()            
                    end)            
                    if ok and tracks then            
                        for _, track in ipairs(tracks) do            
                            if trackIsTarget(track) and not playedTracks[track] then            
                                playedTracks[track] = true            
                                pcall(doJump)            
                                track.Stopped:Connect(function()            
                                    playedTracks[track] = nil            
                                end)            
                            end            
                        end            
                    end            
                end            
                task.wait(0.08)            
            end            
        end)            
    end            
            
    local function stopMonitoring()            
        monitoring = false            
        playedTracks = {}            
    end            
            
    -- === Character initialization ===  
    local function refreshCharacter(char)  
        humanoid = char and char:FindFirstChildOfClass("Humanoid") or nil  
        animator = nil  
        if humanoid then  
            animator = humanoid:FindFirstChildOfClass("Animator")  
            if not animator then  
                animator = Instance.new("Animator")  
                animator.Name = "AutoAnimator"  
                animator.Parent = humanoid  
            end  
        end  
        playedTracks = {}  
    end  
  
    refreshCharacter(LocalPlayer.Character)  

    -- === Restore toggle state after respawn ===
    local function restoreAutoJump()
        local persisted = false
        pcall(function()
            persisted = LocalPlayer:GetAttribute("AutoJumpEnabled")
        end)
        if persisted then
            task.delay(0.2, startMonitoring)
        end
    end
    restoreAutoJump()

    LocalPlayer.CharacterAdded:Connect(function(ch)  
        -- Wait for character to fully load  
        ch:WaitForChild("Humanoid", 5)  
        ch:WaitForChild("HumanoidRootPart", 5)  
        refreshCharacter(ch)  
        restoreAutoJump()
    end)  

    local LegitSection = MainTab:Section({            
        Title = "Legit Thingys",            
        Icon = "shield-check",            
        Opened = false            
    })            
            
    -- === WindUI Toggle Setup ===            
    local AutoJumpToggle = LegitSection:Toggle({            
        Title = "Auto Jump",            
        Flag = "Legit_AutoJump",
        Desc = "Makes you jump When Thrusting Your Weapon",            
        Default = false,            
        Callback = function(value)            
            pcall(function() LocalPlayer:SetAttribute("AutoJumpEnabled", value) end)
            if value then            
                startMonitoring()            
                WindUI:Notify({            
                    Title = "Jump On Swing",            
                    Content = "Auto Jump Enabled",            
                    Duration = 2,            
                    Icon = "activity",            
                })            
            else            
                stopMonitoring()            
                WindUI:Notify({            
                    Title = "Jump On Swing",            
                    Content = "Auto Jump Disabled",            
                    Duration = 2,            
                    Icon = "activity-off",            
                })            
            end            
        end            
    })
    _G.KatchiToggleElements = _G.KatchiToggleElements or {}
    _G.KatchiToggleElements.AutoJump = AutoJumpToggle

    -- Jump Height Slider
    LegitSection:Slider({
        Title = "Jump Height",
        Flag = "Legit_JumpHeight",
        Desc = "Adjust the height of auto jump (studs)",
        Default = 7.2,
        Min = 1,
        Max = 50,
        Callback = function(value)
            AutoJumpHeight = value
        end
    })
     
local HitboxSection = MainTab:Section({
        Title = "Hitbox",
        Icon = "box",
        Opened = false
    })

-- Hitbox Expander (robust, non-blocking, locks UI on error + notifies)
hitboxEnabled = false -- Global for keybind access
hitboxSize = 10

local Workspace = game:GetService("Workspace")
local Players = game:GetService("Players")

-- prefer non-blocking find; if missing, use nil and continue
local zombieFolder = Workspace:FindFirstChild("Zombies")
if not zombieFolder then
    warn("Bruh")
end

-- Helper to notify + lock UI widgets safely
local function notifyHitboxErrorAndLock(widgets)
    pcall(function()
        if WindUI then
            WindUI:Notify({
                Title = "Hitbox — Error",
                Content = "Hitbox had an error and will be locked.",
                Duration = 4,
                Icon = "alert-circle",
            })
        end
    end)
    -- lock all provided widgets (toggle + sliders)
    pcall(function()
        for _, w in ipairs(widgets or {}) do
            if w and type(w.Lock) == "function" then
                w:Lock()
            end
        end
    end)
end

-- safe create hitbox part
local function safeCreateHitbox(parent, name, size, attachPart)
    local ok, err = pcall(function()
        if not parent or not parent.Parent then return end
        local part = Instance.new("Part")
        -- Use stealth name for anti-detection
        part.Name = _G.getRandomStealthName and _G.getRandomStealthName() or (name .. "_" .. math.random(10000, 99999))
        part.Size = Vector3.new(size, size, size)
        part.Transparency = 1
        part.Anchored = false
        part.CanCollide = false
        part.Massless = true
        part.CanTouch = true
        part.CFrame = attachPart.CFrame
        part.Parent = parent

        local weld = Instance.new("WeldConstraint")
        weld.Part0 = attachPart
        weld.Part1 = part
        weld.Parent = part
    end)
    return ok, err
end

local function addOuterHitbox(zombie)
    if not zombie or not zombie.Parent then return end
    local hrp = zombie:FindFirstChild("HumanoidRootPart")
    if hrp and not zombie:FindFirstChild("OuterHitbox") then
        local ok, err = safeCreateHitbox(zombie, "OuterHitbox", hitboxSize, hrp)
        if not ok then
            warn("Failed to create OuterHitbox:", err)
            return false, err
        end
    end
    return true
end

local function addHeadHitbox(zombie)
    if not zombie or not zombie.Parent then return end
    local head = zombie:FindFirstChild("Head")
    if head and not zombie:FindFirstChild("HeadHitbox") then
        local ok, err = safeCreateHitbox(zombie, "HeadHitbox", hitboxSize/2, head)
        if not ok then
            warn("Failed to create HeadHitbox:", err)
            return false, err
        end
    end
    return true
end

local function removeHitboxes(zombie)
    if not zombie then return end
    pcall(function()
        local outer = zombie:FindFirstChild("OuterHitbox")
        local head = zombie:FindFirstChild("HeadHitbox")
        if outer then outer:Destroy() end
        if head then head:Destroy() end
    end)
end

local function updateHitboxes(zombie)
    if not zombie then return end
    if hitboxEnabled then
        -- remove old then create new; use pcall to catch errors
        local ok, err = pcall(function()
            removeHitboxes(zombie)
            task.wait(0.05)
            addOuterHitbox(zombie)
            addHeadHitbox(zombie)
        end)
        if not ok then
            return false, err
        end
    else
        removeHitboxes(zombie)
    end
    return true
end

local function setHitboxSize(newSize, widgetsToLock)
    hitboxSize = newSize
    if hitboxEnabled then
        local ok, err = pcall(function()
            -- Attempt on zombieFolder if exists
            if zombieFolder then
                for _, zombie in pairs(zombieFolder:GetChildren()) do
                    updateHitboxes(zombie)
                end
            end
            -- Camera fallback (some maps put m_Zombie under Camera)
            if Workspace:FindFirstChild("Camera") then
                for _, zombie in pairs(Workspace.Camera:GetChildren()) do
                    if zombie.Name == "m_Zombie" then
                        updateHitboxes(zombie)
                    end
                end
            end
        end)
        if not ok then
            warn("setHitboxSize encountered an error:", err)
            notifyHitboxErrorAndLock(widgetsToLock)
        end
    end
end

local function toggleHitboxExpander(enabled, widgetsToLock)
    hitboxEnabled = enabled

    local ok, err = pcall(function()
        if zombieFolder then
            for _, zombie in pairs(zombieFolder:GetChildren()) do
                updateHitboxes(zombie)
            end
        end
        if Workspace:FindFirstChild("Camera") then
            for _, zombie in pairs(Workspace.Camera:GetChildren()) do
                if zombie.Name == "m_Zombie" then
                    updateHitboxes(zombie)
                end
            end
        end
    end)

    if not ok then
        warn("toggleHitboxExpander encountered an error:", err)
        -- rollback logical state
        hitboxEnabled = false
        -- remove any partial hitboxes
        pcall(function()
            if zombieFolder then
                for _, z in pairs(zombieFolder:GetChildren()) do removeHitboxes(z) end
            end
        end)
        notifyHitboxErrorAndLock(widgetsToLock)
    end
end

-- auto-apply to new zombies (guards to ensure no yield)
if zombieFolder then
    zombieFolder.ChildAdded:Connect(function(zombie)
        if hitboxEnabled then
            task.wait(0.2)
            pcall(function() updateHitboxes(zombie) end)
        end
    end)
end

-- Camera fallback connection (non-blocking)
if Workspace:FindFirstChild("Camera") then
    Workspace.Camera.ChildAdded:Connect(function(zombie)
        if zombie.Name == "m_Zombie" and hitboxEnabled then
            task.wait(0.2)
            pcall(function() updateHitboxes(zombie) end)
        end
    end)
end

-- Keep references to UI widgets so we can lock them on errors
toggleWidgetRef = nil -- Global for keybind access
local sliderSizeWidgetRef
local sliderRangeWidgetRef

-- Create toggle (capture reference)
toggleWidgetRef = HitboxSection:Toggle({
    Title = "Hitbox Expander",
    Flag = "Hitbox_HitboxExpander",
    Desc = "Expands zombie hitboxes for easier hits.",
    Default = false,
    Callback = function(value)
        -- pass the UI widgets list so errors lock them
        toggleHitboxExpander(value, { toggleWidgetRef, sliderSizeWidgetRef, sliderRangeWidgetRef })
        pcall(function()
            if WindUI then
                WindUI:Notify({
                    Title = "Hitbox",
                    Content = value and "Hitbox Expander enabled" or "Hitbox Expander disabled",
                    Duration = 2,
                    Icon = value and "scan" or "scan-line",
                })
            end
        end)
    end
})
_G.KatchiToggleElements = _G.KatchiToggleElements or {}
_G.KatchiToggleElements.HitboxExpander = toggleWidgetRef

-- Slider: Hitbox Size (capture reference)
sliderSizeWidgetRef = HitboxSection:Slider({
    Title = "Hitbox Zombie Size",
    Flag = "Hitbox_HitboxSize",
    Step = 1,
    Value = {
        Min = 1,
        Max = 30,
        Default = hitboxSize,
    },
    Callback = function(value)
        -- pass widgets so setHitboxSize can lock them on error
        setHitboxSize(value, { toggleWidgetRef, sliderSizeWidgetRef, sliderRangeWidgetRef })
    end
})

-- Slider: Hitbox Range (capture reference)
sliderRangeWidgetRef = HitboxSection:Slider({
    Title = "Hitbox Zombie Range",
    Flag = "Hitbox_HitboxRange",
    Step = 1,
    Value = {
        Min = 0,
        Max = 30,
        Default = MaxRange or 30,
    },
    Callback = function(value)
        -- just set MaxRange; if you need errors to lock, call notifyHitboxErrorAndLock
        local ok, err = pcall(function()
            MaxRange = value
        end)
        if not ok then
            warn("Setting MaxRange failed:", err)
            notifyHitboxErrorAndLock({ toggleWidgetRef, sliderSizeWidgetRef, sliderRangeWidgetRef })
        end
    end
})

-- If initial state is broken (e.g., Camera and Zombies missing), lock UI immediately and notify
local cameraExists = Workspace:FindFirstChild("Camera") ~= nil
if (not zombieFolder) and (not cameraExists) then
    warn("Hitbox Locked Due to an error.")
    notifyHitboxErrorAndLock({ toggleWidgetRef, sliderSizeWidgetRef, sliderRangeWidgetRef })
end
end -- end of Legit & Hitbox Section

task.wait(0.1) -- Delay to prevent lag
do -- // Shove Hitbox Section
-- ===== SHOVE HITBOX EXPANDER SECTION =====
-- Initialize global variables for Shove Hitbox Expander (so they exist before Classes section loads)
ShoveHitboxExpanderEnabled = false
ShoveHitboxExpanderRange = 20
ShoveHitboxExpanderTargets = 10
ShoveHitboxExpanderDelay = 0.03
ShoveHitboxAnimConnection = nil

local ShoveHitboxSection = MainTab:Section({ Title = "Shove Hitbox Expander", Icon = "zap", Opened = false })

local ShoveHitboxToggle = ShoveHitboxSection:Toggle({
    Title = "Shove Hitbox Expander",
    Flag = "ShoveHitbox_Enabled",
    Desc = "Will make the Shove Hitbox Larger.",
    Default = false,
    Callback = function(v)
        ShoveHitboxExpanderEnabled = v
        WindUI:Notify({
            Title = "Shove Hitbox Expander",
            Content = v and ("Shove Hitbox Expander Enabled") or "Shove Hitbox Expander Disabled",
            Duration = 2,
            Icon = v and "zap" or "x"
        })
    end
})
_G.KatchiToggleElements = _G.KatchiToggleElements or {}
_G.KatchiToggleElements.ShoveHitbox = ShoveHitboxToggle

ShoveHitboxSection:Slider({
    Title = "Hit Range",
    Flag = "ShoveHitbox_Range",
    Desc = "How far your shove can reach zombies.",
    Step = 1,
    Value = { Min = 1, Max = 15, Default = 15 },
    Callback = function(v)
        ShoveHitboxExpanderRange = v
    end
})

ShoveHitboxSection:Slider({
    Title = "Max Targets",
    Flag = "ShoveHitbox_Targets",
    Desc = "How many zombies to hit per shove.",
    Step = 1,
    Value = { Min = 1, Max = 10, Default = 10 },
    Callback = function(v)
        ShoveHitboxExpanderTargets = v
    end
})

-- ===== AUTO PARRY SAPPER SECTION =====
-- Initialize global variable
AutoParrySapperMeleeEnabled = false

local AutoParrySapperToggle = ShoveHitboxSection:Toggle({
    Title = "Auto Parry Sapper",
    Flag = "ShoveHitbox_AutoParrySapper",
    Desc = "Will Parry An Zapper When Its Attacking (Axe And Pickaxe).",
    Default = false,
    Callback = function(v)
        AutoParrySapperMeleeEnabled = v
        WindUI:Notify({
            Title = "Auto Parry Sapper",
            Content = v and "Auto Parry Enabled" or "Auto Parry Disabled",
            Duration = 2,
            Icon = v and "shield" or "shield-off"
        })
    end
})
_G.KatchiToggleElements.AutoParrySapper = AutoParrySapperToggle

    -- Cleanup function  
    local function cleanup()  
        changeBayonet(false)  
        changeMelee(false)  
        AutoHeadEnabled = false  
        LastHitTime = {}  
        IsIgniter = {}  
        Remote = nil  
    end  
  
    _G.KatchiHeadHitCleanup = cleanup
end -- end of Shove Hitbox Section

task.wait(0.1) -- Delay to prevent lag
do -- // Auto Gun Aim Section
-- Auto Universal Gun Aim — IMPROVED: multi-type selection, movement-based time-shots,
-- dynamic retargeting if obstructed/died, and preserves previous features (reload, wall checks, save players)
-- + FOV FEATURE + TARGET ESP (yellow chams)
local Players = game:GetService("Players")
local RunService = game:GetService("RunService")
local Workspace = game:GetService("Workspace")
local StarterGui = game:GetService("StarterGui")
local UserInputService = game:GetService("UserInputService")
local GuiService = game:GetService("GuiService")
local LocalPlayer = Players.LocalPlayer
-- === CONFIG (core timings) ===
local LOOK_DURATION = 0.28
local MAX_TARGET_RANGE = 200
local FIRE_DELAY_AFTER_LOOK = 0.03
local CHECK_INTERVAL = 0.12
local APPEAR_DELAY_DEFAULT = 0.5
local APPEAR_DELAY = APPEAR_DELAY_DEFAULT
-- Auto Shoot Delay: total time from starting aim to firing (in seconds)
local AUTO_SHOOT_DELAY = 0.5
-- UI-exposed toggles (defaults) - Global for keybind access
CHECK_WALLS = true
AUTO_RELOAD_ENABLED = false
USER_AUTO_SHOOT_TOGGLE = false
-- Instant shoot toggle
INSTANT_SHOOT_ENABLED = false
-- Silent Aim settings (redirects user shots instead of auto-shooting)
SILENT_AIM_ENABLED = false
SILENT_AIM_SAVE_PLAYERS_ENABLED = false
SILENT_AIM_BOMBER_NEAR_ENABLED = false
SILENT_AIM_AUTO_AIM = false -- When true, character aims at target. When false, only bullet is redirected.
local silentAimCurrentTarget = nil -- Current target part for silent aim redirection
local silentAimCurrentModel = nil -- Current target model for silent aim
local silentAimIsPlayerTarget = false -- Whether current target is for saving a player
local silentAimSavedPlayer = nil -- The player being saved (if any)

-- Silent Aim zombie type selection (must be declared here so loop can access it)
-- Note: These are intentionally not local so they can be accessed by the Gun Tab UI section
SilentAimZombieTypes = { "Bomber", "Cuirassier", "Runner", "Zapper", "Igniter", "Shambler" }
SilentAimSelectedTypes = {} -- Array of selected zombie types for silent aim
SilentAimEnabledTypes = {} -- Per-type enabled state
for _, t in ipairs(SilentAimZombieTypes) do SilentAimEnabledTypes[t] = false end

-- Silent Aim FOV settings (must be declared here so loop can access it)
local SILENT_AIM_USE_FOV = false
local SILENT_AIM_SHOW_FOV = false
SILENT_AIM_MOBILE_FOV = false
local SILENT_AIM_FOV_SIZE = 50

-- Forward declaration for Silent Aim FOV check function (defined later in UI section)
local isWorldPosInSilentAimFov = function(worldPos)
    -- Stub that returns true (no FOV restriction) until the real function is defined
    if not SILENT_AIM_USE_FOV then return true end
    -- Basic screen-center FOV check as fallback
    local cam = Workspace.CurrentCamera
    if not cam then return true end
    local screenPos, onScreen = cam:WorldToViewportPoint(worldPos)
    if not onScreen then return false end
    local viewportSize = cam.ViewportSize
    local centerVec = Vector2.new(viewportSize.X / 2, viewportSize.Y / 2)
    local dist = (Vector2.new(screenPos.X, screenPos.Y) - centerVec).Magnitude
    local sizePx = (math.clamp(SILENT_AIM_FOV_SIZE, 10, 120) / 40) * 250
    return dist <= (sizePx / 2)
end

-- Auto Shoot target (for VirtualInputManager shooting - hooks redirect to this)
local autoShootCurrentTarget = nil -- Current target part for auto shoot redirection
local autoShootCurrentModel = nil -- Current target model for auto shoot
local autoShootActive = false -- Whether auto shoot is currently firing

-- VirtualInputManager for simulating mouse clicks
local VirtualInputManager = game:GetService("VirtualInputManager")

-- Bomber Safety settings (global for config)
BOMBER_SAFE_TEAMMATES = false -- Don't shoot bombers near teammates
BOMBER_SAFE_SELF = false -- Don't shoot bombers near self
BOMBER_SAFE_RADIUS = 10 -- Radius to check for teammates/self
BOMBER_VISUALIZE_RADIUS = false -- Show explosion radius visualization (global for UI access)
-- Use weak keys so entries for destroyed bombers are garbage collected
BomberRadiusVisuals = setmetatable({}, { __mode = "k" }) -- Store visual parts for bomber radius (global for UI access)
local SHOOT_BOMBER_NEAR_TEAMMATES = false -- ONLY shoot bombers when near teammates (opposite behavior)
local BomberSafetyWhitelist = {} -- array of player names to protect from bomber shots (Don't Shoot Near)
local ShootBomberNearWhitelist = {} -- array of player names to trigger bomber shots (Shoot Bomber Near)
local AutoSaveWhitelist = {} -- array of player names to auto-save (empty = save all)
-- Auto Save Players settings - Global for keybind access
AUTO_SAVE_PLAYERS_ENABLED = false
local MAX_SAVE_PLAYERS_RANGE = MAX_TARGET_RANGE
local INSTANT_SAVE_PLAYERS_ENABLED = false
-- Save player delay slider
local SAVE_PLAYER_DELAY = 0.5
PREDICTION_DISTANCE = 0 -- seconds to lead target positions (global for config)
local PREDICTION_MIN_SPEED = 2 -- studs/sec; below this we treat targets as stationary
local PREDICTION_STILLNESS_WINDOW = 0.4 -- seconds of low movement before treating as stationary
-- Wall check thresholds
local WALL_CHECK_TRANSPARENCY_THRESHOLD = 0.95
local WALL_CHECK_SAMPLE_AXIS_SCALE = 0.35 -- percentage of part size to offset LOS samples by
local WALL_CHECK_MIN_SAMPLE_OFFSET = 0.4 -- studs; prevents offsets from collapsing on tiny parts
local WALL_CHECK_MAX_SAMPLE_OFFSET = 2.75 -- studs; avoids overextending samples into other cover
local WALL_CHECK_REQUIRED_CLEAR_RATIO = 0.6 -- at least this fraction of samples must be unobstructed
local EPS = 1e-4
-- State management
local isAiming = false
-- Use weak tables so dead tool/connection references get garbage collected
local watchedTools = setmetatable({}, { __mode = "k" })
local activeConnections = {}
local characterAddedConn = nil
local reloadInProgress = setmetatable({}, { __mode = "k" })  -- Track which tools are currently reloading
-- Shooting type selection state (multi-select)
-- Note: These are intentionally not local so they can be accessed by the Gun Tab UI section
ShootTypeList = { "Bomber", "Cuirassier", "Runner", "Zapper", "Igniter", "Shambler" }
SelectedShootTypes = {} -- array of strings selected in UI
EnabledShootTypes = {} -- toggled enabled per selected type (keeps parity with UI)
for _, t in ipairs(ShootTypeList) do EnabledShootTypes[t] = false end
local getPredictedAimPosition -- forward declaration
local getAimPosition -- forward declaration
local PartVelocityCache = setmetatable({}, { __mode = "k" })
local function getHistoricalVelocity(part)
    if not part or not part.Parent then return nil end
    local now = os.clock()
    local pos = part.Position
    local entry = PartVelocityCache[part]
    if entry then
        local dt = math.max(now - entry.time, EPS)
        if dt < (1 / 240) then
            return entry.vel
        end
        local vel = (pos - entry.pos) / dt
        entry.pos = pos
        entry.time = now
        entry.vel = vel
        entry.lastSpeed = vel.Magnitude
        if entry.lastSpeed >= PREDICTION_MIN_SPEED then
            entry.lastMoveTime = now
        end
        return vel
    else
        PartVelocityCache[part] = {
            pos = pos,
            time = now,
            vel = Vector3.new(0, 0, 0),
            lastSpeed = 0,
            lastMoveTime = nil,
        }
    end
    return nil
end

local function hasRecentMovement(part)
    local entry = PartVelocityCache[part]
    if not entry or not entry.lastMoveTime then
        return false
    end
    return (os.clock() - entry.lastMoveTime) <= PREDICTION_STILLNESS_WINDOW
end
local function getModelVelocityFromPart(part)
    if not part then return nil end
    local model = part:FindFirstAncestorWhichIsA("Model")
    if not model then return nil end
    local root = model:FindFirstChild("HumanoidRootPart")
        or model:FindFirstChild("Torso")
        or model:FindFirstChild("UpperTorso")
        or model.PrimaryPart
    if root and root:IsA("BasePart") then
        local vel = root.AssemblyLinearVelocity or Vector3.new(0, 0, 0)
        if vel.Magnitude > EPS then
            return vel
        end
    end
    return nil
end

-- ===== FOV SETTINGS ===== (Global for keybind access)
USE_FOV = false      -- "Use Fov" toggle
SHOW_FOV = false     -- "Show Fov" toggle
MOBILE_FOV = false   -- "Mobile Fov" toggle (centered) / off = follow cursor

FOV_SIZE_DEG = 50 -- default FOV angle in degrees (global for config)
local FOV_MIN_DEG, FOV_MAX_DEG = 10, 120

local fovGui = nil
local fovCircle = nil
local fovUpdateConn = nil

local function ensureFovGui()
    if fovGui and fovGui.Parent then
        return fovGui, fovCircle
    end

    local pg
    if type(getPlayerGui) == "function" then
        pg = getPlayerGui()
    else
        pg = LocalPlayer:FindFirstChild("PlayerGui") or LocalPlayer:WaitForChild("PlayerGui")
    end

    fovGui = Instance.new("ScreenGui")
    fovGui.ResetOnSpawn = false
    if _G.protectGUI then _G.protectGUI(fovGui) else fovGui.Parent = pg end -- Use stealth protection

    local circle = Instance.new("Frame")
    circle.Name = "Circle"
    circle.AnchorPoint = Vector2.new(0.5, 0.5)
    circle.Position = UDim2.new(0.5, 0, 0.5, 0)
    circle.BackgroundTransparency = 1 -- no fill
    circle.BorderSizePixel = 0
    circle.Parent = fovGui

    local corner = Instance.new("UICorner")
    corner.CornerRadius = UDim.new(1, 0)
    corner.Parent = circle

    local stroke = Instance.new("UIStroke")
    stroke.Thickness = 2
    stroke.Color = Color3.fromRGB(255, 255, 0)
    stroke.Transparency = 0.2
    stroke.Parent = circle

    fovCircle = circle
    return fovGui, fovCircle
end

local function getFovScreenCenter()
    local cam = Workspace.CurrentCamera
    if not cam then
        return Vector2.new(0, 0)
    end

    local viewportSize = cam.ViewportSize

    -- If MOBILE FOV is on OR mouse is locked (ShiftLock / right-click lock),
    -- use the center of the screen
    if MOBILE_FOV or UserInputService.MouseBehavior == Enum.MouseBehavior.LockCenter then
        return Vector2.new(viewportSize.X / 2, viewportSize.Y / 2)
    end

    -- Otherwise, use the real mouse position, adjusted for GUI inset
    local mousePos = UserInputService:GetMouseLocation()
    local inset = GuiService:GetGuiInset()

    -- mousePos includes the top bar; ViewportPoint uses inset-removed coords.
    -- So we subtract inset to get into the same space as ViewportPoint.
    return mousePos - Vector2.new(inset.X, inset.Y)
end

local fovFrameCounter = 0
local FOV_UPDATE_INTERVAL = 2 -- Update every N frames for performance
local function ensureFovUpdateLoop()
    if fovUpdateConn then return end

    fovUpdateConn = RunService.RenderStepped:Connect(function()
        if not (USE_FOV and SHOW_FOV) then
            if fovGui then fovGui.Enabled = false end
            return
        end
        
        -- Throttle updates for performance
        fovFrameCounter = fovFrameCounter + 1
        if fovFrameCounter < FOV_UPDATE_INTERVAL then return end
        fovFrameCounter = 0

        local gui, circle = ensureFovGui()
        gui.Enabled = true

        local cam = Workspace.CurrentCamera
        if not cam then return end

        -- size in pixels (same mapping as before: 40° -> 250px)
        local clamped = math.clamp(FOV_SIZE_DEG, FOV_MIN_DEG, FOV_MAX_DEG)
        local sizePx = math.floor((clamped / 40) * 250)
        circle.Size = UDim2.new(0, sizePx, 0, sizePx)

        -- center position using unified helper (handles mobile + shiftlock + inset)
        local viewportSize = cam.ViewportSize
        local centerVec = getFovScreenCenter()

        local xScale = centerVec.X / viewportSize.X
        local yScale = centerVec.Y / viewportSize.Y

        circle.Position = UDim2.new(xScale, 0, yScale, 0)
    end)
end

function updateFovCircle() -- Global for keybind access
    if not (USE_FOV and SHOW_FOV) then
        if fovGui then fovGui.Enabled = false end
        return
    end
    -- make sure the render-stepped loop is running
    ensureFovUpdateLoop()
end

-- FOV check that matches the circle on screen (pixel-based)
local function isWorldPosInFov(worldPos)
    if not USE_FOV then return true end

    local cam = Workspace.CurrentCamera
    if not cam then return true end

    local viewportSize = cam.ViewportSize
    if not viewportSize or viewportSize.X <= 0 or viewportSize.Y <= 0 then
        return true
    end

    local screenPos, onScreen = cam:WorldToViewportPoint(worldPos)
    if not onScreen then
        -- if it's behind us / off screen, just treat as outside FOV
        return false
    end

    -- same center used as the circle
    local centerVec = getFovScreenCenter()
    local dist = (Vector2.new(screenPos.X, screenPos.Y) - centerVec).Magnitude

    local clamped = math.clamp(FOV_SIZE_DEG, FOV_MIN_DEG, FOV_MAX_DEG)
    local sizePx = (clamped / 40) * 250
    local radius = sizePx / 2

    return dist <= radius
end
-- ===== TARGET VISUALS (TARGET ESP) =====
TARGET_ESP_ENABLED = false -- global for config
AIM_DOT_ENABLED = false -- Show dot at aim position (global for config)

-- Make these global so they can be accessed from multiple places
activeAimModel = nil
activeAimPart = nil
activeHighlight = nil -- Highlight instance for target esp
local activeAimDot = nil -- BillboardGui for aim position dot
local activeAimDotPart = nil -- Invisible part to attach billboard to
local activeAimDotCurrentPos = nil -- Current interpolated position

local TARGET_CHAMS_TRANSPARENCY = 0.4
local TARGET_CHAMS_COLOR = Color3.fromRGB(255, 220, 50) -- yellow
local AIM_DOT_COLOR = Color3.fromRGB(255, 0, 0) -- red dot
local AIM_DOT_SIZE = 12 -- pixels
local AIM_DOT_LERP_SPEED = 15 -- How fast the dot moves to target (higher = faster)

-- Get player head position as default dot position
local function getPlayerHeadPosition()
    local char = LocalPlayer and LocalPlayer.Character
    if not char then return nil end
    local head = char:FindFirstChild("Head")
    if head and head:IsA("BasePart") then
        return head.Position + Vector3.new(0, 1, 0) -- Slightly above head
    end
    local hrp = char:FindFirstChild("HumanoidRootPart")
    if hrp and hrp:IsA("BasePart") then
        return hrp.Position + Vector3.new(0, 2, 0)
    end
    return nil
end

-- Create billboard aim dot
local function createAimDot()
    if activeAimDot and activeAimDot.Parent then return activeAimDot end
    
    local startPos = getPlayerHeadPosition() or Vector3.new(0, 100, 0)
    
    -- Create invisible anchor part
    local anchorPart = Instance.new("Part")
    -- Use stealth name for anti-detection
    anchorPart.Name = _G.getRandomStealthName and _G.getRandomStealthName() or ("Anchor_" .. math.random(10000, 99999))
    anchorPart.Size = Vector3.new(0.1, 0.1, 0.1)
    anchorPart.Position = startPos
    anchorPart.Anchored = true
    anchorPart.CanCollide = false
    anchorPart.CanQuery = false
    anchorPart.CanTouch = false
    anchorPart.Transparency = 1
    anchorPart.Parent = Workspace.CurrentCamera
    activeAimDotPart = anchorPart
    
    -- Create billboard GUI
    local billboard = Instance.new("BillboardGui")
    -- Use stealth name for anti-detection
    billboard.Name = _G.getRandomStealthName and _G.getRandomStealthName() or ("DotBB_" .. math.random(10000, 99999))
    billboard.Adornee = anchorPart
    billboard.Size = UDim2.new(0, AIM_DOT_SIZE * 2, 0, AIM_DOT_SIZE * 2)
    billboard.StudsOffset = Vector3.new(0, 0, 0)
    billboard.AlwaysOnTop = true
    billboard.LightInfluence = 0
    billboard.Parent = anchorPart
    
    -- Create circular dot frame
    local dot = Instance.new("Frame")
    dot.Name = "Dot"
    dot.AnchorPoint = Vector2.new(0.5, 0.5)
    dot.Position = UDim2.new(0.5, 0, 0.5, 0)
    dot.Size = UDim2.new(0, AIM_DOT_SIZE, 0, AIM_DOT_SIZE)
    dot.BackgroundColor3 = AIM_DOT_COLOR
    dot.BorderSizePixel = 0
    dot.Parent = billboard
    
    -- Make it circular
    local corner = Instance.new("UICorner")
    corner.CornerRadius = UDim.new(1, 0)
    corner.Parent = dot
    
    -- Add outline/stroke
    local stroke = Instance.new("UIStroke")
    stroke.Color = Color3.fromRGB(255, 255, 255)
    stroke.Thickness = 2
    stroke.Transparency = 0.3
    stroke.Parent = dot
    
    activeAimDot = billboard
    activeAimDotCurrentPos = startPos
    
    -- PROTECT aim dot visuals from anti-cheat detection
    pcall(function()
        if _G.protectESP then
            _G.protectESP(anchorPart)
            _G.protectESP(billboard)
        end
    end)
    
    return billboard
end

-- Clear/destroy aim dot
local function clearAimDot()
    if activeAimDot then
        pcall(function() activeAimDot:Destroy() end)
        activeAimDot = nil
    end
    if activeAimDotPart then
        pcall(function() activeAimDotPart:Destroy() end)
        activeAimDotPart = nil
    end
    activeAimDotCurrentPos = nil
end

-- RenderStepped loop to continuously update aim dot position with smooth lerp
local aimDotUpdateConn = nil
local aimDotFrameCounter = 0
local AIM_DOT_UPDATE_INTERVAL = 2 -- Update every N frames when no target
local function startAimDotUpdateLoop()
    if aimDotUpdateConn then return end
    aimDotUpdateConn = RunService.RenderStepped:Connect(function(deltaTime)
        -- If disabled, clear and skip
        if not AIM_DOT_ENABLED then
            if activeAimDot then clearAimDot() end
            return
        end
        
        -- Ensure dot exists
        if not activeAimDot or not activeAimDot.Parent or not activeAimDotPart or not activeAimDotPart.Parent then
            createAimDot()
        end
        
        if not activeAimDotPart then return end
        
        -- Determine target position
        local targetPos = nil
        local hasActiveTarget = false
        
        -- Priority 1: Auto shoot active target (when auto shooting is in progress)
        if autoShootActive and autoShootCurrentTarget and autoShootCurrentTarget.Parent then
            targetPos = autoShootCurrentTarget.Position
            hasActiveTarget = true
            if type(getPredictedAimPosition) == "function" then
                local predicted = getPredictedAimPosition(autoShootCurrentTarget)
                if predicted then targetPos = predicted end
            end
        -- Priority 2: Silent aim target (when silent aim is enabled and has a target)
        elseif silentAimCurrentTarget and silentAimCurrentTarget.Parent then
            local hasSilentAim = SILENT_AIM_ENABLED or SILENT_AIM_SAVE_PLAYERS_ENABLED or SILENT_AIM_BOMBER_NEAR_ENABLED
            if hasSilentAim then
                targetPos = silentAimCurrentTarget.Position
                hasActiveTarget = true
                if type(getPredictedAimPosition) == "function" then
                    local predicted = getPredictedAimPosition(silentAimCurrentTarget)
                    if predicted then targetPos = predicted end
                end
            end
        -- Priority 3: Active aim part from auto shoot system
        elseif activeAimPart and activeAimPart.Parent then
            -- We have a target - get predicted aim position
            targetPos = activeAimPart.Position
            hasActiveTarget = true
            -- Try to get predicted position with velocity
            if type(getPredictedAimPosition) == "function" then
                local predicted = getPredictedAimPosition(activeAimPart)
                if predicted then
                    targetPos = predicted
                end
            elseif type(getAimPosition) == "function" then
                local predicted = getAimPosition(activeAimPart)
                if predicted then
                    targetPos = predicted
                end
            end
        end
        
        -- Performance: Skip frames when no active target (dot just resting at head)
        if not hasActiveTarget then
            aimDotFrameCounter = aimDotFrameCounter + 1
            if aimDotFrameCounter < AIM_DOT_UPDATE_INTERVAL then return end
            aimDotFrameCounter = 0
        else
            aimDotFrameCounter = 0 -- Reset counter when we have a target
        end
        
        -- Fallback: rest at player's head if no target
        if not targetPos then
            targetPos = getPlayerHeadPosition()
        end
        
        if not targetPos then
            targetPos = getPlayerHeadPosition() or Vector3.new(0, 100, 0)
        end
        
        -- Initialize current position if needed
        if not activeAimDotCurrentPos then
            activeAimDotCurrentPos = activeAimDotPart.Position
        end
        
        -- Smoothly interpolate to target position
        local lerpAlpha = math.clamp(deltaTime * AIM_DOT_LERP_SPEED, 0, 1)
        activeAimDotCurrentPos = activeAimDotCurrentPos:Lerp(targetPos, lerpAlpha)
        
        -- Update anchor part position (billboard follows it)
        activeAimDotPart.Position = activeAimDotCurrentPos
    end)
end

-- Start the aim dot update loop immediately
startAimDotUpdateLoop()

local function clearActiveTargetVisuals()
    activeAimModel = nil
    activeAimPart = nil
    if activeHighlight then
        pcall(function() activeHighlight:Destroy() end)
        activeHighlight = nil
    end
    -- Don't clear aim dot here - it will smoothly return to head position
end
local function createTargetHighlight(model)
    if not model or not model.Parent then return nil end
    if activeHighlight then
        pcall(function() activeHighlight:Destroy() end)
        activeHighlight = nil
    end
    local hl = Instance.new("Highlight")
    -- Use stealth name for anti-detection
    hl.Name = _G.getRandomStealthName and _G.getRandomStealthName() or ("TgtHL_" .. math.random(10000, 99999))
    hl.Adornee = model
    hl.Parent = model
    hl.FillColor = TARGET_CHAMS_COLOR
    hl.OutlineColor = Color3.fromRGB(255, 255, 255)
    hl.FillTransparency = math.clamp(TARGET_CHAMS_TRANSPARENCY, 0, 1)
    hl.OutlineTransparency = 0
    activeHighlight = hl
    
    -- PROTECT target highlight from anti-cheat detection
    pcall(function()
        if _G.protectESP then _G.protectESP(hl) end
    end)
    
    return hl
end
local function updateActiveTargetVisuals(model, part)
    if not model or not part then
        clearActiveTargetVisuals()
        return
    end
    -- same target: just ensure state matches toggles
    if activeAimModel == model and activeAimPart == part then
        if TARGET_ESP_ENABLED and not activeHighlight then
            pcall(function() createTargetHighlight(model) end)
        end
        -- Aim dot is handled by RenderStepped loop - no need to update here
        return
    end
    -- new target
    clearActiveTargetVisuals()
    activeAimModel = model
    activeAimPart = part
    if TARGET_ESP_ENABLED then
        pcall(function() createTargetHighlight(model) end)
    end
    -- Aim dot position is handled by RenderStepped loop automatically
end

-- Notification helper
local lastReloadNotify = 0
local NOTIFY_COOLDOWN = 4
local function notifyReload()
    local now = tick()
    if now - lastReloadNotify < NOTIFY_COOLDOWN then return end
    lastReloadNotify = now
    pcall(function()
        if type(WindUI) == "table" and type(WindUI.Notify) == "function" then
            pcall(function()
                WindUI:Notify({ Title = "Auto Reload", Content = "A Round Has Been Reloaded.", Duration = 3, Icon = "refresh-cw" })
            end)
            return
        end
        pcall(function()
            StarterGui:SetCore("SendNotification", { Title = "Auto Reload"; Text = "A Round Has Been Reloaded."; Duration = 3; })
        end)
    end)
end
-- Helper: is this tool a gun?
local function isGun(tool)
    if not tool or not tool:IsA("Tool") then return false end
    local animFolder = tool:FindFirstChild("Animations")
    if not animFolder then return false end
    if animFolder:FindFirstChild("Aim") then return true end
    if animFolder:FindFirstChild("Aiming") then return true end
    return false
end
-- Utility: build a base ignore list for raycasts (players and camera zombies)
local function buildBaseIgnore()
    local baseIgnore = {}
    for _, pl in ipairs(Players:GetPlayers()) do
        local ch = pl.Character
        if ch and ch:IsA("Model") then table.insert(baseIgnore, ch) end
    end
    local camFolderInst = Workspace:FindFirstChild("Camera")
    if camFolderInst then
        for _, d in ipairs(camFolderInst:GetDescendants()) do
            if d and d:IsA("Model") and d.Name == "m_Zombie" then table.insert(baseIgnore, d) end
        end
    end
    return baseIgnore
end

local function getWallCheckOrigin()
    if LocalPlayer and LocalPlayer.Character and LocalPlayer.Character.Parent then
        local head = LocalPlayer.Character:FindFirstChild("Head")
        if head and head:IsA("BasePart") then
            return head.Position
        end
    end
    local cam = Workspace.CurrentCamera
    if cam then
        return cam.CFrame.Position
    end
    return nil
end
-- NEW: stricter, whitelist-aware obstruction check.
-- Returns true => obstructed; false => not obstructed.
local function isObstructedBetweenIterative(origin, targetPos, targetModel, baseIgnore)
    if not CHECK_WALLS then return false end
    if not targetPos then return false end
    
    -- Always use player's head as the origin for wall checks (more accurate detection)
    local actualOrigin = origin
    if LocalPlayer and LocalPlayer.Character then
        local head = LocalPlayer.Character:FindFirstChild("Head")
        if head and head:IsA("BasePart") then
            actualOrigin = head.Position
        end
    end
    
    if not actualOrigin then return false end
    
    local dir = targetPos - actualOrigin
    local dist = dir.Magnitude
    if dist <= 0 then return false end
    local params = RaycastParams.new()
    params.FilterType = Enum.RaycastFilterType.Blacklist
    local filter = {}
    if baseIgnore then
        for i = 1, #baseIgnore do filter[#filter + 1] = baseIgnore[i] end
    end
    -- always ignore the local player's character so we don't accidentally hit ourselves
    if LocalPlayer and LocalPlayer.Character then table.insert(filter, LocalPlayer.Character) end
    params.FilterDescendantsInstances = filter
    local maxIterations = 16
    local remainingDistance = dist
    local originPos = actualOrigin
    local dirUnit = dir.Unit
    local epsilon = 0.25
    for i = 1, maxIterations do
        local ok, result = pcall(function()
            return Workspace:Raycast(originPos, dirUnit * remainingDistance, params)
        end)
        -- If raycast failed or no hit -> clear line of sight
        if not ok or not result then
            return false
        end
        local hitInst = result.Instance
        if not hitInst then return false end
        -- If the part belongs to the targetModel, treat as clear
        if targetModel and hitInst:IsDescendantOf(targetModel) then
            return false
        end
        -- Whitelist: transparent or non-collidable parts are ignored
        local isBasePart = hitInst:IsA("BasePart")
        local transparency = isBasePart and hitInst.Transparency or 0
        local canCollide = isBasePart and hitInst.CanCollide
        local effectiveInvisible = (isBasePart and transparency >= WALL_CHECK_TRANSPARENCY_THRESHOLD)
        local nonBlocking = false
        -- If part is non-collidable or effectively invisible, ignore it
        if isBasePart and (not canCollide or effectiveInvisible) then nonBlocking = true end
        -- If part belongs to a player model or camera m_Zombie but is not the target, ignore it
        local ancestor = hitInst
        while ancestor and ancestor.Parent do
            if ancestor:IsA("Model") and (ancestor.Name == "m_Zombie") then
                nonBlocking = true; break
            end
            ancestor = ancestor.Parent
        end
        -- If hit is part of any Player character (not the target) we consider it non-blocking for aim checks
        for _, pl in ipairs(Players:GetPlayers()) do
            local ch = pl.Character
            if ch and hitInst:IsDescendantOf(ch) then nonBlocking = true; break end
        end
        if nonBlocking then
            -- add this instance to the filter and continue the ray
            table.insert(params.FilterDescendantsInstances, hitInst)
            local advancePos = result.Position + dirUnit * epsilon
            if (advancePos - actualOrigin).Magnitude >= dist - EPS then return false end
            originPos = advancePos
            remainingDistance = (targetPos - originPos).Magnitude
            -- loop continues to next iteration
        else
            -- this is a blocking object
            return true
        end
    end
    -- conservative: assume obstructed if we reached iteration limit
    return true
end

-- Helper: sample multiple positions around the aim part so we only fire when most of the part is visible.
local function getWallCheckSamplePositions(part, aimPosOverride)
    if not part or not part.Parent then return {} end
    local basePos = aimPosOverride or part.Position
    local cf = part.CFrame
    local size = part.Size or Vector3.new(1, 1, 1)
    local function axisOffset(component)
        local scaled = component * WALL_CHECK_SAMPLE_AXIS_SCALE
        if scaled < WALL_CHECK_MIN_SAMPLE_OFFSET then
            scaled = WALL_CHECK_MIN_SAMPLE_OFFSET
        end
        if scaled > WALL_CHECK_MAX_SAMPLE_OFFSET then
            scaled = WALL_CHECK_MAX_SAMPLE_OFFSET
        end
        return scaled
    end
    local xOff = axisOffset(size.X)
    local yOff = axisOffset(size.Y)
    local zOff = axisOffset(size.Z)
    local offsets = {
        Vector3.new(0, 0, 0),
        Vector3.new(0, yOff, 0),
        Vector3.new(0, -yOff, 0),
        Vector3.new(xOff, 0, 0),
        Vector3.new(-xOff, 0, 0),
        Vector3.new(0, 0, zOff),
        Vector3.new(0, 0, -zOff)
    }
    local samples = {}
    for _, offset in ipairs(offsets) do
        local worldOffset = cf:VectorToWorldSpace(offset)
        samples[#samples + 1] = basePos + worldOffset
    end
    return samples
end

local function hasClearShotOnPart(originPos, aimPart, targetModel, baseIgnore, aimPosOverride)
    if not CHECK_WALLS then return true end
    if not originPos or not aimPart or not aimPart.Parent then return false end
    local samples = getWallCheckSamplePositions(aimPart, aimPosOverride)
    if #samples == 0 then return false end
    local requiredClear = math.max(1, math.ceil(#samples * WALL_CHECK_REQUIRED_CLEAR_RATIO))
    local clearCount = 0
    for _, samplePos in ipairs(samples) do
        local obstructed = isObstructedBetweenIterative(originPos, samplePos, targetModel, baseIgnore)
        if not obstructed then
            clearCount = clearCount + 1
            if clearCount >= requiredClear then
                return true
            end
        end
    end
    return false
end
-- (Timing helper removed; prediction slider handles movement compensation)
-- Helper: check if a zombie model is moving
local function isZombieMoving(zombie)
    if not zombie or not zombie.Parent then return false end
    
    -- Try to get velocity from HumanoidRootPart or any BasePart
    local hrp = zombie:FindFirstChild("HumanoidRootPart") or zombie:FindFirstChild("Torso") or zombie:FindFirstChild("UpperTorso")
    if hrp and hrp:IsA("BasePart") then
        local vel = hrp.AssemblyLinearVelocity
        if vel and vel.Magnitude > 0.5 then -- Moving threshold
            return true
        end
    end
    
    -- Fallback: check any part's velocity
    for _, part in ipairs(zombie:GetDescendants()) do
        if part:IsA("BasePart") then
            local vel = part.AssemblyLinearVelocity
            if vel and vel.Magnitude > 0.5 then
                return true
            end
            break -- Only check one part for performance
        end
    end
    
    return false
end

-- Helper: get adornee/aim part from zombie model.
-- If moving: aim for Torso (larger target, better for prediction)
-- If stationary: aim for Head (more damage)
local function findBestAimPart(zombie)
    if not zombie or not zombie.Parent then return nil end
    
    -- Check if zombie is moving
    local moving = isZombieMoving(zombie)
    
    if moving then
        -- Moving target: prioritize Torso for better hit chance with prediction
        local torso = zombie:FindFirstChild("Torso")
            or zombie:FindFirstChild("UpperTorso")
            or zombie:FindFirstChild("HumanoidRootPart")
        if torso and torso:IsA("BasePart") then return torso end
        
        -- Fallback to head if no torso
        local head = zombie:FindFirstChild("Head", true)
        if head and head:IsA("BasePart") then return head end
    else
        -- Stationary target: prioritize Head for more damage
        local head = zombie:FindFirstChild("Head", true)
        if head and head:IsA("BasePart") then return head end
        
        -- Fallback to torso if no head
        local torso = zombie:FindFirstChild("Torso")
            or zombie:FindFirstChild("UpperTorso")
            or zombie:FindFirstChild("HumanoidRootPart")
        if torso and torso:IsA("BasePart") then return torso end
    end
    
    -- Special case: Bomber barrel (always valid target)
    local barrel = zombie:FindFirstChild("Barrel", true)
    if barrel and barrel:IsA("BasePart") then return barrel end
    
    -- Fallback: PrimaryPart or any BasePart
    if zombie.PrimaryPart and zombie.PrimaryPart:IsA("BasePart") then
        return zombie.PrimaryPart
    end
    for _, p in ipairs(zombie:GetDescendants()) do
        if p:IsA("BasePart") then
            return p
        end
    end
    return nil
end
getPredictedAimPosition = function(part)
    if not part or not part.Parent or not part:IsA("BasePart") then return nil end
    local position = part.Position
    local leadTime = tonumber(PREDICTION_DISTANCE) or 0
    if leadTime <= EPS then
        return position
    end
    local vel = part.AssemblyLinearVelocity or Vector3.new(0, 0, 0)
    local historical = getHistoricalVelocity(part)
    local recentlyMoving = hasRecentMovement(part)
    local entry = PartVelocityCache[part]
    local function isValidVelocity(v)
        return v and v.Magnitude >= PREDICTION_MIN_SPEED
    end
    if not isValidVelocity(vel) then
        local fallback = getModelVelocityFromPart(part)
        if isValidVelocity(fallback) then
            vel = fallback
        end
    end
    if not isValidVelocity(vel) and isValidVelocity(historical) then
        vel = historical
    end
    local movingNow = isValidVelocity(vel)
    if movingNow and entry then
        entry.lastSpeed = vel.Magnitude
        entry.lastMoveTime = os.clock()
    end
    if not movingNow and not recentlyMoving then
        return position
    end
    return position + vel * leadTime
end

local function getAimPosition(part, opts)
    if not part or not part.Parent or not part:IsA("BasePart") then return nil end
    opts = opts or {}
    if opts.skipPrediction then
        return part.Position
    end
    return getPredictedAimPosition(part) or part.Position
end
-- Helper: resolve zombie type from real zombie models in workspace.Zombies.Agent or workspace.Zombies.Slim
local function GetZombieTypeFromModel(model)
    if not model or not model:IsA("Model") then return nil end
    local parent = model.Parent
    
    -- Cuirassier: any model under Zombies.Slim
    if parent and parent.Name == "Slim" and parent.Parent and parent.Parent.Name == "Zombies" then
        return "Cuirassier"
    end
    
    -- Agent types: check Agent folder inside the zombie model for Type
    -- Structure: workspace.Zombies.Agent.Zombie.Agent.Type (StringValue)
    local agent = model:FindFirstChild("Agent")
    if agent then
        local typeValue = agent:FindFirstChild("Type")
        if typeValue and typeValue:IsA("StringValue") then
            local t = string.lower(typeValue.Value or "")
            if t == "normal" then return "Shambler" end
            if t == "barrel" then return "Bomber" end
            if t == "fast" then return "Runner" end
            if t == "sapper" then return "Zapper" end
            if t == "igniter" then return "Igniter" end
            if t == "cuirassier" then return "Cuirassier" end
        end
    end
    
    -- Fallback: check model attribute
    if typeof(model.GetAttribute) == "function" then
        local t = model:GetAttribute("Type")
        if type(t) == "string" then
            local lower = string.lower(t)
            if lower == "normal" then return "Shambler" end
            if lower == "barrel" then return "Bomber" end
            if lower == "fast" then return "Runner" end
            if lower == "sapper" then return "Zapper" end
            if lower == "igniter" then return "Igniter" end
            if lower == "cuirassier" then return "Cuirassier" end
        end
    end
    
    -- Fallback heuristics for detection
    if model:FindFirstChild("Barrel", true) then return "Bomber" end
    if model:FindFirstChild("Whale Oil Lantern", true) then return "Igniter" end
    if model:FindFirstChild("Sword", true) then return "Cuirassier" end
    if model:FindFirstChild("Axe", true) and model:FindFirstChild("Head", true) then return "Zapper" end
    if model:FindFirstChild("Eye", true) and not model:FindFirstChild("Axe", true) then return "Runner" end
    
    -- Default for unknown
    return "Shambler"
end
-- Helper: check if model matches a given typeName
local function isZombieOfType(model, typeName)
    if not model or not model:IsA("Model") then return false end
    if type(typeName) ~= "string" then return false end
    
    -- Use the unified GetZombieTypeFromModel which has all detection logic
    local mappedType = GetZombieTypeFromModel(model)
    return mappedType == typeName
end

-- Helper: Check if a bomber is near any teammate (within radius)
local function isBomberNearTeammate(bomberModel, radius)
    if not bomberModel then return false end
    radius = radius or BOMBER_SAFE_RADIUS
    
    local bomberPart = bomberModel:FindFirstChild("HumanoidRootPart") or bomberModel:FindFirstChildWhichIsA("BasePart")
    if not bomberPart then return false end
    local bomberPos = bomberPart.Position
    
    for _, player in ipairs(Players:GetPlayers()) do
        if player ~= LocalPlayer and player.Character then
            local hrp = player.Character:FindFirstChild("HumanoidRootPart")
            if hrp then
                local dist = (hrp.Position - bomberPos).Magnitude
                if dist <= radius then
                    return true
                end
            end
        end
    end
    return false
end

-- Helper: Check if a bomber is near the local player (within radius)
local function isBomberNearSelf(bomberModel, radius)
    if not bomberModel then return false end
    radius = radius or BOMBER_SAFE_RADIUS
    
    local bomberPart = bomberModel:FindFirstChild("HumanoidRootPart") or bomberModel:FindFirstChildWhichIsA("BasePart")
    if not bomberPart then return false end
    local bomberPos = bomberPart.Position
    
    local char = LocalPlayer.Character
    if not char then return false end
    local hrp = char:FindFirstChild("HumanoidRootPart")
    if not hrp then return false end
    
    local dist = (hrp.Position - bomberPos).Magnitude
    return dist <= radius
end

-- Helper: Check if bomber should be skipped due to safety settings
local function shouldSkipBomberForSafety(model, zombieType)
    if zombieType ~= "Bomber" then return false end
    
    if BOMBER_SAFE_TEAMMATES and isBomberNearTeammate(model, BOMBER_SAFE_RADIUS) then
        return true
    end
    
    if BOMBER_SAFE_SELF and isBomberNearSelf(model, BOMBER_SAFE_RADIUS) then
        return true
    end
    
    -- Check "Don't Shoot Near" whitelist - skip if any whitelisted player is near the bomber
    if #BomberSafetyWhitelist > 0 then
        for _, player in ipairs(Players:GetPlayers()) do
            if player ~= LocalPlayer then
                local isWhitelisted = false
                for _, name in ipairs(BomberSafetyWhitelist) do
                    if player.Name == name or player.DisplayName == name then
                        isWhitelisted = true
                        break
                    end
                end
                if isWhitelisted then
                    local char = player.Character
                    if char then
                        local hrp = char:FindFirstChild("HumanoidRootPart")
                        if hrp then
                            local bomberPart = model:FindFirstChild("HumanoidRootPart") or model:FindFirstChildWhichIsA("BasePart")
                            if bomberPart then
                                local dist = (hrp.Position - bomberPart.Position).Magnitude
                                if dist <= BOMBER_SAFE_RADIUS then
                                    return true
                                end
                            end
                        end
                    end
                end
            end
        end
    end
    
    -- If SHOOT_BOMBER_NEAR_TEAMMATES is enabled, check whitelist or all teammates
    if SHOOT_BOMBER_NEAR_TEAMMATES then
        -- If whitelist has entries, only shoot if whitelisted player is near
        if #ShootBomberNearWhitelist > 0 then
            local whitelistedPlayerNear = false
            for _, player in ipairs(Players:GetPlayers()) do
                if player ~= LocalPlayer then
                    local isWhitelisted = false
                    for _, name in ipairs(ShootBomberNearWhitelist) do
                        if player.Name == name or player.DisplayName == name then
                            isWhitelisted = true
                            break
                        end
                    end
                    if isWhitelisted then
                        local char = player.Character
                        if char then
                            local hrp = char:FindFirstChild("HumanoidRootPart")
                            if hrp then
                                local bomberPart = model:FindFirstChild("HumanoidRootPart") or model:FindFirstChildWhichIsA("BasePart")
                                if bomberPart then
                                    local dist = (hrp.Position - bomberPart.Position).Magnitude
                                    if dist <= BOMBER_SAFE_RADIUS then
                                        whitelistedPlayerNear = true
                                        break
                                    end
                                end
                            end
                        end
                    end
                end
            end
            -- Skip if no whitelisted player is near
            if not whitelistedPlayerNear then
                return true
            end
        else
            -- No whitelist, check any teammate
            if not isBomberNearTeammate(model, BOMBER_SAFE_RADIUS) then
                return true
            end
        end
    end
    
    return false
end

-- Helper: Create/update bomber radius visualization
local function updateBomberRadiusVisuals()
    if not BOMBER_VISUALIZE_RADIUS then return end
    
    local zombiesFolder = Workspace:FindFirstChild("Zombies")
    if not zombiesFolder then return end
    
    -- Track which bombers we've seen this frame
    local seenBombers = {}
    
    for _, model in ipairs(zombiesFolder:GetDescendants()) do
        if model:IsA("Model") and GetZombieTypeFromModel(model) == "Bomber" then
            seenBombers[model] = true
            
            local bomberPart = model:FindFirstChild("HumanoidRootPart") or model:FindFirstChildWhichIsA("BasePart")
            if bomberPart then
                -- Create or update visual
                if not BomberRadiusVisuals[model] then
                    local circle = Instance.new("Part")
                    -- Use stealth name for anti-detection
                    circle.Name = _G.getRandomStealthName and _G.getRandomStealthName() or ("RadVis_" .. math.random(10000, 99999))
                    circle.Shape = Enum.PartType.Cylinder
                    circle.Size = Vector3.new(0.2, BOMBER_SAFE_RADIUS * 2, BOMBER_SAFE_RADIUS * 2) -- Thin flat cylinder
                    circle.Anchored = true
                    circle.CanCollide = false
                    circle.Transparency = 0 -- Fully opaque
                    circle.Material = Enum.Material.Neon
                    circle.Color = Color3.fromRGB(255, 100, 0) -- Default orange
                    circle.CFrame = CFrame.new(bomberPart.Position) * CFrame.Angles(0, 0, math.rad(90)) -- Rotate to be flat
                    circle.Parent = Workspace
                    BomberRadiusVisuals[model] = circle
                end
                
                -- Get the bomber's foot position (ground level)
                local bomberPos = bomberPart.Position
                local footY = bomberPos.Y - 3 -- Approximate feet position (HRP is ~3 studs above ground)
                
                -- Update position - flat circle at feet level
                BomberRadiusVisuals[model].CFrame = CFrame.new(bomberPos.X, footY, bomberPos.Z) * CFrame.Angles(0, 0, math.rad(90))
                
                -- Determine circle color based on who's inside the blast radius
                local selfInside = false
                local teammateInside = false
                
                -- Check if local player is inside
                if BOMBER_SAFE_SELF then
                    local char = LocalPlayer.Character
                    if char then
                        local hrp = char:FindFirstChild("HumanoidRootPart")
                        if hrp then
                            local dist = (hrp.Position - bomberPos).Magnitude
                            if dist <= BOMBER_SAFE_RADIUS then
                                selfInside = true
                            end
                        end
                    end
                end
                
                -- Check if any teammate is inside
                if BOMBER_SAFE_TEAMMATES then
                    for _, player in ipairs(Players:GetPlayers()) do
                        if player ~= LocalPlayer and player.Character then
                            local hrp = player.Character:FindFirstChild("HumanoidRootPart")
                            if hrp then
                                local dist = (hrp.Position - bomberPos).Magnitude
                                if dist <= BOMBER_SAFE_RADIUS then
                                    teammateInside = true
                                    break
                                end
                            end
                        end
                    end
                end
                
                -- Set color: Red if self inside (priority), Yellow if teammate inside, Orange otherwise
                if selfInside then
                    BomberRadiusVisuals[model].Color = Color3.fromRGB(255, 0, 0) -- Red
                elseif teammateInside then
                    BomberRadiusVisuals[model].Color = Color3.fromRGB(255, 255, 0) -- Yellow
                else
                    BomberRadiusVisuals[model].Color = Color3.fromRGB(255, 100, 0) -- Default orange
                end
            end
        end
    end
    
    -- Clean up visuals for bombers that no longer exist
    for model, visual in pairs(BomberRadiusVisuals) do
        if not seenBombers[model] or not model.Parent then
            pcall(function() visual:Destroy() end)
            BomberRadiusVisuals[model] = nil
        end
    end
end

-- Run bomber visualization loop (deferred to prevent load freeze)
task.defer(function()
    task.wait(2) -- Stagger start
    while true do
        task.wait(0.5) -- Reduced frequency for performance
        if BOMBER_VISUALIZE_RADIUS then
            if _G.KatchiPerf then _G.KatchiPerf.markActive("BomberVis") end
            pcall(updateBomberRadiusVisuals)
        end
    end
end)

-- Helper: Check if zombie is still spawning (skip if State == "Spawn")
local function isZombieSpawning(model)
    if not model then return false end
    -- Check direct State on model (workspace.Zombies.ZombieName.State)
    local state = model:FindFirstChild("State")
    if state and state:IsA("StringValue") and state.Value == "Spawn" then
        return true
    end
    -- Also check Agent.State (for some zombie types)
    local agent = model:FindFirstChild("Agent")
    if agent then
        local agentState = agent:FindFirstChild("State")
        if agentState and agentState:IsA("StringValue") and agentState.Value == "Spawn" then
            return true
        end
    end
    return false
end

-- Get nearest zombie among selected types; returns aimPart, zombieModel, typeName
-- Scans workspace.Camera for visual models (for targeting) but can use real zombies for velocity
local function getNearestSelectedZombie(range, selectionList, useFovFlag, fovChecker)
    range = range or MAX_TARGET_RANGE
    local cam = Workspace.CurrentCamera
    local originPos
    if LocalPlayer and LocalPlayer.Character and LocalPlayer.Character.Parent then
        local head = LocalPlayer.Character:FindFirstChild("Head")
        if head and head:IsA("BasePart") then
            originPos = head.Position
        end
    end
    if not originPos and cam then
        originPos = cam.CFrame.Position
    end
    if not originPos then
        return nil, nil, nil
    end
    local baseIgnore = buildBaseIgnore()
    local bestPart, bestDist, bestModel, bestType = nil, range + EPS, nil, nil
    
    -- build a selected types lookup
    local selection = selectionList or SelectedShootTypes
    local sel = {}
    for _, t in ipairs(selection or {}) do
        sel[t] = true
    end
    if not next(sel) then
        return nil, nil, nil
    end
    -- choose FOV config (defaults to auto-shoot FOV)
    local useFov = (useFovFlag ~= nil) and useFovFlag or USE_FOV
    local fovFunc = fovChecker or isWorldPosInFov
    
    -- Scan real zombies in workspace.Zombies using GetAttribute("Type") for accurate detection
    local zombiesFolder = Workspace:FindFirstChild("Zombies")
    if not zombiesFolder then
        return nil, nil, nil
    end
    
    -- Scan all descendants in Zombies folder (covers Agent, Slim, and any other subfolders)
    for _, model in ipairs(zombiesFolder:GetDescendants()) do
        if model:IsA("Model") then
            -- Skip zombies that are still spawning
            if isZombieSpawning(model) then
                -- Zombie is spawning, skip it
            else
                -- Use GetZombieTypeFromModel which checks GetAttribute("Type") first
                local matchedType = GetZombieTypeFromModel(model)
                
                -- Check if this zombie type is selected
                if matchedType and sel[matchedType] then
                    -- Check bomber safety before targeting
                    if shouldSkipBomberForSafety(model, matchedType) then
                        -- Skip this bomber - too close to teammate or self
                    else
                        local aimPart = findBestAimPart(model)
                        if aimPart and aimPart:IsA("BasePart") then
                            local aimPos = getAimPosition(aimPart)
                            local passedFovCheck = true
                            if useFov then
                                local okFov, inFov = pcall(function()
                                    return fovFunc(aimPos)
                                end)
                                if not okFov or not inFov then
                                    passedFovCheck = false
                                end
                            end
                            if passedFovCheck then
                                local okDist, d = pcall(function()
                                    return (aimPos - originPos).Magnitude
                                end)
                                if okDist and d and d <= range + EPS and d < bestDist then
                                    -- Wall check for real zombies too
                                    local okVis, hasClear = pcall(function()
                                        return hasClearShotOnPart(originPos, aimPart, model, baseIgnore)
                                    end)
                                    if okVis and hasClear then
                                        bestPart, bestDist, bestModel, bestType = aimPart, d, model, matchedType
                                    end
                                end
                            end
                        end
                    end
                end
            end
        end
    end
    
    return bestPart, bestModel, bestType
end

-- Get nearest zombie Torso to a visible player that needs saving
-- RETURNS: zombieTorso, zombieModel, targetPlayer
-- Now scans workspace.Zombies.Agent and workspace.Zombies.Slim for real zombie models with proper velocity
local function getNearestZombieToSavePlayer(range)
    -- (unchanged from original)
    local cam = Workspace.CurrentCamera
    local originPos
    if LocalPlayer and LocalPlayer.Character and LocalPlayer.Character.Parent then
        local head = LocalPlayer.Character:FindFirstChild("Head")
        if head and head:IsA("BasePart") then
            originPos = head.Position
        end
    end
    if not originPos and cam then
        originPos = cam.CFrame.Position
    end
    if not originPos then
        return nil, nil, nil
    end
    local wsPlayersFolder = Workspace:FindFirstChild("Players")
    local zombiesFolder = Workspace:FindFirstChild("Zombies")
    if not wsPlayersFolder or not zombiesFolder then
        return nil, nil, nil
    end
    local baseIgnore = buildBaseIgnore()
    local bestZombieTorso, bestZombieModel, bestPlayer, bestDist = nil, nil, nil, range + EPS
    
    -- Helper to scan a zombie folder
    local function scanZombieFolder(folder)
        if not folder then return end
        for _, model in ipairs(folder:GetChildren()) do
            if model:IsA("Model") then
                -- Skip zombies that are still spawning
                if isZombieSpawning(model) then
                    continue
                end
                local zombieTorso = model:FindFirstChild("Torso") or model:FindFirstChild("UpperTorso") or model:FindFirstChild("HumanoidRootPart")
                if zombieTorso and zombieTorso:IsA("BasePart") then
                    local zombiePos = getAimPosition(zombieTorso, { skipPrediction = true })
                    -- Check against each grabbed player
                    for _, player in ipairs(Players:GetPlayers()) do
                        if player ~= LocalPlayer then
                            -- Check whitelist: if whitelist has entries, only save whitelisted players
                            local shouldSavePlayer = true
                            if #AutoSaveWhitelist > 0 then
                                shouldSavePlayer = false
                                for _, name in ipairs(AutoSaveWhitelist) do
                                    if player.Name == name or player.DisplayName == name then
                                        shouldSavePlayer = true
                                        break
                                    end
                                end
                            end
                            if shouldSavePlayer then
                                local playerFolder = wsPlayersFolder:FindFirstChild(player.Name)
                                if playerFolder then
                                    local userStates = playerFolder:FindFirstChild("UserStates")
                                    if userStates then
                                        local grabbedVal = userStates:FindFirstChild("Grabbed")
                                        local pinVal = userStates:FindFirstChild("Pin")
                                        local grabbed = (grabbedVal and tonumber(grabbedVal.Value) or 0) ~= 0
                                        local pinnedVal = (pinVal and pinVal.Value) or ""
                                        local pinned = pinnedVal == "RunnerAttack" or pinnedVal == "RunnerClaw" or pinnedVal == "RunnerVomit"
                                        if grabbed or pinned then
                                            local character = player.Character
                                            local humanoid = character and character:FindFirstChildOfClass("Humanoid")
                                            if humanoid and humanoid.Health >= 1 then
                                                if character and character:IsA("Model") then
                                                    local playerRoot = character:FindFirstChild("HumanoidRootPart")
                                                    if playerRoot and playerRoot:IsA("BasePart") then
                                                        local hasClearToPlayer = hasClearShotOnPart(originPos, playerRoot, character, baseIgnore)
                                                        if hasClearToPlayer then
                                                            local okDist, d = pcall(function()
                                                                return (zombiePos - playerRoot.Position).Magnitude
                                                            end)
                                                            if okDist and d and d <= range + EPS and d < bestDist then
                                                                local hasClearToZombie = hasClearShotOnPart(originPos, zombieTorso, model, baseIgnore)
                                                                if hasClearToZombie then
                                                                    bestZombieTorso = zombieTorso
                                                                    bestZombieModel = model
                                                                    bestPlayer = player
                                                                    bestDist = d
                                                                end
                                                            end
                                                        end
                                                    end
                                                end
                                            end
                                        end
                                    end
                                end
                            end
                        end
                    end
                end
            end
        end
    end
    
    -- Scan both Agent and Slim folders
    scanZombieFolder(zombiesFolder:FindFirstChild("Agent"))
    scanZombieFolder(zombiesFolder:FindFirstChild("Slim"))
    
    -- If no result from real zombies, fallback to Camera folder
    if not bestZombieTorso then
        local camFolder = Workspace:FindFirstChild("Camera")
        if camFolder then
            for _, player in ipairs(Players:GetPlayers()) do
                if player ~= LocalPlayer then
                    local playerFolder = wsPlayersFolder:FindFirstChild(player.Name)
                    if playerFolder then
                        local userStates = playerFolder:FindFirstChild("UserStates")
                        if userStates then
                            local grabbedVal = userStates:FindFirstChild("Grabbed")
                            local pinVal = userStates:FindFirstChild("Pin")
                            local grabbed = (grabbedVal and tonumber(grabbedVal.Value) or 0) ~= 0
                            local pinnedVal = (pinVal and pinVal.Value) or ""
                            local pinned = pinnedVal == "RunnerAttack" or pinnedVal == "RunnerClaw" or pinnedVal == "RunnerVomit"
                            if grabbed or pinned then
                                local character = player.Character
                                local humanoid = character and character:FindFirstChildOfClass("Humanoid")
                                if humanoid and humanoid.Health >= 1 then
                                    if character and character:IsA("Model") then
                                        local playerRoot = character:FindFirstChild("HumanoidRootPart")
                                        if playerRoot and playerRoot:IsA("BasePart") then
                                            local hasClearToPlayer = hasClearShotOnPart(originPos, playerRoot, character, baseIgnore)
                                            if hasClearToPlayer then
                                                for _, model in ipairs(camFolder:GetChildren()) do
                                                    if model:IsA("Model") and model.Name == "m_Zombie" then
                                                        -- Skip zombies that are still spawning
                                                        if isZombieSpawning(model) then
                                                            continue
                                                        end
                                                        local zombieTorso = model:FindFirstChild("Torso") or model:FindFirstChild("UpperTorso")
                                                        if zombieTorso and zombieTorso:IsA("BasePart") then
                                                            local zombiePos = getAimPosition(zombieTorso, { skipPrediction = true })
                                                            local okDist, d = pcall(function()
                                                                return (zombiePos - playerRoot.Position).Magnitude
                                                            end)
                                                            if okDist and d and d <= range + EPS and d < bestDist then
                                                                local hasClearToZombie = hasClearShotOnPart(originPos, zombieTorso, model, baseIgnore)
                                                                if hasClearToZombie then
                                                                    bestZombieTorso = zombieTorso
                                                                    bestZombieModel = model
                                                                    bestPlayer = player
                                                                    bestDist = d
                                                                end
                                                            end
                                                        end
                                                    end
                                                end
                                            end
                                        end
                                    end
                                end
                            end
                        end
                    end
                end
            end
        end
    end
    
    return bestZombieTorso, bestZombieModel, bestPlayer
end
-- ShotsLoaded helper, findRemote, reload/watch functions (unchanged)
local function getShotsLoadedForTool(tool)
    if not tool then return 0 end
    local s = tool:FindFirstChild("ShotsLoaded")
    if s and (s:IsA("IntValue") or s:IsA("NumberValue")) then return s.Value end
    local wsPlayersFolder = Workspace:FindFirstChild("Players")
    if not wsPlayersFolder then return 0 end
    local playerFolder = wsPlayersFolder:FindFirstChild(LocalPlayer.Name)
    if not playerFolder then return 0 end
    local toolFolder = playerFolder:FindFirstChild(tool.Name)
    if not toolFolder then return 0 end
    local shots = toolFolder:FindFirstChild("ShotsLoaded")
    if shots and (shots:IsA("IntValue") or shots:IsA("NumberValue")) then return shots.Value end
    return 0
end
local function findRemoteForTool(tool)
    if not tool then return nil end
    local remote = tool:FindFirstChild("RemoteEvent")
    if remote then return remote end
    local wsPlayersFolder = Workspace:FindFirstChild("Players")
    if not wsPlayersFolder then return nil end
    local playerFolder = wsPlayersFolder:FindFirstChild(LocalPlayer.Name)
    if not playerFolder then return nil end
    local toolFolder = playerFolder:FindFirstChild(tool.Name)
    if not toolFolder then return nil end
    return toolFolder:FindFirstChild("RemoteEvent")
end

-- Special reload handlers for specific gun types
local function reloadNockGun(tool)
    -- Nock Gun: StartReload, then spam Reload until ShotsLoaded reaches 7 (only if under 7)
    if not tool then return end
    
    -- Prevent overlapping reloads for the same tool
    if reloadInProgress[tool] then return end
    reloadInProgress[tool] = true
    
    local shots = getShotsLoadedForTool(tool)
    if shots >= 7 then
        print("Nock Gun already full: ShotsLoaded =", shots)
        reloadInProgress[tool] = nil
        return
    end
    
    local remote = findRemoteForTool(tool) or tool:FindFirstChild("RemoteEvent")
    if not remote then
        reloadInProgress[tool] = nil
        return
    end
    
    -- Step 1: Fire StartReload
    pcall(function() _G.SafeFireServer(remote, "StartReload") end)
    task.wait(0.1)
    
    -- Step 2: Spam Reload until ShotsLoaded is 7
    local attempts = 0
    local maxAttempts = 50
    while attempts < maxAttempts do
        local currentShots = getShotsLoadedForTool(tool)
        if currentShots >= 7 then
            print("Nock Gun reload complete: ShotsLoaded =", currentShots)
            -- Unequip and re-equip when full
            pcall(function() tool.Parent = LocalPlayer.Backpack end)
            task.wait(0.02)
            pcall(function() tool.Parent = LocalPlayer.Character end)
            break
        end
        pcall(function() _G.SafeFireServer(remote, "Reload") end)
        task.wait(0.05)
        attempts = attempts + 1
    end
    
    reloadInProgress[tool] = nil
end

local function reloadDoubleBarrelPistol(tool)
    -- Double Barrel Pistol: spam Reload until ShotsLoaded reaches 2 (only if at 0)
    if not tool then return end
    
    -- Prevent overlapping reloads for the same tool
    if reloadInProgress[tool] then return end
    reloadInProgress[tool] = true
    
    local shots = getShotsLoadedForTool(tool)
    if shots ~= 0 then
        print(tool.Name .. " has shots remaining: ShotsLoaded =", shots)
        reloadInProgress[tool] = nil
        return
    end
    
    local remote = findRemoteForTool(tool) or tool:FindFirstChild("RemoteEvent")
    if not remote then
        reloadInProgress[tool] = nil
        return
    end
    
    local attempts = 0
    local maxAttempts = 50
    while attempts < maxAttempts do
        local currentShots = getShotsLoadedForTool(tool)
        if currentShots >= 2 then
            print(tool.Name .. " reload complete: ShotsLoaded =", currentShots)
            -- Unequip and re-equip when full
            reloadInProgress[tool] = nil  -- Clear flag before unequip/reequip
            pcall(function() tool.Parent = LocalPlayer.Backpack end)
            task.wait(0.02)
            pcall(function() tool.Parent = LocalPlayer.Character end)
            task.wait(0.1)  -- Wait for reequip to complete
            return
        end
        pcall(function() _G.SafeFireServer(remote, "Reload") end)
        task.wait(0.05)
        attempts = attempts + 1
    end
    
    reloadInProgress[tool] = nil
end

local function reloadHorseArtilleryPistol(tool)
    -- Horse Artillery Pistol: StartReload, then spam Reload until ShotsLoaded reaches 2 (only if at 0)
    if not tool then return end
    
    -- Prevent overlapping reloads for the same tool
    if reloadInProgress[tool] then return end
    reloadInProgress[tool] = true
    
    local shots = getShotsLoadedForTool(tool)
    if shots ~= 0 then
        print(tool.Name .. " has shots remaining: ShotsLoaded =", shots)
        reloadInProgress[tool] = nil
        return
    end
    
    local remote = findRemoteForTool(tool) or tool:FindFirstChild("RemoteEvent")
    if not remote then
        reloadInProgress[tool] = nil
        return
    end
    
    -- Step 1: Fire StartReload
    pcall(function() _G.SafeFireServer(remote, "StartReload") end)
    task.wait(0.1)

    -- Step 2: Spam Reload until ShotsLoaded is 2
    local attempts = 0
    local maxAttempts = 50
    while attempts < maxAttempts do
        local currentShots = getShotsLoadedForTool(tool)
        if currentShots >= 2 then
            -- Unequip and re-equip when full
            reloadInProgress[tool] = nil  -- Clear flag before unequip/reequip
            
            -- Verify tool still exists and is in character
            if tool and tool.Parent == LocalPlayer.Character then
                pcall(function() 
                    tool.Parent = LocalPlayer.Backpack
                end)
                task.wait(0.02)
                pcall(function() 
                    tool.Parent = LocalPlayer.Character
                end)
                task.wait(0.1)  -- Wait for reequip to complete
            end
            return
        end
        pcall(function() _G.SafeFireServer(remote, "Reload") end)
        task.wait(0.05)
        attempts = attempts + 1
    end
    
    reloadInProgress[tool] = nil
end

local function quickUnequipReequip(tool)
    -- Quickly move tool from Character to Backpack and back
    if not tool or not tool.Parent then return end
    
    task.spawn(function()
        pcall(function()
            -- Move to Backpack
            tool.Parent = LocalPlayer.Backpack
        end)
        task.wait(0.02)  -- Very fast unequip
        pcall(function()
            -- Move back to Character
            tool.Parent = LocalPlayer.Character
        end)
    end)
end

local function reloadNormalGun(tool)
    -- All other guns: just fire Reload once
    if not tool then return end
    
    -- Prevent overlapping reloads for the same tool
    if reloadInProgress[tool] then return end
    reloadInProgress[tool] = true
    
    local remote = findRemoteForTool(tool) or tool:FindFirstChild("RemoteEvent")
    if not remote then
        reloadInProgress[tool] = nil
        return
    end
    pcall(function() _G.SafeFireServer(remote, "Reload") end)
    
    -- When ShotsLoaded reaches 1, unequip and re-equip the gun
    task.wait(0.2)
    local shots = getShotsLoadedForTool(tool)
    if shots == 1 then
        quickUnequipReequip(tool)
    end
    
    reloadInProgress[tool] = nil
end
local function tryReloadTool(tool)
    if not tool then return end
    if not AUTO_RELOAD_ENABLED then return end
    if not isGun(tool) then return end
    local shots = getShotsLoadedForTool(tool)
    
    if tool.Name == "Horse Artillery Pistol" then
        print("tryReloadTool: Checking Horse Artillery Pistol, shots =", shots)
    end
    
    -- Determine if reload is needed based on gun type
    local shouldReload = false
    if tool.Name == "Nock Gun" then
        shouldReload = shots < 7
    elseif tool.Name == "Double Barrel Pistol" or tool.Name == "Horse Artillery Pistol" then
        shouldReload = shots == 0
    else
        shouldReload = shots == 0  -- Normal guns reload only when empty
    end
    
    if tool.Name == "Horse Artillery Pistol" then
        print("tryReloadTool: Horse Artillery Pistol shouldReload =", shouldReload)
    end
    
    if shouldReload then
        if tool.Name == "Horse Artillery Pistol" then
            print("tryReloadTool: Spawning reloadHorseArtilleryPistol")
        end
        -- Check gun name and fire appropriate reload sequence
        if tool.Name == "Nock Gun" then
            task.spawn(reloadNockGun, tool)
        elseif tool.Name == "Double Barrel Pistol" then
            task.spawn(reloadDoubleBarrelPistol, tool)
        elseif tool.Name == "Horse Artillery Pistol" then
            task.spawn(reloadHorseArtilleryPistol, tool)
        else
            task.spawn(reloadNormalGun, tool)
        end
    end
end

-- Simulate reload animations locally when auto-reload fires.
-- Plays reload animations found in the tool's `Animations` folder (ReloadP1/ReloadP2/ReloadP3/Reload)
local function simulateReloadAnimations(tool, forcePlay)
    if not tool then return end
    local char = LocalPlayer and LocalPlayer.Character
    if not char then return end
    local humanoid = char:FindFirstChildOfClass("Humanoid")
    if not humanoid then return end
    local animator = humanoid:FindFirstChildOfClass("Animator") or Instance.new("Animator", humanoid)
    if not animator then return end

    -- We'll search for specific animation names in several likely locations
    local function findAnimationByName(name)
        if not name then return nil end
        -- 1) tool.Animations
        local animFolder = tool:FindFirstChild("Animations")
        if animFolder then
            local a = animFolder:FindFirstChild(name)
            if a and a:IsA("Animation") then return a end
        end
        -- 2) tool.Model or ModelReference -> Animations
        local modelRef = tool:FindFirstChild("Model") or tool:FindFirstChild("ModelReference")
        if modelRef then
            local model = (modelRef.Value and modelRef.Value) or modelRef
            if model and model:IsA("Model") then
                local mf = model:FindFirstChild("Animations")
                if mf then
                    local a = mf:FindFirstChild(name)
                    if a and a:IsA("Animation") then return a end
                end
            end
        end
        -- 3) Workspace.Players.<LocalPlayer>.<ToolName>.Animations (decompiled-style path)
        local wsPlayers = Workspace:FindFirstChild("Players")
        if wsPlayers and LocalPlayer and LocalPlayer.Name then
            local playerFolder = wsPlayers:FindFirstChild(LocalPlayer.Name)
            if playerFolder then
                local toolFolder = playerFolder:FindFirstChild(tool.Name)
                if toolFolder then
                    local af = toolFolder:FindFirstChild("Animations")
                    if af then
                        local a = af:FindFirstChild(name)
                        if a and a:IsA("Animation") then return a end
                    end
                end
            end
        end
        -- 4) search descendants as a last resort
        for _, d in ipairs(tool:GetDescendants()) do
            if d.Name == name and d:IsA("Animation") then return d end
        end
        return nil
    end

    local order = {"HammerDownLoaded", "ReloadP1", "ReloadP2", "HammerPull"}
    local seq = {}
    for _, name in ipairs(order) do
        local anim = findAnimationByName(name)
        if anim then table.insert(seq, anim) end
    end
    -- nothing to play
    if #seq == 0 then return end

    -- Helper: try to find a cartridge part in the tool or its model
    local function findCartridgePart(tool)
        if not tool then return nil end
        if tool:FindFirstChild("Cartridge") and tool.Cartridge:IsA("BasePart") then
            return tool.Cartridge
        end
        local model = tool:FindFirstChild("Model") or tool:FindFirstChild("ModelReference")
        if model and model.Value and model.Value:IsA("Model") then
            local c = model.Value:FindFirstChild("Cartridge")
            if c and c:IsA("BasePart") then return c end
        elseif model and model:IsA("Model") then
            local c = model:FindFirstChild("Cartridge")
            if c and c:IsA("BasePart") then return c end
        end
        return nil
    end

    -- Play sequentially without blocking main thread, and respond to animation markers
    task.spawn(function()
        local rightPart = nil
        local char = LocalPlayer and LocalPlayer.Character
        if char then
            rightPart = char:FindFirstChild("RightHand") or char:FindFirstChild("Right Arm") or char:FindFirstChild("RightLowerArm") or char:FindFirstChild("RightUpperArm") or char:FindFirstChild("RightArm")
        end

        local handCart = nil
        local originalCartridge = findCartridgePart(tool)

        for _, anim in ipairs(seq) do
            local ok, track = pcall(function() return animator:LoadAnimation(anim) end)
            if not ok or not track then
                task.wait(0.02)
            else
                track.Priority = Enum.AnimationPriority.Action

                -- Connect common marker events if available
                local conns = {}
                local function safeConnect(mName, fn)
                    local succ, conn = pcall(function() return track:GetMarkerReachedSignal(mName):Connect(fn) end)
                    if succ and conn then table.insert(conns, conn) end
                end

                safeConnect("HandCart", function()
                    -- create a hand cart clone and weld to right arm
                    if handCart then return end
                    local cartSrc = originalCartridge
                    if not cartSrc then
                        -- try to find a Cartridge under tool model
                        cartSrc = tool:FindFirstChild("Cartridge") or (tool:FindFirstChild("Model") and tool.Model:FindFirstChild("Cartridge"))
                    end
                    if cartSrc and rightPart then
                        local ok2, cloned = pcall(function() return cartSrc:Clone() end)
                        if ok2 and cloned then
                            cloned.Parent = tool
                            cloned.Transparency = 0
                            local weld = Instance.new("Weld")
                            weld.Part0 = rightPart
                            weld.Part1 = cloned
                            weld.C0 = CFrame.new(0, -0.85, -0.4)
                            weld.Parent = cloned
                            handCart = cloned
                        end
                    end
                end)

                safeConnect("HandCartOff", function()
                    if handCart and handCart.Parent then
                        handCart:Destroy()
                        handCart = nil
                    end
                    if originalCartridge and originalCartridge:IsA("BasePart") then
                        pcall(function() originalCartridge.Transparency = 0 end)
                    end
                end)

                safeConnect("PourPowder", function()
                    if handCart then
                        local powder = handCart:FindFirstChild("Powder", true)
                        if powder and powder:IsA("ParticleEmitter") then
                            powder.Enabled = true
                            task.delay(0.3, function() pcall(function() powder.Enabled = false end) end)
                        end
                    else
                        -- try to find particle on tool
                        local powder = tool:FindFirstChild("Powder", true)
                        if powder and powder:IsA("ParticleEmitter") then
                            powder.Enabled = true
                            task.delay(0.3, function() pcall(function() powder.Enabled = false end) end)
                        end
                    end
                end)

                safeConnect("CartOff", function()
                    if originalCartridge and originalCartridge:IsA("BasePart") then
                        pcall(function() originalCartridge.Transparency = 1 end)
                    end
                end)

                safeConnect("RipCart", function()
                    if handCart then
                        local ripped = handCart:FindFirstChild("Ripped")
                        if ripped then
                            ripped.Transparency = 0
                            handCart.Transparency = 1
                        end
                    end
                end)

                safeConnect("CartridgeStart", function()
                    if originalCartridge and originalCartridge:IsA("BasePart") then
                        pcall(function()
                            if originalCartridge.Parent and originalCartridge.Parent:IsA("Model") then
                                -- try to nudge weld if present
                                for _, w in ipairs(originalCartridge:GetJoints()) do
                                    if w:IsA("Weld") then
                                        w.C1 = w.C1 * CFrame.new(0, -0.03, 0)
                                        break
                                    end
                                end
                            end
                        end)
                    end
                end)

                -- Play and wait
                track:Play(0.02, 1, 1)
                pcall(function() track.Stopped:Wait() end)

                -- cleanup connections
                for _, c in ipairs(conns) do pcall(function() c:Disconnect() end) end
                task.wait(0.02)
            end
        end

        -- ensure handCart cleanup
        if handCart and handCart.Parent then
            pcall(function() handCart:Destroy() end)
            handCart = nil
        end
    end)
end
local function watchShotsForTool(tool)
    if not tool then return end
    if not isGun(tool) then return end
    if watchedTools[tool] then return end
    watchedTools[tool] = true
    local function attach(shotsObj, reloadRemote)
        if not shotsObj then return end
        local prevVal = (shotsObj.Value ~= nil) and shotsObj.Value or 0
        
        -- Initial check: reload if below threshold for this gun
        if AUTO_RELOAD_ENABLED then
            local shouldReload = false
            if tool.Name == "Nock Gun" then
                shouldReload = prevVal < 7
            elseif tool.Name == "Double Barrel Pistol" or tool.Name == "Horse Artillery Pistol" then
                shouldReload = prevVal == 0
            else
                shouldReload = prevVal == 0
            end
            
            if tool.Name == "Horse Artillery Pistol" then
                print("watchShotsForTool INITIAL: Horse Artillery Pistol detected, prevVal =", prevVal, ", shouldReload =", shouldReload, ", reloadRemote =", reloadRemote ~= nil)
            end
            
            if shouldReload and reloadRemote then
                if tool.Name == "Horse Artillery Pistol" then
                    print("watchShotsForTool INITIAL: Spawning reloadHorseArtilleryPistol")
                end
                if tool.Name == "Nock Gun" then
                    task.spawn(reloadNockGun, tool)
                elseif tool.Name == "Double Barrel Pistol" then
                    task.spawn(reloadDoubleBarrelPistol, tool)
                elseif tool.Name == "Horse Artillery Pistol" then
                    task.spawn(reloadHorseArtilleryPistol, tool)
                else
                    task.spawn(reloadNormalGun, tool)
                end
            end
        end
        
        local reloadDebounce = false
        local conn
        conn = shotsObj.Changed:Connect(function()
            local v = shotsObj.Value
            if AUTO_RELOAD_ENABLED and type(v) == "number" and type(prevVal) == "number" and v > prevVal then
                for i = prevVal + 1, v do task.spawn(notifyReload) end
            end
            
            -- Check if reload is needed based on gun type
            local shouldReload = false
            if tool.Name == "Nock Gun" then
                shouldReload = v < 7
            elseif tool.Name == "Double Barrel Pistol" or tool.Name == "Horse Artillery Pistol" then
                shouldReload = v == 0
            else
                shouldReload = v == 0
            end
            
            if shouldReload and reloadRemote and not reloadDebounce then
                reloadDebounce = true
                if AUTO_RELOAD_ENABLED then
                    -- Trigger reload with appropriate handler for this tool
                    if tool.Name == "Nock Gun" then
                        task.spawn(reloadNockGun, tool)
                    elseif tool.Name == "Double Barrel Pistol" then
                        task.spawn(reloadDoubleBarrelPistol, tool)
                    elseif tool.Name == "Horse Artillery Pistol" then
                        task.spawn(reloadHorseArtilleryPistol, tool)
                    else
                        task.spawn(reloadNormalGun, tool)
                    end
                end
                task.delay(1.2, function() reloadDebounce = false end)
            end
            prevVal = v
        end)
        tool.AncestryChanged:Connect(function(_, parent)
            if not parent and conn then conn:Disconnect() end
        end)
    end
    local shotsInst = tool:FindFirstChild("ShotsLoaded")
    local remoteInst = tool:FindFirstChild("RemoteEvent")
    if shotsInst and (shotsInst:IsA("IntValue") or shotsInst:IsA("NumberValue")) then
        attach(shotsInst, remoteInst); return
    end
    local wsPlayersFolder = Workspace:FindFirstChild("Players")
    if not wsPlayersFolder then return end
    local playerFolder = wsPlayersFolder:FindFirstChild(LocalPlayer.Name)
    if not playerFolder then return end
    local toolFolder = playerFolder:FindFirstChild(tool.Name)
    local serverRemote = (toolFolder and toolFolder:FindFirstChild("RemoteEvent")) or remoteInst
    if toolFolder then
        local shots = toolFolder:FindFirstChild("ShotsLoaded")
        if shots and (shots:IsA("IntValue") or shots:IsA("NumberValue")) then attach(shots, serverRemote); return end
    end
end
-- Smoothing + animation helpers - improved with smoother easing
local function smoothLookAtDynamic(rootPart, getPosFunc, duration)
    if not rootPart or not getPosFunc then return end
    local start = tick()
    local startCFrame = rootPart.CFrame
    local ok, initTarget = pcall(getPosFunc)
    if not ok or not initTarget then return end
    
    -- Smoother ease-in-out quintic function for more natural rotation
    local function easeInOutQuint(t)
        if t < 0.5 then
            return 16 * t * t * t * t * t
        else
            local f = (2 * t) - 2
            return 0.5 * f * f * f * f * f + 1
        end
    end
    
    while tick() - start < duration do
        if not rootPart.Parent then return end
        local curPos = nil
        pcall(function() curPos = getPosFunc() end)
        if not curPos then curPos = initTarget end
        local desired = CFrame.new(rootPart.Position, Vector3.new(curPos.X, rootPart.Position.Y, curPos.Z))
        local t = math.clamp((tick() - start) / duration, 0, 1)
        -- Use smoother quintic easing for more natural rotation
        local smoothT = easeInOutQuint(t)
        local lerped = startCFrame:Lerp(desired, smoothT)
        local safeCFrame = CFrame.new(rootPart.Position, rootPart.Position + lerped.LookVector)
        pcall(function() rootPart.CFrame = safeCFrame end)
        RunService.RenderStepped:Wait()
    end
    local finalPos = nil
    pcall(function() finalPos = getPosFunc() end)
    if finalPos then pcall(function() rootPart.CFrame = CFrame.new(rootPart.Position, rootPart.Position + CFrame.new(rootPart.Position, Vector3.new(finalPos.X, rootPart.Position.Y, finalPos.Z)).LookVector) end) end
end
-- Cache for animations to avoid recreating them
-- Uses weak values so dead tracks get garbage collected
local animationCache = setmetatable({}, { __mode = "v" })
local animationCacheLastClean = 0
local function playAnimation(animId, animator)
    if not animId or not animator then return nil end
    local cacheKey = animId .. tostring(animator)
    
    -- Periodic cache cleanup (every 30 seconds)
    local now = tick()
    if now - animationCacheLastClean > 30 then
        animationCacheLastClean = now
        for key, track in pairs(animationCache) do
            if not track or not track.Parent then
                animationCache[key] = nil
            end
        end
    end
    
    -- Check cache first
    if animationCache[cacheKey] and animationCache[cacheKey].Parent then
        local track = animationCache[cacheKey]
        if track.IsPlaying then track:Stop(0.02) end
        track:Play(0.02, 1, 1)
        return track
    end
    
    local ok, track = pcall(function()
        local anim = Instance.new("Animation")
        anim.AnimationId = animId
        return animator:LoadAnimation(anim)
    end)
    if not ok or not track then return nil end
    track.Priority = Enum.AnimationPriority.Action
    track:Play(0.02, 1, 1)
    animationCache[cacheKey] = track
    return track
end
-- aimThenShootGun — Uses animations (Aim, Aiming, Fire) + remote:FireServer("Fire") with silent aim hooks
local function aimThenShootGun(targetModel, initialPart, tool, isPlayerTarget, savedPlayer)
    if not targetModel or not targetModel.Parent then return end
    if not initialPart or not initialPart.Parent or not initialPart:IsA("BasePart") then return end
    if not tool or not tool.Parent or not tool:IsDescendantOf(LocalPlayer.Character) then return end
    if not isGun(tool) then return end
    -- Bomber safety: abort if targeting a bomber that's near me or teammates
    local zombieType = GetZombieTypeFromModel and GetZombieTypeFromModel(targetModel) or nil
    if zombieType == "Bomber" and shouldSkipBomberForSafety(targetModel, zombieType) then
        return
    end
    local char = LocalPlayer.Character
    if not char then return end
    local humanoid = char:FindFirstChildOfClass("Humanoid")
    if not humanoid then return end
    local animator = humanoid:FindFirstChildOfClass("Animator") or Instance.new("Animator", humanoid)
    pcall(watchShotsForTool, tool)
    local remote = tool:FindFirstChild("RemoteEvent") or findRemoteForTool(tool)
    
    -- Discover animations from tool
    local animFolder = tool:FindFirstChild("Animations")
    local animAId, animBId, fireAnimId
    if animFolder then
        local aim = animFolder:FindFirstChild("Aim")
        local aiming = animFolder:FindFirstChild("Aiming")
        local fire = animFolder:FindFirstChild("Fire")
        if aim and aim:IsA("Animation") then animAId = aim.AnimationId end
        if aiming and aiming:IsA("Animation") then animBId = aiming.AnimationId end
        if fire and fire:IsA("Animation") then fireAnimId = fire.AnimationId end
    end
    -- Fallback animation IDs
    animAId = animAId or "rbxassetid://83511222574103"
    animBId = animBId or "rbxassetid://136849639865723"
    
    -- Origin function
    local function getAimOrigin()
        if LocalPlayer and LocalPlayer.Character and LocalPlayer.Character.Parent then
            local head = LocalPlayer.Character:FindFirstChild("Head")
            if head and head:IsA("BasePart") then return head.Position end
        end
        local cam = Workspace.CurrentCamera
        if cam then return cam.CFrame.Position end
        return nil
    end
    
    local currentTargetPart = initialPart
    local currentTargetModel = targetModel
    
    -- Helper to resolve aim position (with prediction for zombies, without for players)
    local function resolveAimPos(part)
        if not part or not part.Parent or not part:IsA("BasePart") then return nil end
        if isPlayerTarget then
            return getAimPosition(part, { skipPrediction = true })
        end
        return getAimPosition(part)
    end
    
    -- Wall check
    local origin = getAimOrigin()
    if CHECK_WALLS and origin and currentTargetPart and currentTargetPart.Parent then
        local baseIgnore = buildBaseIgnore()
        local hasClear = hasClearShotOnPart(origin, currentTargetPart, currentTargetModel, baseIgnore)
        if not hasClear then return end
    end
    
    -- Check zombie still alive
    local finalHum = currentTargetModel and currentTargetModel:FindFirstChildOfClass("Humanoid")
    if finalHum and finalHum.Health and finalHum.Health < 1 then return end
    
    -- Final bomber safety check right before firing
    if zombieType == "Bomber" and shouldSkipBomberForSafety(currentTargetModel, zombieType) then
        return
    end
    
    -- Set silent aim target so hooks redirect Mouse.Hit/Target/Raycast
    autoShootCurrentTarget = currentTargetPart
    autoShootCurrentModel = currentTargetModel
    autoShootActive = true
    
    -- Animation tracks
    local trackA, trackB, fireTrack
    
    -- Calculate timing based on AUTO_SHOOT_DELAY
    local totalDelay = AUTO_SHOOT_DELAY or 0.5
    local rotationDuration = math.max(totalDelay * 0.7, 0.2)
    
    -- Start Aim animation (trackA)
    trackA = playAnimation(animAId, animator)
    
    -- Smooth rotation to target
    local root = char:FindFirstChild("HumanoidRootPart")
    if root then
        local originalAutoRotate = humanoid.AutoRotate
        humanoid.AutoRotate = false
        
        local function getPosFunc()
            if currentTargetPart and currentTargetPart.Parent then
                return resolveAimPos(currentTargetPart)
            end
            return nil
        end
        
        -- Start rotation in parallel
        task.spawn(function()
            pcall(function() smoothLookAtDynamic(root, getPosFunc, rotationDuration) end)
        end)
        
        -- Wait for Aim animation to finish briefly
        task.wait(0.15)
        
        -- Stop trackA and start trackB (Aiming pose)
        if trackA and trackA.IsPlaying then
            pcall(function() trackA:Stop(0.1) end)
        end
        
        trackB = playAnimation(animBId, animator)
        
        -- Wait remaining time for the total delay
        local remainingWait = totalDelay - 0.15 - 0.03
        if remainingWait > 0 then
            task.wait(remainingWait)
        end
        
        humanoid.AutoRotate = originalAutoRotate
    end
    
    -- Wait for shots to be loaded
    local WAIT_TIMEOUT = 3.0
    local waited = 0
    local POLL_INTERVAL = 0.06
    local shotsNow = getShotsLoadedForTool(tool)
    while (not shotsNow or shotsNow < 1) and waited < WAIT_TIMEOUT do
        if not tool or not tool.Parent then break end
        if not (USER_AUTO_SHOOT_TOGGLE or AUTO_SAVE_PLAYERS_ENABLED) then break end
        task.wait(POLL_INTERVAL)
        waited = waited + POLL_INTERVAL
        shotsNow = getShotsLoadedForTool(tool)
    end
    
    if not shotsNow or shotsNow < 1 then
        if trackB and trackB.IsPlaying then pcall(function() trackB:Stop(0.1) end) end
        autoShootActive = false
        autoShootCurrentTarget = nil
        autoShootCurrentModel = nil
        return
    end
    
    -- Final checks before firing
    if not currentTargetPart or not currentTargetPart.Parent then
        if trackB and trackB.IsPlaying then pcall(function() trackB:Stop(0.1) end) end
        autoShootActive = false
        autoShootCurrentTarget = nil
        autoShootCurrentModel = nil
        return
    end
    if not currentTargetModel or not currentTargetModel.Parent then
        if trackB and trackB.IsPlaying then pcall(function() trackB:Stop(0.1) end) end
        autoShootActive = false
        autoShootCurrentTarget = nil
        autoShootCurrentModel = nil
        return
    end
    
    local hum = currentTargetModel:FindFirstChildOfClass("Humanoid")
    if hum and hum.Health and hum.Health < 1 then
        if trackB and trackB.IsPlaying then pcall(function() trackB:Stop(0.1) end) end
        autoShootActive = false
        autoShootCurrentTarget = nil
        autoShootCurrentModel = nil
        return
    end
    
    -- Play Fire animation
    if fireAnimId then
        fireTrack = playAnimation(fireAnimId, animator)
    end
    
    -- Fire the remote
    pcall(function()
        local modelRef = char:FindFirstChild("Model") or char
        local t = Workspace:GetServerTimeNow()
        local aimPos = resolveAimPos(currentTargetPart)
        if remote and aimPos then
            _G.SafeFireServer(remote, "Fire", modelRef, aimPos, t)
        end
    end)
    
    -- Cleanup
    if fireTrack then task.delay(0.35, function() pcall(function() fireTrack:Stop(0.07) end) end) end
    if trackB and trackB.IsPlaying then pcall(function() trackB:Stop(0.1) end) end
    
    task.delay(0.1, function()
        autoShootActive = false
        autoShootCurrentTarget = nil
        autoShootCurrentModel = nil
    end)
end

-- instantShootGun — Fires remote directly with silent aim (no animations for speed)
local function instantShootGun(targetModel, initialPart, tool, skipPrediction)
    if not targetModel or not targetModel.Parent then return end
    if not initialPart or not initialPart.Parent or not initialPart:IsA("BasePart") then return end
    if not tool or not tool.Parent or not tool:IsDescendantOf(LocalPlayer.Character) then return end
    if not isGun(tool) then return end
    -- Bomber safety: abort if targeting a bomber that's near me or teammates
    local zombieType = GetZombieTypeFromModel and GetZombieTypeFromModel(targetModel) or nil
    if zombieType == "Bomber" and shouldSkipBomberForSafety(targetModel, zombieType) then
        return
    end
    pcall(watchShotsForTool, tool)
    local char = LocalPlayer.Character
    if not char then return end
    local origin = (LocalPlayer.Character and LocalPlayer.Character:FindFirstChild("Head") and LocalPlayer.Character.Head.Position) or (Workspace.CurrentCamera and Workspace.CurrentCamera.CFrame.Position)
    if origin and CHECK_WALLS then
        local baseIgnore = buildBaseIgnore()
        local hasClear = hasClearShotOnPart(origin, initialPart, targetModel, baseIgnore)
        if not hasClear then return end
    end
    -- additional check: alive
    if targetModel and (not targetModel.Parent) then return end
    local hum = (targetModel and targetModel:FindFirstChildOfClass("Humanoid")) or nil
    if hum and hum.Health and hum.Health < 1 then return end
    
    -- Set silent aim flags so hooks redirect Mouse.Hit/Target/Raycast
    autoShootCurrentTarget = initialPart
    autoShootCurrentModel = targetModel
    autoShootActive = true
    
    -- Get aim position
    local aimPos = getAimPosition(initialPart, skipPrediction and { skipPrediction = true }) or initialPart.Position
    
    -- Fire the remote directly
    pcall(function()
        local remote = tool:FindFirstChild("RemoteEvent") or findRemoteForTool(tool)
        local modelRef = char:FindFirstChild("Model") or char
        local t = Workspace:GetServerTimeNow()
        if remote and initialPart and initialPart.Parent then
            _G.SafeFireServer(remote, "Fire", modelRef, aimPos, t)
        end
    end)
    
    -- Clear flags
    task.delay(0.05, function()
        autoShootActive = false
        autoShootCurrentTarget = nil
        autoShootCurrentModel = nil
    end)
end
-- Cleanup function for profile load
local function cleanupConnections()
    for _, conn in ipairs(activeConnections) do
        pcall(function() conn:Disconnect() end)
    end
    activeConnections = {}
    watchedTools = setmetatable({}, { __mode = "k" })
    isAiming = false
end
-- MAIN LOOP — updated to use selected types rather than bombers only
local mainLoopRunning = false
local function startMainLoop()
    if mainLoopRunning then return end
    mainLoopRunning = true
    task.spawn(function()
        while mainLoopRunning do
            local equippedTool = LocalPlayer.Character and LocalPlayer.Character:FindFirstChildOfClass("Tool")
            local equippedIsGun = equippedTool and isGun(equippedTool)
            local shotsForEquipped = (equippedTool and equippedIsGun) and getShotsLoadedForTool(equippedTool) or 0
            
            -- Check if silent aim is handling targeting (don't auto-shoot if using silent aim)
            local hasSilentAimSelection = SILENT_AIM_ENABLED and (SilentAimSelectedTypes and #SilentAimSelectedTypes > 0)
            local usingSilentAimForZombies = hasSilentAimSelection
            local usingSilentAimForSave = SILENT_AIM_ENABLED and SILENT_AIM_SAVE_PLAYERS_ENABLED
            
            -- Only auto-shoot if NOT using silent aim for that feature
            local shouldAutoShootZombies = USER_AUTO_SHOOT_TOGGLE and (not usingSilentAimForZombies)
            local shouldAutoSavePlayers = AUTO_SAVE_PLAYERS_ENABLED and (not usingSilentAimForSave)
            
            local effectiveAutoShoot = (equippedTool ~= nil) and equippedIsGun and (shotsForEquipped >= 1) and (shouldAutoShootZombies or shouldAutoSavePlayers)
            -- Attempt to auto-reload on equip if requested
            if AUTO_RELOAD_ENABLED and equippedTool and equippedIsGun then
            pcall(tryReloadTool, equippedTool)
            end
            if effectiveAutoShoot and not isAiming then
            local targetPart, targetModel, isPlayerTarget, savedPlayer = nil, nil, false, nil
            -- Save players ALWAYS first (use pcall to avoid crashes from unexpected runtime errors)
            if shouldAutoSavePlayers then
                local ok, zPart, zModel, pl = pcall(getNearestZombieToSavePlayer, MAX_SAVE_PLAYERS_RANGE)
                if ok and zPart and zModel then targetPart, targetModel, isPlayerTarget, savedPlayer = zPart, zModel, true, pl end
            end
            -- Only check selected types if no save target found
            if not targetPart and shouldAutoShootZombies then
                -- If no selection -> skip
                if SelectedShootTypes and #SelectedShootTypes > 0 then
                local sPart, sModel, sType = getNearestSelectedZombie(MAX_TARGET_RANGE)
                if sPart and sModel then targetPart, targetModel, isPlayerTarget = sPart, sModel, false end
                end
            end
            if targetPart and targetModel then
                isAiming = true
                -- update visuals immediately
                pcall(function()
                updateActiveTargetVisuals(targetModel, targetPart)
                end)
                local baseIgnoreCache = nil
                local function targetHasClearLOS(customIgnore)
                if not CHECK_WALLS then return true end
                if not targetPart or not targetPart.Parent then return false end
                local originPos = getWallCheckOrigin()
                if not originPos then return true end
                if customIgnore then
                    baseIgnoreCache = customIgnore
                elseif not baseIgnoreCache then
                    baseIgnoreCache = buildBaseIgnore()
                end
                local ignoreList = customIgnore or baseIgnoreCache
                local ok, res = pcall(function()
                    return hasClearShotOnPart(originPos, targetPart, targetModel, ignoreList)
                end)
                return ok and res
                end
                -- smarter appear delay: poll during delay so we can abort quickly
                local appearDelay = (isPlayerTarget and INSTANT_SAVE_PLAYERS_ENABLED and 0.1)
                or (not isPlayerTarget and INSTANT_SHOOT_ENABLED and 0.1)
                or APPEAR_DELAY
                local startT = tick()
                local aborted = false
                local targetZombieType = GetZombieTypeFromModel and GetZombieTypeFromModel(targetModel) or nil
                while tick() - startT < appearDelay do
                -- abort if target removed
                if not targetModel or not targetModel.Parent then aborted = true; break end
                -- if target became dead
                local hum = (targetModel and targetModel:FindFirstChildOfClass("Humanoid")) or nil
                if hum and hum.Health and hum.Health < 1 then aborted = true; break end
                -- Bomber safety: abort if targeting a bomber that enters safety zone
                if targetZombieType == "Bomber" and shouldSkipBomberForSafety(targetModel, targetZombieType) then
                    aborted = true; break
                end
                -- if player target: ensure still grabbed
                if isPlayerTarget and savedPlayer then
                    local wsPlayersFolder = Workspace:FindFirstChild("Players")
                    local playerFolder = (wsPlayersFolder and wsPlayersFolder:FindFirstChild(savedPlayer.Name)) or nil
                    local stillGrabbed = false
                    if playerFolder then
                    local userStates = playerFolder:FindFirstChild("UserStates")
                    if userStates then
                        local grabbedVal = userStates:FindFirstChild("Grabbed")
                        local pinVal = userStates:FindFirstChild("Pin")
                        local grabbed = (grabbedVal and tonumber(grabbedVal.Value) or 0) ~= 0
                        local pinState = (pinVal and pinVal.Value) or ""
                        local pinned = (pinState == "RunnerAttack" or pinState == "RunnerClaw" or pinState == "RunnerVomit")
                        stillGrabbed = grabbed or pinned
                    end
                    end
                    local plChar = savedPlayer.Character
                    local plHum = plChar and plChar:FindFirstChildOfClass("Humanoid")
                    if (not stillGrabbed) or (not plHum) or (plHum.Health < 1) then aborted = true; break end
                end
                if CHECK_WALLS then
                    if not targetHasClearLOS() then
                    aborted = true
                    break
                    end
                end
                task.wait(0.03)
                end
                if aborted then
                pcall(function() clearActiveTargetVisuals() end)
                isAiming = false
                else
                -- Final wall check before shooting
                if CHECK_WALLS then
                    local freshIgnore = buildBaseIgnore()
                    if not targetHasClearLOS(freshIgnore) then
                    pcall(function() clearActiveTargetVisuals() end)
                    isAiming = false
                    end
                end
                
                -- Final bomber safety check
                if isAiming and targetZombieType == "Bomber" and shouldSkipBomberForSafety(targetModel, targetZombieType) then
                    pcall(function() clearActiveTargetVisuals() end)
                    isAiming = false
                end
                
                -- Only proceed if still aiming (not aborted by wall check)
                if isAiming then
                    if equippedTool and equippedTool.Parent and isGun(equippedTool) then
                    local currentTool = LocalPlayer.Character and LocalPlayer.Character:FindFirstChildOfClass("Tool")
                    if currentTool and currentTool == equippedTool then
                        task.spawn(function()
                        local success, err = pcall(function()
                            if (isPlayerTarget and INSTANT_SAVE_PLAYERS_ENABLED) or (not isPlayerTarget and INSTANT_SHOOT_ENABLED) then
                            instantShootGun(targetModel, targetPart, currentTool, isPlayerTarget)
                            else
                            aimThenShootGun(targetModel, targetPart, currentTool, isPlayerTarget, savedPlayer)
                            end
                        end)
                        if not success then
                            warn("Error in shoot function: " .. tostring(err))
                        end
                        task.wait(0.05)
                        pcall(function() clearActiveTargetVisuals() end)
                        isAiming = false
                        end)
                    else
                        pcall(function() clearActiveTargetVisuals() end)
                        isAiming = false
                    end
                    else
                    pcall(function() clearActiveTargetVisuals() end)
                    isAiming = false
                    end
                end
                end
            end
            end
            task.wait(CHECK_INTERVAL)
        end
    end)
end
-- Attach watchers for tools that might be on character when script loads (and watch Equip)
local function monitorCharacterTools(char)
    if not char then return end
    -- Clean up existing connections for this character
    cleanupConnections()
    -- Attach hand mortar watcher once per character (not per tool)
    pcall(function() attachHandMortarWatcher() end)
    -- Watch existing tools
    for _, c in ipairs(char:GetChildren()) do
        if c:IsA("Tool") then
            -- Watch guns
            if isGun(c) then
                pcall(watchShotsForTool, c)
                pcall(tryReloadTool, c)
                -- Equip listener
                local ok, eqConn = pcall(function()
                    return c.Equipped:Connect(function()
                        pcall(tryReloadTool, c)
                    end)
                end)
                if ok and eqConn then table.insert(activeConnections, eqConn) end
            end
        end
    end
    -- Set up new connections for tools added later
    local childAddedConn = char.ChildAdded:Connect(function(child)
        if child and child:IsA("Tool") then
            -- Watch guns added later
            if isGun(child) then
                pcall(watchShotsForTool, child)
                pcall(tryReloadTool, child)
                local ok, eqConn = pcall(function()
                    return child.Equipped:Connect(function()
                        pcall(tryReloadTool, child)
                    end)
                end)
                if ok and eqConn then table.insert(activeConnections, eqConn) end
            end
        end
    end)
    table.insert(activeConnections, childAddedConn)
end
-- Set up character monitoring
local function setupCharacterMonitoring()
    -- Disconnect any existing CharacterAdded connection if present
    for i, conn in ipairs(activeConnections) do
        if conn == characterAddedConn then
            pcall(function() conn:Disconnect() end)
            table.remove(activeConnections, i)
            break
        end
    end
    characterAddedConn = LocalPlayer.CharacterAdded:Connect(monitorCharacterTools)
    table.insert(activeConnections, characterAddedConn)
    if LocalPlayer.Character then
        monitorCharacterTools(LocalPlayer.Character)
    end
end
-- Start the script
setupCharacterMonitoring()
startMainLoop()

-- ===== SILENT AIM HOOKS =====
-- Silent Aim redirects user-initiated shots to the current target instead of auto-shooting
-- This hooks into the game's raycast and mouse systems to redirect bullets

-- Silent Aim target update loop (updates current target for redirection)
local silentAimUpdateConn = nil
local silentAimFrameCounter = 0
local SILENT_AIM_UPDATE_INTERVAL = 5 -- Update every N frames to reduce lag (increased from 3)
local function startSilentAimLoop()
    if silentAimUpdateConn then return end
    silentAimUpdateConn = RunService.Heartbeat:Connect(function()
        -- Throttle updates to every N frames for performance
        silentAimFrameCounter = silentAimFrameCounter + 1
        if silentAimFrameCounter < SILENT_AIM_UPDATE_INTERVAL then return end
        silentAimFrameCounter = 0
        
        local hasZombieSelection = SILENT_AIM_ENABLED and (SilentAimSelectedTypes and #SilentAimSelectedTypes > 0)
        -- Only update if any silent aim feature is enabled
        if not (hasZombieSelection or SILENT_AIM_SAVE_PLAYERS_ENABLED or SILENT_AIM_BOMBER_NEAR_ENABLED) then
            silentAimCurrentTarget = nil
            silentAimCurrentModel = nil
            silentAimIsPlayerTarget = false
            silentAimSavedPlayer = nil
            return
        end
        
        -- PERFORMANCE: Mark feature as active
        if _G.KatchiPerf then _G.KatchiPerf.markActive("SilentAim") end
        
        local equippedTool = LocalPlayer.Character and LocalPlayer.Character:FindFirstChildOfClass("Tool")
        local equippedIsGun = equippedTool and isGun(equippedTool)
        if not equippedIsGun then
            silentAimCurrentTarget = nil
            silentAimCurrentModel = nil
            return
        end
        
        local targetPart, targetModel, isPlayerTarget, savedPlayer = nil, nil, false, nil
        
        -- Priority 1: Save players (if silent aim save players enabled)
        if SILENT_AIM_SAVE_PLAYERS_ENABLED and AUTO_SAVE_PLAYERS_ENABLED then
            local ok, zPart, zModel, pl = pcall(getNearestZombieToSavePlayer, MAX_SAVE_PLAYERS_RANGE)
            if ok and zPart and zModel then
                targetPart, targetModel, isPlayerTarget, savedPlayer = zPart, zModel, true, pl
            end
        end
        
        -- Priority 2: Zombie targeting (if silent aim zombie enabled)
        if not targetPart and hasZombieSelection then
            if SilentAimSelectedTypes and #SilentAimSelectedTypes > 0 then
                local sPart, sModel, sType = getNearestSelectedZombie(MAX_TARGET_RANGE, SilentAimSelectedTypes, SILENT_AIM_USE_FOV, isWorldPosInSilentAimFov)
                if sPart and sModel then
                    -- Check bomber safety if targeting bomber with silent aim bomber near
                    local zombieType = GetZombieTypeFromModel and GetZombieTypeFromModel(sModel) or nil
                    local skipBomber = false
                    if zombieType == "Bomber" then
                        if SILENT_AIM_BOMBER_NEAR_ENABLED then
                            -- Only target bombers near teammates when this is enabled
                            if not isBomberNearTeammate(sModel, BOMBER_SAFE_RADIUS) then
                                skipBomber = true
                            end
                        elseif shouldSkipBomberForSafety(sModel, zombieType) then
                            skipBomber = true
                        end
                    end
                    if not skipBomber then
                        targetPart, targetModel, isPlayerTarget = sPart, sModel, false
                    end
                end
            end
        end
        
        -- Wall check
        if targetPart and CHECK_WALLS then
            local origin = getWallCheckOrigin()
            if origin then
                local baseIgnore = buildBaseIgnore()
                local hasClear = hasClearShotOnPart(origin, targetPart, targetModel, baseIgnore)
                if not hasClear then
                    targetPart = nil
                    targetModel = nil
                end
            end
        end
        
        -- FOV check (Silent Aim-specific)
        if targetPart and SILENT_AIM_USE_FOV then
            local aimPos = getAimPosition(targetPart) or targetPart.Position
            if not isWorldPosInSilentAimFov(aimPos) then
                targetPart = nil
                targetModel = nil
            end
        end
        
        silentAimCurrentTarget = targetPart
        silentAimCurrentModel = targetModel
        silentAimIsPlayerTarget = isPlayerTarget
        silentAimSavedPlayer = savedPlayer
        
        -- Update visuals if target ESP is enabled
        if TARGET_ESP_ENABLED and targetPart and targetModel then
            pcall(function() updateActiveTargetVisuals(targetModel, targetPart) end)
        elseif TARGET_ESP_ENABLED then
            pcall(function() clearActiveTargetVisuals() end)
        end
        
        -- Auto Aim: Make character look at target if enabled
        if SILENT_AIM_AUTO_AIM and targetPart and targetPart.Parent then
            pcall(function()
                local char = LocalPlayer.Character
                local hrp = char and char:FindFirstChild("HumanoidRootPart")
                if hrp then
                    local aimPos = targetPart.Position
                    local flatAimPos = Vector3.new(aimPos.X, hrp.Position.Y, aimPos.Z)
                    local lookDir = (flatAimPos - hrp.Position)
                    if lookDir.Magnitude > 0.1 then
                        hrp.CFrame = CFrame.new(hrp.Position, flatAimPos)
                    end
                end
            end)
        end
    end)
end
startSilentAimLoop()

-- Hook into game's raycast system for silent aim redirection
local silentAimOldNamecall = nil
local silentAimOldIndex = nil

-- Recursion guards to prevent C stack overflow
local inNamecallHook = false
local inIndexHook = false

local function setupSilentAimHooks()
    -- Only set up hooks if they don't exist yet
    if silentAimOldNamecall then return end
    
    -- Check if hookmetamethod exists (executor support)
    if type(hookmetamethod) ~= "function" then
        warn("hookmetamethod not available, Silent Aim will not work on this executor")
        return
    end
    
    local checkcaller = checkcaller or function() return false end
    local Mouse = LocalPlayer:GetMouse()
    
    -- Hook __namecall for Raycast redirection
    pcall(function()
        silentAimOldNamecall = hookmetamethod(game, "__namecall", function(self, ...)
            -- Prevent recursion
            if inNamecallHook then
                return silentAimOldNamecall(self, ...)
            end
            
            local method = getnamecallmethod()
            local args = {...}
            
            -- Only intercept Raycast on Workspace
            if method ~= "Raycast" or (self ~= Workspace and self.ClassName ~= "Workspace") then
                return silentAimOldNamecall(self, ...)
            end
            
            -- Skip if caller is this script
            if checkcaller() then
                return silentAimOldNamecall(self, ...)
            end
            
            -- Determine which target to use (auto shoot takes priority when active)
            local targetToUse = nil
            if autoShootActive and autoShootCurrentTarget then
                -- Check Parent without triggering hooks
                inNamecallHook = true
                local hasParent = autoShootCurrentTarget.Parent ~= nil
                inNamecallHook = false
                if hasParent then
                    targetToUse = autoShootCurrentTarget
                end
            elseif (SILENT_AIM_ENABLED or SILENT_AIM_SAVE_PLAYERS_ENABLED or SILENT_AIM_BOMBER_NEAR_ENABLED) and silentAimCurrentTarget then
                targetToUse = silentAimCurrentTarget
            end
            
            if targetToUse then
                inNamecallHook = true
                local origin = args[1]
                -- Get position directly without calling getAimPosition to avoid recursion
                local aimPos = targetToUse.Position
                inNamecallHook = false
                
                local dir = (aimPos - origin)
                -- Redirect the ray towards the target with slight range compensation
                args[2] = dir.Unit * (dir.Magnitude + 10)
                return silentAimOldNamecall(self, unpack(args))
            end
            return silentAimOldNamecall(self, ...)
        end)
    end)
    
    -- Hook __index for Mouse.Hit and Mouse.Target redirection
    pcall(function()
        silentAimOldIndex = hookmetamethod(game, "__index", function(self, index)
            -- Prevent recursion
            if inIndexHook then
                return silentAimOldIndex(self, index)
            end
            
            -- Only intercept Mouse.Hit and Mouse.Target
            if self ~= Mouse or (index ~= "Hit" and index ~= "Target") then
                return silentAimOldIndex(self, index)
            end
            
            -- Skip if caller is this script
            if checkcaller() then
                return silentAimOldIndex(self, index)
            end
            
            -- Determine which target to use (auto shoot takes priority when active)
            local targetToUse = nil
            if autoShootActive and autoShootCurrentTarget then
                inIndexHook = true
                local hasParent = autoShootCurrentTarget.Parent ~= nil
                inIndexHook = false
                if hasParent then
                    targetToUse = autoShootCurrentTarget
                end
            elseif (SILENT_AIM_ENABLED or SILENT_AIM_SAVE_PLAYERS_ENABLED or SILENT_AIM_BOMBER_NEAR_ENABLED) and silentAimCurrentTarget then
                targetToUse = silentAimCurrentTarget
            end
            
            if targetToUse then
                inIndexHook = true
                -- Get position/CFrame directly without calling getAimPosition
                local aimPos = targetToUse.Position
                local aimCFrame = targetToUse.CFrame
                inIndexHook = false
                
                return index == "Hit" and aimCFrame or targetToUse
            end
            return silentAimOldIndex(self, index)
        end)
    end)
end

-- Initialize hooks
setupSilentAimHooks()
end -- End Auto Gun Aim Logic scope

do -- Gun Tab UI Section scope
-- // Gun Tab UI Section (continues Auto Gun Aim Section scope)
-- UI — create GunTab and sections once, then add toggles
local GunTab = Main1Section and Main1Section:Tab({ Title = "Gun Modifiers", Icon = "target" }) or nil
local GunModSection, AutoShootSection, SilentAimSection, SavePlayersSection, SafetyTrollingSection, TargetsSection

-- PERFORMANCE FIX: Flag to suppress notifications during UI initialization
local GunTab_InitComplete = false

-- Silent Aim FOV GUI elements (local to UI section)
local silentAimFovGui = nil
local silentAimFovCircle = nil
local silentAimFovUpdateConn = nil

-- Silent Aim whitelists
local SilentAimSavePlayersWhitelist = {} -- empty = all
local SilentAimBomberNearWhitelist = {} -- empty = all

-- Auto Save Players FOV settings
local AUTO_SAVE_USE_FOV = false
local AUTO_SAVE_SHOW_FOV = false
AUTO_SAVE_MOBILE_FOV = false
local AUTO_SAVE_FOV_SIZE = 50
local autoSaveFovGui = nil
local autoSaveFovCircle = nil
local autoSaveFovUpdateConn = nil

-- Forward declarations for whitelist dropdown references (for mutual exclusion)
local DontShootNearWhitelistDropdown = nil
local ShootBomberNearWhitelistDropdown = nil
local ShootBomberNearTeammatesToggle = nil

-- Helper: Get available players excluding those in another whitelist
local function getAvailablePlayersExcluding(excludeList)
    local names = {}
    for _, player in ipairs(Players:GetPlayers()) do
        if player ~= LocalPlayer then
            local isExcluded = false
            for _, excludedName in ipairs(excludeList or {}) do
                if player.Name == excludedName or player.DisplayName == excludedName then
                    isExcluded = true
                    break
                end
            end
            if not isExcluded then
                table.insert(names, player.Name)
            end
        end
    end
    return names
end

-- Helper: Refresh dropdown values
-- PERFORMANCE FIX: Added guard to prevent infinite recursion from dropdown callbacks
local isRefreshingWhitelistDropdowns = false
local function refreshWhitelistDropdowns()
    -- Prevent infinite recursion - if we're already refreshing, don't re-enter
    if isRefreshingWhitelistDropdowns then return end
    isRefreshingWhitelistDropdowns = true
    
    pcall(function()
        if DontShootNearWhitelistDropdown and DontShootNearWhitelistDropdown.Refresh then
            local availableForDontShoot = getAvailablePlayersExcluding(ShootBomberNearWhitelist)
            table.insert(availableForDontShoot, 1, "None")
            DontShootNearWhitelistDropdown:Refresh(availableForDontShoot)
        end
    end)
    
    pcall(function()
        if ShootBomberNearWhitelistDropdown and ShootBomberNearWhitelistDropdown.Refresh then
            local availableForShootNear = getAvailablePlayersExcluding(BomberSafetyWhitelist)
            table.insert(availableForShootNear, 1, "None")
            ShootBomberNearWhitelistDropdown:Refresh(availableForShootNear)
        end
    end)
    
    isRefreshingWhitelistDropdowns = false
end

-- Helper: Lock/unlock toggle with notification
local function lockToggleWithNotify(toggle, title, reason)
    pcall(function()
        if WindUI then
            WindUI:Notify({
                Title = title,
                Content = reason,
                Duration = 3,
                Icon = "lock",
            })
        end
    end)
    pcall(function()
        if toggle and toggle.Lock then toggle:Lock() end
    end)
end

local function unlockToggle(toggle)
    pcall(function()
        if toggle and toggle.Unlock then toggle:Unlock() end
    end)
end

-- Silent Aim FOV functions
local function ensureSilentAimFovGui()
    if silentAimFovGui and silentAimFovGui.Parent then
        return silentAimFovGui, silentAimFovCircle
    end
    local pg = LocalPlayer:FindFirstChild("PlayerGui") or LocalPlayer:WaitForChild("PlayerGui")
    silentAimFovGui = Instance.new("ScreenGui")
    silentAimFovGui.ResetOnSpawn = false
    if _G.protectGUI then _G.protectGUI(silentAimFovGui) else silentAimFovGui.Parent = pg end -- Use stealth protection
    local circle = Instance.new("Frame")
    circle.Name = "Circle"
    circle.AnchorPoint = Vector2.new(0.5, 0.5)
    circle.Position = UDim2.new(0.5, 0, 0.5, 0)
    circle.BackgroundTransparency = 1
    circle.BorderSizePixel = 0
    circle.Parent = silentAimFovGui
    local corner = Instance.new("UICorner")
    corner.CornerRadius = UDim.new(1, 0)
    corner.Parent = circle
    local stroke = Instance.new("UIStroke")
    stroke.Thickness = 2
    stroke.Color = Color3.fromRGB(0, 200, 255)
    stroke.Transparency = 0.2
    stroke.Parent = circle
    silentAimFovCircle = circle
    return silentAimFovGui, silentAimFovCircle
end

local function getSilentAimFovScreenCenter()
    local cam = Workspace.CurrentCamera
    if not cam then return Vector2.new(0, 0) end
    local viewportSize = cam.ViewportSize
    if SILENT_AIM_MOBILE_FOV or UserInputService.MouseBehavior == Enum.MouseBehavior.LockCenter then
        return Vector2.new(viewportSize.X / 2, viewportSize.Y / 2)
    end
    local mousePos = UserInputService:GetMouseLocation()
    local inset = GuiService:GetGuiInset()
    return mousePos - Vector2.new(inset.X, inset.Y)
end

local silentAimFovFrameCounter = 0
local SILENT_AIM_FOV_UPDATE_INTERVAL = 2 -- Update every N frames
local function ensureSilentAimFovUpdateLoop()
    if silentAimFovUpdateConn then return end
    silentAimFovUpdateConn = RunService.RenderStepped:Connect(function()
        if not (SILENT_AIM_USE_FOV and SILENT_AIM_SHOW_FOV) then
            if silentAimFovGui then silentAimFovGui.Enabled = false end
            return
        end
        -- Throttle updates for performance
        silentAimFovFrameCounter = silentAimFovFrameCounter + 1
        if silentAimFovFrameCounter < SILENT_AIM_FOV_UPDATE_INTERVAL then return end
        silentAimFovFrameCounter = 0
        
        local gui, circle = ensureSilentAimFovGui()
        gui.Enabled = true
        local cam = Workspace.CurrentCamera
        if not cam then return end
        local viewportSize = cam.ViewportSize
        local clamped = math.clamp(SILENT_AIM_FOV_SIZE, FOV_MIN_DEG, FOV_MAX_DEG)
        local sizePx = (clamped / 40) * 250
        circle.Size = UDim2.new(0, sizePx, 0, sizePx)
        local center = getSilentAimFovScreenCenter()
        local xScale = center.X / viewportSize.X
        local yScale = center.Y / viewportSize.Y
        circle.Position = UDim2.new(xScale, 0, yScale, 0)
    end)
end

local function updateSilentAimFovCircle()
    if not (SILENT_AIM_USE_FOV and SILENT_AIM_SHOW_FOV) then
        if silentAimFovGui then silentAimFovGui.Enabled = false end
        return
    end
    ensureSilentAimFovUpdateLoop()
end

-- Replace the forward declaration stub with the real implementation
isWorldPosInSilentAimFov = function(worldPos)
    if not SILENT_AIM_USE_FOV then return true end
    local cam = Workspace.CurrentCamera
    if not cam then return true end
    local viewportSize = cam.ViewportSize
    if not viewportSize or viewportSize.X <= 0 or viewportSize.Y <= 0 then return true end
    local screenPos, onScreen = cam:WorldToViewportPoint(worldPos)
    if not onScreen then return false end
    local centerVec = getSilentAimFovScreenCenter()
    local dist = (Vector2.new(screenPos.X, screenPos.Y) - centerVec).Magnitude
    local clamped = math.clamp(SILENT_AIM_FOV_SIZE, FOV_MIN_DEG, FOV_MAX_DEG)
    local sizePx = (clamped / 40) * 250
    local radius = sizePx / 2
    return dist <= radius
end

-- Auto Save FOV functions
local function ensureAutoSaveFovGui()
    if autoSaveFovGui and autoSaveFovGui.Parent then
        return autoSaveFovGui, autoSaveFovCircle
    end
    local pg = LocalPlayer:FindFirstChild("PlayerGui") or LocalPlayer:WaitForChild("PlayerGui")
    autoSaveFovGui = Instance.new("ScreenGui")
    autoSaveFovGui.ResetOnSpawn = false
    if _G.protectGUI then _G.protectGUI(autoSaveFovGui) else autoSaveFovGui.Parent = pg end -- Use stealth protection
    local circle = Instance.new("Frame")
    circle.Name = "Circle"
    circle.AnchorPoint = Vector2.new(0.5, 0.5)
    circle.Position = UDim2.new(0.5, 0, 0.5, 0)
    circle.BackgroundTransparency = 1
    circle.BorderSizePixel = 0
    circle.Parent = autoSaveFovGui
    local corner = Instance.new("UICorner")
    corner.CornerRadius = UDim.new(1, 0)
    corner.Parent = circle
    local stroke = Instance.new("UIStroke")
    stroke.Thickness = 2
    stroke.Color = Color3.fromRGB(0, 255, 100)
    stroke.Transparency = 0.2
    stroke.Parent = circle
    autoSaveFovCircle = circle
    return autoSaveFovGui, autoSaveFovCircle
end

local function getAutoSaveFovScreenCenter()
    local cam = Workspace.CurrentCamera
    if not cam then return Vector2.new(0, 0) end
    local viewportSize = cam.ViewportSize
    if AUTO_SAVE_MOBILE_FOV or UserInputService.MouseBehavior == Enum.MouseBehavior.LockCenter then
        return Vector2.new(viewportSize.X / 2, viewportSize.Y / 2)
    end
    local mousePos = UserInputService:GetMouseLocation()
    local inset = GuiService:GetGuiInset()
    return mousePos - Vector2.new(inset.X, inset.Y)
end

local autoSaveFovFrameCounter = 0
local AUTO_SAVE_FOV_UPDATE_INTERVAL = 2 -- Update every N frames
local function ensureAutoSaveFovUpdateLoop()
    if autoSaveFovUpdateConn then return end
    autoSaveFovUpdateConn = RunService.RenderStepped:Connect(function()
        if not (AUTO_SAVE_USE_FOV and AUTO_SAVE_SHOW_FOV) then
            if autoSaveFovGui then autoSaveFovGui.Enabled = false end
            return
        end
        -- Throttle updates for performance
        autoSaveFovFrameCounter = autoSaveFovFrameCounter + 1
        if autoSaveFovFrameCounter < AUTO_SAVE_FOV_UPDATE_INTERVAL then return end
        autoSaveFovFrameCounter = 0
        
        local gui, circle = ensureAutoSaveFovGui()
        gui.Enabled = true
        local cam = Workspace.CurrentCamera
        if not cam then return end
        local viewportSize = cam.ViewportSize
        local clamped = math.clamp(AUTO_SAVE_FOV_SIZE, FOV_MIN_DEG, FOV_MAX_DEG)
        local sizePx = (clamped / 40) * 250
        circle.Size = UDim2.new(0, sizePx, 0, sizePx)
        local center = getAutoSaveFovScreenCenter()
        local xScale = center.X / viewportSize.X
        local yScale = center.Y / viewportSize.Y
        circle.Position = UDim2.new(xScale, 0, yScale, 0)
    end)
end

local function updateAutoSaveFovCircle()
    if not (AUTO_SAVE_USE_FOV and AUTO_SAVE_SHOW_FOV) then
        if autoSaveFovGui then autoSaveFovGui.Enabled = false end
        return
    end
    ensureAutoSaveFovUpdateLoop()
end

local function isWorldPosInAutoSaveFov(worldPos)
    if not AUTO_SAVE_USE_FOV then return true end
    local cam = Workspace.CurrentCamera
    if not cam then return true end
    local viewportSize = cam.ViewportSize
    if not viewportSize or viewportSize.X <= 0 or viewportSize.Y <= 0 then return true end
    local screenPos, onScreen = cam:WorldToViewportPoint(worldPos)
    if not onScreen then return false end
    local centerVec = getAutoSaveFovScreenCenter()
    local dist = (Vector2.new(screenPos.X, screenPos.Y) - centerVec).Magnitude
    local clamped = math.clamp(AUTO_SAVE_FOV_SIZE, FOV_MIN_DEG, FOV_MAX_DEG)
    local sizePx = (clamped / 40) * 250
    local radius = sizePx / 2
    return dist <= radius
end

if GunTab then
    do -- Auto Shoot Section scope
    GunModSection = GunTab:Section({ Title = "Gun Mod", Icon = "zap", Opened = false })
    AutoShootSection = GunTab:Section({ Title = "Auto Shoot", Icon = "target", Opened = false })
    
    -- Multi-select dropdown for zombie types to auto-shoot
    local shootDropdown = AutoShootSection:Dropdown({
        Title = "Select Zombie Types To AutoShoot",
        Flag = "Shooting_Type_Select",
        Desc = "Choose which zombie types to target.",
        Values = ShootTypeList,
        Value = {},
        Multi = true,
        Callback = function(selection)
            local newSelection = selection or {}
            SelectedShootTypes = {}
            for _, v in ipairs(newSelection) do table.insert(SelectedShootTypes, tostring(v)) end
            -- Keep EnabledShootTypes consistent: if some types were deselected, disable them
            for _, t in ipairs(ShootTypeList) do
                local found = false
                for _, s in ipairs(SelectedShootTypes) do if s == t then found = true; break end end
                if not found then EnabledShootTypes[t] = false end
            end
            if GunTab_InitComplete then
                pcall(function()
                    WindUI:Notify({
                        Title = "Shooting Selection",
                        Content = (#SelectedShootTypes > 0) and ("Selected: " .. table.concat(SelectedShootTypes, ", ")) or "No selection",
                        Icon = "target",
                        Duration = 1
                    })
                end)
            end
        end
    })
    -- Toggle: enables/disables auto-shoot for selected types
    local AutoShootToggle = AutoShootSection:Toggle({
        Title = "Enable Auto Shoot",
        Flag = "Shooting_Enable_Selected",
        Desc = "Enable Auto Shooting for the selected zombie types.",
        Icon = "play",
        Value = USER_AUTO_SHOOT_TOGGLE,
        Callback = function(state)
            USER_AUTO_SHOOT_TOGGLE = state
            -- If disabled, clear per-type enabled flags
            if not state then
                for t, _ in pairs(EnabledShootTypes) do EnabledShootTypes[t] = false end
            else
                -- enable all selected types for simplicity
                for _, t in ipairs(SelectedShootTypes) do EnabledShootTypes[t] = true end
            end
        end
    })
    _G.KatchiToggleElements = _G.KatchiToggleElements or {}
    _G.KatchiToggleElements.AutoShoot = AutoShootToggle

    -- Keep "Instant Shoot" behavior but generalized: instant for any selected type
    local InstantShootToggle = AutoShootSection:Toggle({
        Title = "Instant Shoot",
        Flag = "Shooting_Instant",
        Desc = "Instantly shoot selected zombies (No Animations)",
        Icon = "zap",
        Value = INSTANT_SHOOT_ENABLED,
        Callback = function(state)
            INSTANT_SHOOT_ENABLED = state
            APPEAR_DELAY = (INSTANT_SHOOT_ENABLED and 0.1) or APPEAR_DELAY_DEFAULT
        end
    })
    _G.KatchiToggleElements.InstantShoot = InstantShootToggle
    
    AutoShootSection:Slider({
        Title = "Auto Shoot Delay",
        Flag = "Shooting_AutoShootDelay",
        Desc = "Total time from aiming to firing (seconds). Set higher for smoother rotation.",
        Step = 0.1,
        Value = { Min = 0.5, Max = 5, Default = AUTO_SHOOT_DELAY },
        Callback = function(val)
            AUTO_SHOOT_DELAY = math.clamp(tonumber(val) or 0.5, 0.3, 10)
        end
    })
    AutoShootSection:Slider({
        Title = "Prediction",
        Flag = "Shooting_Prediction",
        Desc = "Lead time in seconds (0.20 is recommended)",
        Step = 0.2,
        Value = { Min = 0, Max = 1, Default = PREDICTION_DISTANCE },
        Callback = function(val)
            PREDICTION_DISTANCE = math.clamp(tonumber(val) or 0, 0, 50)
        end
    })
    AutoShootSection:Slider({
        Title = "Max Target Range",
        Flag = "Shooting_MaxRange",
        Desc = "Maximum detection range.",
        Step = 1,
        Value = { Min = 1, Max = 600, Default = MAX_TARGET_RANGE },
        Callback = function(val) MAX_TARGET_RANGE = val end
    })
    -- ===== AUTO SHOOT FOV UI =====
    local UseFovToggle = AutoShootSection:Toggle({
        Title = "Use Fov",
        Flag = "Shooting_UseFov",
        Desc = "Only target zombies inside the FOV.",
        Icon = "circle",
        Value = USE_FOV,
        Callback = function(state)
            USE_FOV = state
            updateFovCircle()
        end
    })
    _G.KatchiToggleElements.UseFov = UseFovToggle

    AutoShootSection:Toggle({
        Title = "Mobile Fov",
        Flag = "Shooting_MobileFov",
        Desc = "Fov stays in the middle (can be used in pc too).",
        Icon = "smartphone",
        Value = MOBILE_FOV,
        Callback = function(state)
            MOBILE_FOV = state
            updateFovCircle()
        end
    })
    local ShowFovToggle = AutoShootSection:Toggle({
        Title = "Show Fov",
        Flag = "Shooting_ShowFov",
        Desc = "Show the fov circle.",
        Icon = "eye",
        Value = SHOW_FOV,
        Callback = function(state)
            SHOW_FOV = state
            updateFovCircle()
        end
    })
    _G.KatchiToggleElements.ShowFov = ShowFovToggle

    AutoShootSection:Slider({
        Title = "Fov Size",
        Flag = "Shooting_FovSize",
        Desc = "change the FOV circle size.",
        Step = 1,
        Value = { Min = FOV_MIN_DEG, Max = FOV_MAX_DEG, Default = FOV_SIZE_DEG },
        Callback = function(val)
            FOV_SIZE_DEG = val
            updateFovCircle()
        end
    })
    local WallCheckToggle = AutoShootSection:Toggle({
        Title = "Wall Check (Raycast)",
        Flag = "Shooting_WallCheck",
        Desc = "Selected zombies behind walls will be ignored.",
        Icon = "shield-off",
        Value = CHECK_WALLS,
        Callback = function(state) CHECK_WALLS = state end
    })
    _G.KatchiToggleElements.WallCheck = WallCheckToggle

    local AutoReloadToggle = GunModSection:Toggle({ Title = "Auto Reload", Flag = "GunMod_AutoReload", Desc = "Automatically reload.", Icon = "refresh-cw", Value = AUTO_RELOAD_ENABLED, Callback = function(state) AUTO_RELOAD_ENABLED = state end })
    _G.KatchiToggleElements.AutoReload = AutoReloadToggle
    end -- End Auto Shoot Section scope
    
    -- ===== SILENT AIM SECTION =====
    do -- Silent Aim Section scope
    SilentAimSection = GunTab:Section({ Title = "Silent Aim", Icon = "crosshair", Opened = false })
    
    local SilentAimToggle = SilentAimSection:Toggle({
        Title = "Enable Silent Aim",
        Flag = "SilentAim_Master",
        Desc = "Master toggle for Silent Aim. Must be enabled for any silent aim features to work.",
        Icon = "power",
        Value = SILENT_AIM_ENABLED,
        Callback = function(state)
            SILENT_AIM_ENABLED = state
            WindUI:Notify({
                Title = "Silent Aim",
                Content = state and "Silent Aim Enabled - Your shots will be redirected to targets" or "Silent Aim Disabled",
                Duration = 2,
                Icon = state and "crosshair" or "x"
            })
        end
    })
    _G.KatchiToggleElements = _G.KatchiToggleElements or {}
    _G.KatchiToggleElements.SilentAim = SilentAimToggle

    _G.KatchiToggleElements.SilentAimAutoAim = SilentAimAutoAimToggle
    
    -- Silent Aim zombie type dropdown (separate from auto shoot)
    SilentAimSection:Dropdown({
        Title = "Select Zombie Types",
        Flag = "SilentAim_Type_Select",
        Desc = "Choose which zombie types Silent Aim will target.",
        Values = SilentAimZombieTypes,
        Value = {},
        Multi = true,
        Callback = function(selection)
            local newSelection = selection or {}
            SilentAimSelectedTypes = {}
            for _, v in ipairs(newSelection) do table.insert(SilentAimSelectedTypes, tostring(v)) end
            for _, t in ipairs(SilentAimZombieTypes) do
                local found = false
                for _, s in ipairs(SilentAimSelectedTypes) do if s == t then found = true; break end end
                if not found then SilentAimEnabledTypes[t] = false else SilentAimEnabledTypes[t] = true end
            end
            if GunTab_InitComplete then
                pcall(function()
                    WindUI:Notify({
                        Title = "Silent Aim Selection",
                        Content = (#SilentAimSelectedTypes > 0) and ("Selected: " .. table.concat(SilentAimSelectedTypes, ", ")) or "No selection",
                        Icon = "crosshair",
                        Duration = 1
                    })
                end)
            end
        end
    })
    
    -- Silent Aim FOV settings
    SilentAimSection:Toggle({
        Title = "Use Fov",
        Flag = "SilentAim_UseFov",
        Desc = "Only target zombies inside the FOV for Silent Aim.",
        Icon = "circle",
        Value = SILENT_AIM_USE_FOV,
        Callback = function(state)
            SILENT_AIM_USE_FOV = state
            updateSilentAimFovCircle()
        end
    })
    
    SilentAimSection:Toggle({
        Title = "Mobile Fov",
        Flag = "SilentAim_MobileFov",
        Desc = "Fov stays in the middle (can be used in pc too).",
        Icon = "smartphone",
        Value = SILENT_AIM_MOBILE_FOV,
        Callback = function(state)
            SILENT_AIM_MOBILE_FOV = state
            updateSilentAimFovCircle()
        end
    })
    
    SilentAimSection:Toggle({
        Title = "Show Fov",
        Flag = "SilentAim_ShowFov",
        Desc = "Show the Silent Aim FOV circle (cyan).",
        Icon = "eye",
        Value = SILENT_AIM_SHOW_FOV,
        Callback = function(state)
            SILENT_AIM_SHOW_FOV = state
            updateSilentAimFovCircle()
        end
    })
    
    SilentAimSection:Slider({
        Title = "Fov Size",
        Flag = "SilentAim_FovSize",
        Desc = "Change the Silent Aim FOV circle size.",
        Step = 1,
        Value = { Min = FOV_MIN_DEG, Max = FOV_MAX_DEG, Default = SILENT_AIM_FOV_SIZE },
        Callback = function(val)
            SILENT_AIM_FOV_SIZE = val
            updateSilentAimFovCircle()
        end
    })
    
    SilentAimSection:Toggle({
        Title = "Silent Aim Save Players",
        Flag = "SilentAim_SavePlayers",
        Desc = "Redirect shots to zombies grabbing players (higher priority than zombie targeting).",
        Icon = "shield",
        Value = SILENT_AIM_SAVE_PLAYERS_ENABLED,
        Callback = function(state)
            SILENT_AIM_SAVE_PLAYERS_ENABLED = state
            WindUI:Notify({
                Title = "Silent Aim Save Players",
                Content = state and "Shots will redirect to zombies grabbing players" or "Disabled",
                Duration = 2,
                Icon = state and "shield" or "x"
            })
        end
    })
    
    -- Silent Aim Save Players Whitelist
    local function getSilentAimSavePlayersNames()
        local names = {"All"}
        for _, player in ipairs(Players:GetPlayers()) do
            if player ~= LocalPlayer then
                table.insert(names, player.Name)
            end
        end
        return names
    end
    
    SilentAimSection:Dropdown({
        Title = "Save Players Whitelist",
        Flag = "SilentAim_SavePlayers_Whitelist",
        Desc = "Only redirect shots to save these players",
        Values = getSilentAimSavePlayersNames(),
        Value = {"All"},
        Multi = true,
        Callback = function(selection)
            local filtered = {}
            local hasAll = false
            for _, name in ipairs(selection or {}) do
                if name == "All" then
                    hasAll = true
                else
                    table.insert(filtered, name)
                end
            end
            if hasAll then
                SilentAimSavePlayersWhitelist = {}
            else
                SilentAimSavePlayersWhitelist = filtered
            end
            if GunTab_InitComplete then
                pcall(function()
                    WindUI:Notify({
                        Title = "Silent Aim Save Whitelist",
                        Content = (#SilentAimSavePlayersWhitelist > 0) and ("Will only save: " .. table.concat(SilentAimSavePlayersWhitelist, ", ")) or "Will save all players",
                        Icon = "users",
                        Duration = 2
                    })
                end)
            end
        end
    })
    
    SilentAimSection:Toggle({
        Title = "Silent Aim Bomber Near Teammates",
        Flag = "SilentAim_BomberNear",
        Desc = "Only redirect shots to bombers when they are near teammates.",
        Icon = "users",
        Value = SILENT_AIM_BOMBER_NEAR_ENABLED,
        Callback = function(state)
            SILENT_AIM_BOMBER_NEAR_ENABLED = state
            WindUI:Notify({
                Title = "Silent Aim Bomber",
                Content = state and "Will only target bombers near teammates" or "Normal bomber targeting",
                Duration = 2,
                Icon = state and "crosshair" or "x"
            })
        end
    })
    
    -- Silent Aim Bomber Near Whitelist
    local function getSilentAimBomberNearNames()
        local names = {"All"}
        for _, player in ipairs(Players:GetPlayers()) do
            if player ~= LocalPlayer then
                table.insert(names, player.Name)
            end
        end
        return names
    end
    
    SilentAimSection:Dropdown({
        Title = "Bomber Near Whitelist",
        Flag = "SilentAim_BomberNear_Whitelist",
        Desc = "Only shoot bombers near these teammates",
        Values = getSilentAimBomberNearNames(),
        Value = {"All"},
        Multi = true,
        Callback = function(selection)
            local filtered = {}
            local hasAll = false
            for _, name in ipairs(selection or {}) do
                if name == "All" then
                    hasAll = true
                else
                    table.insert(filtered, name)
                end
            end
            if hasAll then
                SilentAimBomberNearWhitelist = {}
            else
                SilentAimBomberNearWhitelist = filtered
            end
            if GunTab_InitComplete then
                pcall(function()
                    WindUI:Notify({
                        Title = "Silent Aim Bomber Near",
                        Content = (#SilentAimBomberNearWhitelist > 0) and ("Will shoot bombers near: " .. table.concat(SilentAimBomberNearWhitelist, ", ")) or "Will shoot near any teammate",
                        Icon = "crosshair",
                        Duration = 2
                    })
                end)
            end
        end
    })
    end -- End Silent Aim Section scope

    -- ===== SAVE PLAYERS SECTION =====
    do -- Save Players Section scope
    SavePlayersSection = GunTab:Section({ Title = "Auto Save Players", Icon = "shield", Opened = false })
    local AutoSavePlayersToggle = SavePlayersSection:Toggle({
        Title = "Auto Save Players",
        Flag = "SavePlayers_AutoSavePlayers",
        Desc = "Shoot Zombies Grabbing The player.",
        Icon = "shield",
        Value = AUTO_SAVE_PLAYERS_ENABLED,
        Callback = function(state) AUTO_SAVE_PLAYERS_ENABLED = state end
    })
    _G.KatchiToggleElements.AutoSavePlayers = AutoSavePlayersToggle

    SavePlayersSection:Toggle({
        Title = "Instant Save Players",
        Flag = "SavePlayers_InstantSavePlayers",
        Desc = "Instantly shoot the zombie grabbing the player (No Animations)",
        Icon = "zap",
        Value = INSTANT_SAVE_PLAYERS_ENABLED,
        Callback = function(state) INSTANT_SAVE_PLAYERS_ENABLED = state end
    })
    SavePlayersSection:Slider({
        Title = "Save Player Delay",
        Flag = "SavePlayers_Delay",
        Desc = "Delay before shooting when saving player (seconds)",
        Step = 0.1,
        Value = { Min = 0, Max = 5, Default = SAVE_PLAYER_DELAY },
        Callback = function(val) SAVE_PLAYER_DELAY = val end
    })
    SavePlayersSection:Slider({
        Title = "Max Save Players Range",
        Flag = "SavePlayers_MaxRange",
        Desc = "Max save players distance.",
        Step = 1,
        Value = { Min = 50, Max = 600, Default = MAX_SAVE_PLAYERS_RANGE },
        Callback = function(val) MAX_SAVE_PLAYERS_RANGE = val end
    })
    
    -- Auto Save Players FOV settings
    SavePlayersSection:Toggle({
        Title = "Use Fov",
        Flag = "SavePlayers_UseFov",
        Desc = "Only save players if zombie is inside the FOV.",
        Icon = "circle",
        Value = AUTO_SAVE_USE_FOV,
        Callback = function(state)
            AUTO_SAVE_USE_FOV = state
            updateAutoSaveFovCircle()
        end
    })
    
    SavePlayersSection:Toggle({
        Title = "Mobile Fov",
        Flag = "SavePlayers_MobileFov",
        Desc = "Fov stays in the middle (can be used in pc too).",
        Icon = "smartphone",
        Value = AUTO_SAVE_MOBILE_FOV,
        Callback = function(state)
            AUTO_SAVE_MOBILE_FOV = state
            updateAutoSaveFovCircle()
        end
    })
    
    SavePlayersSection:Toggle({
        Title = "Show Fov",
        Flag = "SavePlayers_ShowFov",
        Desc = "Show the Auto Save FOV circle (green).",
        Icon = "eye",
        Value = AUTO_SAVE_SHOW_FOV,
        Callback = function(state)
            AUTO_SAVE_SHOW_FOV = state
            updateAutoSaveFovCircle()
        end
    })
    
    SavePlayersSection:Slider({
        Title = "Fov Size",
        Flag = "SavePlayers_FovSize",
        Desc = "Change the Auto Save FOV circle size.",
        Step = 1,
        Value = { Min = FOV_MIN_DEG, Max = FOV_MAX_DEG, Default = AUTO_SAVE_FOV_SIZE },
        Callback = function(val)
            AUTO_SAVE_FOV_SIZE = val
            updateAutoSaveFovCircle()
        end
    })
    
    -- Auto Save Whitelist Dropdown
    local function getAutoSavePlayerNames()
        local names = {"All"} -- Add All option first (default = save all)
        for _, player in ipairs(Players:GetPlayers()) do
            if player ~= LocalPlayer then
                table.insert(names, player.Name)
            end
        end
        return names
    end
    SavePlayersSection:Dropdown({
        Title = "Auto Save Whitelist",
        Flag = "SavePlayers_Whitelist",
        Desc = "Only save these players",
        Values = getAutoSavePlayerNames(),
        Value = {"All"},
        Multi = true,
        Callback = function(selection)
            local filtered = {}
            local hasAll = false
            for _, name in ipairs(selection or {}) do
                if name == "All" then
                    hasAll = true
                else
                    table.insert(filtered, name)
                end
            end
            if hasAll then
                AutoSaveWhitelist = {}
            else
                AutoSaveWhitelist = filtered
            end
            if GunTab_InitComplete then
                pcall(function()
                    WindUI:Notify({
                        Title = "Auto Save Whitelist",
                        Content = (#AutoSaveWhitelist > 0) and ("Will only save: " .. table.concat(AutoSaveWhitelist, ", ")) or "Will save all players",
                        Icon = "users",
                        Duration = 2
                    })
                end)
            end
        end
    })
    end -- End Save Players Section scope
    
    -- ===== SAFETY & TROLLING SECTION =====
    do -- Scoped block to reduce local register count
    SafetyTrollingSection = GunTab:Section({ Title = "Safety & Trolling", Icon = "shield-alert", Opened = false })
    
    -- Don't Shoot Bomber Near Teammates toggle
    local DontShootBomberNearTeammatesToggle = SafetyTrollingSection:Toggle({
        Title = "Don't Shoot Bomber Near Teammates",
        Flag = "Safety_BomberSafeTeammates",
        Desc = "Won't shoot bombers within the safety radius of teammates.",
        Icon = "shield",
        Value = BOMBER_SAFE_TEAMMATES,
        Callback = function(state)
            BOMBER_SAFE_TEAMMATES = state
            -- If enabled, lock and disable the opposite toggle
            if state then
                if SHOOT_BOMBER_NEAR_TEAMMATES then
                    SHOOT_BOMBER_NEAR_TEAMMATES = false
                    if ShootBomberNearTeammatesToggle then
                        pcall(function() ShootBomberNearTeammatesToggle:SetValue(false) end)
                    end
                end
                if ShootBomberNearTeammatesToggle then
                    lockToggleWithNotify(ShootBomberNearTeammatesToggle, "Safety Conflict", "Cannot use 'Shoot Bomber Near Teammates' while 'Don't Shoot' is enabled.")
                end
            else
                -- Unlock the opposite toggle
                if ShootBomberNearTeammatesToggle then
                    unlockToggle(ShootBomberNearTeammatesToggle)
                end
            end
            WindUI:Notify({
                Title = "Bomber Safety",
                Content = state and "Won't shoot bombers near teammates" or "Disabled",
                Duration = 2,
                Icon = state and "shield" or "x"
            })
        end
    })
    
    -- Don't Shoot Near Teammates Whitelist (mutual exclusion with Shoot Near)
    DontShootNearWhitelistDropdown = SafetyTrollingSection:Dropdown({
        Title = "Don't Shoot Near Teammates Whitelist",
        Flag = "Safety_DontShootNear_Whitelist",
        Desc = "Won't shoot bombers if these specific players are within blast radius",
        Values = (function()
            local names = {"None"}
            for _, player in ipairs(Players:GetPlayers()) do
                if player ~= LocalPlayer then
                    table.insert(names, player.Name)
                end
            end
            return names
        end)(),
        Value = {},
        Multi = true,
        Callback = function(selection)
            local filtered = {}
            local hasNone = false
            for _, name in ipairs(selection or {}) do
                if name == "None" then
                    hasNone = true
                else
                    table.insert(filtered, name)
                end
            end
            if hasNone then
                filtered = {}
            end
            BomberSafetyWhitelist = filtered
            -- Refresh the opposite whitelist to exclude these players (only after init complete)
            if GunTab_InitComplete then
                refreshWhitelistDropdowns()
                pcall(function()
                    WindUI:Notify({
                        Title = "Don't Shoot Near Whitelist",
                        Content = (#BomberSafetyWhitelist > 0) and ("Protecting: " .. table.concat(BomberSafetyWhitelist, ", ")) or "No players whitelisted",
                        Icon = "shield",
                        Duration = 2
                    })
                end)
            end
        end
    })
    
    -- Shoot Bomber Near Teammates toggle
    ShootBomberNearTeammatesToggle = SafetyTrollingSection:Toggle({
        Title = "Shoot Bomber Near Teammates",
        Flag = "Safety_ShootBomberNearTeammates",
        Desc = "ONLY shoot bombers when teammates are within the safety radius (trolling feature).",
        Icon = "crosshair",
        Value = SHOOT_BOMBER_NEAR_TEAMMATES,
        Callback = function(state)
            SHOOT_BOMBER_NEAR_TEAMMATES = state
            WindUI:Notify({
                Title = "Bomber Targeting",
                Content = state and "Will ONLY shoot bombers near teammates" or "Normal bomber targeting",
                Duration = 2,
                Icon = state and "crosshair" or "target"
            })
        end
    })
    
    -- Lock it initially if Don't Shoot is enabled
    if BOMBER_SAFE_TEAMMATES and ShootBomberNearTeammatesToggle then
        task.defer(function()
            lockToggleWithNotify(ShootBomberNearTeammatesToggle, "Safety Conflict", "Cannot use while 'Don't Shoot Bomber Near Teammates' is enabled.")
        end)
    end
    
    -- Shoot Bomber Near Teammates Whitelist (mutual exclusion with Don't Shoot Near)
    ShootBomberNearWhitelistDropdown = SafetyTrollingSection:Dropdown({
        Title = "Shoot Bomber Near Teammates Whitelist",
        Flag = "Safety_ShootBomberNear_Whitelist",
        Desc = "ONLY shoot bombers when these specific players are within blast radius",
        Values = (function()
            local names = {"None"}
            for _, player in ipairs(Players:GetPlayers()) do
                if player ~= LocalPlayer then
                    table.insert(names, player.Name)
                end
            end
            return names
        end)(),
        Value = {},
        Multi = true,
        Callback = function(selection)
            local filtered = {}
            local hasNone = false
            for _, name in ipairs(selection or {}) do
                if name == "None" then
                    hasNone = true
                else
                    table.insert(filtered, name)
                end
            end
            if hasNone then
                filtered = {}
            end
            ShootBomberNearWhitelist = filtered
            -- Refresh the opposite whitelist to exclude these players (only after init complete)
            if GunTab_InitComplete then
                refreshWhitelistDropdowns()
                pcall(function()
                    WindUI:Notify({
                        Title = "Shoot Near Whitelist",
                        Content = (#ShootBomberNearWhitelist > 0) and ("Will shoot bombers near: " .. table.concat(ShootBomberNearWhitelist, ", ")) or "Will shoot near any teammate",
                        Icon = "crosshair",
                        Duration = 2
                    })
                end)
            end
        end
    })
    
    -- Don't Shoot Bomber Near Me toggle
    SafetyTrollingSection:Toggle({
        Title = "Don't Shoot Bomber Near Me",
        Flag = "Safety_BomberSafeSelf",
        Desc = "Won't shoot bombers within the safety radius of yourself.",
        Icon = "user",
        Value = BOMBER_SAFE_SELF,
        Callback = function(state)
            BOMBER_SAFE_SELF = state
            WindUI:Notify({
                Title = "Bomber Safety",
                Content = state and "Won't shoot bombers near you" or "Disabled",
                Duration = 2,
                Icon = state and "shield" or "x"
            })
        end
    })
    
    -- Bomber Safety Radius slider
    SafetyTrollingSection:Slider({
        Title = "Bomber Safety Radius",
        Flag = "Safety_BomberSafeRadius",
        Desc = "The radius (in studs) for all bomber safety/trolling features.",
        Step = 1,
        Value = { Min = 5, Max = 30, Default = BOMBER_SAFE_RADIUS },
        Callback = function(val)
            BOMBER_SAFE_RADIUS = val
            -- Update any existing bomber visualizations to reflect new radius
            for model, visual in pairs(BomberRadiusVisuals) do
                if visual and visual.Parent then
                    visual.Size = Vector3.new(0.2, BOMBER_SAFE_RADIUS * 2, BOMBER_SAFE_RADIUS * 2)
                end
            end
        end
    })
    end -- End Safety & Trolling scoped block
    
    -- ===== TARGET SETTINGS SECTION =====
    do -- Scoped block to reduce local register count
    TargetsSection = GunTab:Section({ Title = "Target Settings", Icon = "eye", Opened = false })
    
    TargetsSection:Toggle({
        Title = "Visualize Bomber Explosion Radius",
        Flag = "Targets_BomberVisualize",
        Desc = "Shows a circle around bombers showing the explosion radius.",
        Icon = "circle",
        Value = BOMBER_VISUALIZE_RADIUS,
        Callback = function(state)
            BOMBER_VISUALIZE_RADIUS = state
            if not state then
                -- Clear all visuals when disabled
                for model, visual in pairs(BomberRadiusVisuals) do
                    pcall(function() visual:Destroy() end)
                end
                BomberRadiusVisuals = {}
            end
            WindUI:Notify({
                Title = "Bomber Visualization",
                Content = state and "Showing explosion radius" or "Hidden",
                Duration = 2,
                Icon = state and "eye" or "eye-off"
            })
        end
    })
    
    TargetsSection:Toggle({
        Title = "Target ESP",
        Flag = "Targets_TargetEsp",
        Desc = "Shows the zombie its currently targeting.",
        Icon = "eye",
        Value = TARGET_ESP_ENABLED,
        Callback = function(state)
            TARGET_ESP_ENABLED = state
            if not state then
                pcall(function() clearActiveTargetVisuals() end)
            else
                if activeAimModel then
                    pcall(function() createTargetHighlight(activeAimModel) end)
                end
            end
        end
    })
    
    TargetsSection:Toggle({
        Title = "Show Aim Position",
        Flag = "Targets_AimDot",
        Desc = "Shows a red dot at the aim position.",
        Icon = "target",
        Value = AIM_DOT_ENABLED,
        Callback = function(state)
            AIM_DOT_ENABLED = state
            if state then
                pcall(function() createAimDot() end)
                WindUI:Notify({
                    Title = "Aim Dot",
                    Content = "Aim position dot enabled",
                    Duration = 2,
                    Icon = "target"
                })
            else
                pcall(function() clearAimDot() end)
                WindUI:Notify({
                    Title = "Aim Dot", 
                    Content = "Aim position dot disabled",
                    Duration = 2,
                    Icon = "x"
                })
            end
        end
    })
    end -- End Target Settings scoped block
end

do -- Hand Mortar Feature scope (reduces local register count)
--- hand mortar feature (updated: supports two anims, 1s delay, first-person overlay)
-- Hand Mortar Timing Feature
local HAND_MORTAR_TIMING_ENABLED = false
local HAND_MORTAR_DURATION = 5 -- seconds, displayed with milliseconds
local HAND_MORTAR_ANIM_IDS = {
    ["rbxassetid://117522716162453"] = true,
    ["rbxassetid://83761082384320"] = true,
}
-- State for GUI and running timer
-- handMortarGui will be a table: { billboard = BillboardGui, screen = ScreenGui }
local handMortarGui = nil
local handMortarUpdateConn = nil
local handMortarCameraConn = nil
local handMortarEndTick = nil
local handMortarRunning = false
local handMortarAnimConn = nil -- AnimationPlayed connection
-- Ensure PlayerGui exists
local function getPlayerGui()
    return LocalPlayer:WaitForChild("PlayerGui")
end
-- Detect first-person by checking camera position relative to head
local function isFirstPerson()
    local cam = Workspace.CurrentCamera
    if not cam then return false end
    local char = LocalPlayer.Character
    if not char then return false end
    local head = char:FindFirstChild("Head")
    if not head or not head:IsA("BasePart") then return false end
    local dist = (cam.CFrame.Position - head.Position).Magnitude
    -- threshold: if camera is very close to head (inside head), treat as first-person
    return dist < 0.7
end
-- Create (or reuse) the BillboardGui + ScreenGui
local function createHandMortarGui()
    -- if existing and parented, return it
    if handMortarGui and ((handMortarGui.billboard and handMortarGui.billboard.Parent) or (handMortarGui.screen and handMortarGui.screen.Parent)) then
        return handMortarGui
    end
    local playerGui = getPlayerGui()
    -- BILLBOARD (for 3rd-person)
    local bg = Instance.new("BillboardGui")
    -- Use stealth name for anti-detection
    bg.Name = _G.getRandomStealthName and _G.getRandomStealthName() or ("TimerBB_" .. math.random(10000, 99999))
    bg.Size = UDim2.new(0, 90, 0, 60)
    bg.StudsOffset = Vector3.new(2.2, 0, 0)
    bg.AlwaysOnTop = true
    bg.MaxDistance = 200
    bg.Parent = playerGui
    local frame = Instance.new("Frame")
    frame.Name = "BG"
    frame.Size = UDim2.new(1, 0, 1, 0)
    frame.BackgroundTransparency = 1
    frame.BorderSizePixel = 0
    frame.Parent = bg
    local plate = Instance.new("Frame")
    plate.Name = "Plate"
    plate.Size = UDim2.new(0, 70, 0, 46)
    plate.Position = UDim2.new(0, 0, 0, 6)
    plate.BackgroundTransparency = 0.5
    plate.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
    plate.BorderSizePixel = 0
    plate.Parent = frame
    local barBg = Instance.new("Frame")
    barBg.Name = "BarBg"
    barBg.Size = UDim2.new(0, 10, 0, 36)
    barBg.Position = UDim2.new(0, 6, 0, 5)
    barBg.BackgroundColor3 = Color3.fromRGB(40, 40, 40)
    barBg.BorderSizePixel = 0
    barBg.Parent = plate
    barBg.AnchorPoint = Vector2.new(0, 0)
    local fill = Instance.new("Frame")
    fill.Name = "Fill"
    fill.Size = UDim2.new(1, 0, 1, 0)
    fill.Position = UDim2.new(0, 0, 0, 0)
    fill.BackgroundColor3 = Color3.fromRGB(180, 80, 0)
    fill.BorderSizePixel = 0
    fill.Parent = barBg
    fill.AnchorPoint = Vector2.new(0, 1)
    fill.Position = UDim2.new(0, 0, 1, 0)
    local lbl = Instance.new("TextLabel")
    lbl.Name = "Timer"
    lbl.Size = UDim2.new(0, 44, 0, 18)
    lbl.Position = UDim2.new(0, 22, 0, 8)
    lbl.BackgroundTransparency = 1
    lbl.TextScaled = false
    lbl.Font = Enum.Font.SourceSansBold
    lbl.TextSize = 16
    lbl.Text = ""
    lbl.TextColor3 = Color3.fromRGB(255, 255, 255)
    lbl.Parent = plate
    local title = Instance.new("TextLabel")
    title.Name = "Title"
    title.Size = UDim2.new(0, 44, 0, 14)
    title.Position = UDim2.new(0, 22, 0, 27)
    title.BackgroundTransparency = 1
    title.TextScaled = false
    title.Font = Enum.Font.SourceSans
    title.TextSize = 12
    title.Text = "Hand Mortar"
    title.TextColor3 = Color3.fromRGB(200, 200, 200)
    title.Parent = plate
    -- SCREEN (for first-person) — overlay in PlayerGui
    local screen = Instance.new("ScreenGui")
    screen.ResetOnSpawn = false
    if _G.protectGUI then _G.protectGUI(screen) else screen.Parent = playerGui end -- Use stealth protection
    local sFrame = Instance.new("Frame")
    sFrame.Name = "Plate"
    sFrame.Size = UDim2.new(0, 120, 0, 60)
    -- Position: right of screen center (adjust as needed)
    sFrame.Position = UDim2.new(0.55, 0, 0.45, 0)
    sFrame.AnchorPoint = Vector2.new(0, 0)
    sFrame.BackgroundTransparency = 0.25
    sFrame.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
    sFrame.BorderSizePixel = 0
    sFrame.Parent = screen
    local sBarBg = Instance.new("Frame")
    sBarBg.Name = "BarBg"
    sBarBg.Size = UDim2.new(0, 10, 0, 36)
    sBarBg.Position = UDim2.new(0, 6, 0, 12)
    sBarBg.BackgroundColor3 = Color3.fromRGB(40, 40, 40)
    sBarBg.BorderSizePixel = 0
    sBarBg.Parent = sFrame
    local sFill = Instance.new("Frame")
    sFill.Name = "Fill"
    sFill.Size = UDim2.new(1, 0, 1, 0)
    sFill.Position = UDim2.new(0, 0, 0, 0)
    sFill.BackgroundColor3 = Color3.fromRGB(180, 80, 0)
    sFill.BorderSizePixel = 0
    sFill.Parent = sBarBg
    sFill.AnchorPoint = Vector2.new(0, 1)
    sFill.Position = UDim2.new(0, 0, 1, 0)
    local sTimer = Instance.new("TextLabel")
    sTimer.Name = "Timer"
    sTimer.Size = UDim2.new(0, 80, 0, 24)
    sTimer.Position = UDim2.new(0, 22, 0, 12)
    sTimer.BackgroundTransparency = 1
    sTimer.TextScaled = false
    sTimer.Font = Enum.Font.SourceSansBold
    sTimer.TextSize = 18
    sTimer.Text = ""
    sTimer.TextColor3 = Color3.fromRGB(255, 255, 255)
    sTimer.Parent = sFrame
    local sTitle = Instance.new("TextLabel")
    sTitle.Name = "Title"
    sTitle.Size = UDim2.new(0, 80, 0, 16)
    sTitle.Position = UDim2.new(0, 22, 0, 38)
    sTitle.BackgroundTransparency = 1
    sTitle.TextScaled = false
    sTitle.Font = Enum.Font.SourceSans
    sTitle.TextSize = 12
    sTitle.Text = "Hand Mortar"
    sTitle.TextColor3 = Color3.fromRGB(200, 200, 200)
    sTitle.Parent = sFrame
    handMortarGui = {
        billboard = bg,
        screen = screen,
    }
    -- hide both initially; startHandMortarTimer will set visibility
    bg.Enabled = false
    screen.Enabled = false
    return handMortarGui
end
local function destroyHandMortarGui()
    if handMortarUpdateConn then
        pcall(function() handMortarUpdateConn:Disconnect() end)
        handMortarUpdateConn = nil
    end
    if handMortarCameraConn then
        pcall(function() handMortarCameraConn:Disconnect() end)
        handMortarCameraConn = nil
    end
    if handMortarGui then
        if handMortarGui.billboard and handMortarGui.billboard.Parent then
            pcall(function() handMortarGui.billboard:Destroy() end)
        end
        if handMortarGui.screen and handMortarGui.screen.Parent then
            pcall(function() handMortarGui.screen:Destroy() end)
        end
        handMortarGui = nil
    end
    handMortarRunning = false
    handMortarEndTick = nil
end
-- Start/restart the timer for given duration (seconds, float)
local function startHandMortarTimer(duration)
    if not HAND_MORTAR_TIMING_ENABLED then return end
    if not duration or type(duration) ~= "number" then duration = HAND_MORTAR_DURATION end
    -- create gui if not present
    local gui = createHandMortarGui()
    -- attach billboard to head if possible
    local char = LocalPlayer.Character
    if char then
        local head = char:FindFirstChild("Head") or char:FindFirstChild("HumanoidRootPart")
        if head and head:IsA("BasePart") and gui.billboard then
            gui.billboard.Adornee = head
        end
    end
    -- mark end tick
    handMortarEndTick = tick() + duration
    handMortarRunning = true
    -- Decide initial visibility depending on first/third person
    local function updateVisibility()
        local fp = isFirstPerson()
        if gui.billboard then gui.billboard.Enabled = not fp end
        if gui.screen then gui.screen.Enabled = fp end
    end
    updateVisibility()
    -- Listen for camera changes so it toggles during countdown
    if handMortarCameraConn then
        -- already listening
    else
        handMortarCameraConn = RunService.RenderStepped:Connect(function()
            if not handMortarRunning then return end
            if handMortarGui then
                local fp = isFirstPerson()
                if handMortarGui.billboard then handMortarGui.billboard.Enabled = not fp end
                if handMortarGui.screen then handMortarGui.screen.Enabled = fp end
            end
        end)
    end
    -- ensure update connection for fill + text
    if handMortarUpdateConn then
        -- already updating; just restart (the loop will pick new end tick)
        return
    end
    handMortarUpdateConn = RunService.RenderStepped:Connect(function()
        if not handMortarRunning or not handMortarGui then
            destroyHandMortarGui()
            return
        end
        local remaining = math.max(0, handMortarEndTick - tick())
        local ratio = remaining / duration
        ratio = math.clamp(ratio, 0, 1)
        pcall(function()
            -- billboard
            if handMortarGui.billboard and handMortarGui.billboard.Parent then
                local plate = handMortarGui.billboard:FindFirstChild("BG") and handMortarGui.billboard.BG:FindFirstChild("Plate")
                if plate then
                    local barBg = plate:FindFirstChild("BarBg")
                    if barBg then
                        local fillFrame = barBg:FindFirstChild("Fill")
                        if fillFrame then
                            fillFrame.Size = UDim2.new(1, 0, ratio, 0)
                        end
                    end
                    local timerLabel = plate:FindFirstChild("Timer")
                    if timerLabel then
                        local ms = math.floor(remaining * 1000 + 0.5)
                        local sec = math.floor(ms / 1000)
                        local remMs = ms - sec * 1000
                        timerLabel.Text = string.format("%d.%03ds", sec, remMs)
                    end
                end
            end
            -- screen
            if handMortarGui.screen and handMortarGui.screen.Parent then
                local sFrame = handMortarGui.screen:FindFirstChild("Plate")
                if sFrame then
                    local sBarBg = sFrame:FindFirstChild("BarBg")
                    if sBarBg then
                        local sFill = sBarBg:FindFirstChild("Fill")
                        if sFill then
                            sFill.Size = UDim2.new(1, 0, ratio, 0)
                        end
                    end
                    local sTimer = sFrame:FindFirstChild("Timer")
                    if sTimer then
                        local ms = math.floor(remaining * 1000 + 0.5)
                        local sec = math.floor(ms / 1000)
                        local remMs = ms - sec * 1000
                        sTimer.Text = string.format("%d.%03ds", sec, remMs)
                    end
                end
            end
        end)
        if remaining <= 0 then
            -- finished
            destroyHandMortarGui()
        end
    end)
end
---------------------------------------------------------------------
-- NEW DETECTION: via animation played on the local Humanoid (supports both anims)
---------------------------------------------------------------------
local function attachHandMortarWatcher()
    -- We only need one AnimationPlayed connection; ignore extra calls
    if handMortarAnimConn then return end
    local char = LocalPlayer.Character
    if not char then return end
    local hum = char:FindFirstChildOfClass("Humanoid")
    if not hum then return end
    local function onAnimPlayed(track)
        local anim = track and track.Animation
        if not anim then return end
        local id = string.lower(tostring(anim.AnimationId or ""))
        -- If this is one of our Hand Mortar fuse animations, wait 1s then start the 5s countdown
        if HAND_MORTAR_ANIM_IDS[id] then
            -- we wait 1s from the animation start, then show the 5s countdown
            task.delay(1, function()
                -- safety checks
                if not HAND_MORTAR_TIMING_ENABLED then return end
                if not LocalPlayer.Character then return end
                -- start the 5s countdown after 1 second delay
                startHandMortarTimer(HAND_MORTAR_DURATION)
            end)
        end
    end
    local ok, conn = pcall(function()
        return hum.AnimationPlayed:Connect(onAnimPlayed)
    end)
    if ok and conn then
        handMortarAnimConn = conn
    end
end
-- re-attach on character spawn + cleanup previous gui
LocalPlayer.CharacterAdded:Connect(function(newChar)
    task.wait(0.1)
    if handMortarAnimConn then
        pcall(function() handMortarAnimConn:Disconnect() end)
        handMortarAnimConn = nil
    end
    attachHandMortarWatcher()
    destroyHandMortarGui()
end)
-- initial attach if character already loaded
pcall(function()
    attachHandMortarWatcher()
end)
-- UI: Misc section and toggle (only if GunTab exists)
if GunTab then
    local MiscGunSection = GunTab:Section({ Title = "Misc", Icon = "settings", Opened = false })
    -- UI Toggle
    MiscGunSection:Toggle({
        Title = "Hand Mortar Timing",
        Flag = "Misc_HandMortarTiming",
        Desc = "Shows The Timer Of The Mortar Before Blowing Up.",
        Icon = "clock",
        Value = HAND_MORTAR_TIMING_ENABLED,
        Callback = function(state)
            HAND_MORTAR_TIMING_ENABLED = state
            if not state then
                -- cleanup UI if disabled
                destroyHandMortarGui()
            end
        end
    })
end
end -- End Hand Mortar Feature scope
print("Skibidi")
-- End hand mortar feature

-- PERFORMANCE FIX: Mark Gun Tab initialization as complete to enable notifications
GunTab_InitComplete = true

end -- End Gun Tab UI Section scope

task.wait(0.1) -- Delay to prevent lag
do -- // ESP Tab
    local EspTab = Esp1Section:Tab({ Title = "Esp", Icon = "eye" })

    -- PERFORMANCE FIX: Flag to suppress notifications during UI initialization
    local ESPTab_InitComplete = false

    local ESPSection = EspTab:Section({
        Title = "ESP & Zombie Alerts",
        Icon = "eye",
        Opened = false
    })

    local RunService = RunService or game:GetService("RunService")
    local CameraFolder = workspace:FindFirstChild("Camera")
    -- Use weak table so dead zombie references are auto-collected by GC
    local IdentifiedIgniters = setmetatable({}, { __mode = "k" })
    ESPConfigs = ESPConfigs or {
        Bomber = {
            color = Color3.fromRGB(255, 180, 60),
            label = "Barrel",
            match = function(model)
                if not model or not model:IsA("Model") then return false end
                local zType = GetZombieTypeFromModel and GetZombieTypeFromModel(model)
                if zType then return zType == "Bomber" end
                return model:FindFirstChild("Barrel", true) ~= nil
            end,
        },
        Cuirassier = {
            color = Color3.fromRGB(0, 200, 255),
            label = "Cuirassier",
            match = function(model)
                local zType = GetZombieTypeFromModel and GetZombieTypeFromModel(model)
                if zType then return zType == "Cuirassier" end
                return model:FindFirstChild("Sword", true) ~= nil
            end,
        },
        Runner = {
            color = Color3.fromRGB(255, 0, 0),
            label = "Runner",
            match = function(model)
                local zType = GetZombieTypeFromModel and GetZombieTypeFromModel(model)
                if zType then return zType == "Runner" end
                return model:FindFirstChild("Eye") and not model:FindFirstChild("Axe") and model:FindFirstChild("Head")
            end,
        },
        Zapper = {
            color = Color3.fromRGB(0, 255, 0),
            label = "Zapper",
            match = function(model)
                local zType = GetZombieTypeFromModel and GetZombieTypeFromModel(model)
                if zType then return zType == "Zapper" end
                return model:FindFirstChild("Axe") and model:FindFirstChild("Head")
            end,
        },
        Igniter = {
            color = Color3.fromRGB(255, 255, 0),
            label = "Igniter",
            match = function(model)
                if not model or not model:IsA("Model") then return false end
                local zType = GetZombieTypeFromModel and GetZombieTypeFromModel(model)
                if zType then return zType == "Igniter" end
                if model:FindFirstChild("Whale Oil Lantern") then
                    IdentifiedIgniters[model] = true
                    return true
                end
                -- If lantern is gone, remove from identified igniters so it can become a shambler
                if IdentifiedIgniters[model] and not model:FindFirstChild("Whale Oil Lantern") then
                    IdentifiedIgniters[model] = nil
                    return false
                end
                return false
            end,
        },
        -- NEW: Shambler (normal)
        Shambler = {
            color = Color3.fromRGB(180, 180, 255),
            label = "Shambler",
            match = function(model)
                if not model or not model:IsA("Model") then return false end
                local zType = GetZombieTypeFromModel and GetZombieTypeFromModel(model)
                if zType then return zType == "Shambler" end
                -- must be the regular zombie model
                if model.Name ~= "m_Zombie" then return false end
                -- if it has any special markers, it's NOT a Shambler
                if model:FindFirstChild("Barrel", true) then return false end
                if model:FindFirstChild("Sword", true) then return false end
                if model:FindFirstChild("Eye", true) then return false end
                if model:FindFirstChild("Axe", true) then return false end
                if model:FindFirstChild("Whale Oil Lantern", true) then return false end
                -- passed all checks -> normal shambler
                return true
            end,
        },
    }

    local ESPData = {
        Bomber = setmetatable({}, { __mode = "k" }),
        Cuirassier = setmetatable({}, { __mode = "k" }),
        Runner = setmetatable({}, { __mode = "k" }),
        Zapper = setmetatable({}, { __mode = "k" }),
        Igniter = setmetatable({}, { __mode = "k" }),
        Shambler = setmetatable({}, { __mode = "k" }), -- added
    }

    -- Track zombies pending removal (grace period to prevent flicker from temporary parent loss)
    -- Use weak keys so dead zombie references are garbage collected
    local ESPPendingRemoval = setmetatable({}, { __mode = "k" }) -- [zombie] = tick() when marked for removal
    local ESP_REMOVAL_GRACE_PERIOD = 0.5 -- seconds to wait before actually removing

    local EnabledESPs = {
        Bomber = false,
        Cuirassier = false,
        Runner = false,
        Zapper = false,
        Igniter = false,
        Shambler = false, -- added
    }

    -- Hidden per-type visual mode (kept defaults from before; not exposed in UI)
    local ESPModes = {
        Bomber = "Both",
        Cuirassier = "Both",
        Runner = "Both",
        Zapper = "Both",
        Igniter = "Both",
        Shambler = "Both", -- added
    }

    -- Default: show billboards disabled
    local ShowBillboards = false
    local ChamsTransparency = 0.6
    local PerformanceMode = false
    local ChamsMaxDistance = 2000
    
    -- PERFORMANCE: Distance culling - don't create ESP for zombies too far away
    local ESP_CREATION_MAX_DISTANCE = 500 -- Only create ESP for zombies within this distance
    local ESP_VISIBLE_MAX_DISTANCE = 300 -- Distance at which ESP becomes visible
    local ESP_SCAN_BATCH_SIZE = 20 -- Max zombies to process per scan cycle

    local activeCount = 0
    local scanLoop
    local renderConn
    
    -- PERFORMANCE: Cache camera position
    local cachedCameraPos = Vector3.new(0, 0, 0)
    local lastCameraCacheTime = 0

    local function GetAdorneePart(model)
        if not model or not model:IsA("Model") then return nil end
        -- PERFORMANCE: Check common parts first without using FindFirstChild with recursive=true
        local head = model:FindFirstChild("Head")
        if head and head:IsA("BasePart") then return head end
        local hrp = model:FindFirstChild("HumanoidRootPart")
        if hrp and hrp:IsA("BasePart") then return hrp end
        if model.PrimaryPart and model.PrimaryPart:IsA("BasePart") then return model.PrimaryPart end
        -- PERFORMANCE: Use GetChildren instead of GetDescendants (much faster)
        local children = model:GetChildren()
        for _, p in ipairs(children) do
            if p:IsA("BasePart") and p.Name ~= "Whale Oil Lantern" then
                return p
            end
        end
        -- Fallback: check first-level folders only
        for _, child in ipairs(children) do
            if child:IsA("Folder") or child:IsA("Model") then
                for _, p in ipairs(child:GetChildren()) do
                    if p:IsA("BasePart") and p.Name ~= "Whale Oil Lantern" then
                        return p
                    end
                end
            end
        end
        return nil
    end

local function CreateVisual(espType, zombie)
    if not zombie or not zombie:IsA("Model") or ESPData[espType][zombie] then return end
    local config = ESPConfigs[espType]
    local headPart = GetAdorneePart(zombie)
    if not headPart then return end

    local mode = ESPModes[espType] or "Both"
    local data = {}
    ESPData[espType][zombie] = data
    data.maxDistance = ChamsMaxDistance
    local offset = Vector3.new(0, 3, 0)

    -- Decide visuals independently:
    local wantHighlight = (mode == "Both" or mode == "Highlight Only") and (not PerformanceMode)
    local wantBillboard = (mode == "Both" or mode == "Billboard Only")
    -- In performance mode we always want a dot (unless the user explicitly picked "Billboard Only" and you
    -- want to change that behavior later). The user's request was: make it a dot with billboard in perf mode,
    -- except if billboard turned off — so dot is always created in PerformanceMode.
    local wantDot = (mode == "Dot Only") or PerformanceMode

    -- DOT (small billboard used as dot)
    if wantDot then
        local dotBb = Instance.new("BillboardGui")
        -- Use stealth name for anti-detection
        dotBb.Name = _G.getRandomStealthName and _G.getRandomStealthName() or ("Dot_" .. math.random(10000, 99999))
        dotBb.Adornee = headPart
        dotBb.AlwaysOnTop = true
        dotBb.Size = UDim2.new(0, 8, 0, 8)
        dotBb.StudsOffset = Vector3.new(0, 0, 0)
        dotBb.MaxDistance = ChamsMaxDistance
        dotBb.Parent = zombie
        data.dot = dotBb

        local dotFrame = Instance.new("Frame")
        dotFrame.Size = UDim2.new(1, 0, 1, 0)
        dotFrame.BackgroundColor3 = config.color
        local corner = Instance.new("UICorner")
        corner.CornerRadius = UDim.new(0.5, 0)
        corner.Parent = dotFrame
        dotFrame.Parent = dotBb
    end

    -- HIGHLIGHT (only when not in performance mode)
    if wantHighlight then
        local hl = Instance.new("Highlight")
        -- Use stealth name for anti-detection
        hl.Name = _G.getRandomStealthName and _G.getRandomStealthName() or ("HL_" .. math.random(10000, 99999))
        hl.Adornee = zombie
        hl.FillColor = config.color
        hl.OutlineColor = Color3.fromRGB(255, 255, 255)
        hl.FillTransparency = ChamsTransparency
        hl.OutlineTransparency = 0
        hl.Parent = zombie
        data.highlight = hl
    end

    -- BILLBOARD (create regardless of whether a dot exists; Enabled will be controlled in UpdateAllBillboards)
    if wantBillboard then
        local bb = Instance.new("BillboardGui")
        -- Use stealth name for anti-detection
        bb.Name = _G.getRandomStealthName and _G.getRandomStealthName() or ("BB_" .. math.random(10000, 99999))
        bb.Adornee = headPart
        bb.AlwaysOnTop = true
        bb.LightInfluence = 0
        bb.Size = UDim2.new(0, 100, 0, 40)
        bb.StudsOffset = offset
        bb.MaxDistance = 1000
        bb.Enabled = ShowBillboards -- initial enabled state; UpdateAllBillboards will adjust per-distance
        bb.Parent = zombie
        data.billboard = bb

        local frame = Instance.new("Frame")
        frame.Size = UDim2.new(1, 0, 1, 0)
        frame.BackgroundColor3 = Color3.fromRGB(30, 30, 30)
        frame.BackgroundTransparency = 0.7
        frame.BorderSizePixel = 1
        frame.BorderColor3 = config.color
        local corner = Instance.new("UICorner")
        corner.CornerRadius = UDim.new(0, 8)
        corner.Parent = frame
        frame.Parent = bb
        data.frame = frame

        local lbl = Instance.new("TextLabel")
        lbl.AnchorPoint = Vector2.new(0.5, 0)
        lbl.Position = UDim2.new(0.5, 0, 0.1, 0)
        lbl.Size = UDim2.new(0.9, 0, 0.5, 0)
        lbl.BackgroundTransparency = 1
        lbl.Text = config.label
        lbl.TextColor3 = config.color
        lbl.TextStrokeTransparency = 0.8
        lbl.TextScaled = true
        lbl.Font = Enum.Font.GothamBold
        lbl.Parent = frame
        data.label = lbl

        local distLbl = Instance.new("TextLabel")
        distLbl.AnchorPoint = Vector2.new(0.5, 1)
        distLbl.Position = UDim2.new(0.5, 0, 0.9, 0)
        distLbl.Size = UDim2.new(0.9, 0, 0.3, 0)
        distLbl.BackgroundTransparency = 1
        distLbl.Text = "0 studs"
        distLbl.TextColor3 = Color3.fromRGB(200, 200, 200)
        distLbl.TextScaled = true
        distLbl.Font = Enum.Font.Gotham
        distLbl.Parent = frame
        data.distLabel = distLbl
    end
    
    -- PROTECT ESP VISUALS from anti-cheat detection
    pcall(function()
        if _G.protectESP then
            if data.highlight then _G.protectESP(data.highlight) end
            if data.billboard then _G.protectESP(data.billboard) end
            if data.dot then _G.protectESP(data.dot) end
        end
    end)
end

    local function RemoveVisual(espType, zombie)
        local data = ESPData[espType][zombie]
        if not data then return end
        -- Destroy instances
        if data.highlight then pcall(function() data.highlight:Destroy() end) end
        if data.billboard then pcall(function() data.billboard:Destroy() end) end
        if data.dot then pcall(function() data.dot:Destroy() end) end
        -- Clear all references in the data table to help GC
        data.highlight = nil
        data.billboard = nil
        data.dot = nil
        data.frame = nil
        data.label = nil
        data.distLabel = nil
        -- Remove from ESPData
        ESPData[espType][zombie] = nil
        -- Also clear pending removal tracker and IdentifiedIgniters
        if zombie then
            ESPPendingRemoval[zombie] = nil
            IdentifiedIgniters[zombie] = nil
        end
    end

    -- Collect zombies from new Agent/Slim folders, with Camera fallback for legacy setups
    local function CollectZombies()
        local list = {}
        local zFolder = workspace:FindFirstChild("Zombies")
        if zFolder then
            local agent = zFolder:FindFirstChild("Agent")
            if agent then
                for _, z in ipairs(agent:GetChildren()) do
                    if z:IsA("Model") then
                        -- Skip temporary swing models (they have a "Character" child, real zombies don't)
                        -- Also skip models with names starting with underscore (like _Bink_xxx)
                        local hasCharacter = z:FindFirstChild("Character")
                        local nameStartsWithUnderscore = z.Name:sub(1, 1) == "_"
                        if not hasCharacter and not nameStartsWithUnderscore then
                            table.insert(list, z)
                        end
                    end
                end
            end
            local slim = zFolder:FindFirstChild("Slim")
            if slim then
                for _, z in ipairs(slim:GetChildren()) do
                    if z:IsA("Model") then
                        -- Same filter for Slim
                        local hasCharacter = z:FindFirstChild("Character")
                        local nameStartsWithUnderscore = z.Name:sub(1, 1) == "_"
                        if not hasCharacter and not nameStartsWithUnderscore then
                            table.insert(list, z)
                        end
                    end
                end
            end
        end
        if #list == 0 and CameraFolder then
            for _, z in ipairs(CameraFolder:GetChildren()) do
                if z:IsA("Model") then
                    table.insert(list, z)
                end
            end
        end
        return list
    end

    local function ScanAll()
        local zombies = CollectZombies()
        
        -- PERFORMANCE FIX: Build a set of current zombies once for faster lookups
        local zombieSet = {}
        for _, z in ipairs(zombies) do
            zombieSet[z] = true
        end
        
        -- PERFORMANCE: Get camera position for distance culling
        local cam = workspace.CurrentCamera
        local camPos = cam and cam.CFrame.Position or Vector3.new(0, 0, 0)
        
        for espType, enabled in pairs(EnabledESPs) do
            if enabled then
                -- Remove visuals for zombies that no longer exist
                for z in pairs(ESPData[espType]) do
                    if not zombieSet[z] then
                        RemoveVisual(espType, z)
                    end
                end
                
                -- PERFORMANCE: Limit how many new visuals we create per scan cycle
                local created = 0
                
                -- Add visuals for new zombies that match this type
                for _, z in ipairs(zombies) do
                    if created >= ESP_SCAN_BATCH_SIZE then break end -- PERFORMANCE: Batch limit
                    
                    if z:IsA("Model") and not ESPData[espType][z] then
                        -- PERFORMANCE: Distance culling - skip zombies too far away
                        local zombiePart = z.PrimaryPart or z:FindFirstChild("HumanoidRootPart") or z:FindFirstChild("Head")
                        if zombiePart then
                            local dist = (camPos - zombiePart.Position).Magnitude
                            if dist > ESP_CREATION_MAX_DISTANCE then continue end -- Skip distant zombies
                        end
                        
                        -- Check if zombie already has ESP from another type
                        local hasOtherESP = false
                        for otherType, otherData in pairs(ESPData) do
                            if otherType ~= espType and otherData[z] then
                                hasOtherESP = true
                                break
                            end
                        end
                        
                        if not hasOtherESP and ESPConfigs[espType].match(z) then
                            CreateVisual(espType, z)
                            created = created + 1
                        end
                    end
                end
            else
                -- ESP type disabled - clear all its visuals
                if next(ESPData[espType]) then
                    for z in pairs(ESPData[espType]) do
                        RemoveVisual(espType, z)
                    end
                    -- Reset to weak table to maintain GC behavior
                    ESPData[espType] = setmetatable({}, { __mode = "k" })
                end
            end
        end
    end

    local function UpdateAllTransparencies()
        for espType, dataTable in pairs(ESPData) do
            for _, data in pairs(dataTable) do
                if data.highlight then data.highlight.FillTransparency = ChamsTransparency end
            end
        end
    end

local function UpdateAllBillboards()
    local Camera = workspace.CurrentCamera
    if not Camera then return end

    local now = tick()
    local cameraPos = Camera.CFrame.Position

    for espType, dataTable in pairs(ESPData) do
        -- Skip if this ESP type is disabled
        if not EnabledESPs[espType] then continue end
        
        for zombie, data in pairs(dataTable) do
            -- Quick nil check without pcall for performance
            if not zombie or not zombie.Parent then
                -- zombie lost parent - use grace period to prevent flicker
                if not ESPPendingRemoval[zombie] then
                    ESPPendingRemoval[zombie] = now
                elseif (now - ESPPendingRemoval[zombie]) >= ESP_REMOVAL_GRACE_PERIOD then
                    -- grace period expired, actually remove
                    RemoveVisual(espType, zombie)
                    ESPPendingRemoval[zombie] = nil
                end
                -- hide visuals during grace period
                if data.highlight then data.highlight.Enabled = false end
                if data.dot then data.dot.Enabled = false end
                if data.billboard then data.billboard.Enabled = false end
                continue
            end
            
            -- zombie has parent again, clear pending removal if any
            if ESPPendingRemoval[zombie] then
                ESPPendingRemoval[zombie] = nil
            end
            
            -- Get adornee for distance calculation
            local adornee = (data.billboard and data.billboard.Adornee) or (data.dot and data.dot.Adornee)
            
            if not adornee or not adornee.Parent then
                local newPart = GetAdorneePart(zombie)
                if newPart then
                    if data.billboard then data.billboard.Adornee = newPart end
                    if data.dot then data.dot.Adornee = newPart end
                    adornee = newPart
                else
                    RemoveVisual(espType, zombie)
                    continue
                end
            end
            
            -- Calculate distance once
            local pos = adornee.Position
            local dist = (cameraPos - pos).Magnitude
            local maxDist = data.maxDistance or ChamsMaxDistance

            -- Precompute flags once
            local highlightAllowed = not PerformanceMode
            local dotAllowed = PerformanceMode

            -- HIGHLIGHT - simple enable/disable
            if data.highlight then
                data.highlight.Enabled = highlightAllowed and (dist <= maxDist)
            end

            -- DOT - simple enable/disable  
            if data.dot then
                data.dot.Enabled = dotAllowed and (dist <= maxDist)
            end

            -- BILLBOARD - only update if enabled
            if data.billboard then
                if not ShowBillboards then
                    data.billboard.Enabled = false
                else
                    local maxBillboardDist = PerformanceMode and 500 or 300
                    if dist < maxBillboardDist then
                        data.billboard.Enabled = true
                        -- Update distance text (less frequently by checking if changed significantly)
                        if data.distLabel then
                            local newText = math.floor(dist) .. " studs"
                            if data.distLabel.Text ~= newText then
                                data.distLabel.Text = newText
                            end
                        end
                    else
                        data.billboard.Enabled = false
                    end
                end
            end
        end
    end
end

    local function StartShared()
        activeCount = activeCount + 1
        if activeCount == 1 then
            ScanAll()
            scanLoop = task.spawn(function()
                local cleanupCounter = 0
                local gcCounter = 0
                while activeCount > 0 do
                    ScanAll()
                    
                    -- Periodic cleanup every 10 scan cycles (~10 seconds)
                    cleanupCounter = cleanupCounter + 1
                    if cleanupCounter >= 10 then
                        cleanupCounter = 0
                        -- Clean up stale pending removal entries
                        local now = tick()
                        for zombie, timestamp in pairs(ESPPendingRemoval) do
                            if not zombie or not zombie.Parent then
                                if (now - timestamp) > 5 then -- 5 second hard timeout
                                    ESPPendingRemoval[zombie] = nil
                                end
                            else
                                -- Zombie has parent again, remove from pending
                                ESPPendingRemoval[zombie] = nil
                            end
                        end
                        -- Clean up IdentifiedIgniters for dead zombies
                        for zombie in pairs(IdentifiedIgniters) do
                            if not zombie or not zombie.Parent then
                                IdentifiedIgniters[zombie] = nil
                            end
                        end
                    end
                    
                    -- PERFORMANCE: Trigger garbage collection every 60 scan cycles (~60 seconds)
                    gcCounter = gcCounter + 1
                    if gcCounter >= 60 then
                        gcCounter = 0
                        pcall(function() collectgarbage("step", 100) end)
                    end
                    
                    task.wait(1.0) -- PERFORMANCE: Increased scan interval to 1 second
                end
            end)
            -- PERFORMANCE: Use Heartbeat with increased throttle interval
            local lastUpdate = 0
            local UPDATE_INTERVAL = 0.2 -- PERFORMANCE: Update every 0.2 seconds (5 FPS for ESP)
            renderConn = RunService.Heartbeat:Connect(function()
                -- PERFORMANCE: Mark ESP as active
                if _G.KatchiPerf then _G.KatchiPerf.markActive("ESP") end
                
                local now = tick()
                if now - lastUpdate < UPDATE_INTERVAL then return end
                lastUpdate = now
                
                -- PERFORMANCE: Update cached camera position
                local cam = workspace.CurrentCamera
                if cam then
                    cachedCameraPos = cam.CFrame.Position
                    lastCameraCacheTime = now
                end
                
                UpdateAllBillboards()
            end)
        end
    end

    local function StopShared()
        activeCount = activeCount - 1
        if activeCount == 0 then
            if scanLoop then task.cancel(scanLoop) scanLoop = nil end
            if renderConn then renderConn:Disconnect() renderConn = nil end
            -- Clear pending removal table (already weak, but clear for good measure)
            for k in pairs(ESPPendingRemoval) do ESPPendingRemoval[k] = nil end
            -- Clear IdentifiedIgniters to free memory
            for k in pairs(IdentifiedIgniters) do IdentifiedIgniters[k] = nil end
            -- Clear any remaining ESP data entries and reset to weak tables
            for espType in pairs(ESPData) do
                for zombie in pairs(ESPData[espType]) do
                    ESPData[espType][zombie] = nil
                end
                -- Reset to weak table to ensure GC works after clearing
                ESPData[espType] = setmetatable({}, { __mode = "k" })
            end
        end
    end

    local function TogglePerformanceMode(state)
        PerformanceMode = state
        -- PERFORMANCE FIX: Instead of recreating all visuals at once, do it gradually
        -- Just toggle visibility - visuals will be recreated on next scan cycle
        for espType in pairs(ESPConfigs) do
            for zombie, data in pairs(ESPData[espType]) do
                -- Toggle highlight/dot based on performance mode
                if data.highlight then
                    data.highlight.Enabled = not state
                end
                if data.dot then
                    data.dot.Enabled = state
                end
            end
        end
    end

    -- Cuirassier-specific state
    local LastChargeState = false
    local NotifyCuirassierCharge = false
    local CuirassierStateLoop

    local function IsCharging(state)
        state = tostring(state or ""):lower()
        return (state == "begincharge" or state == "charge")
    end

    local function UpdateCuirassierState()
        local zFolder = workspace:FindFirstChild("Zombies")
        if not zFolder then return end
        local slim = zFolder:FindFirstChild("Slim")
        if not slim then return end
        local stateVal = slim:FindFirstChild("State")
        if not stateVal or not stateVal:IsA("StringValue") then return end

        local charging = IsCharging(stateVal.Value)
        for _, data in pairs(ESPData.Cuirassier) do
            if data.label and (data.frame or true) then
                if charging then
                    data.label.Text = "Charging"
                    data.label.TextColor3 = Color3.fromRGB(255, 80, 80)
                    if data.frame then data.frame.BorderColor3 = Color3.fromRGB(255, 80, 80) end
                else
                    data.label.Text = "Cuirassier"
                    data.label.TextColor3 = ESPConfigs.Cuirassier.color
                    if data.frame then data.frame.BorderColor3 = ESPConfigs.Cuirassier.color end
                end
            end
        end
        if charging and NotifyCuirassierCharge and not LastChargeState then
            pcall(function()
                if WindUI and typeof(WindUI.Notify) == "function" then
                    WindUI:Notify({ Title = "Cuirassier Charge", Content = "A Cuirassier is Charging!", Icon = "bell", Duration = 3 })
                end
            end)
        end
        LastChargeState = charging
    end

    local function StartCuirassierSpecific()
        LastChargeState = false
        UpdateCuirassierState()
        CuirassierStateLoop = task.spawn(function()
            while EnabledESPs.Cuirassier do
                UpdateCuirassierState()
                task.wait(0.5)
            end
        end)
    end

    local function StopCuirassierSpecific()
        if CuirassierStateLoop then task.cancel(CuirassierStateLoop) CuirassierStateLoop = nil end
        LastChargeState = false
    end

    local function ApplyColorToExisting(espType, color)
        local dataTable = ESPData[espType]
        if not dataTable then return end
        for zombie, data in pairs(dataTable) do
            pcall(function()
                if data.highlight then data.highlight.FillColor = color end
                if data.frame then data.frame.BorderColor3 = color end
                if data.label then data.label.TextColor3 = color end
                if data.dot then
                    for _, child in ipairs(data.dot:GetDescendants()) do
                        if child:IsA("Frame") then child.BackgroundColor3 = color end
                    end
                end
            end)
        end
    end

-- ===== Improved multi-select ESP dropdown + enable toggle =====
local EspList = { "Bomber", "Cuirassier", "Runner", "Zapper", "Igniter", "Shambler" }
SelectedESPs = SelectedESPs or {} -- list/table of selected types (global for config)
previousSelectedESPs = previousSelectedESPs or {} -- global for config
local espToggle -- forward ref
ESPData = ESPData or {}       -- make sure table exists
EnabledESPs = EnabledESPs or {} -- ensure exists

-- helper: remove all visuals safely for given type
local function RemoveAllVisualsForType(typeName)
    local t = ESPData[typeName]
    if not t then return end
    -- PERFORMANCE FIX: Batch destroy visuals and clear all references
    for zombieModel, data in pairs(t) do
        if data then
            if data.highlight then pcall(function() data.highlight:Destroy() end) end
            if data.billboard then pcall(function() data.billboard:Destroy() end) end
            if data.dot then pcall(function() data.dot:Destroy() end) end
            -- Clear references to help GC
            data.highlight = nil
            data.billboard = nil
            data.dot = nil
            data.frame = nil
            data.label = nil
            data.distLabel = nil
        end
        -- Clear from IdentifiedIgniters and pending removal
        if zombieModel then
            IdentifiedIgniters[zombieModel] = nil
            ESPPendingRemoval[zombieModel] = nil
        end
    end
    -- Reset to weak table to ensure GC works properly
    ESPData[typeName] = setmetatable({}, { __mode = "k" })
end

-- helper: check if any ESP type is currently enabled
local function AnyESPEnabled()
    for k, v in pairs(EnabledESPs) do
        if v then return true end
    end
    return false
end

local espDropdown = ESPSection:Dropdown({
    Title = "Select ESP Types",
    Flag = "DropdowwnEsp",
    Desc = "Type Of Zombies To Enable Esp At.",
    Values = EspList,
    Value = {},            -- default empty
    Multi = true,
    Callback = function(selection)
        local newSelection = selection or {}
        -- normalize to array of strings
        local normalized = {}
        for _, v in ipairs(newSelection) do table.insert(normalized, tostring(v)) end

        -- build lookup sets
        local prevSet = {}
        for _, v in ipairs(previousSelectedESPs) do prevSet[tostring(v)] = true end
        local newSet = {}
        for _, v in ipairs(normalized) do newSet[tostring(v)] = true end

        -- 1) Handle removals: previously selected but not present now
        for _, removedKey in ipairs(previousSelectedESPs) do
            if not newSet[tostring(removedKey)] then
                -- Always remove any visuals and clear runtime state for this type
                RemoveAllVisualsForType(removedKey)
                EnabledESPs[removedKey] = false
                -- Cuirassier specific cleanup
                if removedKey == "Cuirassier" then
                    pcall(function() StopCuirassierSpecific() end)
                end
                -- if no types enabled now, stop shared routines
                if not AnyESPEnabled() then pcall(function() StopShared() end) end

                if ESPTab_InitComplete then
                    pcall(function()
                        WindUI:Notify({
                            Title = (removedKey .. " ESP"),
                            Content = (removedKey .. " ESP disabled (deselected)"),
                            Icon = "eye-off",
                            Duration = 1
                        })
                    end)
                end
            end
        end

        -- 2) Update SelectedESPs / previousSelectedESPs
        SelectedESPs = {}
        for _, v in ipairs(normalized) do table.insert(SelectedESPs, v) end

        previousSelectedESPs = {}
        for _, v in ipairs(SelectedESPs) do table.insert(previousSelectedESPs, v) end

        -- 3) Sync toggle UI: if nothing selected -> false, else true only if *all* selected are enabled
        if espToggle then
            local anySelected = (#SelectedESPs > 0)
            if not anySelected then
                pcall(function() espToggle:Select(false) end)
            else
                local allEnabled = true
                for _, key in ipairs(SelectedESPs) do
                    if not EnabledESPs[key] then
                        allEnabled = false
                        break
                    end
                end
                pcall(function() espToggle:Select(allEnabled) end)
            end
        end

        if ESPTab_InitComplete then
            pcall(function()
                WindUI:Notify({
                    Title = "ESP Selection",
                    Content = (#SelectedESPs > 0) and ("Selected: " .. table.concat(SelectedESPs, ", ")) or "No selection",
                    Icon = "eye",
                    Duration = 1
                })
            end)
        end
    end
})

-- Toggle: enables/disables all currently selected ESP types
espToggle = ESPSection:Toggle({
    Title = "Enable Selected ESP",
    Flag = "Esp_Select_Toggle",
    Desc = "Enable Esp From The Selected Type.",
    Default = false,
    Callback = function(state)
        -- ensure SelectedESPs is a table
        if not SelectedESPs or #SelectedESPs == 0 then
            pcall(function() WindUI:Notify({ Title = "ESP", Content = "No ESP types selected.", Icon = "alert-circle", Duration = 2 }) end)
            -- keep the toggle UI false if nothing selected
            pcall(function() espToggle:Select(false) end)
            return
        end

        for _, key in ipairs(SelectedESPs) do
            -- skip invalid keys (guard block instead of goto)
            if key then
                -- only act if the state actually changes for that key
                if EnabledESPs[key] ~= state then
                    EnabledESPs[key] = state

                    if state then
                        -- enabling this ESP type
                        ESPData[key] = ESPData[key] or {}
                        pcall(function() StartShared() end)
                        if key == "Cuirassier" then pcall(function() StartCuirassierSpecific() end) end
                        pcall(function()
                            WindUI:Notify({ Title = (key .. " ESP"), Content = (key .. " ESP enabled"), Icon = "eye", Duration = 1 })
                        end)
                    else
                        -- disabling this ESP type: remove visuals & clear data
                        pcall(function() RemoveAllVisualsForType(key) end)
                        EnabledESPs[key] = false
                        if key == "Cuirassier" then pcall(function() StopCuirassierSpecific() end) end
                        -- only stop shared if nothing else is enabled
                        if not AnyESPEnabled() then pcall(function() StopShared() end) end
                        pcall(function()
                            WindUI:Notify({ Title = (key .. " ESP"), Content = (key .. " ESP disabled"), Icon = "eye-off", Duration = 1 })
                        end)
                    end
                end
            end
        end
    end
})

    -- =========================
    -- ESP Colors (unchanged + new Shambler color)
    -- =========================
    local ColorsSection = EspTab:Section({ Title = "ESP Colors", Icon = "palette", Opened = false })
    ColorsSection:Colorpicker({ Title = "Barrel (Bomber)", Flag = "Color1", Desc = "Color for Barrel zombies (Bomber)", Default = ESPConfigs.Bomber.color, Transparency = 0, Locked = false, Callback = function(color) ESPConfigs.Bomber.color = color ApplyColorToExisting("Bomber", color) end })
    ColorsSection:Colorpicker({ Title = "Cuirassier", Flag = "Color2", Desc = "Color for Cuirassier zombies", Default = ESPConfigs.Cuirassier.color, Transparency = 0, Locked = false, Callback = function(color) ESPConfigs.Cuirassier.color = color ApplyColorToExisting("Cuirassier", color) end })
    ColorsSection:Colorpicker({ Title = "Runner", Flag = "Color3", Desc = "Color for Runner zombies", Default = ESPConfigs.Runner.color, Transparency = 0, Locked = false, Callback = function(color) ESPConfigs.Runner.color = color ApplyColorToExisting("Runner", color) end })
    ColorsSection:Colorpicker({ Title = "Zapper", Flag = "Color4", Desc = "Color for Zapper zombies", Default = ESPConfigs.Zapper.color, Transparency = 0, Locked = false, Callback = function(color) ESPConfigs.Zapper.color = color ApplyColorToExisting("Zapper", color) end })
    ColorsSection:Colorpicker({ Title = "Igniter", Flag = "Color5", Desc = "Color for Igniter zombies", Default = ESPConfigs.Igniter.color, Transparency = 0, Locked = false, Callback = function(color) ESPConfigs.Igniter.color = color ApplyColorToExisting("Igniter", color) end })
    ColorsSection:Colorpicker({ Title = "Shambler (Normal)", Flag = "Color6", Desc = "Color for normal Shambler zombies", Default = ESPConfigs.Shambler.color, Transparency = 0, Locked = false, Callback = function(color) ESPConfigs.Shambler.color = color ApplyColorToExisting("Shambler", color) end })

    local SettingsSection = EspTab:Section({ Title = "Settings", Icon = "settings", Opened = false })
    SettingsSection:Toggle({ Title = "Show Billboard", Flag = "Esp_6", Desc = "Toggles billboards above the zombies", Default = false, Callback = function(state) ShowBillboards = state end })
    SettingsSection:Slider({ Title = "Chams Transparency", Flag = "Esp_7", Desc = "Controls the transparency of the chams", Value = { Min = 0, Max = 1, Default = 0.6 }, Step = 0.05, Callback = function(value) ChamsTransparency = math.clamp(tonumber(value) or 0.6, 0, 1) UpdateAllTransparencies() end })
    SettingsSection:Slider({
        Title = "Chams View Distance",
        Flag = "Esp_10",
        Desc = "Maximum distance to render zombie chams/highlights (in studs)",
        Value = { Min = 500, Max = 5000, Default = 2000 },
        Step = 100,
        Callback = function(value)
            ChamsMaxDistance = math.clamp(tonumber(value) or 2000, 500, 5000)
            for _, dataTable in pairs(ESPData) do
                for _, data in pairs(dataTable) do
                    data.maxDistance = ChamsMaxDistance
                    if data.dot then
                        data.dot.MaxDistance = ChamsMaxDistance
                    end
                end
            end
        end
    })
    SettingsSection:Toggle({ Title = "Performance", Flag = "Esp_8", Desc = "Makes chams into a dot and makes billboard simple", Default = false, Callback = function(state) TogglePerformanceMode(state) end })
    SettingsSection:Toggle({ Title = "Notify Cuirassier Charge", Flag = "Esp_9", Desc = "Sends a notification when a Cuirassier starts charging", Default = false, Callback = function(state) NotifyCuirassierCharge = state end })
    
    -- PERFORMANCE FIX: Mark ESP Tab initialization as complete
    ESPTab_InitComplete = true
end -- end of ESP Tab

task.wait(0.1) -- Delay to prevent lag
do -- // KillAura Tab
local KillAuraTab = Main1Section:Tab({ Title = "Kill Aura", Icon = "sword" })

-- === Kill Aura + Hitbox Expander (Position-match Barrel Mapping) ===
-- Uses position matching to exclude camera barrel zombies from real zombie targeting

-- PERFORMANCE FIX: Flag to suppress notifications during UI initialization
local KillAuraTab_InitComplete = false

local Players = game:GetService("Players")
local RunService = game:GetService("RunService")
local Workspace = game:GetService("Workspace")
local LocalPlayer = Players.LocalPlayer

-- Config
local DEBUG = false

-- Anti-Detection Settings (Balanced: fast but safe)
local KILLAURA_ANTICHEAT_BYPASS = true -- Enable anti-detection measures
local KILLAURA_MIN_DELAY = 0.03 -- Minimum delay between attacks (30ms - fast but safe)
local KILLAURA_RANDOMIZE_DELAY = true -- Add random variation to timing
local KILLAURA_MAX_ATTACKS_PER_SECOND = 30 -- Maximum attacks per second (faster than do.lua)
local KILLAURA_ATTACK_COUNTER = 0 -- Track attacks this second
local KILLAURA_LAST_SECOND = 0 -- Track which second we're in
local KILLAURA_VALIDATE_DISTANCE = false -- Disabled for better range
local KILLAURA_MAX_REALISTIC_RANGE = 30 -- Maximum melee range (studs)
local KILLAURA_SWING_TO_HIT_DELAY = 0.02 -- Delay between Swing and HitZombie (20ms - minimal but present)

-- State variables (Global for keybind access)
KillAuraEnabled = false
KillAuraRange = 10
KillAuraAttackSpeed = 0.1 -- Default attack speed (seconds)
KillAuraRandomness = 0 -- Random variation (0-1, percentage of attack speed)
KillAuraMode = "Fast" -- "Legit" (human-like) or "Fast" (0.5s interval)
KillAura_MaxRange = 30 -- Max range restored to 30 studs
KillAuraMultiTargets = 5
KillAuraAutoLook = false
KillAura_AutoEquipMelee = false
IgnoreSpawningZombies = true
KillAura_HitboxExpanderEnabled = false

-- Zombie type targeting (which types to kill) - global for config
-- Types: Shambler (Normal), Bomber (Barrel), Runner (Fast), Zapper (Sapper), Igniter, Cuirassier (Slim)
KillAura_SelectedZombieTypes = {
    ["Shambler"] = true,
    ["Bomber"] = false,
    ["Runner"] = true,
    ["Zapper"] = true,
    ["Igniter"] = true,
    ["Cuirassier"] = true
}

-- NEW: bayonet setting (global for config)
KillAura_EnableBayonet = false

-- ADDED: Store reference to Hitbox Expander toggle for programmatic control
local HitboxExpanderToggleElement = nil

-- Internal state
-- Use weak keys so destroyed remotes get garbage collected
local KillAura_remotes = setmetatable({}, { __mode = "k" })
local KillAura_lastRemoteScan = 0

-- Primary remote optimization
local KillAura_primaryRemote = nil
local KillAura_remotesCount = 0

local KillAura_weaponRangeOverrides = {
    Pike = 11,
    Axe = 9,
    -- OPTIONAL: tweak musket / bayonet range if you want it a bit longer
    Musket = 15,
}

local function KillAura_isPinnedOrGrabbed()
    local wsPlayers = Workspace:FindFirstChild("Players")
    if not wsPlayers then return false end
    local folder = wsPlayers:FindFirstChild(LocalPlayer and LocalPlayer.Name or "")
    if not folder then return false end
    local userStates = folder:FindFirstChild("UserStates")
    if not userStates then return false end

    local grabbedVal = userStates:FindFirstChild("Grabbed")
    local pinVal = userStates:FindFirstChild("Pin")

    local function valIndicatesTrue(v)
        if not v or v.Value == nil then return false end
        local val = v.Value
        if type(val) == "boolean" and val == true then return true end
        local n = tonumber(val)
        if n and n > 0 then return true end
        if tostring(val):lower() == "true" then return true end
        if tostring(val) == "RunnerAttack" then return true end
        return false
    end

    return valIndicatesTrue(grabbedVal) or valIndicatesTrue(pinVal)
end

-- Helper functions
local function KillAura_findHead(zombie)
    if not zombie or not zombie:IsA("Model") then return nil end
    return zombie:FindFirstChild("Head") or zombie:FindFirstChild("head") or 
           zombie:FindFirstChild("HumanoidRootPart") or zombie:FindFirstChildWhichIsA("BasePart")
end

local function KillAura_isSpawning(model)
    local agent = model:FindFirstChild("Agent")
    if not agent then return false end
    local state = agent:FindFirstChild("State")
    if not state or not state:IsA("StringValue") then return false end
    return state.Value == "Spawn"
end

local function KillAura_distSq(a, b)
    if not a or not b then return math.huge end
    local dx = a.X - b.X
    local dy = a.Y - b.Y
    local dz = a.Z - b.Z
    return dx*dx + dy*dy + dz*dz
end

-- Anti-detection: Check if we're within rate limits
local function KillAura_canAttack()
    if not KILLAURA_ANTICHEAT_BYPASS then return true end
    
    local currentSecond = math.floor(tick())
    if currentSecond ~= KILLAURA_LAST_SECOND then
        KILLAURA_LAST_SECOND = currentSecond
        KILLAURA_ATTACK_COUNTER = 0
    end
    
    if KILLAURA_ATTACK_COUNTER >= KILLAURA_MAX_ATTACKS_PER_SECOND then
        return false -- Rate limited
    end
    
    return true
end

-- Anti-detection: Register an attack
local function KillAura_registerAttack()
    if KILLAURA_ANTICHEAT_BYPASS then
        KILLAURA_ATTACK_COUNTER = KILLAURA_ATTACK_COUNTER + 1
    end
end

-- Anti-detection: Get randomized delay
local function KillAura_getRandomizedDelay(baseDelay)
    if KillAuraRandomness <= 0 then return baseDelay end
    -- Add random variation based on slider value
    local variation = baseDelay * KillAuraRandomness
    return baseDelay + (math.random() * variation * 2 - variation)
end

-- Anti-detection: Validate attack distance
local function KillAura_isValidAttackDistance(hrpPos, targetPos)
    if not KILLAURA_VALIDATE_DISTANCE then return true end
    if not hrpPos or not targetPos then return false end
    local dist = (hrpPos - targetPos).Magnitude
    return dist <= KILLAURA_MAX_REALISTIC_RANGE
end

local function KillAura_fireSwing(remote)
    if not (remote and remote:IsA("RemoteEvent")) then return end
    pcall(function() _G.SafeFireServer(remote, "Swing", "Side") end)
end

local function KillAura_registerRemote(remote)
    if not (remote and remote:IsA("RemoteEvent")) then return nil end
    if not KillAura_remotes[remote] then
        KillAura_remotes[remote] = true
        KillAura_remotesCount = KillAura_remotesCount + 1
    end
    return remote
end

-- Primary remote getter
local function KillAura_getPrimaryRemote()
    if KillAura_primaryRemote and KillAura_remotes[KillAura_primaryRemote] then 
        return KillAura_primaryRemote 
    end
    for r,_ in pairs(KillAura_remotes) do
        KillAura_primaryRemote = r
        return r
    end
    return nil
end

-- Remote scanning
local function KillAura_ScanRemotesNow()
    table.clear(KillAura_remotes)
    KillAura_primaryRemote = nil
    KillAura_remotesCount = 0
    local char = LocalPlayer.Character
    if not char then return end
    for _, tool in ipairs(char:GetChildren()) do
        if tool:IsA("Tool") then
            for _, c in ipairs(tool:GetChildren()) do
                if KillAura_registerRemote(c) and not KillAura_primaryRemote then
                    KillAura_primaryRemote = c
                end
            end
        end
    end
    KillAura_lastRemoteScan = tick()
end

-- Debounce remote scanning to prevent lag when spamming equip/unequip
local KillAura_scanDebounce = false
local function KillAura_DebouncedScan()
    if KillAura_scanDebounce then return end
    KillAura_scanDebounce = true
    task.delay(0.15, function()
        KillAura_scanDebounce = false
        KillAura_ScanRemotesNow()
    end)
end

LocalPlayer.CharacterAdded:Connect(function(char)
    task.wait(0.6)
    KillAura_ScanRemotesNow()
    char.ChildAdded:Connect(function(child)
        if child:IsA("Tool") then KillAura_DebouncedScan() end
    end)
    char.ChildRemoved:Connect(function(child)
        if child:IsA("Tool") then KillAura_DebouncedScan() end
    end)
end)
if LocalPlayer.Character then KillAura_ScanRemotesNow() end

local function KillAura_isGun(tool)
    if not tool or not tool:IsA("Tool") then return false end
    if tool:FindFirstChild("Ammo") or tool:FindFirstChild("ShotsLoaded") then return true end
    if tool:FindFirstChild("GunSettings") then return true end
    local cfg = tool:FindFirstChild("Configuration")
    if cfg and (cfg:FindFirstChild("Ammo") or cfg:FindFirstChild("ShotsLoaded")) then return true end
    return false
end

-- Helper: detect bayonet-usable tool (Musket) when enabled
local function KillAura_isBayonetTool(tool)
    if not (tool and tool:IsA("Tool")) then return false end
    if not KillAura_EnableBayonet then return false end
    local name = string.lower(tool.Name)
    -- You can tighten this check if your game uses a different name
    return name == "musket" or string.find(name, "musket")
end

local function KillAura_isMelee(tool)
    if not tool or not tool:IsA("Tool") then return false end

    -- Normal rule: guns are not melee
    if KillAura_isGun(tool) and not KillAura_isBayonetTool(tool) then
        return false
    end

    -- If bayonet is enabled and this is a Musket, treat it as melee
    if KillAura_isBayonetTool(tool) then
        return true
    end

    if tool:GetAttribute("Melee") == true then return true end
    if tool:FindFirstChild("Melee") or tool:FindFirstChild("MeleeConfig") then return true end
    local name = string.lower(tool.Name)
    return name:find("axe") or name:find("pike") or name:find("sword") or name:find("sabre") or name:find("bayonet") or name:find("dagger") or name:find("knife")
end

local function KillAura_findMeleeToolIn(container)
    if not container then return nil end
    for _, tool in ipairs(container:GetChildren()) do
        if KillAura_isMelee(tool) then
            return tool
        end
    end
    return nil
end

local function KillAura_getMeleeTool()
    local char = LocalPlayer.Character
    if not char then return nil end

    local equipped = KillAura_findMeleeToolIn(char)
    if equipped then return equipped end

    local backpack = LocalPlayer:FindFirstChildOfClass("Backpack") or LocalPlayer:FindFirstChild("Backpack")
    if not backpack then return nil end

    local stored = KillAura_findMeleeToolIn(backpack)
    if stored and KillAura_AutoEquipMelee then
        local ok = pcall(function()
            stored.Parent = char
        end)
        if ok then
            task.defer(KillAura_ScanRemotesNow)
            return stored
        end
    end

    return nil
end

local function KillAura_getWeaponRange(tool)
    local range = KillAuraRange
    if not tool then return range end

    local attrRange = tonumber(tool:GetAttribute("Range"))
    if attrRange then
        range = math.max(range, attrRange)
    end

    local override = KillAura_weaponRangeOverrides[tool.Name]
    if override then
        range = math.max(range, override)
    end

    return range
end

local function KillAura_getRemoteForTool(tool)
    if tool then
        local remote = tool:FindFirstChild("RemoteEvent")
        if not remote then
            remote = tool:FindFirstChildWhichIsA("RemoteEvent")
        end
        if remote then
            KillAura_registerRemote(remote)
            KillAura_primaryRemote = remote
            return remote
        end
    end
    return KillAura_getPrimaryRemote()
end

-- Helper: Get zombie type from model
local function KillAura_getZombieType(model)
    if not (model and model:IsA("Model")) then return nil end
    
    -- Check Agent folder for Type attribute
    local agent = model:FindFirstChild("Agent")
    if agent then
        local typeValue = agent:FindFirstChild("Type")
        if typeValue and typeValue:IsA("StringValue") then
            local attrType = string.lower(typeValue.Value or "")
            if attrType == "normal" then return "Shambler" end
            if attrType == "barrel" then return "Bomber" end
            if attrType == "fast" then return "Runner" end
            if attrType == "sapper" then return "Zapper" end
            if attrType == "igniter" then return "Igniter" end
            if attrType == "cuirassier" then return "Cuirassier" end
        end
    end
    
    -- Fallback: check model attributes
    if typeof(model.GetAttribute) == "function" then
        local attrType = string.lower(tostring(model:GetAttribute("Type") or ""))
        if attrType == "normal" then return "Shambler" end
        if attrType == "barrel" then return "Bomber" end
        if attrType == "fast" then return "Runner" end
        if attrType == "sapper" then return "Zapper" end
        if attrType == "igniter" then return "Igniter" end
        if attrType == "cuirassier" then return "Cuirassier" end
    end
    
    -- Default to Shambler if no type found
    return "Shambler"
end

-- Helper: Get random part from Cuirassier for attack targeting
local function KillAura_getRandomCuirassierPart(model)
    if not (model and model:IsA("Model")) then return nil end
    local parts = {}
    for _, child in ipairs(model:GetDescendants()) do
        if child:IsA("BasePart") then
            table.insert(parts, child)
        end
    end
    if #parts == 0 then return nil end
    return parts[math.random(1, #parts)]
end

-- Helper: Get attack position (random part for Cuirassier, head for others)
local function KillAura_getAttackPosition(model, head)
    -- Validate inputs
    if not model or not model.Parent then return nil end
    if not head or not head.Parent then return nil end
    
    local zombieType = KillAura_getZombieType(model)
    if zombieType == "Cuirassier" then
        local randomPart = KillAura_getRandomCuirassierPart(model)
        if randomPart and randomPart.Parent then
            return randomPart.Position
        end
    end
    
    -- Ensure head still exists
    if head and head.Parent then
        return head.Position
    end
    return nil
end

local function KillAura_shouldSkipZombie(model)
    if not (model and model:IsA("Model")) then return true end
    if IgnoreSpawningZombies and KillAura_isSpawning(model) then return true end
    
    -- Get the zombie type and check if it's selected
    local zombieType = KillAura_getZombieType(model)
    if zombieType and not KillAura_SelectedZombieTypes[zombieType] then
        return true -- Skip this zombie type (not selected)
    end
    
    return false
end

-- Kill aura logic - continuous attack, no cache
-- Legit mode helper: plays animations and smooth body rotation
local function KillAura_performLegitAttack(hrp, meleeTool, primaryRemote, entry, isBayonet)
    -- Anti-detection: Rate limit check
    if not KillAura_canAttack() then return end
    
    local char = LocalPlayer.Character
    local hum = char and char:FindFirstChildOfClass("Humanoid")
    local attackPos = KillAura_getAttackPosition(entry.model, entry.head)
    
    -- Anti-detection: Distance validation
    if hrp and not KillAura_isValidAttackDistance(hrp.Position, attackPos) then
        return -- Skip attacks that would be detected as impossible
    end
    
    -- Register this attack for rate limiting
    KillAura_registerAttack()
    
    -- Mark remote as protected for anti-ban
    if _G.MarkRemoteProtected then
        _G.MarkRemoteProtected(primaryRemote)
    end
    
    pcall(function()
        -- Play swing animation if available
        if hum then
            local animFolder = meleeTool:FindFirstChild("Animations") or meleeTool:FindFirstChild("Anims")
            local swingAnim = animFolder and (animFolder:FindFirstChild("Swing") or animFolder:FindFirstChild("Attack"))
            if swingAnim and swingAnim:IsA("Animation") then
                local track = hum:LoadAnimation(swingAnim)
                track:Play()
            end
        end
        
        -- Smooth dynamic body rotation (human-like)
        if hrp then
            local targetPos = entry.head.Position
            local lookCF = CFrame.new(hrp.Position, Vector3.new(targetPos.X, hrp.Position.Y, targetPos.Z))
            local side = math.random() > 0.5 and 1 or -1
            local angle = math.random(15, 30)
            
            task.spawn(function()
                -- Flick Left/Right
                for i = 0, 1, 0.25 do
                    if hrp and hrp.Parent then
                        hrp.CFrame = hrp.CFrame:Lerp(lookCF * CFrame.Angles(0, math.rad(angle * side), 0), i)
                    end
                    task.wait(0.01)
                end
                for i = 0, 1, 0.25 do
                    if hrp and hrp.Parent then
                        hrp.CFrame = hrp.CFrame:Lerp(lookCF * CFrame.Angles(0, math.rad(-angle * side), 0), i)
                    end
                    task.wait(0.01)
                end
                if hrp and hrp.Parent then hrp.CFrame = hrp.CFrame:Lerp(lookCF, 0.5) end
            end)
        end
        
        -- Axe specific logic
        if meleeTool.Name == "Axe" and entry.model and entry.model.Parent and entry.head and entry.head.Parent then
            _G.SafeFireServer(primaryRemote, "BraceBlock")
            _G.SafeFireServer(primaryRemote, "StopBraceBlock")
            _G.SafeFireServer(primaryRemote, "FeedbackStun", entry.model, entry.head.Position)
        end
        
        -- Validate entry still exists before attacking
        if not entry.model or not entry.model.Parent or not attackPos then return end
        
        -- Send attack commands
        if isBayonet then
            _G.SafeFireServer(primaryRemote, "ThrustBayonet")
            task.wait(0.15) -- Delay for realism
            if entry.model and entry.model.Parent then
                _G.SafeFireServer(primaryRemote, "Bayonet_HitZombie", entry.model, attackPos, true)
            end
        else
            _G.SafeFireServer(primaryRemote, "Swing", "Thrust")
            task.wait(0.15) -- Delay for realism
            if entry.model and entry.model.Parent then
                _G.SafeFireServer(primaryRemote, "HitZombie", entry.model, attackPos, true, Vector3.new(0, 15, 0), "Head", Vector3.new(0, 1, 0))
            end
        end
        
        -- Play hit animation if available
        if hum then
            local animFolder = meleeTool:FindFirstChild("Animations") or meleeTool:FindFirstChild("Anims")
            local hitAnim = animFolder and (animFolder:FindFirstChild("Hit") or animFolder:FindFirstChild("Impact"))
            if hitAnim and hitAnim:IsA("Animation") then
                local track = hum:LoadAnimation(hitAnim)
                track:Play()
            end
        end
    end)
end

-- Fast mode helper: fires remotes with SafeFireServer for anti-detection
local function KillAura_performFastAttack(meleeTool, primaryRemote, entry, isBayonet, hrpPos)
    -- Anti-detection: Rate limit check
    if not KillAura_canAttack() then return end
    
    -- Quick validation
    local model = entry.model
    local head = entry.head
    if not model or not model.Parent or not head or not head.Parent then return end
    
    -- Get attack position
    local attackPos = head.Position
    if not attackPos then return end
    
    -- Register this attack for rate limiting
    KillAura_registerAttack()
    
    -- Mark remote as protected for anti-ban
    if _G.MarkRemoteProtected then
        _G.MarkRemoteProtected(primaryRemote)
    end
    
    -- Use SafeFireServer with realistic timing between actions
    local isAxe = meleeTool.Name == "Axe"
    
    pcall(function()
        if isAxe then
            _G.SafeFireServer(primaryRemote, "BraceBlock")
            task.wait(0.02)
            _G.SafeFireServer(primaryRemote, "StopBraceBlock")
            task.wait(0.02)
            _G.SafeFireServer(primaryRemote, "FeedbackStun", model, attackPos)
        end
        
        if isBayonet then
            _G.SafeFireServer(primaryRemote, "ThrustBayonet")
            task.wait(KILLAURA_SWING_TO_HIT_DELAY) -- Delay between thrust and hit
            if model and model.Parent then -- Re-validate
                _G.SafeFireServer(primaryRemote, "Bayonet_HitZombie", model, attackPos, true)
            end
        else
            _G.SafeFireServer(primaryRemote, "Swing", "Thrust")
            task.wait(KILLAURA_SWING_TO_HIT_DELAY) -- Delay between swing and hit
            if model and model.Parent then -- Re-validate
                _G.SafeFireServer(primaryRemote, "HitZombie", model, attackPos, true, Vector3.new(0, 15, 0), "Head", Vector3.new(0, 1, 0))
            end
        end
    end)
end

-- Cached zombies folder reference for speed
local KillAura_zombiesFolder = nil
local KillAura_lastZombieFolderCheck = 0

local function KillAura_getZombiesFolder()
    local now = tick()
    if now - KillAura_lastZombieFolderCheck > 2 then
        KillAura_zombiesFolder = Workspace:FindFirstChild("Zombies")
        KillAura_lastZombieFolderCheck = now
    end
    return KillAura_zombiesFolder
end

local function KillAura_performKillAura(hrp)
    if not KillAuraEnabled then return end

    local meleeTool = KillAura_getMeleeTool()
    if not meleeTool then return end

    local primaryRemote = KillAura_getRemoteForTool(meleeTool)
    if not primaryRemote then return end

    local isBayonet = KillAura_isBayonetTool(meleeTool)
    local hrpPos = hrp.Position
    local effectiveRange = KillAura_getWeaponRange(meleeTool)
    local rangeSq = effectiveRange * effectiveRange

    -- Use cached zombies folder
    local zombiesFolder = KillAura_getZombiesFolder()
    if not zombiesFolder then return end
    
    -- Optimized target collection with pre-allocated table
    local targets = {}
    local targetCount = 0
    local maxTargets = KillAuraMultiTargets or 5
    
    -- Use GetChildren on Zombies folder (faster than GetDescendants for direct children)
    for _, model in ipairs(zombiesFolder:GetChildren()) do
        if model:IsA("Model") then
            -- Inline skip check for speed (with nil safety)
            local shouldSkip = false
            if IgnoreSpawningZombies then
                local agent = model:FindFirstChild("Agent")
                if agent then
                    local state = agent:FindFirstChild("State")
                    if state and state:IsA("StringValue") and state.Value == "Spawn" then
                        shouldSkip = true
                    end
                end
            end
            
            if not shouldSkip then
                -- Check zombie type selection
                local zombieType = KillAura_getZombieType(model)
                if not zombieType or KillAura_SelectedZombieTypes[zombieType] then
                    local head = model:FindFirstChild("Head") or model:FindFirstChild("HumanoidRootPart")
                    if head then
                        local headPos = head.Position
                        local dx, dy, dz = headPos.X - hrpPos.X, headPos.Y - hrpPos.Y, headPos.Z - hrpPos.Z
                        local d2 = dx*dx + dy*dy + dz*dz
                        if d2 <= rangeSq then
                            targetCount = targetCount + 1
                            targets[targetCount] = { model = model, head = head, d2 = d2 }
                            -- Early exit if we have enough targets
                            if targetCount >= maxTargets * 2 then break end
                        end
                    end
                end
            end
        end
    end

    if targetCount == 0 then return end
    
    -- Only sort if we have more targets than needed
    if targetCount > maxTargets then
        table.sort(targets, function(a, b) return a.d2 < b.d2 end)
    end

    local attackCount = math.min(maxTargets, targetCount)
    local firstTarget = targets[1]
    
    -- Batch attack all targets (no delay between)
    for i = 1, attackCount do
        local entry = targets[i]
        if entry then
            KillAura_performFastAttack(meleeTool, primaryRemote, entry, isBayonet, hrpPos)
        end
    end

    -- Auto-look is now handled separately in KillAura_performAutoLook
end

-- Separate Auto Look function that finds the nearest zombie independently
-- Uses high-responsiveness BodyGyro for instant feel without disrupting movement
local KillAura_autoLookGyro = nil

local function KillAura_cleanupAutoLook()
    -- Always clean up when disabled
    pcall(function()
        if KillAura_autoLookGyro then
            KillAura_autoLookGyro:Destroy()
            KillAura_autoLookGyro = nil
        end
    end)
    -- Also search and destroy any lingering gyros
    pcall(function()
        local char = LocalPlayer.Character
        if char then
            local hrp = char:FindFirstChild("HumanoidRootPart")
            if hrp then
                local gyro = hrp:FindFirstChild("KatchiAutoLookGyro")
                if gyro then gyro:Destroy() end
            end
        end
    end)
    -- Re-enable fly gyro if flying
    if FlyEnabled and FlyBodyGyro then
        pcall(function() FlyBodyGyro.MaxTorque = Vector3.new(math.huge, math.huge, math.huge) end)
    end
end

local function KillAura_performAutoLook(hrp)
    -- If disabled, clean up everything and return
    if not KillAuraAutoLook then
        KillAura_cleanupAutoLook()
        return
    end
    
    local hrpPos = hrp.Position
    
    -- Find the actual nearest zombie (independent of Kill Aura targeting)
    local zombiesFolder = KillAura_getZombiesFolder()
    if not zombiesFolder then
        KillAura_cleanupAutoLook()
        return
    end
    
    local nearestHead = nil
    local nearestDistSq = math.huge
    local maxRange = 50 -- Auto look range (independent of kill aura range)
    local maxRangeSq = maxRange * maxRange
    
    for _, model in ipairs(zombiesFolder:GetChildren()) do
        if model:IsA("Model") then
            local head = model:FindFirstChild("Head")
            if head then
                local headPos = head.Position
                local dx, dy, dz = headPos.X - hrpPos.X, headPos.Y - hrpPos.Y, headPos.Z - hrpPos.Z
                local d2 = dx*dx + dy*dy + dz*dz
                if d2 < nearestDistSq and d2 <= maxRangeSq then
                    nearestDistSq = d2
                    nearestHead = head
                end
            end
        end
    end
    
    if nearestHead and nearestHead.Parent then
        local targetPos = nearestHead.Position
        -- Calculate look direction (Y-axis only - horizontal rotation)
        local lookAt = Vector3.new(targetPos.X, hrpPos.Y, targetPos.Z)
        local direction = (lookAt - hrpPos)
        
        if direction.Magnitude > 0.1 then
            if FlyEnabled then
                -- When flying: disable fly's BodyGyro and use our own with very high responsiveness
                if FlyBodyGyro then
                    pcall(function() FlyBodyGyro.MaxTorque = Vector3.new(0, 0, 0) end)
                end
                
                -- Find or create our AutoLook BodyGyro with VERY high P for instant response
                local autoLookGyro = hrp:FindFirstChild("KatchiAutoLookGyro")
                if not autoLookGyro then
                    autoLookGyro = Instance.new("BodyGyro")
                    autoLookGyro.Name = "KatchiAutoLookGyro"
                    autoLookGyro.MaxTorque = Vector3.new(math.huge, math.huge, math.huge)
                    autoLookGyro.P = 1000000 -- Very high P for near-instant rotation
                    autoLookGyro.D = 500 -- Lower D to reduce oscillation
                    autoLookGyro.Parent = hrp
                    KillAura_autoLookGyro = autoLookGyro
                end
                
                -- Set target rotation (full 3D look at target)
                autoLookGyro.CFrame = CFrame.lookAt(hrpPos, lookAt)
            else
                -- Not flying: use Y-axis only rotation with very high responsiveness
                local autoLookGyro = hrp:FindFirstChild("KatchiAutoLookGyro")
                if not autoLookGyro then
                    autoLookGyro = Instance.new("BodyGyro")
                    autoLookGyro.Name = "KatchiAutoLookGyro"
                    autoLookGyro.MaxTorque = Vector3.new(0, math.huge, 0) -- Only Y-axis rotation (doesn't affect movement)
                    autoLookGyro.P = 1000000 -- Very high P for near-instant rotation
                    autoLookGyro.D = 500 -- Lower D to reduce oscillation
                    autoLookGyro.Parent = hrp
                    KillAura_autoLookGyro = autoLookGyro
                end
                
                -- Set target rotation
                autoLookGyro.CFrame = CFrame.lookAt(hrpPos, lookAt)
            end
        end
    else
        -- No target: clean up BodyGyro and re-enable fly's BodyGyro
        pcall(function()
            local autoLookGyro = hrp:FindFirstChild("KatchiAutoLookGyro")
            if autoLookGyro then
                autoLookGyro:Destroy()
                KillAura_autoLookGyro = nil
            end
        end)
        
        -- Re-enable fly's BodyGyro if flying
        if FlyEnabled and FlyBodyGyro then
            pcall(function() FlyBodyGyro.MaxTorque = Vector3.new(math.huge, math.huge, math.huge) end)
        end
    end
end

local function KillAura_performAutoHead(hrp)
    if not KillAura_HitboxExpanderEnabled then return end
    
    local meleeTool = KillAura_getMeleeTool()
    if not meleeTool then return end

    local primaryRemote = KillAura_getRemoteForTool(meleeTool)
    if not primaryRemote then return end

    local maxRangeSq = KillAura_MaxRange * KillAura_MaxRange
    local hrpPos = hrp.Position
    local isBayonet = KillAura_isBayonetTool(meleeTool)
    
    -- Direct scan - no cache
    local targets = {}
    local zombiesFolder = Workspace:FindFirstChild("Zombies")
    if not zombiesFolder then return end
    
    for _, model in ipairs(zombiesFolder:GetDescendants()) do
        if model:IsA("Model") and not KillAura_shouldSkipZombie(model) then
            local head = KillAura_findHead(model)
            if head then
                local d2 = KillAura_distSq(head.Position, hrpPos)
                if d2 <= maxRangeSq then
                    targets[#targets + 1] = { model = model, head = head, d2 = d2 }
                end
            end
        end
    end
    
    if #targets == 0 then return end
    table.sort(targets, function(a, b) return a.d2 < b.d2 end)
    
    local maxTargets = KillAuraEnabled and math.min(KillAuraMultiTargets or 1, #targets) or 1
    for i = 1, maxTargets do
        local entry = targets[i]
        if not entry then break end
        
        -- Anti-detection: Rate limit and distance check
        if not KillAura_canAttack() then break end
        
        local attackPos = KillAura_getAttackPosition(entry.model, entry.head)
        
        -- Anti-detection: Distance validation
        if not KillAura_isValidAttackDistance(hrpPos, attackPos) then
            continue -- Skip this target, try next
        end
        
        -- Register this attack for rate limiting
        KillAura_registerAttack()
        
        -- Mark remote as protected for anti-ban
        if _G.MarkRemoteProtected then
            _G.MarkRemoteProtected(primaryRemote)
        end
        
        if isBayonet then
            pcall(function()
                if not entry.model or not entry.model.Parent or not attackPos then return end
                _G.SafeFireServer(primaryRemote, "ThrustBayonet")
                _G.SafeFireServer(primaryRemote, "Bayonet_HitZombie", entry.model, attackPos, true)
            end)
        else
            pcall(function()
                if not entry.model or not entry.model.Parent or not attackPos then return end
                _G.SafeFireServer(primaryRemote, "HitZombie", entry.model, attackPos, true)
            end)
        end
    end
end

-- Heartbeat loop - continuous (deferred to prevent load freeze)
local KillAura_nextTick = 0

task.defer(function()
    task.wait(0.5) -- Stagger start
    RunService.Heartbeat:Connect(function()
        -- PERFORMANCE: Skip entirely if both features are disabled
        if not KillAuraEnabled and not KillAura_HitboxExpanderEnabled then return end
        
        local char = LocalPlayer.Character
        local hrp = char and char:FindFirstChild("HumanoidRootPart")
        if not hrp then return end

        -- Pause while grabbed/pinned
        if KillAura_isPinnedOrGrabbed() then return end

        local now = tick()
        
        -- Attack speed throttle
        if now < KillAura_nextTick then return end
        
        -- Calculate delay based on attack speed
        local baseDelay = KillAuraAttackSpeed
        
        -- ALWAYS add some randomness for anti-detection (looks more human)
        if KILLAURA_RANDOMIZE_DELAY then
            -- Add 10-30% random variation
            local variation = baseDelay * (0.1 + KillAuraRandomness * 0.2)
            baseDelay = baseDelay + (math.random() * variation * 2 - variation)
        end
        
        -- Ensure minimum delay for safety
        baseDelay = math.max(baseDelay, KILLAURA_MIN_DELAY)
        
        KillAura_nextTick = now + baseDelay

        -- Scan remotes periodically
        if now - KillAura_lastRemoteScan > 5 then KillAura_ScanRemotesNow() end

        -- Execute attacks
        if KillAura_HitboxExpanderEnabled then
            KillAura_performAutoHead(hrp)
        end
        if KillAuraEnabled then
            KillAura_performKillAura(hrp)
        end
        
        -- Auto Look runs independently (even without Kill Aura enabled)
        if KillAuraAutoLook then
            KillAura_performAutoLook(hrp)
        end
    end)
end)

-- UI Creation
-- Hitbox Expander Settings
local HitboxExpanderSection = KillAuraTab:Section({ Title = "Reach", Icon = "box", Opened = false })

-- Store toggle element reference and use helper function
local function SetHitboxExpanderState(enabled)
    KillAura_HitboxExpanderEnabled = enabled
    
    -- Update UI toggle state without triggering callback if framework supports it
    if HitboxExpanderToggleElement and HitboxExpanderToggleElement.SetValue then
        HitboxExpanderToggleElement:SetValue(enabled)
    end
    
    WindUI:Notify({
        Title = "Reach",
        Content = enabled and "Reach Enabled" or "Reach Disabled",
        Duration = 2,
        Icon = enabled and "scan" or "x"
    })
end

-- ===== KillAura API for external suppression (AntiGrab) =====
local KillAura_SuppressedByAntiGrab = false
local KillAura_StoredEnabled = nil
local KillAura_StoredHitbox = nil

local function KillAura_suppressByAntiGrab()
    if KillAura_SuppressedByAntiGrab then return end
    KillAura_SuppressedByAntiGrab = true

    -- store current values to restore later
    KillAura_StoredEnabled = KillAuraEnabled
    KillAura_StoredHitbox = KillAura_HitboxExpanderEnabled

    local notifyOnChange = (KillAuraEnabled == true) or (KillAura_HitboxExpanderEnabled == true)

    -- force off
    KillAuraEnabled = false
    -- also force off hitbox/reach safely via helper (keeps UI state consistent if possible)
    pcall(SetHitboxExpanderState, false)

    if notifyOnChange then
        pcall(function()
            if WindUI and WindUI.Notify then
                WindUI:Notify({ Title = "Kill Aura", Content = "Disabled by Anti-Grab", Duration = 1.5 })
            end
        end)
    end
end

local function KillAura_unsuppressByAntiGrab()
    if not KillAura_SuppressedByAntiGrab then return end
    KillAura_SuppressedByAntiGrab = false

    local hadStored = (KillAura_StoredEnabled ~= nil) or (KillAura_StoredHitbox ~= nil)

    -- restore previously stored state (only if we stored something)
    if KillAura_StoredEnabled ~= nil then
        KillAuraEnabled = KillAura_StoredEnabled
        KillAura_StoredEnabled = nil
    end
    if KillAura_StoredHitbox ~= nil then
        pcall(SetHitboxExpanderState, KillAura_StoredHitbox)
        KillAura_StoredHitbox = nil
    end

    if hadStored then
        pcall(function()
            if WindUI and WindUI.Notify then
                WindUI:Notify({ Title = "Kill Aura", Content = "Restored", Duration = 1.5 })
            end
        end)
    end
end

-- expose API for other scripts (AntiGrab) in a robust way
if type(getgenv) == "function" then
    local g = getgenv()
    g.KillAuraAPI = g.KillAuraAPI or {}
    g.KillAuraAPI.suppress = KillAura_suppressByAntiGrab
    g.KillAuraAPI.unsuppress = KillAura_unsuppressByAntiGrab
else
    _G.KillAuraAPI = _G.KillAuraAPI or {}
    _G.KillAuraAPI.suppress = KillAura_suppressByAntiGrab
    _G.KillAuraAPI.unsuppress = KillAura_unsuppressByAntiGrab
end
-- ============================================================

HitboxExpanderToggleElement = HitboxExpanderSection:Toggle({
    Title = "Reach",
    Flag = "KillAura_HitboxExpander",
    Desc = "Will Reach The Zombie For About 30 studs (Might Be Lower)",
    Default = false,
    Callback = function(v)
        KillAura_HitboxExpanderEnabled = v
        WindUI:Notify({
            Title = "Reach",
            Content = v and "Reach Enabled" or "Reach Disabled",
            Duration = 2,
            Icon = v and "scan" or "x"
        })
    end
})
_G.KatchiToggleElements = _G.KatchiToggleElements or {}
_G.KatchiToggleElements.Reach = HitboxExpanderToggleElement

HitboxExpanderSection:Slider({
    Title = "Reach Range",
    Flag = "KillAura_HitboxRange",
    Desc = "Range of Reach",
    Step = 1,
    Value = { Min = 5, Max = 30, Default = KillAura_MaxRange },
    Callback = function(v)
        KillAura_MaxRange = v
    end
})

-- Kill Aura Settings
local KillAuraSection = KillAuraTab:Section({ Title = "Kill Aura", Icon = "sword", Opened = false })

local KillAuraToggle = KillAuraSection:Toggle({
    Title = "Kill Aura",
    Flag = "KillAura_Enabled",
    Desc = "Automatically Kills Zombie In Range",
    Default = false,
    Callback = function(v)
        KillAuraEnabled = v
        
        -- Auto-toggle Hitbox Expander to match Kill Aura state
        SetHitboxExpanderState(v)
        
        WindUI:Notify({
            Title = "Kill Aura",
            Content = v and "Kill Aura Enabled" or "Kill Aura Disabled",
            Duration = 2,
            Icon = v and "sword" or "x"
        })
    end
})
_G.KatchiToggleElements.KillAura = KillAuraToggle

KillAuraSection:Slider({
    Title = "Kill Aura Range",
    Desc = "The Range Of Where Kill Aura Will Start Attacking If a zombie crosses the range.",
    Flag = "KillAura_Range",
    Step = 1,
    Value = { Min = 5, Max = 30, Default = KillAuraRange },
    Callback = function(v)
        KillAuraRange = v
    end
})

KillAuraSection:Slider({
    Title = "Attack Speed",
    Desc = "Delay between attacks (lower = faster).",
    Flag = "KillAura_AttackSpeed",
    Step = 0.01,
    Value = { Min = 0.01, Max = 0.5, Default = KillAuraAttackSpeed },
    Callback = function(v)
        KillAuraAttackSpeed = v
    end
})

KillAuraSection:Slider({
    Title = "Randomness",
    Desc = "Random delay in attack timing.",
    Flag = "KillAura_Randomness",
    Step = 0.05,
    Value = { Min = 0, Max = 1, Default = KillAuraRandomness },
    Callback = function(v)
        KillAuraRandomness = v
    end
})

KillAuraSection:Slider({
    Title = "Multi-Target",
    Desc = "Number of zombies to target in 1 swing.",
    Flag = "KillAura_MultiTargets",
    Step = 1,
    Value = { Min = 1, Max = 10, Default = KillAuraMultiTargets },
    Callback = function(v)
        KillAuraMultiTargets = v
    end
})

local AutoEquipMeleeToggle = KillAuraSection:Toggle({
    Title = "Auto Equip Melee",
    Flag = "KillAura_AutoEquipMelee",
    Desc = "Automatically equips a melee from backpack when Kill Aura is on.",
    Default = KillAura_AutoEquipMelee,
    Callback = function(v)
        KillAura_AutoEquipMelee = v
    end
})
_G.KatchiToggleElements.AutoEquipMelee = AutoEquipMeleeToggle

KillAuraSection:Dropdown({
    Title = "Target Zombie Types",
    Flag = "KillAura_ZombieTypes",
    Desc = "Select which zombie types to target",
    Multi = true,
    Values = {"Shambler", "Bomber", "Runner", "Zapper", "Igniter", "Cuirassier"},
    Default = {"Shambler", "Runner", "Zapper", "Igniter", "Cuirassier"},
    Callback = function(selected)
        -- Reset all to false
        for k, _ in pairs(KillAura_SelectedZombieTypes) do
            KillAura_SelectedZombieTypes[k] = false
        end
        -- Enable selected types
        if type(selected) == "table" then
            for _, typeName in ipairs(selected) do
                KillAura_SelectedZombieTypes[typeName] = true
            end
        end
        if KillAuraTab_InitComplete then
            local count = 0
            for _, v in pairs(KillAura_SelectedZombieTypes) do
                if v then count = count + 1 end
            end
            WindUI:Notify({
                Title = "Kill Aura",
                Content = "Targeting " .. count .. " zombie type(s)",
                Duration = 2,
                Icon = "target"
            })
        end
    end
})

-- NEW: Enable Bayonet Kill Aura setting
local BayonetKillAuraToggle = KillAuraSection:Toggle({
    Title = "Enable Bayonet Kill Aura",
    Flag = "KillAura_EnableBayonet",
    Desc = "Kill aura will use bayonet.",
    Default = KillAura_EnableBayonet,
    Callback = function(v)
        KillAura_EnableBayonet = v
        WindUI:Notify({
            Title = "Kill Aura",
            Content = v and "Bayonet Kill Aura Enabled" or "Bayonet Kill Aura Disabled",
            Duration = 2,
            Icon = v and "sword" or "x"
        })
    end
})
_G.KatchiToggleElements.BayonetKillAura = BayonetKillAuraToggle

local AutoLookToggle = KillAuraSection:Toggle({
    Title = "Auto Look",
    Flag = "KillAura_AutoLook",
    Desc = "Automatically looks at the nearest zombie (instant)",
    Default = false,
    Callback = function(v)
        KillAuraAutoLook = v
        if not v then
            -- Immediately cleanup when disabled
            KillAura_cleanupAutoLook()
        end
        WindUI:Notify({
            Title = "Kill Aura",
            Content = v and "Auto Look ON" or "Auto Look OFF",
            Duration = 2,
            Icon = v and "eye" or "eye-off"
        })
    end
})
_G.KatchiToggleElements.AutoLook = AutoLookToggle

-- PERFORMANCE FIX: Mark KillAura Tab initialization as complete
KillAuraTab_InitComplete = true

end -- end of KillAuraTab block

-- Define ClassesTab at outer scope so it's accessible to all sub-sections
local ClassesTab = Main1Section:Tab({ Title = "Classes", Icon = "heart" })

task.wait(0.1) -- Delay to prevent lag
do -- // Classes Tab (Musician Section)
    local MusicianSection = ClassesTab:Section({
        Title = "Musician",
        Icon = "music-2",
        Opened = false
    })

    -- Auto Play (fife/drum/bagpipe) — simplified, no lag, always finds tools
    local Players = game:GetService("Players")
    local RunService = game:GetService("RunService")
    local ReplicatedStorage = game:GetService("ReplicatedStorage")

    local LocalPlayer = Players.LocalPlayer

    -- start OFF by default; toggle controls everything
    local AutoInstrumentEnabled = false
    local autoplay = false

    -- configurable
    local playInterval = 2                -- seconds between Play attempts
    local accuracyCooldown = 0.5          -- seconds between UpdateAccuracy
    local defaultSong = "La Marseillaise" -- change this or wire a dropdown

    -- state & caches
    local guiCache = { fife = nil, drum = nil, bagpipe = nil }
    local connections = {}
    local currentSong = defaultSong

    local function safeDisconnect(conn)
        if conn and typeof(conn) == "RBXScriptConnection" then
            pcall(function()
                conn:Disconnect()
            end)
        end
    end

    local function instrumentTools()
        local char = LocalPlayer and LocalPlayer.Character
        if not char then return {} end
        local list = {}
        for _, tool in ipairs(char:GetChildren()) do
            if tool:IsA("Tool") and (tool.Name:find("Fife") or tool.Name:find("Drum") or tool.Name:find("Bagpipe")) then
                table.insert(list, tool)
            end
        end
        return list
    end

    local function tintInstrumentGui(enabled)
        local pg = LocalPlayer and LocalPlayer:FindFirstChild("PlayerGui")
        if not pg then return end

        local function handleGui(name, cacheKey)
            local gui = pg:FindFirstChild(name)
                or (ReplicatedStorage:FindFirstChild("Modules")
                and ReplicatedStorage.Modules:FindFirstChild("Weapons")
                and ReplicatedStorage.Modules.Weapons:FindFirstChild(name:gsub("Gui", ""))
                and ReplicatedStorage.Modules.Weapons[name:gsub("Gui", "")]:FindFirstChild(name))
            if not gui then return end
            local root = gui:FindFirstChild("Root")
            if not root then return end
            local bg = root:FindFirstChild("BG")
            if not bg then return end
            if enabled then
                if not guiCache[cacheKey] then
                    guiCache[cacheKey] = { bg.BackgroundColor3, bg.BackgroundTransparency }
                end
                bg.BackgroundColor3 = Color3.fromRGB(255, 255, 255)
                bg.BackgroundTransparency = 0
            elseif guiCache[cacheKey] then
                bg.BackgroundColor3 = guiCache[cacheKey][1]
                bg.BackgroundTransparency = guiCache[cacheKey][2]
            end
        end

        handleGui("FifeGui", "fife")
        handleGui("DrumGui", "drum")
        handleGui("BagpipesGui", "bagpipe")
    end

    local function fireUpdateAccuracy()
        if not autoplay then return end
        local tools = instrumentTools()
        for _, tool in ipairs(tools) do
            local remote = tool:FindFirstChild("RemoteEvent") or tool:FindFirstChild("Remote")
            if remote then
                pcall(function()
                    _G.SafeFireServer(remote, "UpdateAccuracy", 100)
                end)
                break
            end
        end
    end

    local function firePlay()
        if not autoplay then return end
        local tools = instrumentTools()
        for _, tool in ipairs(tools) do
            local remote = tool:FindFirstChild("RemoteEvent") or tool:FindFirstChild("Remote")
            local soundSource = tool:FindFirstChild("Model")
                and tool.Model:FindFirstChild("Handle")
                and tool.Model.Handle:FindFirstChild("SoundSource")
            if remote and soundSource and not soundSource.IsPlaying then
                pcall(function()
                    _G.SafeFireServer(remote, "Play", currentSong)
                end)
                -- no task.wait here = no lag spike
                break
            end
        end
    end

    -- single heartbeat loop (no spawn/wait spam)
    local function startAutoplayHeartbeat()
        if connections.heartbeat then return end
        local playTimer = 0
        local accuracyTimer = 0
        local tintTimer = 0

        connections.heartbeat = RunService.Heartbeat:Connect(function(dt)
            if not autoplay then return end

            playTimer = playTimer - dt
            accuracyTimer = accuracyTimer - dt
            tintTimer = tintTimer - dt

            if playTimer <= 0 then
                playTimer = playInterval
                firePlay()
            end

            if accuracyTimer <= 0 then
                accuracyTimer = accuracyCooldown
                fireUpdateAccuracy()
            end

            if tintTimer <= 0 then
                tintTimer = 0.5
                tintInstrumentGui(true)
            end
        end)
    end

    local function stopAutoplayHeartbeat()
        safeDisconnect(connections.heartbeat)
        connections.heartbeat = nil
    end

    local function startAutoplay()
        if autoplay then return end
        autoplay = true
        AutoInstrumentEnabled = true
        tintInstrumentGui(true)
        startAutoplayHeartbeat()
    end

    local function stopAutoplay()
        if not autoplay then return end
        autoplay = false
        AutoInstrumentEnabled = false
        tintInstrumentGui(false)
        stopAutoplayHeartbeat()
    end

    -- song picker helper: call this from your UI when player picks a song
    local function setAutoplaySong(songName)
        if type(songName) == "string" and #songName > 0 then
            currentSong = songName
        end
    end

    local function setAutoInstrument(state)
        if state then
            startAutoplay()
        else
            stopAutoplay()
        end
    end

    -- UI: Toggle (starts OFF; user must enable)
    MusicianSection:Toggle({
        Title = "Auto Play Fife/Drum/Bagpipe",
        Flag = "GunMod_AutoInstrument",
        Desc = "Automatically plays instruments.",
        Icon = "music-2",
        Value = AutoInstrumentEnabled,
        Callback = function(state)
            setAutoInstrument(state)
            WindUI:Notify({
                Title = "Gun Modifiers",
                Content = state and "Auto instrument ON" or "Auto instrument OFF",
                Duration = 2,
                Icon = state and "music-2" or "x"
            })
        end
    })
end -- end of Musician Section in Classes Tab

task.wait(0.1) -- Delay to prevent lag
do -- // Medic Section in Classes Tab
    local Players = game:GetService("Players")
    local LocalPlayer = Players.LocalPlayer
    
    local MedicSection = ClassesTab:Section({
        Title = "Medic",
        Icon = "heart",
        Opened = false
    })

    local AutoRequestHealEnabled = false
    local HealRange = 10
    local HealCooldown = 3
    local HealThreshold = 25
    -- Use weak keys so entries for players who left are garbage collected
    local HealData = setmetatable({}, { __mode = "k" })
    local HealNotify = setmetatable({}, { __mode = "k" })

    local function RequestHeal(player, humanoid)
        if not player or not humanoid then return end
        if humanoid.Health > humanoid.MaxHealth * (HealThreshold / 100) then return end

        local lastReq = HealData[player] or 0
        if tick() - lastReq < HealCooldown then return end
        HealData[player] = tick()

        local localChar = LocalPlayer.Character
        if not localChar then return end
        local localHRP = localChar:FindFirstChild("HumanoidRootPart")
        if not localHRP then return end

        local targetHRP = humanoid.Parent:FindFirstChild("HumanoidRootPart") or humanoid.Parent:FindFirstChild("Torso")
        if not targetHRP then return end

        if (localHRP.Position - targetHRP.Position).Magnitude > HealRange then return end

        local medSupplies = localChar:FindFirstChild("Medical Supplies")
        if not medSupplies then return end
        local remote = medSupplies:FindFirstChild("RemoteEvent")
        if not remote then return end

        pcall(function()
            _G.SafeFireServer(remote, "SendRequest", humanoid)
            local lastNotify = HealNotify[player] or 0
            if tick() - lastNotify >= HealCooldown then
                HealNotify[player] = tick()
                WindUI:Notify({
                    Title = "Auto Heal",
                    Content = "Requested heal for " .. player.Name,
                    Duration = 2,
                    Icon = "heart",
                })
            end
        end)
    end

    task.defer(function()
        task.wait(1.5) -- Stagger start
        while task.wait(0.35) do 
            if AutoRequestHealEnabled then
                for _, player in ipairs(Players:GetPlayers()) do
                    if player ~= LocalPlayer and player.Character then
                        local humanoid = player.Character:FindFirstChildWhichIsA("Humanoid")
                        if humanoid and humanoid.Health <= humanoid.MaxHealth * (HealThreshold / 100) then
                            pcall(function() RequestHeal(player, humanoid) end)
                        end
                    end
                end
            end
        end
    end)

    MedicSection:Toggle({
        Title = "Auto Request Heal Dying Players",
        Flag = "Classes_1",
        Desc = "Automatically requests heal for players with low health when nearby",
        Default = false,
        Callback = function(state)
            AutoRequestHealEnabled = state
            WindUI:Notify({
                Title = "Auto Heal",
                Content = state and "Auto Request Heal Enabled" or "Auto Request Heal Disabled",
                Duration = 2,
                Icon = state and "heart" or "x",
            })
        end
    })

    MedicSection:Slider({
        Title = "Heal Threshold (%)",
        Flag = "Classes_2",
        Desc = "Health percentage threshold for auto heal",
        Step = 1,
        Value = {Min = 1, Max = 100, Default = HealThreshold},
        Callback = function(val)
            HealThreshold = val
        end
    })

    -- Auto Pick Up Supplies feature
    local AutoPickUpSuppliesEnabled = false
    
    local function IsMeterFull()
        -- Simple and direct approach: find the meter in workspace.Players.[PlayerName]
        local wsPlayers = Workspace:FindFirstChild("Players")
        if not wsPlayers then return false end -- Can't find players folder, try to pick up
        
        local playerFolder = wsPlayers:FindFirstChild(LocalPlayer.Name)
        if not playerFolder then return false end -- Can't find our folder, try to pick up
        
        local meter = playerFolder:FindFirstChild("Meter")
        if not meter then return false end -- No meter found, try to pick up
        
        -- Get current value
        local currentValue = nil
        local ok1, _ = pcall(function()
            currentValue = meter.Value
        end)
        if not ok1 or currentValue == nil then return false end
        
        -- Get max value - try multiple ways
        local maxValue = nil
        
        -- Try 1: Attribute "Max" on meter
        pcall(function()
            maxValue = meter:GetAttribute("Max")
        end)
        
        -- Try 2: Attribute "Max" on player folder
        if maxValue == nil then
            pcall(function()
                maxValue = playerFolder:GetAttribute("Max")
            end)
        end
        
        -- Try 3: Look for MaxMeter or Max value in player folder
        if maxValue == nil then
            local maxMeter = playerFolder:FindFirstChild("MaxMeter") or playerFolder:FindFirstChild("Max")
            if maxMeter and maxMeter:IsA("ValueBase") then
                pcall(function()
                    maxValue = maxMeter.Value
                end)
            end
        end
        
        -- Try 4: Common max values for medic supplies (fallback)
        if maxValue == nil then
            -- If we can't find max, assume a common max of 6 for medic supplies
            -- This way if current < 6, we'll still try to pick up
            maxValue = 6
        end
        
        -- Safety check
        if maxValue == nil or maxValue <= 0 then return false end
        
        -- Return true ONLY if current >= max (meter is full)
        return currentValue >= maxValue
    end
    
    -- Cache for supply prompts to avoid searching all descendants every frame
    local cachedSupplyPrompts = {}
    local lastPromptCacheTime = 0
    local PROMPT_CACHE_DURATION = 2 -- Refresh cache every 2 seconds
    
    local function RefreshPromptCache()
        local now = tick()
        if now - lastPromptCacheTime < PROMPT_CACHE_DURATION then return end
        lastPromptCacheTime = now
        
        cachedSupplyPrompts = {}
        -- Search common locations for supply prompts
        local searchLocations = {
            Workspace:FindFirstChild("Supplies"),
            Workspace:FindFirstChild("SupplyBoxes"),
            Workspace:FindFirstChild("Interactables"),
            Workspace:FindFirstChild("Map"),
        }
        
        -- Add workspace itself as fallback but limit search
        local function searchIn(container)
            if not container then return end
            for _, obj in ipairs(container:GetDescendants()) do
                if obj:IsA("ProximityPrompt") then
                    local name = obj.Name:lower()
                    if name:find("replenish") or name:find("supply") or obj.Name == "ReplenishPrompt" then
                        table.insert(cachedSupplyPrompts, obj)
                    end
                end
            end
        end
        
        for _, loc in ipairs(searchLocations) do
            searchIn(loc)
        end
        
        -- If no prompts found in common locations, do a limited workspace search
        if #cachedSupplyPrompts == 0 then
            for _, obj in ipairs(Workspace:GetDescendants()) do
                if obj:IsA("ProximityPrompt") then
                    local name = obj.Name:lower()
                    if name:find("replenish") or name:find("supply") or obj.Name == "ReplenishPrompt" then
                        table.insert(cachedSupplyPrompts, obj)
                    end
                end
            end
        end
    end
    
    local function FireReplenishPrompt()
        local char = LocalPlayer.Character
        local hrp = char and char:FindFirstChild("HumanoidRootPart")
        if not hrp then return end
        
        -- Refresh cache periodically
        RefreshPromptCache()
        
        -- Find the CLOSEST replenish/supply prompt to the player from cache
        local bestPrompt = nil
        local bestDist = 8 -- max search range in studs
        
        for _, prompt in ipairs(cachedSupplyPrompts) do
            if prompt and prompt.Parent then
                local parent = prompt.Parent
                local part = nil
                
                if parent and parent:IsA("BasePart") then
                    part = parent
                elseif parent and parent:IsA("Model") then
                    part = parent:FindFirstChild("HumanoidRootPart") or parent.PrimaryPart or parent:FindFirstChildWhichIsA("BasePart")
                elseif parent then
                    part = parent:FindFirstAncestorWhichIsA("BasePart") or parent:FindFirstChildWhichIsA("BasePart")
                end
                
                if part then
                    local dist = (hrp.Position - part.Position).Magnitude
                    if dist < bestDist then
                        bestDist = dist
                        bestPrompt = prompt
                    end
                end
            end
        end
        
        -- No prompt found nearby
        if not bestPrompt then return end
        
        -- Fire the closest proximity prompt
        pcall(function()
            fireproximityprompt(bestPrompt)
        end)
    end
    
    task.defer(function()
        task.wait(2) -- Stagger start
        while true do
            task.wait(0.25) -- Increased from 0.15 to 0.25 for better performance
            if AutoPickUpSuppliesEnabled then
                -- Always try to pick up - the game will naturally stop us if full
                -- The fireproximityprompt will fail silently if we can't pick up more
                FireReplenishPrompt()
            end
        end
    end)
    
    MedicSection:Toggle({
        Title = "Auto Pick Up Supplies",
        Flag = "Classes_AutoPickUpSupplies",
        Desc = "Automatically picks up supplies.",
        Default = false,
        Callback = function(state)
            AutoPickUpSuppliesEnabled = state
            WindUI:Notify({
                Title = "Auto Pick Up Supplies",
                Content = state and "Auto Pickup Supplies Enabled" or "Auto Pickup Supplies Disabled",
                Duration = 2,
                Icon = state and "package" or "x",
            })
        end
    })
end -- end of Medic Section in Classes Tab

task.wait(0.1) -- Delay to prevent lag

-- Define SapperSection at outer scope so it's accessible to Anti-Grab section
local SapperSection = ClassesTab:Section({
    Title = "Sapper",
    Icon = "hammer",
    Opened = false
})

do -- // Sapper Section in Classes Tab
    local Players = game:GetService("Players")
    local LocalPlayer = Players.LocalPlayer
    local Workspace = game:GetService("Workspace")
    
    local AutoRepairEnabled = false
    local AutoRepairCooldown = 0.1

    local function FireRepair(buildHealth)
        local char = LocalPlayer.Character
        if not (char and buildHealth) then return end

        local hammer = char:FindFirstChild("Hammer")
        if not hammer or not hammer:FindFirstChild("RemoteEvent") then return end

        local args = {"Repair", buildHealth}
        pcall(function()
            _G.SafeFireServer(hammer.RemoteEvent, unpack(args))
        end)
    end

    local function GetLookedStructure()
        local hrp = LocalPlayer.Character and LocalPlayer.Character:FindFirstChild("HumanoidRootPart")
        if not hrp then return nil end

        local origin = Workspace.CurrentCamera.CFrame.Position
        local direction = Workspace.CurrentCamera.CFrame.LookVector * 50

        local params = RaycastParams.new()
        params.FilterDescendantsInstances = {LocalPlayer.Character}
        params.FilterType = Enum.RaycastFilterType.Blacklist

        local rayResult = Workspace:Raycast(origin, direction, params)
        if not rayResult or not rayResult.Instance then return nil end

        local hit = rayResult.Instance
        local model = hit:FindFirstAncestorOfClass("Model")
        if not model then return nil end

        local buildHealth = model:FindFirstChild("BuildingHealth") or (model.Parent and model.Parent:FindFirstChild("BuildingHealth"))
        return buildHealth
    end

    task.defer(function()
        task.wait(2.5) -- Stagger start
        while true do
            task.wait(AutoRepairCooldown)
            if AutoRepairEnabled then
                local buildHealth = GetLookedStructure()
                if buildHealth then
                    local currentHealth = buildHealth.Value
                    local maxHealth = buildHealth:GetAttribute("MaxHealth")

                    if maxHealth and currentHealth < maxHealth then
                        FireRepair(buildHealth)
                    end
                end
            end
        end
    end)

    SapperSection:Toggle({
        Title = "Auto Repair",
        Flag = "Classes_3",
        Desc = "Auto repair's Buildings",
        Default = false,
        Callback = function(state)
            AutoRepairEnabled = state
            WindUI:Notify({
                Title = "Auto Repair",
                Content = state and "Auto Repair enabled" or "Auto Repair disabled",
                Duration = 2,
                Icon = state and "wrench" or "x",
            })
        end
    })
end -- end of Sapper Section in Classes Tab

task.wait(0.1) -- Delay to prevent lag
do -- // Anti-Grab & Shove Aura Section in Classes Tab
-- Anti Grab (Sapper) + Improved Shove Aura (RETRY EQUIP UNTIL FREED)
-- Maintains earlier behavior but will keep equipping weapon/tool while pinned/grabbed.

local Players = game:GetService("Players")
local LocalPlayer = Players.LocalPlayer
local Workspace = workspace

-- config
local ToolNamesPriority = {"Carbine", "Navy Pistol", "Axe", "Pickaxe", "Baguette"}
local AntiGrabPollRate = 0.05
local AntiGrabRange = 12

local ShoveAuraRange = 12
local ShoveTargets = 3
local ShoveAuraCooldown = 0.10
local ShovePreferEquipped = true
local AutoParrySapperEnabled = false

-- Carbine/Navy combo settings
local ComboStunRange = 15
local ComboStunMaxTargets = 10
local ComboStunDelay = 0.10

-- Shove Hitbox Expander (detects shove animation and fires at extended range)
-- Using global variables so UI can access them
ShoveHitboxExpanderEnabled = ShoveHitboxExpanderEnabled or false
ShoveHitboxExpanderRange = ShoveHitboxExpanderRange or 20
ShoveHitboxExpanderTargets = ShoveHitboxExpanderTargets or 10
ShoveHitboxExpanderDelay = ShoveHitboxExpanderDelay or 0.03
ShoveHitboxAnimConnection = ShoveHitboxAnimConnection or nil
AutoParrySapperMeleeEnabled = AutoParrySapperMeleeEnabled or false

AntiGrabEnabled = false -- Global for keybind access
ShoveAuraEnabled = false -- Global for keybind access
local shoving = false

local function safeWait(t)
    t = tonumber(t) or 0
    if t > 0 then task.wait(t) end
end

local function GetBackpack()
    if not LocalPlayer then return nil end
    return LocalPlayer:FindFirstChild("Backpack") or LocalPlayer:FindFirstChild("BackPack")
end

local function FindToolInstanceByName(toolName)
    if not toolName or not LocalPlayer then return nil end
    local char = LocalPlayer.Character
    if char then
        local t = char:FindFirstChild(toolName)
        if t and t:IsA("Tool") then return t end
    end
    local bp = GetBackpack()
    if bp then
        local t = bp:FindFirstChild(toolName)
        if t and t:IsA("Tool") then return t end
    end
    local wsPlayers = Workspace:FindFirstChild("Players")
    if wsPlayers then
        local folder = wsPlayers:FindFirstChild(LocalPlayer.Name)
        if folder then
            local t = folder:FindFirstChild(toolName)
            if t and t:IsA("Tool") then return t end
        end
    end
    return nil
end

local function TryEquipToolInstance(tool)
    if not tool or not LocalPlayer then return false end
    if LocalPlayer.Character and tool.Parent == LocalPlayer.Character then return true end

    -- try humanoid:EquipTool
    local char = LocalPlayer.Character
    if char then
        local humanoid = char:FindFirstChildOfClass("Humanoid")
        if humanoid then
            local ok = pcall(function() humanoid:EquipTool(tool) end)
            if ok then
                for i=1,8 do
                    if tool.Parent == LocalPlayer.Character then return true end
                    safeWait(0.05)
                end
            end
        end
    end

    -- fallback parent
    if LocalPlayer.Character then
        local ok2 = pcall(function() tool.Parent = LocalPlayer.Character end)
        if ok2 then
            for i=1,8 do
                if tool.Parent == LocalPlayer.Character then return true end
                    safeWait(0.05)
            end
        end
    end

    -- Player:EquipTool if exists
    if LocalPlayer and LocalPlayer.EquipTool then
        local ok3 = pcall(function() LocalPlayer:EquipTool(tool) end)
        if ok3 then
            for i=1,8 do
                if tool.Parent == LocalPlayer.Character then return true end
                safeWait(0.05)
            end
        end
    end

    return false
end

local function TryEquipFromBackpack(timeout)
    timeout = tonumber(timeout) or 0.8
    local start = tick()
    while tick() - start < timeout do
        for _, name in ipairs(ToolNamesPriority) do
            local candidate = FindToolInstanceByName(name)
            if candidate and candidate:IsA("Tool") then
                if LocalPlayer.Character and candidate.Parent == LocalPlayer.Character then
                    return name
                end
                local ok = TryEquipToolInstance(candidate)
                if ok then
                    safeWait(0.06)
                    return name
                end
            end
        end
        safeWait(0.06)
    end
    return nil
end

local function GetToolRemoteByName(toolName)
    if not toolName then return nil end
    local char = LocalPlayer.Character
    local bp = GetBackpack()
    local tool = (char and char:FindFirstChild(toolName)) or (bp and bp:FindFirstChild(toolName))
    if tool and tool:FindFirstChild("RemoteEvent") then return tool.RemoteEvent end
    local wsPlayers = Workspace:FindFirstChild("Players")
    if wsPlayers and wsPlayers:FindFirstChild(LocalPlayer.Name) then
        local folder = wsPlayers:FindFirstChild(LocalPlayer.Name)
        local toolFolder = folder:FindFirstChild(toolName)
        if toolFolder and toolFolder:FindFirstChild("RemoteEvent") then return toolFolder.RemoteEvent end
    end
    return nil
end

local function CollectZombiesForTargeting()
    local zombiesFolder = Workspace:FindFirstChild("Zombies")
    if not zombiesFolder then return {} end
    local list = {}
    local function collect(folder)
        if not folder then return end
        for _, z in ipairs(folder:GetChildren()) do
            if z and z:IsA("Model") then
                table.insert(list, z)
            end
        end
    end
    local agent = zombiesFolder:FindFirstChild("Agent")
    local slim = zombiesFolder:FindFirstChild("Slim")
    collect(agent)
    collect(slim)
    if #list == 0 then
        collect(zombiesFolder)
    end
    return list
end

local function FindNearestAgentParts(pos, maxRange, n)
    if not pos then return {} end
    n = n or 1
    local list = {}
    for _, z in ipairs(CollectZombiesForTargeting()) do
        local part = z:FindFirstChild("HumanoidRootPart") or z:FindFirstChildWhichIsA("BasePart")
        if part then
            local ok, d = pcall(function() return (part.Position - pos).Magnitude end)
            if ok and d and d <= (maxRange or math.huge) then
                table.insert(list, {part = part, dist = d, model = z})
            end
        end
    end
    table.sort(list, function(a,b) return a.dist < b.dist end)
    local out = {}
    for i=1, math.min(n, #list) do
        table.insert(out, list[i].part)
    end
    return out
end

local function GetZombiesInComboRange(originPos, radius, maxTargets)
    if not originPos then return {} end
    radius = radius or ComboStunRange
    maxTargets = maxTargets or ComboStunMaxTargets
    local zombies = CollectZombiesForTargeting()
    local list = {}
    for _, z in ipairs(zombies) do
        local hrp = z:FindFirstChild("HumanoidRootPart") or z:FindFirstChildWhichIsA("BasePart")
        if hrp then
            local d = (hrp.Position - originPos).Magnitude
            if d <= radius then
                table.insert(list, {model = z, part = hrp, dist = d})
            end
        end
    end
    table.sort(list, function(a,b) return a.dist < b.dist end)
    local out = {}
    for i=1, math.min(maxTargets, #list) do
        table.insert(out, list[i])
    end
    return out
end

local function PerformGunStunCombo(remote, originPos)
    if not remote or not originPos then return end
    local targets = GetZombiesInComboRange(originPos, ComboStunRange, ComboStunMaxTargets)
    for i, entry in ipairs(targets) do
        if entry.model and entry.part then
            pcall(function() _G.SafeFireServer(remote, "FeedbackStun", entry.model, entry.part.Position) end)
            if i < #targets then safeWait(ComboStunDelay) end
        end
    end
end

-- make pinned/grabbed detection tolerant of numbers, numeric-strings, and booleans
local function IsPinnedOrGrabbed(grabbedVal, pinVal)
    if not grabbedVal and not pinVal then return false end

    if grabbedVal and grabbedVal.Value ~= nil then
        local v = grabbedVal.Value
        if type(v) == "boolean" and v == true then return true end
        local n = tonumber(v)
        if n and n > 0 then return true end
        -- also accept string "true"
        if tostring(v):lower() == "true" then return true end
    end

    if pinVal and pinVal.Value ~= nil then
        local v = pinVal.Value
        if type(v) == "boolean" and v == true then return true end
        local n = tonumber(v)
        if n and n > 0 then return true end
        if tostring(v) == "RunnerAttack" then return true end
        if tostring(v):lower() == "true" then return true end
    end

    return false
end

-- Live-check helper (reads current Workspace user state each time)
local function CurrentPinnedOrGrabbed()
    local wsPlayers = Workspace:FindFirstChild("Players")
    if not wsPlayers then return false end
    local folder = wsPlayers:FindFirstChild(LocalPlayer and LocalPlayer.Name or "")
    if not folder then return false end
    local userStates = folder:FindFirstChild("UserStates")
    if not userStates then return false end
    local grabbedVal = userStates:FindFirstChild("Grabbed")
    local pinVal = userStates:FindFirstChild("Pin")
    return IsPinnedOrGrabbed(grabbedVal, pinVal)
end

local function IsToolEquipped(toolName)
    if not toolName then return false end
    if not LocalPlayer or not LocalPlayer.Character then return false end
    return LocalPlayer.Character:FindFirstChild(toolName) ~= nil
end

local function FireShoveRemote(remote, agentPart, toolName)
    if not remote then return end
    local tname = tostring(toolName or ""):lower()
    local char = LocalPlayer.Character
    local hrp = char and char:FindFirstChild("HumanoidRootPart")
    -- Baguette uses same shove mechanics as melee weapons
    if tname == "carbine" or tname == "navy pistol" then
        pcall(function() _G.SafeFireServer(remote, "Shove") end)
        if hrp then PerformGunStunCombo(remote, hrp.Position) end
    else
        if not agentPart then return end
        pcall(function() _G.SafeFireServer(remote, "FeedbackStun", agentPart.Parent, agentPart.Position) end)
        pcall(function() _G.SafeFireServer(remote, "StopBraceBlock") end)
    end
end

-- ALWAYS try to keep equipping while pinned; if tool disappears keep retrying until freed
local function StartShovingLoop(initialEquipName)
    if shoving then return end
    shoving = true

    task.spawn(function()
        local equippedName = initialEquipName
        local remote = equippedName and GetToolRemoteByName(equippedName) or nil

        while true do
            -- If AntiGrab disabled externally, break out
            if not AntiGrabEnabled then break end

            -- If not currently pinned/grabbed, attempt a small confirmation window
            if not CurrentPinnedOrGrabbed() then
                local releaseConfirmed = true
                -- require a few consecutive checks to avoid flicker issues
                for i = 1, 4 do
                    safeWait(AntiGrabPollRate) -- small pause per check
                    if CurrentPinnedOrGrabbed() then
                        releaseConfirmed = false
                        break
                    end
                end
                if releaseConfirmed then break end
            end

            -- ensure we have a valid equipped tool; if not, keep trying while still pinned (no time cap)
            if not (equippedName and IsToolEquipped(equippedName)) then
                local newName = TryEquipFromBackpack(0.6)
                if newName then
                    equippedName = newName
                end
                -- refresh remote after each attempt
                remote = equippedName and GetToolRemoteByName(equippedName) or nil
            end

            -- if remote missing try to refresh but don't block long (keep trying across loop iterations)
            if not remote and equippedName then
                remote = GetToolRemoteByName(equippedName)
            end

            -- perform shove attempts if we have hrp and targets
            local char = LocalPlayer.Character
            local hrp = char and char:FindFirstChild("HumanoidRootPart")
            if hrp then
                local targets = FindNearestAgentParts(hrp.Position, AntiGrabRange, 2)
                for _, agentPart in ipairs(targets) do
                    -- lightweight refresh of remote per-target
                    if not remote and equippedName then
                        remote = GetToolRemoteByName(equippedName)
                    end
                    if remote then
                        FireShoveRemote(remote, agentPart, equippedName)
                    end
                end
            end

            task.wait(0.06)
        end

        shoving = false
    end)
end

-- monitor loop (debounced) — now notifies Kill Aura to disable/restore
task.defer(function()
    task.wait(3) -- Stagger start
    local lastState = false
    while true do
        task.wait(AntiGrabPollRate)
        if not AntiGrabEnabled then
            -- if anti-grab got disabled while previously suppressing, try to unsuppress KillAura
            if lastState then
                pcall(function()
                    local ka = (type(getgenv) == "function" and getgenv().KillAuraAPI) or _G.KillAuraAPI
                    if ka and ka.unsuppress then ka.unsuppress() end
                end)
            end
            lastState = false
        else

            local currentlyPinnedOrGrabbed = CurrentPinnedOrGrabbed()

        -- transition: not grabbed -> grabbed
        if currentlyPinnedOrGrabbed and not lastState then
            -- try to equip aggressively once the state transitions
            local equippedName = TryEquipFromBackpack(1.0)
            StartShovingLoop(equippedName)

            -- request Kill Aura be disabled while we're grabbed
            pcall(function()
                local ka = (type(getgenv) == "function" and getgenv().KillAuraAPI) or _G.KillAuraAPI
                if ka and ka.suppress then ka.suppress() end
            end)
        end

        -- ensure loop has started if pinned
        if currentlyPinnedOrGrabbed and not shoving then
            local equippedName = TryEquipFromBackpack(1.0)
            StartShovingLoop(equippedName)

            pcall(function()
                local ka = (type(getgenv) == "function" and getgenv().KillAuraAPI) or _G.KillAuraAPI
                if ka and ka.suppress then ka.suppress() end
            end)
        end

            -- transition: grabbed -> released (use lastState to detect transition)
            if (not currentlyPinnedOrGrabbed) and lastState then
                -- Ask Kill Aura to restore previous state (after release)
                pcall(function()
                    local ka = (type(getgenv) == "function" and getgenv().KillAuraAPI) or _G.KillAuraAPI
                    if ka and ka.unsuppress then ka.unsuppress() end
                end)
            end

            lastState = currentlyPinnedOrGrabbed
        end
    end
end)

-- Shove Aura: unchanged aside from using the same robust remote lookup and gun/melee behavior
local function RemoteFromToolInstance(tool)
    if not tool then return nil end
    if tool:FindFirstChild("RemoteEvent") then return tool.RemoteEvent end
    local wsPlayers = Workspace:FindFirstChild("Players")
    if wsPlayers and wsPlayers:FindFirstChild(LocalPlayer.Name) then
        local folder = wsPlayers:FindFirstChild(LocalPlayer.Name)
        local t = folder:FindFirstChild(tool.Name)
        if t and t:FindFirstChild("RemoteEvent") then return t.RemoteEvent end
    end
    return nil
end

local function GetBestToolRemoteAndName()
    if ShovePreferEquipped and LocalPlayer.Character then
        local equipped = LocalPlayer.Character:FindFirstChildOfClass("Tool")
        if equipped then
            local r = RemoteFromToolInstance(equipped)
            if r then return r, equipped.Name end
        end
    end

    for _, name in ipairs(ToolNamesPriority) do
        local charTool = LocalPlayer.Character and LocalPlayer.Character:FindFirstChild(name)
        if charTool then
            local r = RemoteFromToolInstance(charTool)
            if r then return r, name end
        end
        local back = GetBackpack()
        if back then
            local btool = back:FindFirstChild(name)
            if btool then
                local r = RemoteFromToolInstance(btool)
                if r then return r, name end
            end
        end
        local wsPlayers = Workspace:FindFirstChild("Players")
        if wsPlayers and wsPlayers:FindFirstChild(LocalPlayer.Name) then
            local folder = wsPlayers:FindFirstChild(LocalPlayer.Name)
            local ftool = folder:FindFirstChild(name)
            if ftool and ftool:FindFirstChild("RemoteEvent") then return ftool.RemoteEvent, name end
        end
    end
    return nil, nil
end

local function FireShove(remote, agentPart, toolName)
    if not remote then return end
    local tname = tostring(toolName or ""):lower()
    local char = LocalPlayer.Character
    local hrp = char and char:FindFirstChild("HumanoidRootPart")
    -- Baguette uses same shove mechanics as melee weapons
    if tname == "carbine" or tname == "navy pistol" then
        pcall(function() _G.SafeFireServer(remote, "Shove") end)
        if hrp then PerformGunStunCombo(remote, hrp.Position) end
    else
        if not agentPart then return end
        pcall(function() _G.SafeFireServer(remote, "FeedbackStun", agentPart.Parent, agentPart.Position) end)
        pcall(function() _G.SafeFireServer(remote, "StopBraceBlock") end)
    end
end

task.defer(function()
    task.wait(3.5) -- Stagger start
    while true do
        task.wait(ShoveAuraCooldown)
        if ShoveAuraEnabled then
            local char = LocalPlayer.Character
            local hrp = char and char:FindFirstChild("HumanoidRootPart")
            if hrp then
                local remote, rname = GetBestToolRemoteAndName()
                if not remote then
                    local equipName = TryEquipFromBackpack(0.6)
                    remote = equipName and GetToolRemoteByName(equipName) or nil
                    rname = rname or equipName
                end

                if remote then
                    local targets = FindNearestAgentParts(hrp.Position, ShoveAuraRange, ShoveTargets)
                    if #targets > 0 then
                        for _, part in ipairs(targets) do
                            FireShove(remote, part, rname)
                        end
                    end
                end
            end
        end
    end
end)

-- ===== SHOVE HITBOX EXPANDER - ANIMATION DETECTION =====
-- Detects when player performs a shove animation and fires shoves at extended range
-- Works exactly like Shove Aura but only triggers when you do a shove animation

-- Helper: Check if animation name contains "shove" (case insensitive)
local function IsShoveAnimation(track)
    if not track then return false end
    local name = track.Name or ""
    if string.lower(name):find("shove") then return true end
    -- Also check animation object name
    local anim = track.Animation
    if anim and anim.Name then
        if string.lower(anim.Name):find("shove") then return true end
    end
    return false
end

-- Perform the extended shove (same logic as Shove Aura)
local function PerformShoveHitboxExpander()
    if not ShoveHitboxExpanderEnabled then return end
    local char = LocalPlayer.Character
    local hrp = char and char:FindFirstChild("HumanoidRootPart")
    if not hrp then return end
    
    -- Get remote and tool name (same as Shove Aura)
    local remote, rname = GetBestToolRemoteAndName()
    if not remote then return end
    
    -- Get zombies in extended range
    local targets = FindNearestAgentParts(hrp.Position, ShoveHitboxExpanderRange, ShoveHitboxExpanderTargets)
    if #targets == 0 then return end
    
    -- Fire at each target (same as Shove Aura)
    for i, part in ipairs(targets) do
        FireShove(remote, part, rname)
        if i < #targets and ShoveHitboxExpanderDelay > 0 then
            safeWait(ShoveHitboxExpanderDelay)
        end
    end
end

-- Animation detection callback
local function OnShoveAnimationPlayed(track)
    if not ShoveHitboxExpanderEnabled then return end
    if not track then return end
    
    -- Check if this is a shove animation
    if IsShoveAnimation(track) then
        -- Fire extended shove immediately
        task.spawn(function()
            PerformShoveHitboxExpander()
        end)
    end
end

-- Attach animation watcher to humanoid
local function AttachShoveHitboxWatcher()
    -- Disconnect previous connection if exists
    if ShoveHitboxAnimConnection then
        pcall(function() ShoveHitboxAnimConnection:Disconnect() end)
        ShoveHitboxAnimConnection = nil
    end
    
    local char = LocalPlayer.Character
    if not char then return end
    local hum = char:FindFirstChildOfClass("Humanoid")
    if not hum then return end
    
    -- Connect to AnimationPlayed
    local ok, conn = pcall(function()
        return hum.AnimationPlayed:Connect(OnShoveAnimationPlayed)
    end)
    if ok and conn then
        ShoveHitboxAnimConnection = conn
    end
end

-- Attach on character spawn
LocalPlayer.CharacterAdded:Connect(function(newChar)
    task.wait(0.2)
    AttachShoveHitboxWatcher()
end)

-- Initial attach if character already loaded
task.spawn(function()
    task.wait(0.5)
    AttachShoveHitboxWatcher()
end)

-- Auto Parry Zapper: spam BraceBlock when a zapper is close (uses ESP detection)
local function FindNearestZapper(pos, maxRange)
    local zombiesFolder = Workspace:FindFirstChild("Zombies")
    if not zombiesFolder or not pos then return nil end
    local nearest = nil
    local nearestDist = math.huge
    for _, z in ipairs(zombiesFolder:GetChildren()) do
        if z and z:IsA("Model") and isZombieOfType and isZombieOfType(z, "Zapper") then
            local part = z:FindFirstChild("HumanoidRootPart") or z:FindFirstChildWhichIsA("BasePart")
            if part then
                local d = (part.Position - pos).Magnitude
                if d <= (maxRange or math.huge) and d < nearestDist then
                    nearestDist = d
                    nearest = part
                end
            end
        end
    end
    return nearest, nearestDist
end

task.defer(function()
    task.wait(4) -- Stagger start
    while true do
        task.wait(0.08) -- Slightly reduced frequency
        if AutoParrySapperEnabled then
            local char = LocalPlayer.Character
            local hrp = char and char:FindFirstChild("HumanoidRootPart")
            if hrp then
                local threshold = ShoveAuraEnabled and 5 or 10
                local zapperPart, dist = FindNearestZapper(hrp.Position, threshold)
                if zapperPart and dist and dist <= threshold then
                    local remote, rname = GetBestToolRemoteAndName()
                    if not remote then
                        local equipName = TryEquipFromBackpack(0.4)
                        remote = equipName and GetToolRemoteByName(equipName) or nil
                        rname = rname or equipName
                    end
                    if remote then
                        pcall(function() _G.SafeFireServer(remote, "BraceBlock") end)
                    end
                end
            end
        end
    end
end)

-- Auto Parry Sapper (Melee only - Axe/Pickaxe): spam BraceBlock when any zombie is within 8 studs
local function FindNearestZombieForParry(pos, maxRange)
    local zombiesFolder = Workspace:FindFirstChild("Zombies")
    if not zombiesFolder or not pos then return nil end
    local nearest = nil
    local nearestDist = math.huge
    
    -- Check in Agent folder (regular zombies)
    local agentFolder = zombiesFolder:FindFirstChild("Agent")
    if agentFolder then
        for _, z in ipairs(agentFolder:GetChildren()) do
            if z and z:IsA("Model") then
                local part = z:FindFirstChild("HumanoidRootPart") or z:FindFirstChildWhichIsA("BasePart")
                if part then
                    local d = (part.Position - pos).Magnitude
                    if d <= (maxRange or math.huge) and d < nearestDist then
                        nearestDist = d
                        nearest = part
                    end
                end
            end
        end
    end
    
    -- Also check Slim folder (Cuirassiers)
    local slimFolder = zombiesFolder:FindFirstChild("Slim")
    if slimFolder then
        for _, z in ipairs(slimFolder:GetChildren()) do
            if z and z:IsA("Model") then
                local part = z:FindFirstChild("HumanoidRootPart") or z:FindFirstChildWhichIsA("BasePart")
                if part then
                    local d = (part.Position - pos).Magnitude
                    if d <= (maxRange or math.huge) and d < nearestDist then
                        nearestDist = d
                        nearest = part
                    end
                end
            end
        end
    end
    
    return nearest, nearestDist
end

-- Helper: Check if player has Axe or Pickaxe equipped
local function HasMeleeEquipped()
    local char = LocalPlayer.Character
    if not char then return false, nil end
    local tool = char:FindFirstChildOfClass("Tool")
    if tool then
        local name = tool.Name
        if name == "Axe" or name == "Pickaxe" then
            return true, name
        end
    end
    return false, nil
end

-- Helper: Get remote for Axe or Pickaxe
local function GetMeleeRemote()
    local hasMelee, toolName = HasMeleeEquipped()
    if not hasMelee then return nil, nil end
    
    local wsPlayers = Workspace:FindFirstChild("Players")
    if wsPlayers then
        local playerFolder = wsPlayers:FindFirstChild(LocalPlayer.Name)
        if playerFolder then
            local toolFolder = playerFolder:FindFirstChild(toolName)
            if toolFolder then
                local remote = toolFolder:FindFirstChild("RemoteEvent")
                if remote then return remote, toolName end
            end
        end
    end
    return nil, nil
end

task.defer(function()
    task.wait(4.5) -- Stagger start
    while true do
        task.wait(0.08) -- Slightly reduced frequency
        if AutoParrySapperMeleeEnabled then
            local char = LocalPlayer.Character
            local hrp = char and char:FindFirstChild("HumanoidRootPart")
            if hrp then
                local hasMelee, meleeName = HasMeleeEquipped()
                if hasMelee then
                    local zombiePart, dist = FindNearestZombieForParry(hrp.Position, 8)
                    if zombiePart and dist and dist <= 8 then
                        local remote = GetMeleeRemote()
                        if remote then
                            pcall(function() _G.SafeFireServer(remote, "BraceBlock") end)
                        end
                    end
                end
            end
        end
    end
end)

local AntiGrabToggle = SapperSection:Toggle({
    Title = "Anti Grab",
    Flag = "Classes_AntiGrab",
    Desc = "Will AutoMattically Shove The Zombie Grabbing You.",
    Default = false,
    Callback = function(v)
        AntiGrabEnabled = v
        if not v then shoving = false end
        pcall(function()
            if WindUI then
                WindUI:Notify({
                    Title = "Sapper — Anti Grab",
                    Content = v and "Anti Grab Enabled" or "Anti Grab Disabled",
                    Duration = 2,
                    Icon = v and "shield-check" or "shield-off",
                })
            end
        end)
    end
})
_G.KatchiToggleElements = _G.KatchiToggleElements or {}
_G.KatchiToggleElements.AntiGrab = AntiGrabToggle

local ShoveAuraToggle = SapperSection:Toggle({
    Title = "Shove Aura",
    Flag = "Sapper_ShoveAura",
    Desc = "Auto Shoves Zombies Near You.",
    Default = ShoveAuraEnabled,
    Callback = function(v)
        ShoveAuraEnabled = v
        pcall(function()
            if WindUI and WindUI.Notify then
                WindUI:Notify({
                    Title = "Shove Aura",
                    Content = (v and ("Enabled — range: "..tostring(ShoveAuraRange)) ) or "Disabled",
                    Duration = 2,
                    Icon = v and "zap" or "x",
                })
            end
        end)
    end
})
_G.KatchiToggleElements.ShoveAura = ShoveAuraToggle

SapperSection:Slider({
    Title = "Shove Range",
    Flag = "ShoveRange",
    Desc = "How Far Shove Aura Will Shove",
    Step = 1,
    Value = {
        Min = 1,
        Max = 30,
        Default = ShoveAuraRange,
    },
    Callback = function(val)
        ShoveAuraRange = math.max(1, math.floor(tonumber(val) or 1))
        pcall(function()
            if WindUI and WindUI.Notify then
                WindUI:Notify({ Title = "Shove Range", Content = tostring(ShoveAuraRange).." studs", Duration = 1 })
            end
        end)
    end
})

SapperSection:Slider({
    Title = "Shove Targets",
    Flag = "ShoveRange2",
    Desc = "How many nearest Zombies to target in 1 shove.",
    Step = 1,
    Value = {
        Min = 1,
        Max = 5,
        Default = ShoveTargets,
    },
    Callback = function(val)
        ShoveTargets = math.max(1, math.floor(tonumber(val) or 1))
    end
})

SapperSection:Slider({
    Title = "Shove Delay",
    Flag = "ShoveRange3",
    Desc = "controls how fast to shove.",
    Step = 0.01,
    Value = {
        Min = 0.02,
        Max = 0.5,
        Default = ShoveAuraCooldown,
    },
    Callback = function(val)
        ShoveAuraCooldown = math.clamp(tonumber(val) or 0.1, 0.02, 0.5)
    end
})
end -- end of Anti-Grab & Shove Aura Section in Classes Tab

task.wait(0.1) -- Delay to prevent lag
do -- // Chaplain Section in Classes Tab
-- ======= Chaplain Section (only acts when Blessing tool is equipped; silent on failures) =======
local ChaplainSection = ClassesTab:Section({
    Title = "Chaplain",
    Icon = "pray",
    Opened = false
})

local PlayersSvc = game:GetService("Players")
local LocalPlayer = PlayersSvc.LocalPlayer

local AutoBlessEnabled = false
local AutoMercyEnabled = false
local BlessThreshold = 50         -- numeric threshold
local BlessCooldown = 2           -- seconds between blessings to same player
local MercyCooldown = 2           -- seconds between mercy to same player
local BlessRange = 15             -- proximity requirement (studs)
local MercyRange = 15             -- proximity requirement for mercy (studs)
-- Use weak keys so data for players who left is garbage collected
local BlessData = setmetatable({}, { __mode = "k" })  -- per-player cooldown storage (keyed by UserId -> Player)
local MercyData = setmetatable({}, { __mode = "k" })  -- per-player cooldown storage for mercy

-- Only look for the Blessing or Divinity tool when it's equipped (in Character). If not equipped, do nothing silently.
local function GetEquippedBlessRemote()
    local localChar = LocalPlayer and LocalPlayer.Character
    if not localChar then return nil end
    
    -- Check for Blessing tool
    local blessing = localChar:FindFirstChild("Blessing")
    if blessing and blessing:FindFirstChild("RemoteEvent") then
        return blessing:FindFirstChild("RemoteEvent")
    end
    
    -- Check for Divinity tool
    local divinity = localChar:FindFirstChild("Divinity")
    if divinity and divinity:FindFirstChild("RemoteEvent") then
        return divinity:FindFirstChild("RemoteEvent")
    end
    
    -- also accept tools with 'bless' or 'divinity' in the name (case-insensitive) when equipped
    for _, child in ipairs(localChar:GetChildren()) do
        if child:IsA("Tool") then
            local nameLower = child.Name:lower()
            if (nameLower:find("bless") or nameLower:find("divinity")) and child:FindFirstChild("RemoteEvent") then
                return child:FindFirstChild("RemoteEvent")
            end
        end
    end
    return nil
end

-- Get equipped Mercy tool remote
local function GetEquippedMercyRemote()
    local localChar = LocalPlayer and LocalPlayer.Character
    if not localChar then return nil end
    
    local mercy = localChar:FindFirstChild("Mercy")
    if mercy and mercy:FindFirstChild("RemoteEvent") then
        return mercy:FindFirstChild("RemoteEvent")
    end
    
    -- also accept tools with 'mercy' in the name (case-insensitive) when equipped
    for _, child in ipairs(localChar:GetChildren()) do
        if child:IsA("Tool") and child.Name:lower():find("mercy") and child:FindFirstChild("RemoteEvent") then
            return child:FindFirstChild("RemoteEvent")
        end
    end
    return nil
end

-- Helper: returns true if target player is within range of local player
local function InRangeOfLocal(player, maxRange)
    local localChar = LocalPlayer and LocalPlayer.Character
    if not (localChar and localChar:FindFirstChild("HumanoidRootPart")) then return false end
    if not (player and player.Character) then return false end
    local targetHRP = player.Character:FindFirstChild("HumanoidRootPart") or player.Character:FindFirstChild("Torso")
    if not targetHRP then return false end
    return (localChar.HumanoidRootPart.Position - targetHRP.Position).Magnitude <= (maxRange or BlessRange)
end

-- Fire bless using the player's humanoid. Fail silently if tool not equipped, out of range, or humanoid missing.
local function FireBlessByPlayer_Silent(player)
    if not player then return false end

    -- require the blessing/divinity tool to be equipped (in character)
    local remote = GetEquippedBlessRemote()
    if not remote then
        return false
    end

    -- must be in range
    if not InRangeOfLocal(player, BlessRange) then
        return false
    end

    local humanoid = player.Character and player.Character:FindFirstChildWhichIsA("Humanoid")
    if not humanoid then
        return false
    end

    local ok, err = pcall(function()
        -- match Medic pattern: remote:FireServer("SendRequest", humanoid)
        _G.SafeFireServer(remote, "SendRequest", humanoid)
    end)
    if not ok then
        -- fail silently
        return false
    end

    return true
end

-- Fire mercy using the player's humanoid. Fail silently if tool not equipped, out of range, or humanoid missing.
local function FireMercyByPlayer_Silent(player)
    if not player then return false end

    -- require the mercy tool to be equipped (in character)
    local remote = GetEquippedMercyRemote()
    if not remote then
        return false
    end

    -- must be in range
    if not InRangeOfLocal(player, MercyRange) then
        return false
    end

    local humanoid = player.Character and player.Character:FindFirstChildWhichIsA("Humanoid")
    if not humanoid then
        return false
    end

    local ok, err = pcall(function()
        -- remote:FireServer("SendRequest", humanoid)
        _G.SafeFireServer(remote, "SendRequest", humanoid)
    end)
    if not ok then
        -- fail silently
        return false
    end

    return true
end

-- Try common locations for a player's "Infected" value
local function GetPlayerInfectedValue(player)
    local ok, val = pcall(function()
        local wsPlayers = Workspace:FindFirstChild("Players")
        if wsPlayers then
            local wsP = wsPlayers:FindFirstChild(player.Name)
            if wsP and wsP:FindFirstChild("UserStates") and wsP.UserStates:FindFirstChild("Infected") then
                return wsP.UserStates.Infected.Value
            end
        end
        if player:FindFirstChild("UserStates") and player.UserStates:FindFirstChild("Infected") then
            return player.UserStates.Infected.Value
        end
        if player.Character and player.Character:FindFirstChild("UserStates") and player.Character.UserStates:FindFirstChild("Infected") then
            return player.Character.UserStates.Infected.Value
        end
        return nil
    end)
    if ok then return val end
    return nil
end

-- Main scan loop (silent on failures; only notifies on successful bless)
task.defer(function()
    task.wait(5) -- Stagger start
    while task.wait(0.35) do
        if AutoBlessEnabled then
            for _, player in ipairs(PlayersSvc:GetPlayers()) do
                if player and player ~= LocalPlayer then
                    local infectedVal = nil
                    pcall(function()
                        infectedVal = GetPlayerInfectedValue(player)
                    end)

                    if infectedVal ~= nil then
                        -- normalize infectedVal to number
                        local numeric = nil
                        if type(infectedVal) == "number" then
                            numeric = infectedVal
                        elseif type(infectedVal) == "string" then
                            numeric = tonumber(infectedVal)
                        elseif type(infectedVal) == "boolean" then
                            numeric = infectedVal and 1 or 0
                        end

                        local thresholdNum = tonumber(BlessThreshold) or 0

                        if numeric and numeric >= thresholdNum and numeric < 100 then
                            local uid = player.UserId or player.Name
                            local last = BlessData[uid] or 0
                            if tick() - last >= (tonumber(BlessCooldown) or 0) then
                                local success = false
                                pcall(function()
                                    success = FireBlessByPlayer_Silent(player)
                                end)
                                if success then
                                    BlessData[uid] = tick()
                                    WindUI:Notify({
                                        Title = "Auto Bless",
                                        Content = "Sent bless to " .. player.Name,
                                        Duration = 2,
                                        Icon = "pray"
                                    })
                                end
                            end
                        end
                    end
                end
            end
        end
    end
end)

-- Auto Mercy loop (only for players with 100% infection)
task.defer(function()
    task.wait(5) -- Stagger start
    while task.wait(0.35) do
        if AutoMercyEnabled then
            for _, player in ipairs(PlayersSvc:GetPlayers()) do
                if player and player ~= LocalPlayer then
                    local infectedVal = nil
                    pcall(function()
                        infectedVal = GetPlayerInfectedValue(player)
                    end)

                    if infectedVal ~= nil then
                        -- normalize infectedVal to number
                        local numeric = nil
                        if type(infectedVal) == "number" then
                            numeric = infectedVal
                        elseif type(infectedVal) == "string" then
                            numeric = tonumber(infectedVal)
                        elseif type(infectedVal) == "boolean" then
                            numeric = infectedVal and 100 or 0
                        end

                        -- Only mercy players with 100% infection
                        if numeric and numeric >= 100 then
                            local uid = player.UserId or player.Name
                            local last = MercyData[uid] or 0
                            if tick() - last >= (tonumber(MercyCooldown) or 0) then
                                local success = false
                                pcall(function()
                                    success = FireMercyByPlayer_Silent(player)
                                end)
                                if success then
                                    MercyData[uid] = tick()
                                    WindUI:Notify({
                                        Title = "Auto Mercy",
                                        Content = "Sent mercy to " .. player.Name,
                                        Duration = 2,
                                        Icon = "heart"
                                    })
                                end
                            end
                        end
                    end
                end
            end
        end
    end
end)

-- UI Controls
ChaplainSection:Toggle({
    Title = "Auto Bless Infected Players",
    Flag = "Classes_4",
    Desc = "Automatically bless players with infection",
    Default = false,
    Callback = function(state)
        AutoBlessEnabled = state
        WindUI:Notify({
            Title = "Chaplain",
            Content = state and "Auto Bless Enabled" or "Auto Bless Disabled",
            Duration = 2,
            Icon = state and "pray" or "x"
        })
    end
})

ChaplainSection:Toggle({
    Title = "Auto Mercy Fully Infected",
    Flag = "Classes_AutoMercy",
    Desc = "Automatically mercy players with 100% infection",
    Default = false,
    Callback = function(state)
        AutoMercyEnabled = state
        WindUI:Notify({
            Title = "Chaplain",
            Content = state and "Auto Mercy Enabled" or "Auto Mercy Disabled",
            Duration = 2,
            Icon = state and "heart" or "x"
        })
    end
})

ChaplainSection:Slider({
    Title = "Infected Threshold",
    Flag = "Classes_5",
    Desc = "Threshold for auto bless (won't bless players at 100%)",
    Step = 1,
    Value = {Min = 0, Max = 99, Default = BlessThreshold},
    Callback = function(val)
        BlessThreshold = tonumber(val) or 0
    end
})
-- ======= END Chaplain Section =======
end -- end of Chaplain Section in Classes Tab

task.wait(0.1) -- Delay to prevent lag
do -- // Dracula (New) — auto melee remote scanner + robust ESP (Dracula + Silver)
    local Players = game:GetService("Players")
    local Workspace = game:GetService("Workspace")
    local CoreGui = game:GetService("CoreGui")
    local LocalPlayer = Players.LocalPlayer

    -- ===== SETTINGS (defaults) =====
    local DEBUG = false
    local DraculaLoopInterval = 0.1

    HitDraculaEnabled   = HitDraculaEnabled or false
    DraculaSpamCount    = DraculaSpamCount or 5
    DraculaRange        = DraculaRange or 15
    DraculaHitSpacing   = DraculaHitSpacing or 0.01  -- default as requested
    DraculaEspEnabled   = DraculaEspEnabled or false
    SilverEspEnabled    = SilverEspEnabled or false

    -- ===== INTERNALS =====
    -- Use weak keys so destroyed remotes get garbage collected
    local draculaRemotes = setmetatable({}, { __mode = "k" })  -- [RemoteEvent] = true
    local lastDraculaRemoteScan = 0

    local draculaHighlight = nil
    -- Use weak keys so destroyed models get garbage collected
    local silverVisuals = setmetatable({}, { __mode = "k" })  -- [Model] = {Highlight = hl, Billboard = bb, Text = txt}

    local ESP_HIGHLIGHT_SUPPORTED = true
    local ESP_GUI_PARENT = CoreGui    -- will fallback to PlayerGui if CoreGui blocked

    -- ===== HELPERS =====
    local function safePcall(fn, ...)
        local ok, a, b, c = pcall(fn, ...)
        return ok, a, b, c
    end

    local function getDracula()
        local trans = Workspace:FindFirstChild("Transylvania")
        if not trans then return nil end
        local modes = trans:FindFirstChild("Modes")
        if not modes then return nil end
        local boss = modes:FindFirstChild("Boss")
        if not boss then return nil end
        return boss:FindFirstChild("Dracula")
    end

    local function getSilverFolder()
        local trans = Workspace:FindFirstChild("Transylvania")
        if not trans then return nil end
        local modes = trans:FindFirstChild("Modes")
        if not modes then return nil end
        local boss = modes:FindFirstChild("Boss")
        if not boss then return nil end
        return boss:FindFirstChild("SilverTrinkets")
    end

    -- Try to determine a usable GUI parent for ESP (CoreGui preferred, fallback to PlayerGui)
    do
        local ok = pcall(function()
            local test = Instance.new("Folder")
            test.Parent = CoreGui
            test:Destroy()
        end)
        if not ok then
            -- fallback to PlayerGui if possible
            local playerGui = (LocalPlayer and LocalPlayer:FindFirstChild("PlayerGui"))
            if playerGui then
                ESP_GUI_PARENT = playerGui
            else
                -- attempt to wait for PlayerGui (if allowed)
                local s, r = pcall(function() return LocalPlayer:WaitForChild("PlayerGui", 2) end)
                if s and r then ESP_GUI_PARENT = r else ESP_HIGHLIGHT_SUPPORTED = false end
        end
        end
    end

    -- ===== Remote scanning (auto, continuous) =====
    local function ScanDraculaRemotes()
        table.clear(draculaRemotes)
        local char = LocalPlayer and LocalPlayer.Character
        if not char then return end
        for _, obj in ipairs(char:GetChildren()) do
            if obj:IsA("Tool") then
                for _, ch in ipairs(obj:GetChildren()) do
                    if ch and ch:IsA("RemoteEvent") then
                        draculaRemotes[ch] = true
                    end
                end
            end
        end
        lastDraculaRemoteScan = tick()
        if DEBUG then
            local c = 0
            for _ in pairs(draculaRemotes) do c = c + 1 end
            print("[Dracula] remotes scanned:", c)
        end
    end

    -- Debounce remote scanning to prevent lag when spamming equip/unequip
    local Dracula_scanDebounce = false
    local function Dracula_DebouncedScan()
        if Dracula_scanDebounce then return end
        Dracula_scanDebounce = true
        task.delay(0.15, function()
            Dracula_scanDebounce = false
            ScanDraculaRemotes()
        end)
    end
    
    -- initial scan + hooks
    if LocalPlayer.Character then ScanDraculaRemotes() end
    LocalPlayer.CharacterAdded:Connect(function(char)
        task.wait(0.5)
        ScanDraculaRemotes()
        char.ChildAdded:Connect(function(c)
            if c and c:IsA("Tool") then Dracula_DebouncedScan() end
        end)
        char.ChildRemoved:Connect(function(c)
            if c and c:IsA("Tool") then Dracula_DebouncedScan() end
        end)
    end)

    -- background auto-scan (always on, deferred)
    task.defer(function()
        task.wait(5.5) -- Stagger start
        while true do
            task.wait(2) -- Reduced frequency
            ScanDraculaRemotes()
        end
    end)

    -- ===== Remote action helpers =====
    local function fireSwingRemote(remote)
        if not (remote and remote:IsA("RemoteEvent")) then return end
        pcall(function() _G.SafeFireServer(remote, "Swing", "Side") end)
    end

    local function fireHitAtDracula(remote, dracModel)
        if not (remote and dracModel) then return end
        local ok, pivot = pcall(function() return dracModel:GetPivot().Position end)
        if not ok or not pivot then return end

        local offset = Vector3.new(
            (math.random() - 0.5) * 6,
            (math.random() - 0.5) * 4,
            (math.random() - 0.5) * 6
        )
        local hitPos = pivot + offset

        local hrp = LocalPlayer.Character and LocalPlayer.Character:FindFirstChild("HumanoidRootPart")
        local hrpPos = (hrp and hrp.Position) or pivot
        local delta = hitPos - hrpPos
        local ok2, dir = pcall(function() return delta.Unit end)
        if not ok2 or not dir then return end
        local normal = -dir
        local velocity = dir * 25

        pcall(function()
            _G.SafeFireServer(remote, "HitZombie", dracModel, hitPos, false, velocity, "Collision", normal)
        end)
    end

    -- ===== ESP helpers =====
    local function safeCreateHighlight(parent, adornee, fillColor, outlineColor, fillTransparency)
        if not ESP_HIGHLIGHT_SUPPORTED then return nil, "not_supported" end
        local ok, hl = pcall(function()
            local h = Instance.new("Highlight")
            -- Use stealth name for anti-detection
            h.Name = _G.getRandomInstanceName and _G.getRandomInstanceName() or ("HL_" .. math.random(10000, 99999))
            h.Adornee = adornee
            if fillColor then h.FillColor = fillColor end
            if outlineColor then h.OutlineColor = outlineColor end
            if fillTransparency then h.FillTransparency = fillTransparency end
            h.Parent = parent
            return h
        end)
        if not ok then
            ESP_HIGHLIGHT_SUPPORTED = false
            return nil, "create_failed"
        end
        return hl
    end

    local function safeCreateBillboard(parent, adornee)
        local ok, bb = pcall(function()
            local b = Instance.new("BillboardGui")
            -- Use stealth name for anti-detection
            b.Name = _G.getRandomInstanceName and _G.getRandomInstanceName() or ("BB_" .. math.random(10000, 99999))
            b.Adornee = adornee
            b.Size = UDim2.new(0, 200, 0, 40)
            b.StudsOffset = Vector3.new(0, 3, 0)
            b.AlwaysOnTop = true
            b.Parent = parent
            local txt = Instance.new("TextLabel")
            txt.Size = UDim2.new(1, 0, 1, 0)
            txt.BackgroundTransparency = 1
            txt.TextColor3 = Color3.new(1, 1, 1)
            txt.TextStrokeTransparency = 0
            txt.Font = Enum.Font.GothamBold
            txt.TextScaled = true
            txt.Parent = b
            return b, txt
        end)
        if not ok then return nil, nil, "create_failed" end
        return bb, bb:FindFirstChildOfClass("TextLabel")
    end

    -- update Dracula Highlight state
    local function updateDraculaESP()
        local drac = getDracula()
        if not DraculaEspEnabled or not drac then
            if draculaHighlight then
                pcall(function() draculaHighlight:Destroy() end)
                draculaHighlight = nil
            end
            return
        end

        if draculaHighlight then return end

        -- create highlight (use previously chosen parent)
        local parent = ESP_GUI_PARENT
        local hl, err = safeCreateHighlight(parent, drac, Color3.fromRGB(255,0,0), Color3.fromRGB(255,255,255), 0.6)
        if not hl then
            -- highlight creation failed — disable Dracula ESP to avoid spamming errors
            DraculaEspEnabled = false
            if DEBUG then warn("[Dracula] Highlight failed:", err) end
            return
        end
        draculaHighlight = hl
    end

    -- clear all silver visuals
    local function clearSilverESP()
        for model, data in pairs(silverVisuals) do
            pcall(function()
                if data.Highlight then data.Highlight:Destroy() end
                if data.Billboard then data.Billboard:Destroy() end
            end)
            silverVisuals[model] = nil
        end
    end

    -- update Silver ESP (robust: re-resolves folder, auto-assigns PrimaryPart, GUI parent fallback)
    local function updateSilverESP()
        local silverFolderNow = getSilverFolder()
        if not silverFolderNow then
            clearSilverESP()
            return
        end

        if not SilverEspEnabled then
            clearSilverESP()
            return
        end

        local hrp = LocalPlayer.Character and LocalPlayer.Character:FindFirstChild("HumanoidRootPart")
        local hrpPos = hrp and hrp.Position

        -- choose GUI parent dynamically in case CoreGui got blocked after script start
        local parent = ESP_GUI_PARENT
        if not parent or not parent.Parent then
            -- try fallback
            parent = LocalPlayer:FindFirstChild("PlayerGui") or parent
        end

        for _, trinket in ipairs(silverFolderNow:GetChildren()) do
            if not trinket:IsA("Model") then continue end

            -- ensure PrimaryPart exists (auto-assign first BasePart)
            if not trinket.PrimaryPart then
                local bp = trinket:FindFirstChildWhichIsA("BasePart")
                if bp then
                    pcall(function() trinket.PrimaryPart = bp end)
                else
                    -- can't display without a part
                    continue
                end
            end

            if not silverVisuals[trinket] then
                -- attempt to create highlight & billboard; if fails, disable Silver ESP
                local okHl, hl = pcall(function()
                    return safeCreateHighlight(parent, trinket, Color3.fromRGB(200,200,255), Color3.fromRGB(255,255,255), 0.5)
                end)
                if not okHl or not hl then
                    -- highlight not supported — try to fallback to only billboard
                    local okBB, bb, txt = pcall(function() return safeCreateBillboard(parent, trinket.PrimaryPart) end)
                    if okBB and bb and txt then
                        silverVisuals[trinket] = { Highlight = nil, Billboard = bb, Text = txt }
                    else
                        -- GUI creation failing; disable Silver ESP to avoid errors
                        SilverEspEnabled = false
                        clearSilverESP()
                        if DEBUG then warn("[SilverESP] Creation failed; disabling Silver ESP") end
                        return
                    end
                else
                    -- create billboard too
                    local bb, txt = safeCreateBillboard(parent, trinket.PrimaryPart)
                    silverVisuals[trinket] = { Highlight = hl, Billboard = bb, Text = txt }
                end
            end
        end

        -- update distances and cleanup removed trinkets
        for model, data in pairs(silverVisuals) do
            if not model.Parent or not model.PrimaryPart then
                pcall(function()
                    if data.Highlight then data.Highlight:Destroy() end
                    if data.Billboard then data.Billboard:Destroy() end
                end)
                silverVisuals[model] = nil
            else
                if hrpPos and data.Text then
                    local dist = (hrpPos - model.PrimaryPart.Position).Magnitude
                    data.Text.Text = string.format("Silver: %.1f", dist)
                end
            end
        end
    end

    -- background updater for Silver ESP (lightweight, deferred)
    task.defer(function()
        task.wait(6) -- Stagger start
        while true do
            task.wait(0.25) -- Reduced frequency
            if SilverEspEnabled then pcall(updateSilverESP) end
        end
    end)

    -- ===== Dracula attack loop (with loop-id cancellation) =====
    local currentDraculaLoopId = 0

    task.defer(function()
        task.wait(6.5) -- Stagger start
        while true do
            task.wait(DraculaLoopInterval)
            if not HitDraculaEnabled then
                -- keep ESP in sync
                pcall(updateDraculaESP)
                continue
            end

            -- new tick: increment loop id to cancel previous spawned tasks
            currentDraculaLoopId = currentDraculaLoopId + 1
            local loopId = currentDraculaLoopId

            local drac = getDracula()
            local hrp = LocalPlayer.Character and LocalPlayer.Character:FindFirstChild("HumanoidRootPart")
            if not (drac and hrp) then
                pcall(updateDraculaESP)
                continue
            end

            -- distance check (safe)
            local ok, pivot = pcall(function() return drac:GetPivot().Position end)
            if not ok or not pivot then
                pcall(updateDraculaESP)
                continue
            end
            local dist = (pivot - hrp.Position).Magnitude
            if dist > DraculaRange then
                pcall(updateDraculaESP)
                continue
            end

            -- ensure remotes are fresh
            if tick() - lastDraculaRemoteScan > 1 then ScanDraculaRemotes() end

            -- update ESP
            pcall(updateDraculaESP)

            -- 1) Swing spam: spawn cancellable tasks
            local spam = math.clamp(math.floor(DraculaSpamCount or 1), 1, 25)
            for remote in pairs(draculaRemotes) do
                if remote then
                    task.spawn(function()
                        for i = 1, spam do
                            if not HitDraculaEnabled or loopId ~= currentDraculaLoopId then break end
                            fireSwingRemote(remote)
                            task.wait(0.01)
                        end
                    end)
                    -- 2) Hit packets burst (also cancellable inside)
                    task.spawn(function()
                        for i = 1, 3 do
                            if not HitDraculaEnabled or loopId ~= currentDraculaLoopId then break end
                            fireHitAtDracula(remote, drac)
                            task.wait(DraculaHitSpacing)
                        end
                    end)
                end
            end
        end
    end)

    -- ===== UI =====
    local DraculaTab = (typeof(DraculaTab) ~= "nil" and DraculaTab) or Event1Section:Tab({ Title = "Dracula", Icon = "flame" })
    local HitSection = DraculaTab:Section({ Title = "Hit Dracula", Icon = "flame", Opened = false })

    HitSection:Toggle({
        Title = "Hit Dracula",
        Flag = "Dracula_1",
        Desc = "Automatically attack Dracula using any melee.",
        Default = HitDraculaEnabled,
        Callback = function(v)
            HitDraculaEnabled = v
            if not v then
                -- cancel any running tasks
                currentDraculaLoopId = currentDraculaLoopId + 1
            end
            WindUI:Notify({
                Title = "Dracula",
                Content = v and "Hit Dracula Enabled" or "Hit Dracula Disabled",
                Duration = 2,
                Icon = v and "flame" or "x",
            })
            pcall(updateDraculaESP)
        end
    })

    HitSection:Slider({
        Title = "Swing Spam Count",
        Flag = "Dracula_2",
        Desc = "Swings per tick (1–25).",
        Step = 1,
        Value = { Min = 1, Max = 25, Default = DraculaSpamCount },
        Callback = function(v) DraculaSpamCount = math.clamp(math.floor(v), 1, 25) end
    })

    HitSection:Slider({
        Title = "Dracula Range",
        Flag = "Dracula_3",
        Desc = "Attack distance (1–25 studs).",
        Step = 1,
        Value = { Min = 1, Max = 25, Default = DraculaRange },
        Callback = function(v) DraculaRange = math.clamp(v, 1, 25) end
    })

    local EspSection = DraculaTab:Section({ Title = "ESP", Icon = "eye", Opened = false })

    EspSection:Toggle({
        Title = "Dracula ESP",
        Flag = "Dracula_4",
        Desc = "Highlight Dracula.",
        Default = DraculaEspEnabled,
        Callback = function(v)
            DraculaEspEnabled = v
            if not v and draculaHighlight then
                pcall(function() draculaHighlight:Destroy() end)
                draculaHighlight = nil
            end
            WindUI:Notify({
                Title = "Dracula ESP",
                Content = v and "Enabled" or "Disabled",
                Duration = 2,
                Icon = v and "eye" or "x",
            })
            pcall(updateDraculaESP)
        end
    })

    EspSection:Toggle({
        Title = "Silver ESP",
        Flag = "Dracula_5",
        Desc = "Highlights Silver Trinkets + shows distance.",
        Default = SilverEspEnabled,
        Callback = function(v)
            -- If highlight/GUIs unsupported, we auto-disable and notify
            if v and not ESP_HIGHLIGHT_SUPPORTED then
                WindUI:Notify({
                    Title = "Silver ESP",
                    Content = "ESP features not supported by executor — disabled.",
                    Duration = 3,
                    Icon = "x",
                })
                SilverEspEnabled = false
                return
            end

            SilverEspEnabled = v
            if not v then clearSilverESP() end
            WindUI:Notify({
                Title = "Silver ESP",
                Content = v and "Enabled" or "Disabled",
                Duration = 2,
                Icon = v and "eye" or "x",
            })
        end
    })
end

task.wait(0.1) -- Delay to prevent lag
do -- // Players Tab
    local Players = game:GetService("Players")
    local RunService = game:GetService("RunService")
    local Workspace = game:GetService("Workspace")
    local LocalPlayer = Players.LocalPlayer

    local PlayersTab = Esp1Section:Tab({ Title = "Players", Icon = "users" })

    local PlayerESPSection = PlayersTab:Section({
        Title = "Player ESP",
        Icon = "user-check",
        Opened = false
    })

    -- flags (global for config save/load)
    ChamsESPEnabled = false
    BillboardESPEnabled = false
    NotifyLowHealthEnabled = false
    -- Use weak keys so entries for players who left are garbage collected
    local PlayerESPData = setmetatable({}, { __mode = "k" })

    -- New toggles for bars (default OFF) - global for config
    ShowHealthBarEnabled = false
    ShowInfectionBarEnabled = false

    -- Configuration variables - global for config
    ChamsFillTransparency = 0.45
    PerformanceModeEnabled = false
    BillboardShowDistance = 5 -- Slider value for "too close" fade
    NotifyGrabbedPinnedEnabled = false

    -- CONFIG (tweak to taste)
    local BILLBOARD_MAX_DISTANCE = 150 -- Roblox's native MaxDistance
    -- moved further down so the billboard sits clearly below the player
    local HEALTH_BILLBOARD_OFFSET = Vector3.new(0, -6.5, 0)
    local STUDS_SMOOTH_ALPHA = 0.22

    -- Make the whole billboard smaller per request
    local BILLBOARD_BASE_SIZE = Vector2.new(120, 52)
    local BILLBOARD_ENABLE_DISTANCE = 300 -- Max distance to render billboard
    local BILLBOARD_MIN_SCALE = 0.5
    local BILLBOARD_MAX_SCALE = 1.5
    
    -- Fade animation configuration
    local FADE_DISTANCE_BUFFER = 10 -- Studs for smooth fade transition

    local function RemovePlayerESP(player)
        local data = PlayerESPData[player]
        if not data then return end
        pcall(function()
            if data.Highlight then data.Highlight:Destroy() end
            if data.Billboard then data.Billboard:Destroy() end
        end)
        PlayerESPData[player] = nil
    end

    local function CreatePlayerESP(player)
        local char = player.Character
        if not char then return end
        local hum = char:FindFirstChildWhichIsA("Humanoid")
        if not hum then return end
        local head = char:FindFirstChild("Head")
        if not head then return end

        RemovePlayerESP(player)

        local highlight = nil
        if ChamsESPEnabled then
            highlight = Instance.new("Highlight")
            -- Use stealth name for anti-detection
            highlight.Name = _G.getRandomInstanceName and _G.getRandomInstanceName() or ("HL_" .. math.random(10000, 99999))
            highlight.Adornee = char
            highlight.FillColor = Color3.fromRGB(0, 255, 0)
            highlight.FillTransparency = ChamsFillTransparency
            highlight.OutlineColor = Color3.fromRGB(255, 255, 255)
            highlight.OutlineTransparency = 0
            highlight.Parent = char
        end

        local billboard = nil
        local espFrame = nil -- Declare outside to ensure it's in scope
        local nameLabel = nil
        local distanceLabel = nil
        local statusBg = nil
        local statusLabel = nil
        
        if BillboardESPEnabled then
            billboard = Instance.new("BillboardGui")
            -- Use stealth name for anti-detection
            billboard.Name = _G.getRandomInstanceName and _G.getRandomInstanceName() or ("BB_" .. math.random(10000, 99999))
            billboard.Adornee = head
            billboard.Size = UDim2.new(0, BILLBOARD_BASE_SIZE.X, 0, BILLBOARD_BASE_SIZE.Y)
            billboard.StudsOffset = HEALTH_BILLBOARD_OFFSET
            billboard.AlwaysOnTop = true
            billboard.LightInfluence = 0
            billboard.MaxDistance = BILLBOARD_MAX_DISTANCE
            billboard.Parent = char

            espFrame = Instance.new("Frame")
            -- Use randomized name for anti-detection
            espFrame.Name = "Frame_" .. math.random(10000, 99999)
            espFrame.Size = UDim2.new(1, 0, 1, 0)
            espFrame.BackgroundColor3 = Color3.fromRGB(0, 0, 0)
            espFrame.BackgroundTransparency = PerformanceModeEnabled and 1 or 0.6
            espFrame.BorderSizePixel = 0
            espFrame.Parent = billboard

            local uiCorner = Instance.new("UICorner")
            uiCorner.CornerRadius = UDim.new(0, 8)
            uiCorner.Parent = espFrame

            -- Status background (semi-transparent rounded box) - used for center MERCY or full-cover grabbed
            statusBg = Instance.new("Frame")
            -- Use randomized name
            statusBg.Name = "Frame_" .. math.random(10000, 99999)
            statusBg.Size = UDim2.new(0.9, 0, 0.36, 0)
            statusBg.Position = UDim2.new(0.05, 0, 0.32, 0) -- centered vertically by default
            statusBg.BackgroundColor3 = Color3.fromRGB(0, 0, 0)
            statusBg.BorderSizePixel = 0
            statusBg.BackgroundTransparency = 0.45
            statusBg.Visible = false
            statusBg.Parent = espFrame

            local statusBgCorner = Instance.new("UICorner")
            statusBgCorner.CornerRadius = UDim.new(0, 8)
            statusBgCorner.Parent = statusBg

            -- Status label (centered inside statusBg)
            statusLabel = Instance.new("TextLabel")
            statusLabel.Name = "Status"
            statusLabel.Text = ""
            statusLabel.Size = UDim2.new(1, -8, 1, 0)
            statusLabel.Position = UDim2.new(0, 4, 0, 0)
            statusLabel.BackgroundTransparency = 1
            statusLabel.TextColor3 = Color3.fromRGB(255, 255, 255)
            statusLabel.TextStrokeTransparency = 0.3
            statusLabel.TextStrokeColor3 = Color3.fromRGB(0, 0, 0)
            statusLabel.TextSize = 16
            statusLabel.Font = Enum.Font.SourceSansBold
            statusLabel.TextWrapped = true
            statusLabel.TextXAlignment = Enum.TextXAlignment.Center
            statusLabel.TextYAlignment = Enum.TextYAlignment.Center
            statusLabel.Visible = false
            statusLabel.Parent = statusBg

            -- Name label (small, above the bars)
            nameLabel = Instance.new("TextLabel")
            nameLabel.Name = "Name"
            nameLabel.Text = player.Name
            nameLabel.Size = UDim2.new(1, 0, 0.14, 0)
            nameLabel.Position = UDim2.new(0, 0, 0.12, 0)
            nameLabel.BackgroundTransparency = 1
            nameLabel.TextColor3 = Color3.fromRGB(255, 255, 255)
            nameLabel.TextStrokeTransparency = 0.5
            nameLabel.TextStrokeColor3 = Color3.fromRGB(0, 0, 0)
            nameLabel.TextSize = 14
            nameLabel.Font = Enum.Font.SourceSansBold
            nameLabel.TextWrapped = true
            nameLabel.TextXAlignment = Enum.TextXAlignment.Center
            nameLabel.Parent = espFrame

            -- Health BAR (outer frame + inner fill + centered label)
            local healthOuter = Instance.new("Frame")
            healthOuter.Name = "HealthOuter"
            healthOuter.Size = UDim2.new(0.9, 0, 0.16, 0) -- relative to billboard
            healthOuter.Position = UDim2.new(0.05, 0, 0.40, 0)
            healthOuter.BackgroundColor3 = Color3.fromRGB(30, 30, 30)
            healthOuter.BorderSizePixel = 0
            healthOuter.Parent = espFrame

            local healthOuterCorner = Instance.new("UICorner")
            healthOuterCorner.CornerRadius = UDim.new(0, 6)
            healthOuterCorner.Parent = healthOuter

            local healthInner = Instance.new("Frame")
            healthInner.Name = "HealthInner"
            healthInner.Size = UDim2.new(0, 0, 1, 0) -- will be set per-health percent
            healthInner.Position = UDim2.new(0, 0, 0, 0)
            healthInner.BorderSizePixel = 0
            healthInner.BackgroundColor3 = Color3.fromRGB(0, 255, 0)
            healthInner.Parent = healthOuter

            local healthInnerCorner = Instance.new("UICorner")
            healthInnerCorner.CornerRadius = UDim.new(0, 6)
            healthInnerCorner.Parent = healthInner

            local healthLabelInside = Instance.new("TextLabel")
            healthLabelInside.Name = "HealthLabelInside"
            healthLabelInside.Text = "100/100"
            healthLabelInside.Size = UDim2.new(1, 0, 1, 0)
            healthLabelInside.Position = UDim2.new(0, 0, 0, 0)
            healthLabelInside.BackgroundTransparency = 1
            healthLabelInside.TextColor3 = Color3.fromRGB(255, 255, 255)
            healthLabelInside.TextStrokeTransparency = 0.6
            healthLabelInside.TextStrokeColor3 = Color3.fromRGB(0, 0, 0)
            healthLabelInside.TextSize = 12
            healthLabelInside.Font = Enum.Font.SourceSansBold
            healthLabelInside.TextWrapped = false
            healthLabelInside.TextXAlignment = Enum.TextXAlignment.Center
            healthLabelInside.TextYAlignment = Enum.TextYAlignment.Center
            healthLabelInside.Parent = healthOuter

            -- Infection BAR (outer + inner + label)
            local infectOuter = Instance.new("Frame")
            infectOuter.Name = "InfectOuter"
            infectOuter.Size = UDim2.new(0.9, 0, 0.16, 0)
            infectOuter.Position = UDim2.new(0.05, 0, 0.60, 0)
            infectOuter.BackgroundColor3 = Color3.fromRGB(30, 30, 30)
            infectOuter.BorderSizePixel = 0
            infectOuter.Parent = espFrame

            local infectOuterCorner = Instance.new("UICorner")
            infectOuterCorner.CornerRadius = UDim.new(0, 6)
            infectOuterCorner.Parent = infectOuter

            local infectInner = Instance.new("Frame")
            infectInner.Name = "InfectInner"
            infectInner.Size = UDim2.new(0, 0, 1, 0) -- will be set by infection percent
            infectInner.Position = UDim2.new(0, 0, 0, 0)
            infectInner.BorderSizePixel = 0
            infectInner.BackgroundColor3 = Color3.fromRGB(0, 255, 0)
            infectInner.Parent = infectOuter

            local infectInnerCorner = Instance.new("UICorner")
            infectInnerCorner.CornerRadius = UDim.new(0, 6)
            infectInnerCorner.Parent = infectInner

            local infectLabelInside = Instance.new("TextLabel")
            infectLabelInside.Name = "InfectLabelInside"
            infectLabelInside.Text = "0/100"
            infectLabelInside.Size = UDim2.new(1, 0, 1, 0)
            infectLabelInside.Position = UDim2.new(0, 0, 0, 0)
            infectLabelInside.BackgroundTransparency = 1
            infectLabelInside.TextColor3 = Color3.fromRGB(255, 255, 255)
            infectLabelInside.TextStrokeTransparency = 0.6
            infectLabelInside.TextStrokeColor3 = Color3.fromRGB(0, 0, 0)
            infectLabelInside.TextSize = 12
            infectLabelInside.Font = Enum.Font.SourceSansBold
            infectLabelInside.TextWrapped = false
            infectLabelInside.TextXAlignment = Enum.TextXAlignment.Center
            infectLabelInside.TextYAlignment = Enum.TextYAlignment.Center
            infectLabelInside.Parent = infectOuter

            -- Distance label (moved down a bit)
            distanceLabel = Instance.new("TextLabel")
            distanceLabel.Name = "Distance"
            distanceLabel.Text = "0 studs"
            distanceLabel.Size = UDim2.new(1, 0, 0.12, 0)
            distanceLabel.Position = UDim2.new(0, 0, 0.86, 0)
            distanceLabel.BackgroundTransparency = 1
            distanceLabel.TextColor3 = Color3.fromRGB(255, 255, 255)
            distanceLabel.TextStrokeTransparency = 0.5
            distanceLabel.TextStrokeColor3 = Color3.fromRGB(0, 0, 0)
            distanceLabel.TextSize = 12
            distanceLabel.Font = Enum.Font.SourceSans
            distanceLabel.TextWrapped = true
            distanceLabel.TextXAlignment = Enum.TextXAlignment.Center
            distanceLabel.Parent = espFrame

            -- Parent other objects to allow easy retrieval
        end

        PlayerESPData[player] = {
            Char = char,
            Humanoid = hum,
            Head = head,
            Highlight = highlight,
            Billboard = billboard,
            ESPFrame = espFrame,
            NameLabel = nameLabel,
            -- bars & labels (may be nil if billboard disabled)
            HealthOuter = espFrame and espFrame:FindFirstChild("HealthOuter") or nil,
            HealthInner = espFrame and espFrame:FindFirstChild("HealthOuter") and espFrame.HealthOuter:FindFirstChild("HealthInner") or nil,
            HealthLabelInside = espFrame and espFrame:FindFirstChild("HealthOuter") and espFrame.HealthOuter:FindFirstChild("HealthLabelInside") or nil,
            InfectOuter = espFrame and espFrame:FindFirstChild("InfectOuter") or nil,
            InfectInner = espFrame and espFrame:FindFirstChild("InfectOuter") and espFrame.InfectOuter:FindFirstChild("InfectInner") or nil,
            InfectLabelInside = espFrame and espFrame:FindFirstChild("InfectOuter") and espFrame.InfectOuter:FindFirstChild("InfectLabelInside") or nil,
            DistanceLabel = distanceLabel,
            StatusBg = espFrame and espFrame:FindFirstChild("StatusBg") or nil,
            StatusLabel = espFrame and espFrame:FindFirstChild("StatusBg") and espFrame.StatusBg:FindFirstChild("Status") or nil,
            NotifState = nil,
            LastNotify = 0,
            CurrentStudsOffset = HEALTH_BILLBOARD_OFFSET,
            DesiredStudsOffset = HEALTH_BILLBOARD_OFFSET
        }
        
        -- PROTECT Player ESP visuals from anti-cheat detection
        pcall(function()
            if _G.protectESP then
                if highlight then _G.protectESP(highlight) end
                if billboard then _G.protectESP(billboard) end
            end
        end)

        -- ensure initial visibility respects settings
        if PlayerESPData[player].HealthOuter then
            PlayerESPData[player].HealthOuter.Visible = ShowHealthBarEnabled and BillboardESPEnabled
        end
        if PlayerESPData[player].InfectOuter then
            PlayerESPData[player].InfectOuter.Visible = ShowInfectionBarEnabled and BillboardESPEnabled
        end
    end

    local function UpdateESPLoop()
        if not (ChamsESPEnabled or BillboardESPEnabled) then return end
        local localChar = LocalPlayer and LocalPlayer.Character
        local localRoot = localChar and localChar:FindFirstChild("HumanoidRootPart")
        local camera = Workspace.CurrentCamera
        if not camera then return end

        for _, player in ipairs(Players:GetPlayers()) do
            if player ~= LocalPlayer then
                local data = PlayerESPData[player]
                local char = player.Character
                if not char or not char.Parent then
                    if data then RemovePlayerESP(player) end
                    continue
                end
                
                -- Re-create ESP if character changed or components missing
                if not data or data.Char ~= char then
                    CreatePlayerESP(player)
                    data = PlayerESPData[player]
                    if not data then continue end
                end

                if ChamsESPEnabled and (not data.Highlight or not data.Highlight.Parent) then
                    CreatePlayerESP(player)
                    data = PlayerESPData[player]
                    if not data then continue end
                end

                if BillboardESPEnabled and (not data.Billboard or not data.Billboard.Parent) then
                    CreatePlayerESP(player)
                    data = PlayerESPData[player]
                    if not data then continue end
                end

                local hum = data.Humanoid
                if not hum then continue end
                local health = hum.Health
                local max = hum.MaxHealth > 0 and hum.MaxHealth or 1
                local percent = math.clamp(health / max, 0, 1)

                -- Check grabbed/pinned/infected
                local grabbed = false
                local pinned = false
                local infectionLevel = 0
                local wPlayers = Workspace:FindFirstChild("Players")
                if wPlayers then
                    local playerFolder = wPlayers:FindFirstChild(player.Name)
                    if playerFolder then
                        local userStates = playerFolder:FindFirstChild("UserStates")
                        if userStates then
                            local grabbedVal = userStates:FindFirstChild("Grabbed")
                            grabbed = (grabbedVal and tonumber(grabbedVal.Value) or 0) ~= 0
                            local pinVal = userStates:FindFirstChild("Pin")
                            pinned = tostring(pinVal and pinVal.Value or "None") ~= "None"
                            local infectedVal = userStates:FindFirstChild("Infected")
                            infectionLevel = infectedVal and tonumber(infectedVal.Value) or 0
                        end
                    end
                end

                -- distance calculation
                local playerRoot = char:FindFirstChild("HumanoidRootPart")
                local dist = nil
                if localRoot and playerRoot then
                    dist = (localRoot.Position - playerRoot.Position).Magnitude
                end

                -- CRITICAL FIX: Proper distance-based fade logic
                local fadeFactor = 1 -- 1 = fully visible, 0 = fully transparent
                local shouldRender = true

                if dist then
                    -- Disable if beyond max render distance
                    if dist >= BILLBOARD_ENABLE_DISTANCE then
                        shouldRender = false
                    end
                    
                    -- Apply fade effect if within "too close" range (slider)
                    if BillboardShowDistance > 0 and dist < BillboardShowDistance then
                        local fadeStart = math.max(BillboardShowDistance - FADE_DISTANCE_BUFFER, 0)
                        
                        if dist <= fadeStart then
                            fadeFactor = 0 -- Fully faded/transparent
                        else
                            -- Smooth fade from 0 to 1
                            fadeFactor = math.clamp((dist - fadeStart) / (BillboardShowDistance - fadeStart), 0, 1)
                        end
                    end
                end

                ----------------------------------------------------------------
                -- Background vs Bars transparency
                ----------------------------------------------------------------

                -- Determine base transparency just for the main background frame
                local frameTransparency
                do
                    local isGrabbedPinned = grabbed or pinned
                    local shouldBeRed = isGrabbedPinned or infectionLevel >= 70
                    -- if PerformanceModeEnabled => hide only the background frame
                    local baseTransparency = PerformanceModeEnabled and 1 or (shouldBeRed and 0.4 or 0.6)
                    frameTransparency = baseTransparency + (1 - fadeFactor) * 0.5
                end

                -- Apply transparency ONLY to the main background + status box
                if data.ESPFrame then
                    data.ESPFrame.BackgroundTransparency = frameTransparency
                end

                if data.StatusBg then
                    -- status box can stay a bit more solid than the frame
                    data.StatusBg.BackgroundTransparency = math.clamp(
                        (PerformanceModeEnabled and 0.7 or 0.45) + (1 - fadeFactor) * 0.3,
                        0, 1
                    )
                end

                -- === Bars have their own transparency, independent from PerformanceModeEnabled ===
                -- Health bar
                if data.HealthOuter then
                    local healthOuterBase = 0.3         -- solid-ish background for the bar
                    local healthOuterTransp = healthOuterBase + (1 - fadeFactor) * 0.4
                    data.HealthOuter.BackgroundTransparency = math.clamp(healthOuterTransp, 0, 1)
                end
                if data.HealthInner then
                    local healthInnerBase = 0           -- keep fill solid, only a little fade
                    local healthInnerTransp = healthInnerBase + (1 - fadeFactor) * 0.25
                    data.HealthInner.BackgroundTransparency = math.clamp(healthInnerTransp, 0, 1)
                end
                if data.HealthLabelInside then
                    data.HealthLabelInside.TextTransparency = 1 - fadeFactor
                end

                -- Infection bar
                if data.InfectOuter then
                    local infectOuterBase = 0.3
                    local infectOuterTransp = infectOuterBase + (1 - fadeFactor) * 0.4
                    data.InfectOuter.BackgroundTransparency = math.clamp(infectOuterTransp, 0, 1)
                end
                if data.InfectInner then
                    local infectInnerBase = 0
                    local infectInnerTransp = infectInnerBase + (1 - fadeFactor) * 0.25
                    data.InfectInner.BackgroundTransparency = math.clamp(infectInnerTransp, 0, 1)
                end
                if data.InfectLabelInside then
                    data.InfectLabelInside.TextTransparency = 1 - fadeFactor
                end

                ----------------------------------------------------------------
                -- Enhanced grabbed/pinned visuals when monitor is enabled + mercy
                ----------------------------------------------------------------

                local isGrabbedPinned = grabbed or pinned
                local isMercy = infectionLevel >= 100

                -- If infection reached 100 -> show MERCY (centered; infection bar remains visible)
                if isMercy and data.StatusLabel then
                    -- position the status box centered (smaller, so infection bar shows)
                    if data.StatusBg then
                        data.StatusBg.Size = UDim2.new(0.9, 0, 0.36, 0)
                        data.StatusBg.Position = UDim2.new(0.05, 0, 0.30, 0)
                        data.StatusBg.Visible = true
                        -- purple-ish background for mercy
                        local pulse = math.sin(tick() * 6)
                        if pulse > 0 then
                            data.StatusBg.BackgroundColor3 = Color3.fromRGB(120, 0, 120)
                        else
                            data.StatusBg.BackgroundColor3 = Color3.fromRGB(80, 0, 80)
                        end
                    end

                    data.StatusLabel.Text = "MERCY"
                    data.StatusLabel.Visible = true
                    data.StatusLabel.TextSize = 16

                    -- hide name and health bar, but DO NOT hide infection bar
                    if data.NameLabel then data.NameLabel.Visible = false end
                    if data.HealthOuter then data.HealthOuter.Visible = false end
                    if data.InfectOuter then data.InfectOuter.Visible = ShowInfectionBarEnabled end
                    if data.DistanceLabel then data.DistanceLabel.Visible = true end

                    -- ensure health inner is reset
                    if data.HealthInner then data.HealthInner.Size = UDim2.new(0,0,1,0) end
                    -- set infection inner to full or according to infectionLevel
                    if data.InfectInner then
                        local infectPercent = math.clamp(infectionLevel / 100, 0, 1)
                        data.InfectInner.Size = UDim2.new(infectPercent, 0, 1, 0)
                    end

                    -- change chams color to purple pulse when mercy
                    if ChamsESPEnabled and data.Highlight then
                        local pulse = math.sin(tick() * 6)
                        if pulse > 0 then
                            data.Highlight.FillColor = Color3.fromRGB(180, 0, 180)
                        else
                            data.Highlight.FillColor = Color3.fromRGB(110, 0, 110)
                        end
                        data.Highlight.FillTransparency = math.clamp(
                            ChamsFillTransparency + 0.2 * math.abs(math.sin(tick() * 8)),
                            0, 1
                        )
                        data.Highlight.OutlineColor = Color3.fromRGB(255, 200, 255)
                    end

                elseif NotifyGrabbedPinnedEnabled and isGrabbedPinned then
                    -- grabbed/pinned: full-cover status (hide both bars)
                    if data.StatusBg then
                        data.StatusBg.Size = UDim2.new(1, 0, 1, 0)
                        data.StatusBg.Position = UDim2.new(0, 0, 0, 0)
                        data.StatusBg.Visible = true
                        -- red pulsing background for grabbed/pinned
                        local pulse = math.sin(tick() * 10)
                        if pulse > 0 then
                            data.StatusBg.BackgroundColor3 = Color3.fromRGB(200, 30, 30)
                        else
                            data.StatusBg.BackgroundColor3 = Color3.fromRGB(120, 10, 10)
                        end
                    end

                    if data.StatusLabel then
                        data.StatusLabel.Text = grabbed and "GRABBED!" or "PINNED!"
                        data.StatusLabel.Visible = true
                        data.StatusLabel.TextSize = 18
                    end

                    if data.NameLabel then data.NameLabel.Visible = false end
                    if data.HealthOuter then data.HealthOuter.Visible = false end
                    if data.InfectOuter then data.InfectOuter.Visible = false end
                    if data.DistanceLabel then data.DistanceLabel.Visible = false end

                    -- ensure inner fills are reset
                    if data.HealthInner then data.HealthInner.Size = UDim2.new(0,0,1,0) end
                    if data.InfectInner then data.InfectInner.Size = UDim2.new(0,0,1,0) end

                    -- Change chams color to flashing red
                    if ChamsESPEnabled and data.Highlight then
                        local pulse = math.sin(tick() * 10)
                        data.Highlight.FillColor = pulse > 0 and Color3.fromRGB(255, 0, 0) or Color3.fromRGB(200, 0, 0)
                        data.Highlight.FillTransparency = math.clamp(
                            ChamsFillTransparency + 0.2 * math.abs(math.sin(tick() * 8)),
                            0, 1
                        )
                        data.Highlight.OutlineColor = Color3.fromRGB(255, 100, 100)
                    end
                else
                    -- Restore normal view
                    if data.StatusBg then data.StatusBg.Visible = false end
                    if data.StatusLabel then data.StatusLabel.Visible = false end
                    if data.NameLabel then data.NameLabel.Visible = true end
                    if data.HealthOuter then data.HealthOuter.Visible = ShowHealthBarEnabled end
                    if data.InfectOuter then data.InfectOuter.Visible = ShowInfectionBarEnabled end
                    if data.DistanceLabel then data.DistanceLabel.Visible = true end
                    
                    -- Restore background color (actual visibility controlled by BackgroundTransparency)
                    if data.ESPFrame then
                        data.ESPFrame.BackgroundColor3 = Color3.fromRGB(0, 0, 0)
                    end

                    -- Restore normal chams
                    if ChamsESPEnabled and data.Highlight then
                        local r = math.floor(255 * (1 - percent))
                        local g = math.floor(255 * percent)
                        data.Highlight.FillColor = Color3.fromRGB(r, g, 0)
                        data.Highlight.FillTransparency = ChamsFillTransparency
                        data.Highlight.OutlineColor = Color3.fromRGB(255, 255, 255)
                    end
                end  -- ✅ this is the missing one (closes isMercy / elseif / else)

                -- Billboard updates
                if BillboardESPEnabled and data.Billboard then
                    -- Set enabled based on render distance only
                    data.Billboard.Enabled = shouldRender
                    
                    if shouldRender then
                        -- Scale calculation with improved text sizing
                        local scale = 1
                        if dist and dist < BILLBOARD_ENABLE_DISTANCE then
                            scale = math.clamp(30 / math.max(dist, 1), BILLBOARD_MIN_SCALE, BILLBOARD_MAX_SCALE)
                        end

                        -- Apply size with scale
                        local w = math.floor(BILLBOARD_BASE_SIZE.X * scale)
                        local h = math.floor(BILLBOARD_BASE_SIZE.Y * scale)
                        data.Billboard.Size = UDim2.new(0, w, 0, h)

                        -- Better text scaling that scales ALL elements proportionally
                        local baseTextSize = math.floor(12 * scale)
                        local nameTextSize = math.floor(14 * scale)
                        local statusSize = math.floor(16 * scale)
                        local minSize = 8
                        
                        if data.StatusLabel and data.StatusLabel.Visible then
                            data.StatusLabel.TextSize = math.max(statusSize, minSize)
                        end
                        if data.NameLabel then
                            data.NameLabel.TextSize = math.max(nameTextSize, minSize)
                        end
                        if data.DistanceLabel then
                            data.DistanceLabel.TextSize = math.max(baseTextSize, minSize)
                        end

                        -- Update text values
                        if data.NameLabel then
                            data.NameLabel.Text = player.Name
                            -- apply fade to name text too
                            data.NameLabel.TextTransparency = 1 - fadeFactor
                            data.NameLabel.TextStrokeTransparency = 0.5 + (1 - fadeFactor) * 0.5
                        end

                        -- Health bar update (hide when grabbed/pinned or mercy)
                        if data.HealthOuter and data.HealthInner and ShowHealthBarEnabled and (not isGrabbedPinned) and (not isMercy) then
                            -- compute percent from hum values
                            local healthPercent = percent -- already computed earlier as health/max
                            -- Set inner fill width (use UDim2 scale)
                            data.HealthInner.Size = UDim2.new(healthPercent, 0, 1, 0)
                            -- Color gradient (green->red)
                            local healthR = math.floor(255 * (1 - healthPercent))
                            local healthG = math.floor(255 * healthPercent)
                            data.HealthInner.BackgroundColor3 = Color3.fromRGB(healthR, healthG, 0)
                            -- Update label text
                            if data.HealthLabelInside then
                                data.HealthLabelInside.Text = math.floor(health) .. "/" .. math.floor(max)
                                data.HealthLabelInside.TextSize = math.max(baseTextSize - 2, 8)
                                data.HealthLabelInside.TextTransparency = 1 - fadeFactor
                            end
                            data.HealthOuter.Visible = true
                        elseif data.HealthOuter then
                            data.HealthOuter.Visible = false
                            if data.HealthInner then data.HealthInner.Size = UDim2.new(0,0,1,0) end
                        end

                        -- Infection bar update (hide only when grabbed/pinned; show during mercy)
                        if data.InfectOuter and data.InfectInner and ShowInfectionBarEnabled and (not isGrabbedPinned) then
                            local infectPercent = math.clamp((infectionLevel or 0) / 100, 0, 1)
                            data.InfectInner.Size = UDim2.new(infectPercent, 0, 1, 0)
                            local infectR = math.floor(255 * infectPercent)
                            local infectG = math.floor(255 * (1 - infectPercent))
                            data.InfectInner.BackgroundColor3 = Color3.fromRGB(infectR, infectG, 0)
                            if data.InfectLabelInside then
                                data.InfectLabelInside.Text = math.floor(infectionLevel) .. "/100"
                                data.InfectLabelInside.TextSize = math.max(baseTextSize - 2, 8)
                                data.InfectLabelInside.TextTransparency = 1 - fadeFactor
                            end
                            data.InfectOuter.Visible = true
                        elseif data.InfectOuter then
                            data.InfectOuter.Visible = false
                            if data.InfectInner then data.InfectInner.Size = UDim2.new(0,0,1,0) end
                        end

                        if data.DistanceLabel and data.DistanceLabel.Visible then
                            data.DistanceLabel.Text = math.floor(dist or 0) .. " studs"
                            data.DistanceLabel.TextTransparency = 1 - fadeFactor
                            data.DistanceLabel.TextStrokeTransparency = 0.5 + (1 - fadeFactor) * 0.5
                        end
                    end

                    -- Apply fade to status label as well
                    if data.StatusLabel and data.StatusLabel.Visible then
                        data.StatusLabel.TextTransparency = 1 - fadeFactor
                        data.StatusLabel.TextStrokeTransparency = 0.5 + (1 - fadeFactor) * 0.5
                    end

                    -- Studs offset smoothing (we move below the head)
                    data.DesiredStudsOffset = grabbed and Vector3.new(0, -2, 0) or HEALTH_BILLBOARD_OFFSET
                    data.CurrentStudsOffset = data.CurrentStudsOffset:Lerp(data.DesiredStudsOffset, STUDS_SMOOTH_ALPHA)
                    data.Billboard.StudsOffset = data.CurrentStudsOffset
                end

                -- Low health notifications
                if NotifyLowHealthEnabled then
                    if health <= 0 then
                        if data.NotifState ~= "dead" then
                            data.NotifState = "dead"
                            WindUI:Notify({
                                Title = "Player Died",
                                Content = player.Name .. " has Died!",
                                Duration = 3,
                                Icon = "skull",
                            })
                        end
                    elseif percent < 0.25 then
                        if data.NotifState ~= "dying" and tick() - data.LastNotify > 3 then
                            data.NotifState = "dying"
                            data.LastNotify = tick()
                            WindUI:Notify({
                                Title = "Player Dying",
                                Content = player.Name .. " is Dying!",
                                Duration = 3,
                                Icon = "heart",
                            })
                        end
                    elseif percent < 0.45 then
                        if data.NotifState ~= "low" and tick() - data.LastNotify > 3 then
                            data.NotifState = "low"
                            data.LastNotify = tick()
                            WindUI:Notify({
                                Title = "Player Low Health",
                                Content = player.Name .. " has Low Health!",
                                Duration = 3,
                                Icon = "activity",
                            })
                        end
                    else
                        data.NotifState = nil
                    end
                end
            end
        end
    end

    -- PERFORMANCE: Throttle Player ESP updates
    local playerESPLastUpdate = 0
    local PLAYER_ESP_UPDATE_INTERVAL = 0.15 -- Update every 0.15 seconds
    
    task.defer(function()
        task.wait(1) -- Stagger start
        RunService.Heartbeat:Connect(function()
            -- PERFORMANCE: Throttle updates
            local now = tick()
            if now - playerESPLastUpdate < PLAYER_ESP_UPDATE_INTERVAL then return end
            playerESPLastUpdate = now
            
            UpdateESPLoop()
        end)
    end)

    Players.PlayerRemoving:Connect(RemovePlayerESP)
    Players.PlayerAdded:Connect(function(p)
        task.wait(0.4)
        if ChamsESPEnabled or BillboardESPEnabled then 
            task.wait()
            CreatePlayerESP(p) 
        end
    end)

    PlayerESPSection:Toggle({
        Title = "Players Chams ESP",
        Flag = "Players_1",
        Desc = "Show Chams ESP on Players",
        Default = false,
        Callback = function(state)
            ChamsESPEnabled = state
            if state then
                for _, pl in ipairs(Players:GetPlayers()) do
                    if pl ~= LocalPlayer then
                        task.wait()
                        CreatePlayerESP(pl)
                    end
                end
                WindUI:Notify({
                    Title = "Player ESP",
                    Content = "Player Chams ESP enabled",
                    Duration = 2,
                    Icon = "eye",
                })
            else
                for p in pairs(PlayerESPData) do
                    local data = PlayerESPData[p]
                    if data and data.Highlight then 
                        data.Highlight:Destroy() 
                        data.Highlight = nil
                    end
                end
                WindUI:Notify({
                    Title = "Player ESP",
                    Content = "Player Chams ESP disabled",
                    Duration = 2,
                    Icon = "eye-off",
                })
            end
        end
    })

    PlayerESPSection:Toggle({
        Title = "Players Billboard ESP",
        Flag = "Players_2",
        Desc = "Show Billboard Text On Players",
        Default = false,
        Callback = function(state)
            BillboardESPEnabled = state
            if state then
                for _, pl in ipairs(Players:GetPlayers()) do
                    if pl ~= LocalPlayer then
                        task.wait()
                        CreatePlayerESP(pl)
                    end
                end
                -- ensure bars respect current settings
                for _, data in pairs(PlayerESPData) do
                    if data and data.HealthOuter then
                        data.HealthOuter.Visible = ShowHealthBarEnabled and data.Billboard and data.Billboard.Enabled
                    end
                    if data and data.InfectOuter then
                        data.InfectOuter.Visible = ShowInfectionBarEnabled and data.Billboard and data.Billboard.Enabled
                    end
                end
                WindUI:Notify({
                    Title = "Player ESP",
                    Content = "Player Billboard ESP enabled",
                    Duration = 2,
                    Icon = "eye",
                })
            else
                for p in pairs(PlayerESPData) do
                    local data = PlayerESPData[p]
                    if data and data.Billboard then 
                        data.Billboard:Destroy() 
                        data.Billboard = nil
                        data.NameLabel = nil
                        -- destroy bar refs if present
                        if data.HealthOuter then 
                            pcall(function() data.HealthOuter:Destroy() end)
                        end
                        if data.InfectOuter then 
                            pcall(function() data.InfectOuter:Destroy() end)
                        end
                        data.HealthOuter = nil
                        data.HealthInner = nil
                        data.HealthLabelInside = nil
                        data.InfectOuter = nil
                        data.InfectInner = nil
                        data.InfectLabelInside = nil
                        data.DistanceLabel = nil
                        data.StatusLabel = nil
                        data.ESPFrame = nil
                    end
                end
                WindUI:Notify({
                    Title = "Player ESP",
                    Content = "Player Billboard ESP disabled",
                    Duration = 2,
                    Icon = "eye-off",
                })
            end
        end
    })

    -- Settings section (renamed from Grabbed & Pinned)
    local SettingsSection = PlayersTab:Section({
        Title = "Settings",
        Icon = "settings",
        Opened = false
    })

    SettingsSection:Toggle({
        Title = "Notify Grabbed and Pinned Players",
        Flag = "Players_4",
        Desc = "Notifies when a player is grabbed or pinned, and shows in chams and billboard.",
        Default = false,
        Callback = function(state)
            NotifyGrabbedPinnedEnabled = state
            WindUI:Notify({
                Title = "Grabbed/Pinned Monitor",
                Content = "Grabbed/Pinned monitor " .. (state and "ON" or "OFF"),
                Duration = 2,
                Icon = state and "eye" or "eye-off",
            })
        end
    })

    SettingsSection:Toggle({
        Title = "Show Health Bar",
        Flag = "Players_ShowHealthBar",
        Desc = "Shows Health Bar On BillBoard",
        Default = false,
        Callback = function(state)
            ShowHealthBarEnabled = state
            WindUI:Notify({
                Title = "Health Bar",
                Content = state and "Health bar ON" or "Health bar OFF",
                Duration = 2,
                Icon = state and "heart" or "heart-off",
            })
            -- update existing billboards immediately
            for _, data in pairs(PlayerESPData) do
                if data and data.HealthOuter then
                    data.HealthOuter.Visible = state and data.Billboard and data.Billboard.Enabled and (not data.StatusLabel or not data.StatusLabel.Visible)
                end
            end
        end
    })

    SettingsSection:Toggle({
        Title = "Show Infection Bar",
        Flag = "Players_ShowInfectionBar",
        Desc = "Shows Infection Bar In BillBoard",
        Default = false,
        Callback = function(state)
            ShowInfectionBarEnabled = state
            WindUI:Notify({
                Title = "Infection Bar",
                Content = state and "Infection bar ON" or "Infection bar OFF",
                Duration = 2,
                Icon = state and "thermometer" or "thermometer-off",
            })
            for _, data in pairs(PlayerESPData) do
                if data and data.InfectOuter then
                    data.InfectOuter.Visible = state and data.Billboard and data.Billboard.Enabled and (not data.StatusLabel or not data.StatusLabel.Visible)
                end
            end
        end
    })

    SettingsSection:Toggle({
        Title = "Notify Low Health Players",
        Flag = "Players_3",
        Desc = "Notify when players reach Low / Dying health",
        Default = false,
        Callback = function(state)
            NotifyLowHealthEnabled = state
            WindUI:Notify({
                Title = "Low Health Notify",
                Content = state and "Low health notifications ON" or "Low health notifications OFF",
                Duration = 2,
                Icon = state and "bell" or "bell-off",
            })
        end
    })

    -- Performance Mode Toggle
    SettingsSection:Toggle({
        Title = "No billboard Background",
        Flag = "Players_Performance",
        Desc = "Removes billboard background",
        Default = true,
        Callback = function(state)
            PerformanceModeEnabled = state
            -- Update existing billboards immediately (only touch backgrounds, not bars)
            for _, data in pairs(PlayerESPData) do
                if data.ESPFrame then
                    data.ESPFrame.BackgroundTransparency = state and 1 or 0.6
                end
                if data.StatusBg then
                    data.StatusBg.BackgroundTransparency = state and 0.7 or 0.45
                end
            end
            WindUI:Notify({
                Title = "Billboard",
                Content = state and "Billboard Background hidden" or "Billboard Background shown.",
                Duration = 2,
                Icon = state and "zap" or "zap-off",
            })
        end
    })

    -- Billboard Distance Slider
    SettingsSection:Slider({
        Title = "Billboard Showing Distance",
        Flag = "Players_BillboardDist",
        Desc = "Hide billboard when closer than this distance",
        Step = 1,
        Value = {
            Min = 5,
            Max = 50,
            Default = 5,
        },
        Callback = function(value)
            -- Clamp value to avoid edge cases
            BillboardShowDistance = math.clamp(value, 0, 100)
        end
    })

    -- Player Chams Transparency Slider
    SettingsSection:Slider({
        Title = "Chams Transparency",
        Flag = "Players_ChamsTransparency",
        Desc = "Controls the transparency of player chams/highlights",
        Step = 0.05,
        Value = {
            Min = 0,
            Max = 1,
            Default = 0.45,
        },
        Callback = function(value)
            local transparency = math.clamp(value, 0, 1)
            ChamsFillTransparency = transparency  -- <-- update global

            -- Update existing player highlights
            for _, data in pairs(PlayerESPData) do
                if data.Highlight then
                    data.Highlight.FillTransparency = transparency
                end
            end
        end
    })

    SettingsSection:Toggle({
        Title = "Notify Low Health Players",
        Flag = "Players_3_Dupe",
        Desc = "Notify when players reach Low / Dying health",
        Default = false,
        Callback = function(state)
            NotifyLowHealthEnabled = state
            WindUI:Notify({
                Title = "Low Health Notify",
                Content = state and "Low health notifications ON" or "Low health notifications OFF",
                Duration = 2,
                Icon = state and "bell" or "bell-off",
            })
        end
    })
end -- end of Players Tab

task.wait(0.1) -- Delay to prevent lag
do -- // Headless Horseman Tab
    -- // Headless Tab (rewritten)
    local TweenService = game:GetService("TweenService")
    local UserInputService = game:GetService("UserInputService")
    local RunService = game:GetService("RunService")
    local Players = game:GetService("Players")
    local Workspace = game:GetService("Workspace")

    local LocalPlayer = Players.LocalPlayer
    local Camera = Workspace.CurrentCamera

    local HeadlessTab = Event1Section:Tab({ Title = "Headless Horseman", Icon = "skull" })

    -- Headless Section
    local HeadlessSection = HeadlessTab:Section({
        Title = "Headless Horseman Features",
        Icon = "skull",
        Opened = false
    })

    -- State
    local HeadlessESPEnabled = false
    local HeadlessAimlockEnabled = false
    local AimlockActive = false
    local manualPing = 90
    local aimButtonSize = 90
    local aimKeybind = Enum.KeyCode.B
    local AimGui, AimButton, AimButtonInner = nil, nil, nil

    local AimBtnDragging = false
    local PotentialDrag = false
    local DragInput = nil
    local DragStartPos = nil
    local BtnTargetPos = nil
    local InputStartTick = 0

    local AimConns = {}         -- connections to be cleaned (aim-related)
    local ActiveTweens = {}
    -- Use weak keys so destroyed models get garbage collected
    local highlightInstances = setmetatable({}, { __mode = "k" }) -- model -> Highlight
    local aimbotConnection = nil
    local inputConn = nil
    local lastBossFound = tick()
    local bossTimeout = 10 -- seconds
    local ListeningForBind = false

    -- separate ESP heartbeat connection so it isn't accidentally disconnected
    local espHeartbeatConn = nil

    -- Helpers
    local function clamp(v, a, b) return math.max(a, math.min(b, v)) end

    local function viewportSize()
        local cam = Workspace.CurrentCamera
        if cam and cam.ViewportSize ~= Vector2.zero then
            return cam.ViewportSize
        end
        return Vector2.new(1280, 720)
    end

    local function ensureOnScreen(positionUDim2, sizePx)
        local vs = viewportSize()
        local x = positionUDim2.X.Offset
        local y = positionUDim2.Y.Offset
        local maxX = math.max(0, vs.X - sizePx)
        local maxY = math.max(0, vs.Y - sizePx)
        x = clamp(x, 0, maxX)
        y = clamp(y, 0, maxY)
        return UDim2.new(0, math.floor(x), 0, math.floor(y))
    end

    local function cancelTweens()
        for _, tween in pairs(ActiveTweens) do
            if tween then
                pcall(function() tween:Cancel() end)
            end
        end
        ActiveTweens = {}
    end

    local function safeDestroy(obj)
        pcall(function() if obj then obj:Destroy() end end)
    end

    -- Robust finder for the HeadlessHorseman model / hitbox
    local function findHeadlessBossModel()
        local rootNames = {"Sleepy Hollow", "SleepyHollow", "Sleepy_Hollow"}
        for _, rn in ipairs(rootNames) do
            local root = Workspace:FindFirstChild(rn)
            if root then
                local modes = root:FindFirstChild("Modes") or root:FindFirstChild("modes")
                if modes then
                    local bossFolder = modes:FindFirstChild("Boss") or modes:FindFirstChild("boss")
                    if bossFolder then
                        local hh = bossFolder:FindFirstChild("HeadlessHorsemanBoss") or bossFolder:FindFirstChild("HeadlessHorseman")
                        if hh then return hh end
                    end
                    local hh2 = modes:FindFirstChild("HeadlessHorsemanBoss") or modes:FindFirstChild("HeadlessHorseman")
                    if hh2 then return hh2 end
                end
                local hh3 = root:FindFirstChild("HeadlessHorsemanBoss") or root:FindFirstChild("HeadlessHorseman")
                if hh3 then return hh3 end
            end
        end

        for _, desc in pairs(Workspace:GetDescendants()) do
            if desc:IsA("Model") and desc:FindFirstChild("ZOMBIE_HITBOX") then
                return desc
            end
        end

        local top = Workspace:FindFirstChild("HeadlessHorsemanBoss") or Workspace:FindFirstChild("HeadlessHorseman")
        if top then return top end
        return nil
    end

    -- Heartbeat: manage ESP highlights (keeps reference to camera updated)
    local headlessLastCheck = 0
    local headlessCachedModel = nil
    local HEADLESS_CHECK_INTERVAL = 0.5 -- Only search for boss every 0.5 seconds instead of every frame
    task.defer(function()
        task.wait(1.5) -- Stagger start
        espHeartbeatConn = RunService.Heartbeat:Connect(function()
            -- PERFORMANCE FIX: Early return if feature is disabled
            if not HeadlessESPEnabled then
                -- Only cleanup if there are highlights to remove
                if next(highlightInstances) then
                    for model, h in pairs(highlightInstances) do
                        safeDestroy(h)
                        highlightInstances[model] = nil
                    end
                end
                headlessCachedModel = nil
                return
            end
            
            Camera = Workspace.CurrentCamera or Camera

            -- clear any invalid highlights
            for model, h in pairs(highlightInstances) do
                if not model or not model.Parent or (h and not h.Parent) then
                    safeDestroy(h)
                    highlightInstances[model] = nil
                end
            end

            -- PERFORMANCE FIX: Only search for boss model every 0.5 seconds instead of every frame
            local now = tick()
            if now - headlessLastCheck > HEADLESS_CHECK_INTERVAL or not headlessCachedModel or not headlessCachedModel.Parent then
                headlessLastCheck = now
                headlessCachedModel = findHeadlessBossModel()
            end
            
            local hhModel = headlessCachedModel
            if not hhModel then
                for model, h in pairs(highlightInstances) do
                    safeDestroy(h)
                    highlightInstances[model] = nil
                end
                return
            end

            -- create highlight for this model if missing
            if not highlightInstances[hhModel] then
                local h = Instance.new("Highlight")
                -- Use stealth name for anti-detection
                h.Name = _G.getRandomInstanceName and _G.getRandomInstanceName() or ("HL_" .. math.random(10000, 99999))
                h.FillColor = Color3.fromRGB(255, 100, 100)
                h.OutlineColor = Color3.fromRGB(255, 255, 255)
                h.DepthMode = Enum.HighlightDepthMode.AlwaysOnTop
                -- Parent the Highlight to the model (model must be descendant of workspace)
                -- this works across model replacements because we key by object reference
                h.Parent = hhModel
                highlightInstances[hhModel] = h
            end
        end)
    end)

    -- safe helper to locate hitbox part (ZOMBIE_HITBOX)
    local function getHeadlessHitbox()
        local model = findHeadlessBossModel()
        if not model then return nil end
        local hh = model:FindFirstChild("HeadlessHorseman") or model
        if hh and hh:FindFirstChild("ZOMBIE_HITBOX") then
            return hh:FindFirstChild("ZOMBIE_HITBOX")
        end
        if model:FindFirstChild("ZOMBIE_HITBOX") then
            return model:FindFirstChild("ZOMBIE_HITBOX")
        end
        -- fallback: search children
        for _, child in ipairs(model:GetDescendants()) do
            if child:IsA("BasePart") and child.Name == "ZOMBIE_HITBOX" then
                return child
            end
        end
        return nil
    end

    -- start aimbot (predict + smooth)
    local function startAimbot()
        if aimbotConnection then
            pcall(function() aimbotConnection:Disconnect() end)
            aimbotConnection = nil
        end

        aimbotConnection = RunService.RenderStepped:Connect(function(delta)
            if not AimlockActive or not HeadlessAimlockEnabled then return end
            Camera = Workspace.CurrentCamera or Camera

            local ok, targetPart = pcall(getHeadlessHitbox)
            if not ok or not targetPart or not targetPart:IsA("BasePart") then
                if tick() - lastBossFound > bossTimeout then
                    setButtonActive(false)
                    if WindUI then
                        WindUI:Notify({
                            Title = "Aimlock",
                            Content = "Headless Horseman not found, aimlock disabled.",
                            Duration = 3,
                            Icon = "x"
                        })
                    end
                end
                return
            end

            if not targetPart.Parent then return end
            lastBossFound = tick()

            local predicted = targetPart.Position + (targetPart.Velocity * (manualPing / 1000))

            local cameraPos = Camera.CFrame.Position
            local direction = predicted - cameraPos
            local dist = direction.Magnitude
            if dist == 0 then return end
            if dist > 2000 then return end

            local targetCFrame = CFrame.new(cameraPos, cameraPos + direction.Unit)
            local lerpAlpha = clamp(delta * 10, 0, 1)
            pcall(function() Camera.CFrame = Camera.CFrame:Lerp(targetCFrame, lerpAlpha) end)
        end)

        table.insert(AimConns, aimbotConnection)
    end

    local function stopAimbot()
        if aimbotConnection then
            pcall(function() aimbotConnection:Disconnect() end)
            aimbotConnection = nil
        end
    end

    -- setButtonActive toggles aim state and updates visuals
    function setButtonActive(active)
        AimlockActive = active
        cancelTweens()

        if AimButton and AimButtonInner then
            if active then
                local tween1 = TweenService:Create(AimButton, TweenInfo.new(0.18, Enum.EasingStyle.Sine), {BackgroundColor3 = Color3.fromRGB(60, 200, 100)})
                local tween2 = TweenService:Create(AimButtonInner, TweenInfo.new(0.18, Enum.EasingStyle.Sine), {BackgroundColor3 = Color3.fromRGB(40, 180, 80)})
                pcall(function() tween1:Play(); tween2:Play() end)
                table.insert(ActiveTweens, tween1); table.insert(ActiveTweens, tween2)
                AimButton.Text = "🔒"
            else
                local tween1 = TweenService:Create(AimButton, TweenInfo.new(0.18, Enum.EasingStyle.Sine), {BackgroundColor3 = Color3.fromRGB(40, 40, 40)})
                local tween2 = TweenService:Create(AimButtonInner, TweenInfo.new(0.18, Enum.EasingStyle.Sine), {BackgroundColor3 = Color3.fromRGB(60, 60, 60)})
                pcall(function() tween1:Play(); tween2:Play() end)
                table.insert(ActiveTweens, tween1); table.insert(ActiveTweens, tween2)
                AimButton.Text = "🎯"
            end
        end

        if active then startAimbot() else stopAimbot() end
    end

    -- Create Aimlock Button (robust + mobile friendly, smooth dragging)
    local function createAimlockButton()
        if AimGui and AimGui.Parent then return AimGui end

        -- cleanup any old UI named AimlockGUI
        local core = game:GetService("CoreGui")
        for _, child in ipairs(core:GetChildren()) do
            if child.Name == "AimlockGUI" then
                safeDestroy(child)
            end
        end

        -- Only disconnect aim-related connections (AimConns). espHeartbeatConn is NOT in AimConns,
        -- so the ESP heartbeat won't be disconnected here anymore.
        for _, c in pairs(AimConns) do
            pcall(function() c:Disconnect() end)
        end
        AimConns = {}

        AimGui = Instance.new("ScreenGui")
        AimGui.ResetOnSpawn = false
        AimGui.IgnoreGuiInset = true
        -- Use full stealth protection
        if _G.protectGUI then
            _G.protectGUI(AimGui)
        else
            -- Fallback: Try CoreGui first, then PlayerGui
            pcall(function()
                if gethui then
                    AimGui.Parent = gethui()
                else
                    AimGui.Parent = core
                end
            end)
            -- Use stealth name
            AimGui.Name = _G.getRandomStealthName and _G.getRandomStealthName() or ("TopBarApp_" .. math.random(10000, 99999))
        end

        local container = Instance.new("Frame")
        -- Use randomized name for child elements too
        container.Name = "Frame_" .. math.random(10000, 99999)
        container.Size = UDim2.new(0, aimButtonSize, 0, aimButtonSize)
        container.Position = UDim2.new(0.5, -aimButtonSize/2, 0.8, -aimButtonSize/2)
        container.BackgroundTransparency = 1
        container.Parent = AimGui

        AimButton = Instance.new("TextButton")
        -- Use randomized name
        AimButton.Name = "Button_" .. math.random(10000, 99999)
        AimButton.Size = UDim2.new(1, 0, 1, 0)
        AimButton.Position = UDim2.new(0, 0, 0, 0)
        AimButton.BackgroundColor3 = Color3.fromRGB(40, 40, 40)
        AimButton.Text = "🎯"
        AimButton.Font = Enum.Font.Roboto
        AimButton.TextSize = math.clamp(aimButtonSize * 0.5, 20, 50)
        AimButton.TextColor3 = Color3.fromRGB(255, 255, 255)
        AimButton.AutoButtonColor = false
        AimButton.BorderSizePixel = 0
        AimButton.Parent = container
        AimButton.ZIndex = 10

        local gradient = Instance.new("UIGradient")
        gradient.Color = ColorSequence.new({
            ColorSequenceKeypoint.new(0, Color3.fromRGB(100, 100, 255)),
            ColorSequenceKeypoint.new(1, Color3.fromRGB(50, 50, 150))
        })
        gradient.Rotation = 45
        gradient.Parent = AimButton

        local shadow = Instance.new("UIStroke")
        shadow.Color = Color3.fromRGB(0, 0, 0)
        shadow.Thickness = 3
        shadow.Transparency = 0.3
        shadow.Parent = AimButton

        local corner = Instance.new("UICorner")
        corner.CornerRadius = UDim.new(0, 12)
        corner.Parent = AimButton

        AimButtonInner = Instance.new("Frame")
        -- Use randomized name
        AimButtonInner.Name = "Frame_" .. math.random(10000, 99999)
        AimButtonInner.Size = UDim2.new(1, -10, 1, -10)
        AimButtonInner.Position = UDim2.new(0, 5, 0, 5)
        AimButtonInner.BackgroundColor3 = Color3.fromRGB(60, 60, 60)
        AimButtonInner.BorderSizePixel = 0
        AimButtonInner.Parent = AimButton
        AimButtonInner.ZIndex = 9

        local innerGradient = Instance.new("UIGradient")
        innerGradient.Color = ColorSequence.new({
            ColorSequenceKeypoint.new(0, Color3.fromRGB(150, 150, 255)),
            ColorSequenceKeypoint.new(1, Color3.fromRGB(80, 80, 180))
        })
        innerGradient.Rotation = 45
        innerGradient.Parent = AimButtonInner

        local innerCorner = Instance.new("UICorner")
        innerCorner.CornerRadius = UDim.new(0, 10)
        innerCorner.Parent = AimButtonInner

        container.Position = ensureOnScreen(container.Position, aimButtonSize)

        -- Dragging: small threshold to distinguish tap vs drag, smooth position lerp
        local DRAG_THRESHOLD = 6 -- pixels
        local HOLD_TIME = 0.12    -- seconds before movement counts more reliably

        local function onInputChanged(input)
            if not DragInput or input ~= DragInput then return end
            if not DragStartPos or not BtnTargetPos then return end

            local inputPos = Vector2.new(input.Position.X, input.Position.Y)
            local delta = inputPos - DragStartPos

            -- decide whether this is a drag
            if not AimBtnDragging and PotentialDrag and delta.Magnitude > DRAG_THRESHOLD and (tick() - InputStartTick) > HOLD_TIME then
                AimBtnDragging = true
            end

            if AimBtnDragging then
                local newX = BtnTargetPos.X.Offset + delta.X
                local newY = BtnTargetPos.Y.Offset + delta.Y
                local targetUD = ensureOnScreen(UDim2.new(0, newX, 0, newY), aimButtonSize)
                -- smooth movement using UDim2:Lerp (less jittery than creating many tweens)
                local curr = container.Position
                local lerped = curr:Lerp(targetUD, 0.35)
                container.Position = lerped
            end
        end

        local function onInputEnded(input)
            if input ~= DragInput then return end

            if AimBtnDragging then
                -- finalize drag: snap to on-screen and animate inner back
                AimBtnDragging = false
                DragInput = nil
                DragStartPos = nil
                BtnTargetPos = nil
                PotentialDrag = false

                local snapped = ensureOnScreen(container.Position, aimButtonSize)
                local tween = TweenService:Create(container, TweenInfo.new(0.12, Enum.EasingStyle.Sine, Enum.EasingDirection.Out), {Position = snapped})
                pcall(function() tween:Play() end)
                table.insert(ActiveTweens, tween)

                local innerTween = TweenService:Create(AimButtonInner, TweenInfo.new(0.18, Enum.EasingStyle.Sine), {Size = UDim2.new(1, -10, 1, -10)})
                pcall(function() innerTween:Play() end)
                table.insert(ActiveTweens, innerTween)
                return
            end

            -- otherwise it's a tap (short press w/o moving) -> toggle
            DragInput = nil
            DragStartPos = nil
            BtnTargetPos = nil
            PotentialDrag = false

            setButtonActive(not AimlockActive)
            if WindUI then
                WindUI:Notify({
                    Title = "Aimlock",
                    Content = AimlockActive and "Aimlock Engaged" or "Aimlock Released",
                    Duration = 2,
                    Icon = AimlockActive and "target" or "x"
                })
            end
        end

        local beginConn = AimButton.InputBegan:Connect(function(input)
            if input.UserInputType == Enum.UserInputType.MouseButton1 or input.UserInputType == Enum.UserInputType.Touch then
                if DragInput then return end
                DragInput = input
                DragStartPos = Vector2.new(input.Position.X, input.Position.Y)
                BtnTargetPos = container.Position
                InputStartTick = tick()
                PotentialDrag = true

                local shrink = TweenService:Create(AimButtonInner, TweenInfo.new(0.12, Enum.EasingStyle.Sine), {Size = UDim2.new(1, -14, 1, -14)})
                pcall(function() shrink:Play() end)
                table.insert(ActiveTweens, shrink)
            end
        end)
        table.insert(AimConns, beginConn)

        local inputChangedConn = UserInputService.InputChanged:Connect(onInputChanged)
        table.insert(AimConns, inputChangedConn)

        local inputEndedConn = UserInputService.InputEnded:Connect(onInputEnded)
        table.insert(AimConns, inputEndedConn)

        local viewportConn = Workspace.CurrentCamera:GetPropertyChangedSignal("ViewportSize"):Connect(function()
            if not AimBtnDragging and container and container.Parent then
                container.Position = ensureOnScreen(container.Position, aimButtonSize)
            end
        end)
        table.insert(AimConns, viewportConn)

        local function updateButtonSize(sizePx)
            aimButtonSize = clamp(tonumber(sizePx) or aimButtonSize, 40, 200)
            if container and AimButton then
                container.Size = UDim2.new(0, aimButtonSize, 0, aimButtonSize)
                AimButton.Size = UDim2.new(1, 0, 1, 0)
                AimButtonInner.Size = UDim2.new(1, -10, 1, -10)
                AimButton.TextSize = math.clamp(aimButtonSize * 0.5, 20, 50)
                container.Position = ensureOnScreen(container.Position, aimButtonSize)
            end
        end

        AimGui._updateSize = updateButtonSize
        return AimGui
    end

    local function destroyAimlockButton()
        cancelTweens()
        stopAimbot()

        for _, c in pairs(AimConns) do
            pcall(function() c:Disconnect() end)
        end
        AimConns = {}

        if AimGui and AimGui.Parent then
            safeDestroy(AimGui)
        end
        AimGui = nil
        AimButton = nil
        AimButtonInner = nil
        ListeningForBind = false
        AimlockActive = false
        DragInput = nil
        AimBtnDragging = false
        PotentialDrag = false
    end

    -- Keybind Input (WindUI)
    local keybindInput = nil
    if WindUI then
        keybindInput = HeadlessSection:Input({
            Flag = "Headless_1",
            Title = "Aimlock Keybind",
            Desc = "Press a key to set the aimlock keybind",
            Placeholder = aimKeybind and aimKeybind.Name or "(Touch)",
            Callback = function()
                if ListeningForBind then return end
                ListeningForBind = true
                keybindInput:SetValue("Press a key...")
                local captureConn
                captureConn = UserInputService.InputBegan:Connect(function(inp, gpe)
                    if gpe or not ListeningForBind then return end
                    if inp.UserInputType == Enum.UserInputType.Keyboard and inp.KeyCode then
                        aimKeybind = inp.KeyCode
                        keybindInput:SetValue(aimKeybind.Name)
                    elseif inp.UserInputType == Enum.UserInputType.Touch then
                        aimKeybind = nil
                        keybindInput:SetValue("(Touch)")
                    end
                    ListeningForBind = false
                    pcall(function() captureConn:Disconnect() end)
                end)
                table.insert(AimConns, captureConn)
            end
        })
    end

    -- Keybind handler (works even if GUI not created)
    inputConn = UserInputService.InputBegan:Connect(function(input, gpe)
        if gpe or not HeadlessAimlockEnabled then return end
        if aimKeybind and input.UserInputType == Enum.UserInputType.Keyboard and input.KeyCode == aimKeybind then
            setButtonActive(not AimlockActive)
        end
    end)
    table.insert(AimConns, inputConn)

    -- WindUI Integration (Toggles + Sliders)
    if WindUI then
        HeadlessSection:Toggle({
            Title = "Headless Horseman ESP",
            Flag = "Headless_2",
            Desc = "Highlight the Headless Horseman boss",
            Default = false,
            Callback = function(state)
                HeadlessESPEnabled = state
                WindUI:Notify({
                    Title = "Headless ESP",
                    Content = state and "Headless Horseman ESP Enabled" or "Headless Horseman ESP Disabled",
                    Duration = 2,
                    Icon = state and "eye" or "eye-off",
                })
            end
        })

        HeadlessSection:Toggle({
            Title = "Headless Horseman Aimlock",
            Flag = "Headless_3",
            Desc = "Aimlock onto the Headless Horseman",
            Default = false,
            Callback = function(state)
                HeadlessAimlockEnabled = state

                -- make sure no stale aimbot is running
                setButtonActive(false)

                if state then
                    createAimlockButton()
                    WindUI:Notify({
                        Title = "Headless Aimlock",
                        Content = "Aimlock Enabled",
                        Duration = 3,
                        Icon = "target",
                    })
                else
                    destroyAimlockButton()
                    WindUI:Notify({
                        Title = "Headless Aimlock",
                        Content = "Aimlock Disabled",
                        Duration = 2,
                        Icon = "x",
                    })
                end
            end
        })

        HeadlessSection:Slider({
            Title = "Prediction (Ping in ms)",
            Flag = "Headless_4",
            Desc = "Adjust aimlock prediction based on your ping",
            Step = 1,
            Value = {Min = 30, Max = 300, Default = manualPing},
            Callback = function(val)
                manualPing = val
            end
        })

        HeadlessSection:Slider({
            Title = "Aim Button Size",
            Flag = "Headless_5",
            Desc = "Adjust on-screen aimlock button size",
            Step = 1,
            Value = {Min = 40, Max = 200, Default = aimButtonSize},
            Callback = function(val)
                aimButtonSize = val
                if AimGui and AimGui._updateSize then
                    AimGui._updateSize(val)
                end
            end
        })
    end

    -- Auto-disable on death
    local function handleDeath()
        if AimlockActive then
            setButtonActive(false)
            if WindUI then
                WindUI:Notify({
                    Title = "Aimlock",
                    Content = "Aimlock Disabled On Death.",
                    Duration = 3,
                    Icon = "x"
                })
            end
        end
    end

    -- Hook into character if present
    local currentChar = LocalPlayer and LocalPlayer.Character
    if currentChar then
        local currentHum = currentChar:FindFirstChildOfClass("Humanoid")
        if currentHum then
            currentHum.Died:Connect(handleDeath)
            local camera = Workspace.CurrentCamera
            if camera then
                camera.CameraSubject = currentHum
            end
        end
    end

    LocalPlayer.CharacterAdded:Connect(function(newChar)
        local newHum = newChar:WaitForChild("Humanoid")
        newHum.Died:Connect(handleDeath)

        task.wait(0.1)
        local camera = Workspace.CurrentCamera
        if camera then
            camera.CameraSubject = newHum
            camera.CameraType = Enum.CameraType.Custom
        end
    end)

    -- Cleanup entrypoint
    local function cleanup()
        destroyAimlockButton()
        stopAimbot()

        -- disconnect aim-related connections
        for _, c in pairs(AimConns) do
            pcall(function() c:Disconnect() end)
        end
        AimConns = {}

        if espHeartbeatConn then
            pcall(function() espHeartbeatConn:Disconnect() end)
            espHeartbeatConn = nil
        end

        if inputConn then
            pcall(function() inputConn:Disconnect() end)
            inputConn = nil
        end

        for model, h in pairs(highlightInstances) do
            safeDestroy(h)
            highlightInstances[model] = nil
        end
    end

    _G.KatchiHeadlessAimlockCleanup = cleanup
end -- end of Headless Horseman Tab

task.wait(0.1) -- Delay to prevent lag
do -- // Configs & Theme Tab
    -- ====== WindUI Built-in Config System ======
    -- Uses WindUI's Flag-based auto-save/load system
    -- All UI elements with Flag="..." are automatically saved
    
    local skibiTab = Others1Section:Tab({
        Title = "Profiles",
        Icon = "save",
        Locked = false,
    })

-- ===== WindUI Built-in Config System =====
-- Uses WindUI's ConfigManager which handles file operations internally
-- All UI elements with Flag="..." are automatically saved/loaded

local ConfigManager = Window.ConfigManager
local ConfigSection = skibiTab:Section({
    Title = "Configs",
    Icon = "file-plus",
    Opened = true
})

local profileName = "default"
local selectedProfile = nil
local ConfigDropdown = nil
local overwriteExisting = true

local function notify(title, content, icon, dur)
    if WindUI then
        pcall(function() WindUI:Notify({ Title = title or "Config", Content = content or "", Icon = icon or "save", Duration = dur or 2 }) end)
    end
end

local function GetAllConfigsSafe()
    local ok, list = pcall(function() return ConfigManager:AllConfigs() end)
    if not ok or type(list) ~= "table" then return {} end
    local out = {}
    for _, v in ipairs(list) do table.insert(out, tostring(v)) end
    return out
end

local function RefreshConfigsDropdown()
    local list = GetAllConfigsSafe()
    if selectedProfile and not table.find(list, selectedProfile) then selectedProfile = nil end

    if ConfigDropdown then
        pcall(function()
            if ConfigDropdown.SetValues then ConfigDropdown:SetValues(list); return end
            if ConfigDropdown.SetOptions then ConfigDropdown:SetOptions(list); return end
            if ConfigDropdown.Update then ConfigDropdown:Update(list); return end
            if ConfigDropdown.Refresh then ConfigDropdown:Refresh(list); return end
            ConfigDropdown.Values = list
            ConfigDropdown.Value = selectedProfile or list[1] or nil
        end)
    end
end

-- textbox for entering profile name
ConfigSection:Input({
    Title = "Profile Name",
    Desc = "Enter a name for the config",
    Placeholder = "default",
    Callback = function(val)
        if val and tostring(val):match("%S") then
            profileName = tostring(val)
        end
    end
})

-- Save button
ConfigSection:Button({
    Title = "Save Profile",
    Desc = "Save all current settings to a profile",
    Callback = function()
        local name = tostring(profileName or ""):gsub("^%s+", ""):gsub("%s+$", "")
        if name == "" then notify("Config", "Enter a profile name first", "alert-circle", 2); return end

        local existing = GetAllConfigsSafe()
        local exists = table.find(existing, name) ~= nil

        if exists and not overwriteExisting then
            notify("Config", ("Profile '%s' already exists. Enable Overwrite to replace it."):format(name), "alert-circle", 2)
            return
        end

        -- Create config object
        local ok, cfg = pcall(function() return ConfigManager:CreateConfig(name) end)
        if not ok or not cfg then notify("Config", "Failed to create config object", "x", 2); return end

        -- If exists and we want to overwrite, delete first then recreate
        if exists and overwriteExisting then
            pcall(function() cfg:Delete() end)
            local ok2, cfg2 = pcall(function() return ConfigManager:CreateConfig(name) end)
            if ok2 and cfg2 then cfg = cfg2 end
        end

        local suc = pcall(function() cfg:Save() end)
        if suc then
            notify("Config", ("Saved '%s' ✓"):format(name), "check", 2)
            selectedProfile = name
            RefreshConfigsDropdown()
        else
            notify("Config", ("Failed to save '%s'"):format(name), "x", 2)
        end
    end
})

-- Dropdown for selecting profiles
ConfigDropdown = ConfigSection:Dropdown({
    Title = "Saved Profiles",
    Desc = "Select a saved profile to load or delete",
    Values = GetAllConfigsSafe(),
    Value = GetAllConfigsSafe()[1] or "",
    Callback = function(option)
        selectedProfile = option
    end
})

-- Load button
ConfigSection:Button({
    Title = "Load Selected",
    Desc = "Load The Selected Config",
    Callback = function()
        if not selectedProfile or tostring(selectedProfile) == "" then 
            notify("Config", "Select a profile first", "alert-circle", 2)
            return 
        end
        
        local ok, cfg = pcall(function() return ConfigManager:CreateConfig(selectedProfile) end)
        if not ok or not cfg then notify("Config", "Failed to create config object", "x", 2); return end
        
        local suc = pcall(function() cfg:Load() end)
        if suc then
            notify("Config", ("Loaded '%s' ✓"):format(selectedProfile), "download", 2)
            RefreshConfigsDropdown()
        else
            notify("Config", ("Failed to load '%s'"):format(selectedProfile), "x", 2)
        end
    end
})

-- Delete button
ConfigSection:Button({
    Title = "Delete Selected",
    Desc = "Delete the selected Config",
    Callback = function()
        if not selectedProfile or tostring(selectedProfile) == "" then 
            notify("Config", "Select a profile first", "alert-circle", 2)
            return 
        end
        
        local ok, cfg = pcall(function() return ConfigManager:CreateConfig(selectedProfile) end)
        if not ok or not cfg then notify("Config", "Failed to create config object", "x", 2); return end
        
        local suc = pcall(function() cfg:Delete() end)
        if suc then
            notify("Config", ("Deleted '%s'"):format(selectedProfile), "trash", 2)
            selectedProfile = nil
            RefreshConfigsDropdown()
        else
            notify("Config", ("Failed to delete '%s'"):format(selectedProfile), "x", 2)
        end
    end
})

-- Refresh button
ConfigSection:Button({
    Title = "Refresh List",
    Desc = "Refresh the dropdown of saved Configs",
    Callback = function()
        RefreshConfigsDropdown()
        notify("Config", "Refreshed list", "refresh-cw", 1.3)
    end
})

-- Overwrite toggle
ConfigSection:Toggle({
    Title = "Overwrite Existing",
    Desc = "Allow overwriting configs with the same name",
    Value = overwriteExisting,
    Callback = function(val)
        overwriteExisting = val
    end
})

-- Initial population
RefreshConfigsDropdown()

-- === Fixed Theme Tab (use this in place of the previous snippet) ===
local ThemeTab = Others1Section:Tab({
    Title = "Theme",
    Icon  = "sun",
})

local ThemeSection = ThemeTab:Section({
    Title = "Themes",
    Icon  = "paintbrush",
    Opened = true,
})

-- Normalize a single theme entry -> string
local function NormalizeThemeEntry(e)
    if type(e) == "string" then return e end
    if type(e) == "table" then
        if e.Name and type(e.Name) == "string" then return e.Name end
        if e.name and type(e.name) == "string" then return e.name end
        if e.Title and type(e.Title) == "string" then return e.Title end
        -- fallback to tostring
        return tostring(e)
    end
    return tostring(e)
end

-- Normalize a list (returns array of strings)
local function NormalizeList(list)
    local out = {}
    if not list then return out end
    -- handle dictionary (pairs) vs array (ipairs)
    local seen = {}
    for k, v in pairs(list) do
        local s = NormalizeThemeEntry(v)
        if s and s ~= "" and not seen[s] then
            table.insert(out, s)
            seen[s] = true
        end
    end
    table.sort(out)
    return out
end

-- gather theme names (defensive)
local function GetAvailableThemes()
    local raw = {}
    pcall(function()
        if WindUI and type(WindUI) == "table" then
            -- WindUI.Themes might be a map name->table
            if type(WindUI.Themes) == "table" then
                for name, _ in pairs(WindUI.Themes) do table.insert(raw, name) end
            end
            -- WindUI.GetThemes() might return list of names or tables
            if type(WindUI.GetThemes) == "function" then
                local ok, res = pcall(WindUI.GetThemes)
                if ok and res then
                    if type(res) == "table" then
                        for _, v in ipairs(res) do table.insert(raw, v) end
                        -- also check pairs in case it's a map
                        for k, v in pairs(res) do
                            if tonumber(k) == nil then table.insert(raw, k) end
                        end
                    end
                end
            end
        end
        -- Window-level fallback
        if Window and type(Window.Themes) == "table" then
            for name, _ in pairs(Window.Themes) do table.insert(raw, name) end
        end
    end)
    return NormalizeList(raw)
end

local function GetCurrentThemeName()
    local cur = nil
    pcall(function()
        cur = (Window and Window.Theme) or (WindUI and WindUI.Theme) or (WindUI and WindUI.CurrentTheme)
    end)
    if type(cur) == "table" then
        return NormalizeThemeEntry(cur)
    end
    if cur == nil or cur == "" then
        return nil
    end
    return tostring(cur)
end

-- create/dropdown reference
local ThemeDropdown

local function SafeSetDropdownValues(dropdown, vals)
    if not dropdown then return end
    local normalized = NormalizeList(vals)
    pcall(function()
        if dropdown.SetValues and type(dropdown.SetValues) == "function" then
            dropdown:SetValues(normalized)
            return
        end
        if dropdown.SetOptions and type(dropdown.SetOptions) == "function" then
            dropdown:SetOptions(normalized)
            return
        end
        -- fallback: directly assign
        dropdown.Values = normalized
    end)
end

local function SafeSetDropdownValue(dropdown, val)
    if not dropdown then return end
    local s = NormalizeThemeEntry(val)
    pcall(function()
        if dropdown.SetValue and type(dropdown.SetValue) == "function" then
            dropdown:SetValue(s)
            return
        end
        if dropdown.Set and type(dropdown.Set) == "function" then
            dropdown:Set(s)
            return
        end
        -- fallback
        dropdown.Value = s
    end)
end

-- Create dropdown (initial)
local themes = GetAvailableThemes()
local initial = GetCurrentThemeName() or (themes[1] or "Default")

ThemeDropdown = ThemeSection:Dropdown({
    Title = "Available Themes",
    Flag = "Theme",
    Desc  = "Select a UI theme",
    Values = themes,
    Value  = red,
    Callback = function(selection)
        if not selection then return end
        -- normalize selection (could be table/string)
        local sel = NormalizeThemeEntry(selection)
        local ok, err = pcall(function()
            if WindUI and type(WindUI.SetTheme) == "function" then
                WindUI:SetTheme(sel)
            elseif Window and type(Window.SetTheme) == "function" then
                Window:SetTheme(sel)
            else
                error("No SetTheme function found on WindUI/Window")
            end
        end)
        if ok then
            pcall(function() if WindUI and WindUI.Notify then WindUI:Notify({ Title = "Theme", Content = ("Theme set to %s"):format(sel), Duration = 2, Icon = "sun" }) end end)
            -- reflect change on dropdown
            SafeSetDropdownValue(ThemeDropdown, sel)
        else
            pcall(function() if WindUI and WindUI.Notify then WindUI:Notify({ Title = "Theme", Content = ("Failed to set theme: %s"):format(tostring(err)), Duration = 4, Icon = "alert-triangle" }) end end)
        end
    end
})

-- small refresh button
ThemeSection:Button({
    Title = "Refresh Themes",
    Desc  = "Scan for more themes.",
    Callback = function()
        local newThemes = GetAvailableThemes()
        SafeSetDropdownValues(ThemeDropdown, newThemes)
        local cur = GetCurrentThemeName()
        if cur then SafeSetDropdownValue(ThemeDropdown, cur) end
        pcall(function() if WindUI and WindUI.Notify then WindUI:Notify({ Title = "Theme", Content = "Theme list refreshed", Duration = 1.5, Icon = "refresh-cw" }) end end)
    end
})

-- sync dropdown value on load (best-effort)
task.delay(0.05, function()
    local cur = GetCurrentThemeName()
    if cur then
        SafeSetDropdownValue(ThemeDropdown, cur)
    end
end)

end -- end of Configs & Theme Tab

task.wait(0.1) -- Delay to prevent lag
do -- // Misc Tab (forceful WalkSpeed loop, looped Fullbright & NoFog, removed JumpPower/Heal/Reset)
    local RunService = game:GetService("RunService")
    local Players = game:GetService("Players")
    local Lighting = game:GetService("Lighting")
    local TeleportService = game:GetService("TeleportService")
    local HttpService = game:GetService("HttpService")
    local UserInputService = game:GetService("UserInputService")

    local LocalPlayer = Players.LocalPlayer
    local MiscTab = Others1Section:Tab({ Title = "Misc", Icon = "settings" })

    -- Sections
    -- NEW: Server Modifiers section (on top)
    local ServerModifiersSection = MiscTab:Section({
        Title = "Server Modifiers",
        Icon = "shield",
        Opened = false,
    })

    local MovementSection = MiscTab:Section({ Title = "Movement", Icon = "user", Opened = false })
    local VisualSection   = MiscTab:Section({ Title = "Visual", Icon = "eye", Opened = false })
    local ServerSection   = MiscTab:Section({ Title = "Server Utilities", Icon = "server", Opened = false })

    -- === ANIMATIONS SECTION ===
    local AnimationsSection = MiscTab:Section({ Title = "Animations", Icon = "play", Opened = false })
    
    do -- Animations scope
        local allAnimations = {}
        local animationDropdown = nil
        local animSearchQuery = ""
        local scanStatusParagraph = nil
        local hasInitialScan = false -- PERFORMANCE: Lazy load - don't scan until user interacts
        
        -- Global seen IDs to prevent duplicates across scans
        local globalSeenIds = {}
        
        -- Normalize animation ID for comparison (extract numeric ID)
        local function normalizeAnimIdForScan(id)
            if not id then return nil end
            local numId = tostring(id):match("(%d+)")
            return numId
        end
        
        -- Scan all animations in the game (PERFORMANCE: chunked processing to prevent freezing)
        local function scanAllAnimations()
            local anims = {}
            local seen = {}
            local processedCount = 0
            local CHUNK_SIZE = 200 -- Process 200 instances per frame to prevent freezing
            
            -- Helper to add animation if not seen
            local function addAnim(name, id)
                if not id or id == "" then return end
                local normId = normalizeAnimIdForScan(id)
                if normId and not seen[normId] then
                    seen[normId] = true
                    table.insert(anims, {name = name or "Unknown", id = id, normId = normId})
                end
            end
            
            -- Helper to scan a container with chunking
            local function scanContainer(container)
                pcall(function()
                    local descendants = container:GetDescendants()
                    for i, desc in ipairs(descendants) do
                        pcall(function()
                            if desc:IsA("Animation") and desc.AnimationId and desc.AnimationId ~= "" then
                                addAnim(desc.Name, desc.AnimationId)
                            end
                            -- Check Animator for playing animations
                            if desc:IsA("Animator") then
                                pcall(function()
                                    for _, track in ipairs(desc:GetPlayingAnimationTracks()) do
                                        if track.Animation then
                                            addAnim(track.Animation.Name or "Playing", track.Animation.AnimationId)
                                        end
                                    end
                                end)
                            end
                        end)
                        
                        -- Yield every CHUNK_SIZE instances to prevent freezing
                        processedCount = processedCount + 1
                        if processedCount % CHUNK_SIZE == 0 then
                            task.wait()
                        end
                    end
                end)
            end
            
            -- Scan Workspace (includes all players, models, everything)
            scanContainer(workspace)
            
            -- Scan ReplicatedStorage
            pcall(function() scanContainer(game:GetService("ReplicatedStorage")) end)
            
            -- Scan ReplicatedFirst
            pcall(function() scanContainer(game:GetService("ReplicatedFirst")) end)
            
            -- Scan StarterPlayer
            pcall(function() scanContainer(game:GetService("StarterPlayer")) end)
            
            -- Scan StarterGui
            pcall(function() scanContainer(game:GetService("StarterGui")) end)
            
            -- Scan StarterPack
            pcall(function() scanContainer(game:GetService("StarterPack")) end)
            
            -- Scan Lighting
            pcall(function() scanContainer(game:GetService("Lighting")) end)
            
            -- Scan all player backpacks
            pcall(function()
                for _, player in ipairs(Players:GetPlayers()) do
                    pcall(function()
                        if player.Backpack then
                            scanContainer(player.Backpack)
                        end
                    end)
                end
            end)
            
            -- Sort alphabetically
            table.sort(anims, function(a, b) return a.name:lower() < b.name:lower() end)
            
            globalSeenIds = seen
            return anims
        end
        
        -- Filter animations based on search query (case-insensitive)
        local function filterAnimations(query)
            if not query or query == "" then
                return allAnimations
            end
            local filtered = {}
            local lowerQuery = query:lower()
            for _, anim in ipairs(allAnimations) do
                if anim.name:lower():find(lowerQuery, 1, true) or anim.id:lower():find(lowerQuery, 1, true) then
                    table.insert(filtered, anim)
                end
            end
            return filtered
        end
        
        -- Get dropdown values from animations
        local function getAnimDropdownValues(anims)
            local values = {}
            for _, anim in ipairs(anims) do
                local shortId = anim.normId and (" [" .. anim.normId:sub(1, 8) .. "]") or ""
                table.insert(values, anim.name .. shortId)
            end
            if #values == 0 then
                table.insert(values, "No animations found")
            end
            return values
        end
        
        -- Lookup table: display name -> animation data
        local animNameToData = {}
        local function updateAnimLookup(anims)
            animNameToData = {}
            for _, anim in ipairs(anims) do
                local shortId = anim.normId and (" [" .. anim.normId:sub(1, 8) .. "]") or ""
                local displayName = anim.name .. shortId
                animNameToData[displayName] = anim
            end
        end
        
        -- PERFORMANCE: Lazy load - don't scan on script load, wait for user interaction
        -- allAnimations starts empty, user must click "Scan Animations" to populate
        
        -- Track playing animation tracks for stopping
        local playingTracks = {}
        
        -- Scan status paragraph
        scanStatusParagraph = AnimationsSection:Paragraph({
            Title = "Animation Count",
            Desc = "Click 'Scan Animations' to load (prevents lag on startup)"
        })
        
        -- Rescan button (now the primary way to load animations)
        AnimationsSection:Button({
            Title = "Scan Animations",
            Desc = "Scan game for animations (runs in background)",
            Callback = function()
                -- Show scanning notification
                WindUI:Notify({
                    Title = "Animations",
                    Content = "Scanning animations in background...",
                    Duration = 2,
                    Icon = "loader"
                })
                
                -- Update status to show scanning
                if scanStatusParagraph then
                    pcall(function()
                        scanStatusParagraph:SetDesc("Scanning... please wait")
                    end)
                end
                
                -- Run scan in background thread
                task.spawn(function()
                    allAnimations = scanAllAnimations()
                    updateAnimLookup(allAnimations)
                    hasInitialScan = true
                    
                    -- Update status
                    if scanStatusParagraph then
                        pcall(function()
                            scanStatusParagraph:SetDesc("Found " .. #allAnimations .. " animations")
                        end)
                    end
                    
                    -- Update dropdown with new values
                    if animationDropdown then
                        pcall(function()
                            local values = getAnimDropdownValues(filterAnimations(animSearchQuery))
                            if animationDropdown.SetValues then
                                animationDropdown:SetValues(values)
                            elseif animationDropdown.Refresh then
                                animationDropdown:Refresh(values)
                            end
                        end)
                    end
                    
                    WindUI:Notify({
                        Title = "Animations",
                        Content = "Found " .. #allAnimations .. " unique animations!",
                        Duration = 3,
                        Icon = "check"
                    })
                end) -- end task.spawn
            end
        })
        
        -- Search input
        AnimationsSection:Input({
            Title = "Search Animations",
            Desc = "Filter animations by name or ID",
            Placeholder = "Type to search...",
            Callback = function(text)
                animSearchQuery = text
                local filtered = filterAnimations(text)
                if animationDropdown then
                    pcall(function()
                        -- Try multiple methods to update dropdown
                        if animationDropdown.SetValues then
                            animationDropdown:SetValues(getAnimDropdownValues(filtered))
                        elseif animationDropdown.Refresh then
                            animationDropdown:Refresh(getAnimDropdownValues(filtered))
                        elseif animationDropdown.UpdateValues then
                            animationDropdown:UpdateValues(getAnimDropdownValues(filtered))
                        end
                    end)
                end
            end
        })
        
        -- Selected animation storage
        local selectedAnimId = nil
        local selectedAnimName = nil
        local loopAnimationEnabled = false
        local loopAnimationTrack = nil
        local loopAnimationConnection = nil
        
        -- Animation details paragraph reference
        local animDetailsParagraph = nil
        
        -- Helper: Get animation duration (requires loading it temporarily)
        local function getAnimationDuration(animId)
            local duration = "Unknown"
            pcall(function()
                local char = LocalPlayer.Character
                if not char then return end
                local humanoid = char:FindFirstChildOfClass("Humanoid")
                if not humanoid then return end
                local animator = humanoid:FindFirstChildOfClass("Animator")
                if not animator then return end
                
                local anim = Instance.new("Animation")
                anim.AnimationId = animId
                local track = animator:LoadAnimation(anim)
                duration = string.format("%.2fs", track.Length)
                track:Destroy()
                anim:Destroy()
            end)
            return duration
        end
        
        -- Helper: Update animation details paragraph
        local function updateAnimDetails()
            if animDetailsParagraph then
                if selectedAnimName and selectedAnimId then
                    local duration = getAnimationDuration(selectedAnimId)
                    animDetailsParagraph:SetDesc(selectedAnimName .. "\n" .. selectedAnimId .. "\nDuration: " .. duration)
                else
                    animDetailsParagraph:SetDesc("No animation selected")
                end
            end
        end
        
        -- Animation dropdown (starts empty - user must scan first)
        animationDropdown = AnimationsSection:Dropdown({
            Title = "Select Animation",
            Desc = "Choose an animation to play",
            Flag = "Animations_Select",
            Multi = false,
            Values = {"Click 'Scan Animations' to load"},
            Callback = function(selected)
                if selected and selected ~= "No animations found" and selected ~= "Click 'Scan Animations' to load" then
                    -- Get animation data from lookup table
                    local animData = animNameToData[selected]
                    if animData then
                        selectedAnimId = animData.id
                        selectedAnimName = animData.name
                        updateAnimDetails()
                    end
                end
            end
        })
        
        -- Animation details paragraph with Copy ID button
        animDetailsParagraph = AnimationsSection:Paragraph({
            Title = "Selected Animation",
            Desc = "No animation selected"
        })
        
        -- Copy ID button
        AnimationsSection:Button({
            Title = "Copy Animation ID",
            Desc = "Copy the selected animation ID to clipboard",
            Callback = function()
                if selectedAnimId then
                    pcall(function()
                        if setclipboard then
                            setclipboard(selectedAnimId)
                        elseif toclipboard then
                            toclipboard(selectedAnimId)
                        end
                    end)
                    WindUI:Notify({
                        Title = "Animations",
                        Content = "Copied ID to clipboard!",
                        Duration = 2,
                        Icon = "copy"
                    })
                else
                    WindUI:Notify({
                        Title = "Animations",
                        Content = "No animation selected!",
                        Duration = 2,
                        Icon = "alert-circle"
                    })
                end
            end
        })
        
        -- Loop Animation toggle
        AnimationsSection:Toggle({
            Title = "Loop Animation",
            Desc = "Loop the selected animation until disabled",
            Default = false,
            Callback = function(state)
                loopAnimationEnabled = state
                if state then
                    if not selectedAnimId then
                        WindUI:Notify({
                            Title = "Animations",
                            Content = "No animation selected!",
                            Duration = 2,
                            Icon = "alert-circle"
                        })
                        return
                    end
                    
                    pcall(function()
                        local char = LocalPlayer.Character
                        if not char then return end
                        local humanoid = char:FindFirstChildOfClass("Humanoid")
                        if not humanoid then return end
                        local animator = humanoid:FindFirstChildOfClass("Animator")
                        if not animator then
                            animator = Instance.new("Animator")
                            animator.Parent = humanoid
                        end
                        
                        local anim = Instance.new("Animation")
                        anim.AnimationId = selectedAnimId
                        loopAnimationTrack = animator:LoadAnimation(anim)
                        loopAnimationTrack.Looped = true
                        loopAnimationTrack:Play()
                        table.insert(playingTracks, loopAnimationTrack)
                        anim:Destroy()
                        
                        WindUI:Notify({
                            Title = "Animations",
                            Content = "Looping animation!",
                            Duration = 2,
                            Icon = "repeat"
                        })
                    end)
                else
                    -- Stop the looping animation
                    if loopAnimationTrack then
                        pcall(function()
                            loopAnimationTrack:Stop()
                        end)
                        loopAnimationTrack = nil
                    end
                    WindUI:Notify({
                        Title = "Animations",
                        Content = "Stopped looping animation!",
                        Duration = 2,
                        Icon = "square"
                    })
                end
            end
        })
        
        -- Play animation button
        AnimationsSection:Button({
            Title = "Play Animation",
            Desc = "Play the selected animation on your character",
            Callback = function()
                if not selectedAnimId then
                    WindUI:Notify({
                        Title = "Animations",
                        Content = "No animation selected!",
                        Duration = 2,
                        Icon = "alert-circle"
                    })
                    return
                end
                
                pcall(function()
                    local char = LocalPlayer.Character
                    if not char then return end
                    local humanoid = char:FindFirstChildOfClass("Humanoid")
                    if not humanoid then return end
                    local animator = humanoid:FindFirstChildOfClass("Animator")
                    if not animator then
                        animator = Instance.new("Animator")
                        animator.Parent = humanoid
                    end
                    
                    local anim = Instance.new("Animation")
                    anim.AnimationId = selectedAnimId
                    local track = animator:LoadAnimation(anim)
                    track:Play()
                    table.insert(playingTracks, track)
                    anim:Destroy()
                    
                    WindUI:Notify({
                        Title = "Animations",
                        Content = "Playing animation!",
                        Duration = 2,
                        Icon = "play"
                    })
                end)
            end
        })
        
        -- Stop animation button
        AnimationsSection:Button({
            Title = "Stop All Animations",
            Desc = "Stop all currently playing animations",
            Callback = function()
                pcall(function()
                    -- Stop tracked animations
                    for _, track in ipairs(playingTracks) do
                        pcall(function()
                            if track and track.Stop then
                                track:Stop()
                            end
                        end)
                    end
                    playingTracks = {}
                    
                    -- Also stop all animations on humanoid
                    local char = LocalPlayer.Character
                    if char then
                        local humanoid = char:FindFirstChildOfClass("Humanoid")
                        if humanoid then
                            local animator = humanoid:FindFirstChildOfClass("Animator")
                            if animator then
                                for _, track in ipairs(animator:GetPlayingAnimationTracks()) do
                                    pcall(function() track:Stop() end)
                                end
                            end
                        end
                    end
                end)
                
                WindUI:Notify({
                    Title = "Animations",
                    Content = "Stopped all animations!",
                    Duration = 2,
                    Icon = "square"
                })
            end
        })
    end -- End Animations scope

    -- === CUSTOM ANIMATION ID SECTION ===
    local CustomAnimSection = MiscTab:Section({ Title = "Custom Animation ID", Icon = "link", Opened = false })
    
    do -- Custom Animation scope
        local customAnimId = ""
        local customLoopEnabled = false
        local customAnimTrack = nil
        local customPlayingTracks = {}
        
        -- Input for custom animation ID
        CustomAnimSection:Input({
            Title = "Animation ID",
            Desc = "Paste an animation ID (e.g. rbxassetid://123456)",
            Placeholder = "rbxassetid://...",
            Callback = function(text)
                customAnimId = text
            end
        })
        
        -- Loop toggle for custom animation
        CustomAnimSection:Toggle({
            Title = "Loop Animation",
            Desc = "Loop the custom animation until disabled",
            Default = false,
            Callback = function(state)
                customLoopEnabled = state
                if state then
                    if not customAnimId or customAnimId == "" then
                        WindUI:Notify({
                            Title = "Custom Animation",
                            Content = "No animation ID entered!",
                            Duration = 2,
                            Icon = "alert-circle"
                        })
                        return
                    end
                    
                    pcall(function()
                        local char = LocalPlayer.Character
                        if not char then return end
                        local humanoid = char:FindFirstChildOfClass("Humanoid")
                        if not humanoid then return end
                        local animator = humanoid:FindFirstChildOfClass("Animator")
                        if not animator then
                            animator = Instance.new("Animator")
                            animator.Parent = humanoid
                        end
                        
                        local anim = Instance.new("Animation")
                        anim.AnimationId = customAnimId
                        customAnimTrack = animator:LoadAnimation(anim)
                        customAnimTrack.Looped = true
                        customAnimTrack:Play()
                        table.insert(customPlayingTracks, customAnimTrack)
                        anim:Destroy()
                        
                        WindUI:Notify({
                            Title = "Custom Animation",
                            Content = "Looping animation!",
                            Duration = 2,
                            Icon = "repeat"
                        })
                    end)
                else
                    -- Stop the looping animation
                    if customAnimTrack then
                        pcall(function()
                            customAnimTrack:Stop()
                        end)
                        customAnimTrack = nil
                    end
                    WindUI:Notify({
                        Title = "Custom Animation",
                        Content = "Stopped looping animation!",
                        Duration = 2,
                        Icon = "square"
                    })
                end
            end
        })
        
        -- Play custom animation button
        CustomAnimSection:Button({
            Title = "Play Animation",
            Desc = "Play the custom animation once",
            Callback = function()
                if not customAnimId or customAnimId == "" then
                    WindUI:Notify({
                        Title = "Custom Animation",
                        Content = "No animation ID entered!",
                        Duration = 2,
                        Icon = "alert-circle"
                    })
                    return
                end
                
                pcall(function()
                    local char = LocalPlayer.Character
                    if not char then return end
                    local humanoid = char:FindFirstChildOfClass("Humanoid")
                    if not humanoid then return end
                    local animator = humanoid:FindFirstChildOfClass("Animator")
                    if not animator then
                        animator = Instance.new("Animator")
                        animator.Parent = humanoid
                    end
                    
                    local anim = Instance.new("Animation")
                    anim.AnimationId = customAnimId
                    local track = animator:LoadAnimation(anim)
                    track:Play()
                    table.insert(customPlayingTracks, track)
                    anim:Destroy()
                    
                    WindUI:Notify({
                        Title = "Custom Animation",
                        Content = "Playing animation!",
                        Duration = 2,
                        Icon = "play"
                    })
                end)
            end
        })
        
        -- Stop custom animation button
        CustomAnimSection:Button({
            Title = "Stop Animation",
            Desc = "Stop all custom animations",
            Callback = function()
                pcall(function()
                    -- Stop tracked custom animations
                    for _, track in ipairs(customPlayingTracks) do
                        pcall(function()
                            if track and track.Stop then
                                track:Stop()
                            end
                        end)
                    end
                    customPlayingTracks = {}
                    
                    -- Stop the loop track too
                    if customAnimTrack then
                        pcall(function()
                            customAnimTrack:Stop()
                        end)
                        customAnimTrack = nil
                    end
                end)
                
                WindUI:Notify({
                    Title = "Custom Animation",
                    Content = "Stopped animations!",
                    Duration = 2,
                    Icon = "square"
                })
            end
        })
    end -- End Custom Animation scope

    -- === ANIMATION PRESETS SECTION ===
    local AnimPresetSection = MiscTab:Section({ Title = "Animation Presets", Icon = "film", Opened = false })
    
    do -- Animation Presets scope
        -- Animation preset state tracking
        local presetPlayingTracks = {}
        local presetLoopConnections = {}
        local presetActiveStates = {}
        
        -- Helper function to get animator
        local function getAnimator()
            local char = LocalPlayer.Character
            if not char then return nil end
            local humanoid = char:FindFirstChildOfClass("Humanoid")
            if not humanoid then return nil end
            local animator = humanoid:FindFirstChildOfClass("Animator")
            if not animator then
                animator = Instance.new("Animator")
                animator.Parent = humanoid
            end
            return animator, humanoid
        end
        
        -- Helper function to stop all preset animations
        local function stopAllPresets()
            for name, tracks in pairs(presetPlayingTracks) do
                for _, track in ipairs(tracks) do
                    pcall(function() track:Stop() end)
                end
            end
            presetPlayingTracks = {}
            for name, conn in pairs(presetLoopConnections) do
                pcall(function() 
                    if type(conn) == "thread" then
                        task.cancel(conn)
                    elseif conn.Disconnect then
                        conn:Disconnect()
                    end
                end)
            end
            presetLoopConnections = {}
            presetActiveStates = {}
            -- Restore walkspeed
            pcall(function()
                local char = LocalPlayer.Character
                if char then
                    local humanoid = char:FindFirstChildOfClass("Humanoid")
                    if humanoid then humanoid.WalkSpeed = 16 end
                end
            end)
        end
        
        -- Helper function to play idle/walk animation preset
        local function playIdleWalkPreset(name, idleId, walkId, priority, walkSpeed)
            local animator, humanoid = getAnimator()
            if not animator then return end
            
            stopAllPresets()
            presetActiveStates[name] = true
            presetPlayingTracks[name] = {}
            
            -- Create idle animation
            local idleAnim = Instance.new("Animation")
            idleAnim.AnimationId = "rbxassetid://" .. idleId
            local idleTrack = animator:LoadAnimation(idleAnim)
            idleTrack.Priority = priority or Enum.AnimationPriority.Action3
            idleTrack.Looped = true
            table.insert(presetPlayingTracks[name], idleTrack)
            
            -- Create walk animation
            local walkAnim = Instance.new("Animation")
            walkAnim.AnimationId = "rbxassetid://" .. walkId
            local walkTrack = animator:LoadAnimation(walkAnim)
            walkTrack.Priority = priority or Enum.AnimationPriority.Action3
            walkTrack.Looped = true
            table.insert(presetPlayingTracks[name], walkTrack)
            
            -- Set walk speed if specified
            if walkSpeed then
                humanoid.WalkSpeed = walkSpeed
            end
            
            -- Play based on movement
            local lastMoving = false
            idleTrack:Play()
            
            presetLoopConnections[name] = RunService.Heartbeat:Connect(function()
                if not presetActiveStates[name] then return end
                local isMoving = humanoid.MoveDirection.Magnitude > 0.1
                if isMoving ~= lastMoving then
                    if isMoving then
                        idleTrack:Stop()
                        walkTrack:Play()
                    else
                        walkTrack:Stop()
                        idleTrack:Play()
                    end
                    lastMoving = isMoving
                end
            end)
            
            WindUI:Notify({ Title = "Animation Preset", Content = name .. " activated!", Duration = 2, Icon = "play" })
        end
        
        -- Helper function to play one-shot animation
        local function playOneShotPreset(name, animId, duration)
            local animator, humanoid = getAnimator()
            if not animator then return end
            
            local anim = Instance.new("Animation")
            anim.AnimationId = "rbxassetid://" .. animId
            local track = animator:LoadAnimation(anim)
            track.Priority = Enum.AnimationPriority.Action4
            track:Play()
            
            if not presetPlayingTracks[name] then presetPlayingTracks[name] = {} end
            table.insert(presetPlayingTracks[name], track)
            
            if duration then
                task.delay(duration, function()
                    pcall(function() track:Stop() end)
                end)
            end
            
            WindUI:Notify({ Title = "Animation Preset", Content = name .. " playing!", Duration = 2, Icon = "play" })
        end
        
        -- Helper function to play looping one-shot animation
        local function playLoopingPreset(name, animId, interval)
            local animator, humanoid = getAnimator()
            if not animator then return end
            
            stopAllPresets()
            presetActiveStates[name] = true
            presetPlayingTracks[name] = {}
            
            local anim = Instance.new("Animation")
            anim.AnimationId = "rbxassetid://" .. animId
            local track = animator:LoadAnimation(anim)
            track.Priority = Enum.AnimationPriority.Action4
            table.insert(presetPlayingTracks[name], track)
            
            presetLoopConnections[name] = task.spawn(function()
                while presetActiveStates[name] do
                    track:Play()
                    task.wait(interval or track.Length or 1)
                end
            end)
            
            WindUI:Notify({ Title = "Animation Preset", Content = name .. " activated!", Duration = 2, Icon = "play" })
        end
        
        -- Stop All Presets Button
        AnimPresetSection:Button({
            Title = "Stop All Presets",
            Desc = "Stop all animation presets and restore normal state",
            Callback = function()
                stopAllPresets()
                WindUI:Notify({ Title = "Animation Preset", Content = "All presets stopped!", Duration = 2, Icon = "square" })
            end
        })
        
        -- ===== ZOMBIE ANIMATIONS =====
        AnimPresetSection:Paragraph({ Title = "━━━ Zombie Animations ━━━", Desc = "" })
        
        AnimPresetSection:Button({
            Title = "Zapper",
            Desc = "Zapper zombie animation with effect",
            Callback = function()
                local animator, humanoid = getAnimator()
                if not animator then return end
                stopAllPresets()
                presetActiveStates["Zapper"] = true
                presetPlayingTracks["Zapper"] = {}
                
                -- Effect animation
                local effectAnim = Instance.new("Animation")
                effectAnim.AnimationId = "rbxassetid://12638401607"
                local effectTrack = animator:LoadAnimation(effectAnim)
                effectTrack.Priority = Enum.AnimationPriority.Action3
                effectTrack.Looped = true
                effectTrack:Play()
                table.insert(presetPlayingTracks["Zapper"], effectTrack)
                
                playIdleWalkPreset("Zapper", "12333488814", "12333490576", Enum.AnimationPriority.Action2, nil)
            end
        })
        
        AnimPresetSection:Button({
            Title = "Zapper Animation",
            Desc = "Standard Zapper zombie animation",
            Callback = function() playIdleWalkPreset("Zapper", "14498563473", "14498289874", Enum.AnimationPriority.Action3, nil) end
        })
        
        AnimPresetSection:Button({
            Title = "Zapper Effect",
            Desc = "Play Zapper special effect once",
            Callback = function() playOneShotPreset("Zapper Effect", "14499470197", nil) end
        })
        
        AnimPresetSection:Button({
            Title = "Shambler Animation",
            Desc = "Shambler zombie idle/walk",
            Callback = function() playIdleWalkPreset("Shambler", "12333488814", "14463730540", Enum.AnimationPriority.Action3, nil) end
        })
        
        AnimPresetSection:Button({
            Title = "Old Shambler",
            Desc = "Old Shambler zombie animation",
            Callback = function() playIdleWalkPreset("Old Shambler", "12333488814", "12333490857", Enum.AnimationPriority.Idle, nil) end
        })
        
        AnimPresetSection:Button({
            Title = "Shambler Eating",
            Desc = "Shambler eating animation (10 sec)",
            Callback = function() playOneShotPreset("Shambler Eating", "18339432914", 10) end
        })
        
        AnimPresetSection:Button({
            Title = "Lantern",
            Desc = "Lantern zombie animation",
            Callback = function() playIdleWalkPreset("Lantern", "14678879479", "14678880308", Enum.AnimationPriority.Action3, nil) end
        })
        
        AnimPresetSection:Button({
            Title = "Cuirassier Animation",
            Desc = "Cuirassier zombie animation",
            Callback = function() playIdleWalkPreset("Cuirassier", "87579228279296", "102081698785465", Enum.AnimationPriority.Action3, nil) end
        })
        
        AnimPresetSection:Button({
            Title = "Cuirassier Alt",
            Desc = "Alternate Cuirassier animation",
            Callback = function() playIdleWalkPreset("Cuirassier Alt", "82800474630427", "118210337289087", Enum.AnimationPriority.Action3, nil) end
        })
        
        AnimPresetSection:Button({
            Title = "Headless zombie",
            Desc = "Headless zombie animation",
            Callback = function() playIdleWalkPreset("Headless zombie", "107080941320600", "74764025513892", Enum.AnimationPriority.Action3, nil) end
        })
        
        AnimPresetSection:Button({
            Title = "Crawler",
            Desc = "Crawling zombie animation",
            Callback = function() playIdleWalkPreset("Crawler", "13726632691", "13726634549", Enum.AnimationPriority.Action3, nil) end
        })
        
        AnimPresetSection:Button({
            Title = "Bomber Animation",
            Desc = "Self-destruct bomber animation",
            Callback = function() playIdleWalkPreset("Bomber Animation", "13211198049", "13211207597", Enum.AnimationPriority.Action3, nil) end
        })
        
        AnimPresetSection:Button({
            Title = "Default",
            Desc = "Default zombie animation",
            Callback = function() playIdleWalkPreset("Default", "180435571", "180426354", Enum.AnimationPriority.Idle, nil) end
        })
        
        -- ===== CHARACTER ANIMATIONS =====
        AnimPresetSection:Paragraph({ Title = "━━━ Character Animations ━━━", Desc = "" })
        
        AnimPresetSection:Button({
            Title = "Boxer",
            Desc = "Boxing animation (click to punch)",
            Callback = function() playIdleWalkPreset("Boxer", "124381258015151", "127477273497271", Enum.AnimationPriority.Action3, 17) end
        })
        
        AnimPresetSection:Button({
            Title = "Dracula",
            Desc = "Dracula vampire animation",
            Callback = function() playIdleWalkPreset("Dracula", "14970033333", "15486477524", Enum.AnimationPriority.Action3, 16) end
        })
        
        AnimPresetSection:Button({
            Title = "Impaled walk",
            Desc = "Impaled walk (slow walk)",
            Callback = function() playIdleWalkPreset("Impaled walk", "111210841378590", "139186204185685", Enum.AnimationPriority.Action3, 5) end
        })
        
        AnimPresetSection:Button({
            Title = "Red Eyes",
            Desc = "Red eyes animation with speed boost (35)",
            Callback = function() playIdleWalkPreset("Red Eyes", "12581784105", "12581785298", Enum.AnimationPriority.Action3, 35) end
        })
        
        AnimPresetSection:Button({
            Title = "Napoleon Hands Behind",
            Desc = "Napoleon hands behind back pose",
            Callback = function() playIdleWalkPreset("Napoleon", "103557875332543", "103557875332543", Enum.AnimationPriority.Action4, nil) end
        })
        
        AnimPresetSection:Button({
            Title = "Freezing/Cold",
            Desc = "Cold shivering animation",
            Callback = function() playIdleWalkPreset("Cold", "16863977222", "16876434500", Enum.AnimationPriority.Action3, nil) end
        })
        
        AnimPresetSection:Button({
            Title = "Low Health",
            Desc = "Injured/low health animation",
            Callback = function() playIdleWalkPreset("Low Health", "14970034680", "15530089342", Enum.AnimationPriority.Idle, nil) end
        })
        
        -- ===== COMBAT ANIMATIONS =====
        AnimPresetSection:Paragraph({ Title = "━━━ Combat Animations ━━━", Desc = "" })
        
        AnimPresetSection:Button({
            Title = "Musket Charge",
            Desc = "Musket charging animation (speed 24)",
            Callback = function() playIdleWalkPreset("Musket Charge", "14292935158", "14292937831", Enum.AnimationPriority.Action3, 24) end
        })
        
        AnimPresetSection:Button({
            Title = "Greatsword Charge",
            Desc = "Greatsword charging animation (speed 24)",
            Callback = function() playIdleWalkPreset("Greatsword Charge", "14284611111", "17406602570", Enum.AnimationPriority.Action3, 24) end
        })
        
        AnimPresetSection:Button({
            Title = "Bayonet Charge",
            Desc = "Standard bayonet charge (speed 24)",
            Callback = function() playIdleWalkPreset("Bayonet Charge", "14284611111", "14284623849", Enum.AnimationPriority.Idle, 24) end
        })
        
        AnimPresetSection:Button({
            Title = "Fake Bayonet",
            Desc = "Fake bayonet stance (click for stab)",
            Callback = function() playIdleWalkPreset("Fake Bayonet", "12333492041", "12333492041", Enum.AnimationPriority.Action3, 17) end
        })
        
        AnimPresetSection:Button({
            Title = "Gun Spin",
            Desc = "Spinning gun trick (looping)",
            Callback = function() playLoopingPreset("Gun Spin", "15827239870", 0.73) end
        })
        
        AnimPresetSection:Button({
            Title = "Elbow Strike",
            Desc = "Elbow strike combo (looping)",
            Callback = function() playLoopingPreset("Elbow Strike", "15345113937", 0.6) end
        })
        
        AnimPresetSection:Button({
            Title = "Skibidi Fast Slash Ahhh",
            Desc = "Super fast slashing with spin",
            Callback = function()
                local animator, humanoid = getAnimator()
                if not animator then return end
                local char = LocalPlayer.Character
                local rootPart = char and char:FindFirstChild("HumanoidRootPart")
                if not rootPart then return end
                
                stopAllPresets()
                presetActiveStates["Skibidi Fast Slash Ahhh"] = true
                presetPlayingTracks["Skibidi Fast Slash Ahhh"] = {}
                
                local anim = Instance.new("Animation")
                anim.AnimationId = "rbxassetid://12591938344"
                local track = animator:LoadAnimation(anim)
                track.Priority = Enum.AnimationPriority.Action4
                table.insert(presetPlayingTracks["Skibidi Fast Slash Ahhh"], track)
                
                local rotationSpeed = 1440
                
                presetLoopConnections["Skibidi Fast Slash Ahhh"] = task.spawn(function()
                    while presetActiveStates["Skibidi Fast Slash Ahhh"] do
                        track:Play()
                        local deltaTime = task.wait(0.1)
                        if rootPart then
                            rootPart.CFrame = rootPart.CFrame * CFrame.Angles(0, math.rad(rotationSpeed * 0.1), 0)
                        end
                    end
                end)
                
                WindUI:Notify({ Title = "Animation Preset", Content = "Skibidi Fast Slash Ahhh activated!", Duration = 2, Icon = "play" })
            end
        })
        
        -- ===== SPECIAL ANIMATIONS =====
        AnimPresetSection:Paragraph({ Title = "━━━ Special Animations ━━━", Desc = "" })
        
        AnimPresetSection:Button({
            Title = "Play Dead",
            Desc = "Play dead/faint animation",
            Callback = function() playOneShotPreset("Play Dead", "89945348540089", nil) end
        })
        
        AnimPresetSection:Button({
            Title = "Sad Dance",
            Desc = "Sad dance (20 sec)",
            Callback = function() playOneShotPreset("Sad Dance", "14860627011", 20) end
        })
        
        AnimPresetSection:Button({
            Title = "Flying",
            Desc = "Flying pose animation (looping)",
            Callback = function() playLoopingPreset("Flying", "110087359963835", nil) end
        })
        
        AnimPresetSection:Button({
            Title = "Headless Horseman",
            Desc = "Headless horseman with music (speed 38)",
            Callback = function()
                local animator, humanoid = getAnimator()
                if not animator then return end
                local char = LocalPlayer.Character
                
                stopAllPresets()
                presetActiveStates["Headless Horseman"] = true
                presetPlayingTracks["Headless Horseman"] = {}
                
                -- Create and play music
                local music = Instance.new("Sound")
                music.SoundId = "rbxassetid://1836635087"
                music.Looped = true
                music.Volume = 5
                music.Parent = char:FindFirstChild("Head") or char
                music:Play()
                
                humanoid.WalkSpeed = 38
                
                playIdleWalkPreset("Headless Horseman", "13936362530", "13936362530", Enum.AnimationPriority.Action3, 38)
                
                -- Store music for cleanup
                presetLoopConnections["Headless Horseman Music"] = music
            end
        })
        
        AnimPresetSection:Button({
            Title = "Eating Long Stick",
            Desc = "Eating something long (Gagging Noises)",
            Callback = function()
                local animator, humanoid = getAnimator()
                if not animator then return end
                
                stopAllPresets()
                presetActiveStates["Eating"] = true
                presetPlayingTracks["Eating"] = {}
                
                local anim = Instance.new("Animation")
                anim.AnimationId = "rbxassetid://16863982325"
                local track = animator:LoadAnimation(anim)
                track.Priority = Enum.AnimationPriority.Action4
                table.insert(presetPlayingTracks["Eating"], track)
                
                presetLoopConnections["Eating"] = task.spawn(function()
                    while presetActiveStates["Eating"] do
                        track:Play()
                        track:AdjustSpeed(0)
                        track.TimePosition = 1.8
                        track:AdjustSpeed(1)
                        task.wait(0.1)
                    end
                end)
                
                WindUI:Notify({ Title = "Animation Preset", Content = "Eating activated!", Duration = 2, Icon = "play" })
            end
        })
        
        AnimPresetSection:Button({
            Title = "Cross Use",
            Desc = "Using a cross animation",
            Callback = function() playOneShotPreset("Cross Use", "15210536563", nil) end
        })
        
        AnimPresetSection:Button({
            Title = "Zombie Breaking The Door",
            Desc = "Zombie breaking door animation",
            Callback = function() playOneShotPreset("Door Breach", "15593727441", nil) end
        })
        
        AnimPresetSection:Button({
            Title = "Crawford",
            Desc = "Crawford special animation",
            Callback = function() playOneShotPreset("Crawford", "77859967130018", nil) end
        })
        
        -- ===== INJURY ANIMATIONS =====
        AnimPresetSection:Paragraph({ Title = "━━━ Injury Animations ━━━", Desc = "" })
        
        AnimPresetSection:Button({
            Title = "Cuirassier Stabbed",
            Desc = "Stabbed by cuirassier animation",
            Callback = function()
                local animator, humanoid = getAnimator()
                if not animator then return end
                
                stopAllPresets()
                presetActiveStates["CuirassierStabbed"] = true
                presetPlayingTracks["CuirassierStabbed"] = {}
                humanoid.WalkSpeed = 0
                
                local anim1 = Instance.new("Animation")
                anim1.AnimationId = "rbxassetid://121955221153387"
                local track1 = animator:LoadAnimation(anim1)
                track1.Priority = Enum.AnimationPriority.Action4
                table.insert(presetPlayingTracks["CuirassierStabbed"], track1)
                track1:Play()
                
                track1.Stopped:Connect(function()
                    -- Check if preset was stopped manually
                    if not presetActiveStates["CuirassierStabbed"] then
                        humanoid.WalkSpeed = 16
                        return
                    end
                    
                    local anim2 = Instance.new("Animation")
                    anim2.AnimationId = "rbxassetid://111210841378590"
                    local track2 = animator:LoadAnimation(anim2)
                    track2.Priority = Enum.AnimationPriority.Action4
                    track2.Looped = true
                    table.insert(presetPlayingTracks["CuirassierStabbed"], track2)
                    track2:Play()
                    
                    track2.Stopped:Connect(function()
                        if presetActiveStates["CuirassierStabbed"] then
                            presetActiveStates["CuirassierStabbed"] = nil
                            presetPlayingTracks["CuirassierStabbed"] = nil
                        end
                        humanoid.WalkSpeed = 16
                    end)
                end)
                
                WindUI:Notify({ Title = "Animation Preset", Content = "Stabbed animation playing!", Duration = 2, Icon = "play" })
            end
        })
        
        AnimPresetSection:Button({
            Title = "Breaking Bones",
            Desc = "Bone breaking/fracture animation",
            Callback = function()
                local animator, humanoid = getAnimator()
                if not animator then return end
                
                stopAllPresets()
                humanoid.WalkSpeed = 0
                
                local anim1 = Instance.new("Animation")
                anim1.AnimationId = "rbxassetid://12333490324"
                local track1 = animator:LoadAnimation(anim1)
                track1.Priority = Enum.AnimationPriority.Action4
                track1:Play()
                
                track1.Stopped:Connect(function()
                    local anim2 = Instance.new("Animation")
                    anim2.AnimationId = "rbxassetid://12333489072"
                    local track2 = animator:LoadAnimation(anim2)
                    track2.Priority = Enum.AnimationPriority.Action4
                    track2:Play()
                    task.delay(3, function()
                        humanoid.WalkSpeed = 16
                    end)
                end)
                
                WindUI:Notify({ Title = "Animation Preset", Content = "Fracture animation playing!", Duration = 2, Icon = "play" })
            end
        })
        
        -- ===== CINEMATIC SEQUENCES =====
        AnimPresetSection:Paragraph({ Title = "━━━ Cinematic Sequences ━━━", Desc = "" })
        
        AnimPresetSection:Button({
            Title = "Blücher",
            Desc = "Blücher cinematic sequence",
            Callback = function()
                local animator, humanoid = getAnimator()
                if not animator then return end
                
                stopAllPresets()
                presetActiveStates["Blucher"] = true
                
                -- Stop all current animations
                for _, track in pairs(humanoid:GetPlayingAnimationTracks()) do
                    track:Stop()
                end
                
                local animIds = {"15603033178", "16168689655", "15680560478", "15688743558", "15637342030"}
                local tracks = {}
                
                for i, id in ipairs(animIds) do
                    local anim = Instance.new("Animation")
                    anim.AnimationId = "rbxassetid://" .. id
                    tracks[i] = animator:LoadAnimation(anim)
                    tracks[i].Priority = Enum.AnimationPriority.Action4
                end
                
                task.spawn(function()
                    if not presetActiveStates["Blucher"] then return end
                    tracks[1]:Play()
                    tracks[1].Stopped:Wait()
                    
                    if not presetActiveStates["Blucher"] then return end
                    tracks[2]:Play()
                    tracks[2].Stopped:Wait()
                    
                    if not presetActiveStates["Blucher"] then return end
                    tracks[3]:Play()
                    task.wait(3)
                    if tracks[3].IsPlaying then tracks[3]:Stop() end
                    
                    if not presetActiveStates["Blucher"] then return end
                    tracks[4]:Play()
                    tracks[4].Stopped:Wait()
                    
                    if not presetActiveStates["Blucher"] then return end
                    tracks[3]:Play()
                    task.wait(3)
                    if tracks[3].IsPlaying then tracks[3]:Stop() end
                    
                    if not presetActiveStates["Blucher"] then return end
                    tracks[5]:Play()
                    tracks[5].Stopped:Wait()
                    
                    presetActiveStates["Blucher"] = false
                    WindUI:Notify({ Title = "Animation Preset", Content = "Blücher sequence complete!", Duration = 2, Icon = "check" })
                end)
                
                WindUI:Notify({ Title = "Animation Preset", Content = "Blücher sequence started!", Duration = 2, Icon = "play" })
            end
        })
        
        AnimPresetSection:Button({
            Title = "idk",
            Desc = "idk officer cinematic sequence",
            Callback = function()
                local animator, humanoid = getAnimator()
                if not animator then return end
                
                stopAllPresets()
                presetActiveStates["Adjutant"] = true
                
                for _, track in pairs(humanoid:GetPlayingAnimationTracks()) do
                    track:Stop()
                end
                
                local animIds = {"15603037116", "15622136729", "15688841016", "15637317651"}
                local tracks = {}
                
                for i, id in ipairs(animIds) do
                    local anim = Instance.new("Animation")
                    anim.AnimationId = "rbxassetid://" .. id
                    tracks[i] = animator:LoadAnimation(anim)
                    tracks[i].Priority = Enum.AnimationPriority.Action4
                end
                
                task.spawn(function()
                    if not presetActiveStates["Adjutant"] then return end
                    tracks[1]:Play()
                    tracks[1].Stopped:Wait()
                    
                    if not presetActiveStates["Adjutant"] then return end
                    tracks[2]:Play()
                    tracks[2].Stopped:Wait()
                    
                    if not presetActiveStates["Adjutant"] then return end
                    tracks[3]:Play()
                    task.wait(9)
                    if tracks[3].IsPlaying then tracks[3]:Stop() end
                    
                    if not presetActiveStates["Adjutant"] then return end
                    tracks[4]:Play()
                    tracks[4].Stopped:Wait()
                    
                    presetActiveStates["Adjutant"] = false
                    WindUI:Notify({ Title = "Animation Preset", Content = "idk sequence complete!", Duration = 2, Icon = "check" })
                end)
                
                WindUI:Notify({ Title = "Animation Preset", Content = "idk sequence started!", Duration = 2, Icon = "play" })
            end
        })
        
        AnimPresetSection:Button({
            Title = "Barry",
            Desc = "Barry getting bitten cinematic sequence",
            Callback = function()
                local animator, humanoid = getAnimator()
                if not animator then return end
                
                stopAllPresets()
                presetActiveStates["Barry"] = true
                
                for _, track in pairs(humanoid:GetPlayingAnimationTracks()) do
                    track:Stop()
                end
                
                local animIds = {"14284371664", "14284387207", "14284382730", "14304936421"}
                local tracks = {}
                
                for i, id in ipairs(animIds) do
                    local anim = Instance.new("Animation")
                    anim.AnimationId = "rbxassetid://" .. id
                    tracks[i] = animator:LoadAnimation(anim)
                    tracks[i].Priority = Enum.AnimationPriority.Action4
                end
                
                task.spawn(function()
                    if not presetActiveStates["Barry"] then return end
                    tracks[1]:Play()
                    tracks[1].Stopped:Wait()
                    
                    if not presetActiveStates["Barry"] then return end
                    tracks[2]:Play()
                    task.wait(10)
                    if tracks[2].IsPlaying then tracks[2]:Stop() end
                    
                    if not presetActiveStates["Barry"] then return end
                    tracks[3]:Play()
                    tracks[3].Stopped:Wait()
                    
                    if not presetActiveStates["Barry"] then return end
                    tracks[2]:Play(0, 1, -1) -- Play reversed
                    task.wait(3)
                    if tracks[2].IsPlaying then tracks[2]:Stop() end
                    
                    if not presetActiveStates["Barry"] then return end
                    tracks[4]:Play()
                    tracks[4].Stopped:Wait()
                    
                    presetActiveStates["Barry"] = false
                    WindUI:Notify({ Title = "Animation Preset", Content = "Barry sequence complete!", Duration = 2, Icon = "check" })
                end)
                
                WindUI:Notify({ Title = "Animation Preset", Content = "Barry sequence started!", Duration = 2, Icon = "play" })
            end
        })
        
    end -- End Animation Presets scope

    -- === OLD GUARD TEMPORARY SECTION ===
    local OldGuardSection = MiscTab:Section({ Title = "Old Guard Temporary", Icon = "shield", Opened = false })
    
    do -- Old Guard scope
        local ChangeClassEvent = game:GetService("ReplicatedStorage").Events.Regiment.ChangeClass
        
        OldGuardSection:Button({
            Title = "Seaman",
            Desc = "Change class to Seaman (French Infantry)",
            Callback = function()
                pcall(function()
                    _G.SafeFireServer(ChangeClassEvent, "Seaman", 5, "French", "Infantry")
                end)
                WindUI:Notify({
                    Title = "Old Guard",
                    Content = "Changed to Seaman!",
                    Duration = 2,
                    Icon = "anchor"
                })
            end
        })
        
        OldGuardSection:Button({
            Title = "Officer",
            Desc = "Change class to Officer (French Infantry)",
            Callback = function()
                pcall(function()
                    _G.SafeFireServer(ChangeClassEvent, "Officer", 5, "French", "Infantry")
                end)
                WindUI:Notify({
                    Title = "Old Guard",
                    Content = "Changed to Officer!",
                    Duration = 2,
                    Icon = "star"
                })
            end
        })
        
        OldGuardSection:Button({
            Title = "Musician",
            Desc = "Change class to Musician (French Infantry)",
            Callback = function()
                pcall(function()
                    _G.SafeFireServer(ChangeClassEvent, "Musician", 5, "French", "Infantry")
                end)
                WindUI:Notify({
                    Title = "Old Guard",
                    Content = "Changed to Musician!",
                    Duration = 2,
                    Icon = "music"
                })
            end
        })
        
        OldGuardSection:Button({
            Title = "LineInfantry",
            Desc = "Change class to Line Infantry (French Infantry)",
            Callback = function()
                pcall(function()
                    _G.SafeFireServer(ChangeClassEvent, "LineInfantry", 5, "French", "Infantry")
                end)
                WindUI:Notify({
                    Title = "Old Guard",
                    Content = "Changed to Line Infantry!",
                    Duration = 2,
                    Icon = "users"
                })
            end
        })
        
        OldGuardSection:Button({
            Title = "Sapper",
            Desc = "Change class to Sapper (French Infantry)",
            Callback = function()
                pcall(function()
                    _G.SafeFireServer(ChangeClassEvent, "Sapper", 5, "French", "Infantry")
                end)
                WindUI:Notify({
                    Title = "Old Guard",
                    Content = "Changed to Sapper!",
                    Duration = 2,
                    Icon = "hammer"
                })
            end
        })
    end -- End Old Guard scope

    -- === COLDSTREAM TEMPORARY SECTION (British) ===
    local ColdStreamSection = MiscTab:Section({ Title = "Temporary ColdStream (British)", Icon = "flag", Opened = false })
    
    do -- ColdStream scope
        local ChangeClassEvent = game:GetService("ReplicatedStorage").Events.Regiment.ChangeClass
        
        ColdStreamSection:Button({
            Title = "Seaman",
            Desc = "Change class to Seaman (British Infantry)",
            Callback = function()
                pcall(function()
                    _G.SafeFireServer(ChangeClassEvent, "Seaman", 4, "British", "Infantry")
                end)
                WindUI:Notify({
                    Title = "ColdStream",
                    Content = "Changed to Seaman!",
                    Duration = 2,
                    Icon = "anchor"
                })
            end
        })
        
        ColdStreamSection:Button({
            Title = "Officer",
            Desc = "Change class to Officer (British Infantry)",
            Callback = function()
                pcall(function()
                    _G.SafeFireServer(ChangeClassEvent, "Officer", 4, "British", "Infantry")
                end)
                WindUI:Notify({
                    Title = "ColdStream",
                    Content = "Changed to Officer!",
                    Duration = 2,
                    Icon = "star"
                })
            end
        })
        
        ColdStreamSection:Button({
            Title = "Musician",
            Desc = "Change class to Musician (British Infantry)",
            Callback = function()
                pcall(function()
                    _G.SafeFireServer(ChangeClassEvent, "Musician", 4, "British", "Infantry")
                end)
                WindUI:Notify({
                    Title = "ColdStream",
                    Content = "Changed to Musician!",
                    Duration = 2,
                    Icon = "music"
                })
            end
        })
        
        ColdStreamSection:Button({
            Title = "LineInfantry",
            Desc = "Change class to Line Infantry (British Infantry)",
            Callback = function()
                pcall(function()
                    _G.SafeFireServer(ChangeClassEvent, "LineInfantry", 4, "British", "Infantry")
                end)
                WindUI:Notify({
                    Title = "ColdStream",
                    Content = "Changed to Line Infantry!",
                    Duration = 2,
                    Icon = "users"
                })
            end
        })
        
        ColdStreamSection:Button({
            Title = "Sapper",
            Desc = "Change class to Sapper (British Infantry)",
            Callback = function()
                pcall(function()
                    _G.SafeFireServer(ChangeClassEvent, "Sapper", 4, "British", "Infantry")
                end)
                WindUI:Notify({
                    Title = "ColdStream",
                    Content = "Changed to Sapper!",
                    Duration = 2,
                    Icon = "hammer"
                })
            end
        })
    end -- End ColdStream scope

    -- === WalkSpeed forcing ===
    desiredWalkSpeed = 16 -- Global for keybind access
    walkLoopEnabled = false -- Global for keybind access
    local heartbeatConn = nil
    -- Use weak keys so entries for destroyed humanoids are garbage collected
    local humPropConns = setmetatable({}, { __mode = "k" }) -- [Humanoid] = connection

    local function safeSetWalk(hum, speed)
        if not (hum and hum.Parent) then return end
        pcall(function()
            hum.WalkSpeed = speed
        end)
    end

    local function onHumanoidPropChanged(hum)
        -- immediate restore if WalkSpeed changed by something else
        return hum:GetPropertyChangedSignal("WalkSpeed"):Connect(function()
            if walkLoopEnabled then
                safeSetWalk(hum, desiredWalkSpeed)
            end
        end)
    end

    function attachToCharacter(character) -- Global for keybind access
        if not character then return end
        local hum = character:FindFirstChildOfClass("Humanoid")
        if not hum then
            hum = character:WaitForChild("Humanoid", 2)
        end
        if hum then
            -- ensure no duplicate connection
            if humPropConns[hum] then
                pcall(function() humPropConns[hum]:Disconnect() end)
                humPropConns[hum] = nil
            end
            humPropConns[hum] = onHumanoidPropChanged(hum)
            -- immediate enforce
            safeSetWalk(hum, desiredWalkSpeed)
        end
    end

    local function detachAllHumanoidConns()
        for hum, conn in pairs(humPropConns) do
            pcall(function() conn:Disconnect() end)
        end
        humPropConns = setmetatable({}, { __mode = "k" })
    end

    function startWalkForceLoop() -- Global for keybind access
        if heartbeatConn then heartbeatConn:Disconnect() end
        heartbeatConn = RunService.Heartbeat:Connect(function()
            if not walkLoopEnabled then return end
            local char = LocalPlayer and LocalPlayer.Character
            if char then
                local hum = char:FindFirstChildOfClass("Humanoid")
                if hum then
                    -- enforce every tick
                    safeSetWalk(hum, desiredWalkSpeed)
                    -- ensure we have a property watcher attached
                    if not humPropConns[hum] then
                        humPropConns[hum] = onHumanoidPropChanged(hum)
                    end
                end
            end
        end)
    end

    function stopWalkForceLoop() -- Global for keybind access
        if heartbeatConn then
            heartbeatConn:Disconnect()
            heartbeatConn = nil
        end
        detachAllHumanoidConns()
        -- restore default on toggle off
        pcall(function()
            local char = LocalPlayer and LocalPlayer.Character
            if char then
                local hum = char:FindFirstChildOfClass("Humanoid")
                if hum then hum.WalkSpeed = 16 end
            end
        end)
    end

    -- keep hooking on character spawn
    if LocalPlayer then
        LocalPlayer.CharacterAdded:Connect(function(char)
            -- wait briefly for humanoid to exist
            task.wait(0.15)
            if walkLoopEnabled then
                attachToCharacter(char)
                startWalkForceLoop()
            end
        end)
    end

    -- Movement UI: slider max 35 (does NOT immediately apply - waits for toggle)
    MovementSection:Slider({
        Title = "WalkSpeed",
        Flag = "Movement_1",
        Desc = "Set walkspeed value",
        Step = 1,
        Value = { Min = 16, Max = 35, Default = desiredWalkSpeed },
        Callback = function(v)
            desiredWalkSpeed = math.clamp(tonumber(v) or desiredWalkSpeed, 16, 35)
            -- Only apply if the toggle is already enabled
            if walkLoopEnabled then
                local char = LocalPlayer and LocalPlayer.Character
                if char then
                    local hum = char:FindFirstChildOfClass("Humanoid")
                    if hum then safeSetWalk(hum, desiredWalkSpeed) end
                end
            end
        end
    })

    local ApplyWalkSpeedToggle = MovementSection:Toggle({
        Title = "Apply WalkSpeed",
        Flag = "Movement_2",
        Desc = "Force Walkspeed",
        Default = false,
        Callback = function(state)
            walkLoopEnabled = state
            if state then
                -- attach to current character, start heartbeat enforcement
                if LocalPlayer and LocalPlayer.Character then attachToCharacter(LocalPlayer.Character) end
                startWalkForceLoop()
                WindUI:Notify({ Title = "Movement", Content = "WalkSpeed enabled.", Duration = 2, Icon = "check" })
            else
                stopWalkForceLoop()
                WindUI:Notify({ Title = "Movement", Content = "WalkSpeed disabled.", Duration = 2, Icon = "x" })
            end
        end
    })
    _G.KatchiToggleElements = _G.KatchiToggleElements or {}
    _G.KatchiToggleElements.ApplyWalkSpeed = ApplyWalkSpeedToggle

-- ===== FLY FEATURE (Freecam with Soul Clone) =====
-- Freecam fly with transparent soul clone that looks where camera is looking
do
    -- State variables
    local freecamEnabled = false
    local flySpeed = 50
    local soulTransparency = 0.6
    local soulHoverPosition = Vector3.new()
    local idleThreshold = 0.1
    
    -- Soul mode variables
    local soulCameraSubject = nil
    local soulModel = nil -- Transparent clone of character
    local originalCameraType = nil
    local originalCameraSubject = nil
    
    -- Saved positions for teleport
    local savedPositions = {} -- { {name=..., position=Vector3}, ... }
    local selectedPositionIndex = nil -- Currently selected position in dropdown
    local teleportLoopEnabled = false
    local teleportLoopConnection = nil
    
    -- Input state
    local keysHeld = { W = false, A = false, S = false, D = false, Space = false, Shift = false }
    local moveDir = Vector3.new()
    
    -- Connections
    local flyRenderConn = nil
    local flyHeartbeatConn = nil
    local flyInputBeganConn = nil
    local flyInputEndedConn = nil
    
    -- UI references (forward declarations)
    local FreecamToggle = nil
    local TeleportDropdown = nil
    local LoopTeleportToggle = nil
    
    -- Get character parts
    local function getCharParts()
        local char = LocalPlayer.Character
        if not char then return nil, nil, nil end
        local rootPart = char:FindFirstChild("HumanoidRootPart")
        local humanoid = char:FindFirstChildOfClass("Humanoid")
        return char, rootPart, humanoid
    end
    
    -- Update movement direction based on CURRENT camera orientation (called every frame)
    local function updateMoveDir()
        local camera = workspace.CurrentCamera
        if not camera then moveDir = Vector3.new(); return end
        
        local forward = camera.CFrame.LookVector
        local right = camera.CFrame.RightVector
        local up = Vector3.new(0, 1, 0)
        
        local direction = Vector3.new()
        
        if keysHeld.W then direction = direction + forward end
        if keysHeld.S then direction = direction - forward end
        if keysHeld.A then direction = direction - right end
        if keysHeld.D then direction = direction + right end
        if keysHeld.Space then direction = direction + up end
        if keysHeld.Shift then direction = direction - up end
        
        if direction.Magnitude > 0.1 then
            moveDir = direction.Unit * flySpeed
        else
            moveDir = Vector3.new()
        end
    end
    
    -- Create soul model (blue transparent orb)
    local function createSoulModel(position)
        if soulModel then soulModel:Destroy() end
        
        -- Create simple blue orb
        soulModel = Instance.new("Part")
        -- Use randomized name for anti-detection
        soulModel.Name = _G.getRandomInstanceName and _G.getRandomInstanceName() or ("Part_" .. math.random(10000, 99999))
        soulModel.Shape = Enum.PartType.Ball
        soulModel.Size = Vector3.new(4, 4, 4)
        soulModel.Position = position
        soulModel.Anchored = true
        soulModel.CanCollide = false
        soulModel.Material = Enum.Material.Neon
        soulModel.Color = Color3.fromRGB(50, 150, 255)
        soulModel.Transparency = soulTransparency
        soulModel.Parent = workspace
        
        return soulModel
    end
    
    -- Update soul model position
    local function updateSoulModel()
        if not soulModel or not freecamEnabled then return end
        
        soulModel.Position = soulHoverPosition
    end
    
    -- Stop teleport loop
    local function stopTeleportLoop()
        teleportLoopEnabled = false
        if teleportLoopConnection then
            teleportLoopConnection:Disconnect()
            teleportLoopConnection = nil
        end
    end
    
    -- Start teleport loop to selected position
    local function startTeleportLoop()
        if not selectedPositionIndex or not savedPositions[selectedPositionIndex] then
            WindUI:Notify({ Title = "Loop Teleport", Content = "Select a position from dropdown first!", Duration = 3, Icon = "alert-circle" })
            return false
        end
        
        stopTeleportLoop()
        teleportLoopEnabled = true
        
        local position = savedPositions[selectedPositionIndex].position
        
        teleportLoopConnection = RunService.Heartbeat:Connect(function()
            local char, rootPart = getCharParts()
            if not rootPart or not rootPart.Parent then
                stopTeleportLoop()
                return
            end
            
            local currentRot = rootPart.CFrame - rootPart.CFrame.Position
            rootPart.CFrame = CFrame.new(position) * currentRot
        end)
        
        return true
    end
    
    -- Start freecam mode
    local function startFreecam()
        local char, rootPart, humanoid = getCharParts()
        if not rootPart then return false end
        
        local camera = workspace.CurrentCamera
        if not camera then return false end
        
        freecamEnabled = true
        
        originalCameraType = camera.CameraType
        originalCameraSubject = camera.CameraSubject
        
        -- Anchor character in place
        rootPart.Anchored = true
        rootPart.AssemblyLinearVelocity = Vector3.new()
        rootPart.AssemblyAngularVelocity = Vector3.new()
        
        -- Create invisible camera subject for freecam
        soulCameraSubject = Instance.new("Part")
        -- Use randomized name for anti-detection
        soulCameraSubject.Name = _G.getRandomInstanceName and _G.getRandomInstanceName() or ("Part_" .. math.random(10000, 99999))
        soulCameraSubject.Size = Vector3.new(1, 1, 1)
        soulCameraSubject.Transparency = 1
        soulCameraSubject.Anchored = true
        soulCameraSubject.CanCollide = false
        soulCameraSubject.Position = camera.CFrame.Position
        soulCameraSubject.Parent = workspace
        
        camera.CameraType = Enum.CameraType.Custom
        camera.CameraSubject = soulCameraSubject
        
        soulHoverPosition = soulCameraSubject.Position
        
        -- Create soul clone (transparent copy of character)
        createSoulModel(soulHoverPosition)
        
        return true
    end
    
    -- Stop freecam mode
    local function stopFreecam()
        freecamEnabled = false
        
        local char, rootPart, humanoid = getCharParts()
        local camera = workspace.CurrentCamera
        
        if camera then
            camera.CameraType = originalCameraType or Enum.CameraType.Custom
            camera.CameraSubject = humanoid or originalCameraSubject
        end
        
        if rootPart then rootPart.Anchored = false end
        if soulCameraSubject then soulCameraSubject:Destroy(); soulCameraSubject = nil end
        if soulModel then soulModel:Destroy(); soulModel = nil end
        
        -- Reset keys
        for k in pairs(keysHeld) do keysHeld[k] = false end
        moveDir = Vector3.new()
    end
    
    -- Refresh dropdown with saved positions
    local function refreshDropdown()
        if TeleportDropdown then
            local names = {}
            for _, p in ipairs(savedPositions) do
                table.insert(names, p.name)
            end
            pcall(function() TeleportDropdown:Refresh(names) end)
        end
    end
    
    -- Save current position (saves soul position)
    local function saveCurrentPosition()
        if not freecamEnabled then
            WindUI:Notify({ Title = "Save Position", Content = "Enable Freecam first to scout and save positions!", Duration = 3, Icon = "alert-circle" })
            return
        end
        
        local pos = soulHoverPosition
        local name = "Pos " .. (#savedPositions + 1)
        table.insert(savedPositions, { name = name, position = pos })
        
        WindUI:Notify({ 
            Title = "Position Saved", 
            Content = string.format("%s: (%.0f, %.0f, %.0f)", name, pos.X, pos.Y, pos.Z), 
            Duration = 3, 
            Icon = "map-pin" 
        })
        
        -- Refresh dropdown
        refreshDropdown()
    end
    
    -- Main update loops
    local function setupFlyLoops()
        if flyRenderConn then flyRenderConn:Disconnect() end
        if flyHeartbeatConn then flyHeartbeatConn:Disconnect() end
        
        -- RenderStepped for smooth visual updates
        flyRenderConn = RunService.RenderStepped:Connect(function()
            -- Always recalculate movement direction based on current camera
            if freecamEnabled then
                updateMoveDir()
                updateSoulModel()
            end
        end)
        
        -- Heartbeat for physics updates
        flyHeartbeatConn = RunService.Heartbeat:Connect(function(dt)
            if not freecamEnabled or not soulCameraSubject then return end
            
            pcall(function()
                -- Move the camera subject (freecam)
                if moveDir.Magnitude > idleThreshold then
                    soulCameraSubject.CFrame = soulCameraSubject.CFrame + moveDir * dt
                    soulHoverPosition = soulCameraSubject.Position
                else
                    soulCameraSubject.CFrame = CFrame.new(soulHoverPosition) * soulCameraSubject.CFrame.Rotation
                end
            end)
        end)
    end
    
    -- Setup input handlers
    local function setupFlyInput()
        if flyInputBeganConn then flyInputBeganConn:Disconnect() end
        if flyInputEndedConn then flyInputEndedConn:Disconnect() end
        
        -- Mobile thumbstick tracking
        local thumbstickMoveDir = Vector3.new()
        local isMobile = UserInputService.TouchEnabled
        
        -- Get move direction from mobile thumbstick/controls
        local function getMobileMovement()
            local success, moveVector = pcall(function()
                local PlayerModule = LocalPlayer:FindFirstChild("PlayerScripts")
                    and LocalPlayer.PlayerScripts:FindFirstChild("PlayerModule")
                if PlayerModule then
                    local ControlModule = require(PlayerModule):GetControls()
                    if ControlModule and ControlModule.GetMoveVector then
                        return ControlModule:GetMoveVector()
                    end
                end
                return Vector3.new()
            end)
            return success and moveVector or Vector3.new()
        end
        
        -- Update movement direction including mobile input
        local originalUpdateMoveDir = updateMoveDir
        updateMoveDir = function()
            local camera = workspace.CurrentCamera
            if not camera then moveDir = Vector3.new(); return end
            
            local forward = camera.CFrame.LookVector
            local right = camera.CFrame.RightVector
            local up = Vector3.new(0, 1, 0)
            
            local direction = Vector3.new()
            
            -- Keyboard input
            if keysHeld.W then direction = direction + forward end
            if keysHeld.S then direction = direction - forward end
            if keysHeld.A then direction = direction - right end
            if keysHeld.D then direction = direction + right end
            if keysHeld.Space then direction = direction + up end
            if keysHeld.Shift then direction = direction - up end
            
            -- Mobile thumbstick input (if no keyboard input)
            if direction.Magnitude < 0.1 and isMobile then
                local mobileMove = getMobileMovement()
                if mobileMove.Magnitude > 0.1 then
                    -- Convert thumbstick input to camera-relative movement
                    -- mobileMove.X = left/right, mobileMove.Z = forward/back
                    direction = direction + (right * mobileMove.X)
                    direction = direction + (forward * -mobileMove.Z) -- Negative because Z is inverted
                end
            end
            
            if direction.Magnitude > 0.1 then
                moveDir = direction.Unit * flySpeed
            else
                moveDir = Vector3.new()
            end
        end
        
        flyInputBeganConn = UserInputService.InputBegan:Connect(function(input, gameProcessed)
            if gameProcessed then return end
            if not freecamEnabled then return end
            
            if input.UserInputType == Enum.UserInputType.Keyboard then
                local key = input.KeyCode
                if key == Enum.KeyCode.W then keysHeld.W = true
                elseif key == Enum.KeyCode.A then keysHeld.A = true
                elseif key == Enum.KeyCode.S then keysHeld.S = true
                elseif key == Enum.KeyCode.D then keysHeld.D = true
                elseif key == Enum.KeyCode.Space then keysHeld.Space = true
                elseif key == Enum.KeyCode.LeftShift or key == Enum.KeyCode.LeftControl then keysHeld.Shift = true
                end
            end
            
            -- Mobile: Jump button = go up
            if input.UserInputType == Enum.UserInputType.Touch then
                -- Check if this is the jump button area (usually bottom right)
                -- We'll use a simpler approach - any touch that triggers Jump action
            end
        end)
        
        flyInputEndedConn = UserInputService.InputEnded:Connect(function(input)
            if not freecamEnabled then return end
            
            if input.UserInputType == Enum.UserInputType.Keyboard then
                local key = input.KeyCode
                if key == Enum.KeyCode.W then keysHeld.W = false
                elseif key == Enum.KeyCode.A then keysHeld.A = false
                elseif key == Enum.KeyCode.S then keysHeld.S = false
                elseif key == Enum.KeyCode.D then keysHeld.D = false
                elseif key == Enum.KeyCode.Space then keysHeld.Space = false
                elseif key == Enum.KeyCode.LeftShift or key == Enum.KeyCode.LeftControl then keysHeld.Shift = false
                end
            end
        end)
        
        -- Mobile: Jump request = go up
        if isMobile then
            local jumpConn = nil
            jumpConn = UserInputService.JumpRequest:Connect(function()
                if freecamEnabled then
                    -- Toggle Space held for 0.3 seconds
                    keysHeld.Space = true
                    task.delay(0.3, function()
                        keysHeld.Space = false
                    end)
                end
            end)
            
            -- Store connection for cleanup
            table.insert(_G.FreecamMobileConns or {}, jumpConn)
            _G.FreecamMobileConns = _G.FreecamMobileConns or {}
            table.insert(_G.FreecamMobileConns, jumpConn)
        end
    end
    
    -- Initialize
    setupFlyLoops()
    setupFlyInput()
    
    -- Clean up on character respawn
    LocalPlayer.CharacterAdded:Connect(function()
        if freecamEnabled then
            stopFreecam()
            pcall(function() if FreecamToggle then FreecamToggle:SetValue(false) end end)
        end
        stopTeleportLoop()
        pcall(function() if LoopTeleportToggle then LoopTeleportToggle:SetValue(false) end end)
    end)
    
    -- ===== UI ELEMENTS =====
    
    -- Freecam Toggle
    FreecamToggle = MovementSection:Toggle({
        Title = "Freecam Fly",
        Flag = "Movement_Freecam",
        Desc = "Freecam Fly to save positions.",
        Default = false,
        Callback = function(state)
            if state then
                local success = startFreecam()
                if success then
                    WindUI:Notify({ Title = "Freecam", Content = "Flying.", Duration = 4, Icon = "ghost" })
                else
                    WindUI:Notify({ Title = "Freecam", Content = "Failed", Duration = 3, Icon = "x" })
                    pcall(function() FreecamToggle:SetValue(false) end)
                end
            else
                stopFreecam()
                WindUI:Notify({ Title = "Freecam", Content = "Freecam disabled", Duration = 2, Icon = "x" })
            end
        end
    })
    _G.KatchiToggleElements = _G.KatchiToggleElements or {}
    _G.KatchiToggleElements.Freecam = FreecamToggle
    
    -- Fly Speed Slider
    MovementSection:Slider({
        Title = "Fly Speed",
        Flag = "Movement_FlySpeed",
        Desc = "Adjust freecam fly speed",
        Step = 1,
        Value = {
            Min = 10,
            Max = 200,
            Default = 25,
        },
        Callback = function(value)
            flySpeed = value
        end
    })
    
    -- Save Position Button
    MovementSection:Button({
        Title = "Save Position",
        Desc = "Save current position. Requires Freecam to be active.",
        Callback = function()
            saveCurrentPosition()
        end
    })
    
    -- Select Position Dropdown (just selects, doesn't teleport)
    TeleportDropdown = MovementSection:Dropdown({
        Title = "Select Position",
        Flag = "Movement_SelectPosition",
        Desc = "Select a saved position for Loop Teleport",
        Values = {},
        Multi = false,
        Callback = function(selected)
            if not selected or type(selected) ~= "string" or selected == "" then 
                selectedPositionIndex = nil
                return 
            end
            
            for i, posData in ipairs(savedPositions) do
                if posData.name == selected then
                    selectedPositionIndex = i
                    WindUI:Notify({ Title = "Selected", Content = posData.name .. " selected for teleport", Duration = 2, Icon = "check" })
                    break
                end
            end
        end
    })
    
    -- Loop Teleport Toggle
    LoopTeleportToggle = MovementSection:Toggle({
        Title = "Loop Teleport",
        Flag = "Movement_LoopTeleport",
        Desc = "Continuously teleport to selected position",
        Default = false,
        Callback = function(state)
            if state then
                -- Exit freecam if active
                if freecamEnabled then
                    stopFreecam()
                    pcall(function() FreecamToggle:SetValue(false) end)
                end
                
                local success = startTeleportLoop()
                if success then
                    WindUI:Notify({ Title = "Loop Teleport", Content = "Looping to " .. savedPositions[selectedPositionIndex].name, Duration = 3, Icon = "repeat" })
                else
                    pcall(function() LoopTeleportToggle:SetValue(false) end)
                end
            else
                stopTeleportLoop()
                WindUI:Notify({ Title = "Loop Teleport", Content = "Loop stopped", Duration = 2, Icon = "x" })
            end
        end
    })
    _G.KatchiToggleElements.LoopTeleport = LoopTeleportToggle
    
    -- Clear Saved Positions Button
    MovementSection:Button({
        Title = "Clear All Saved Positions",
        Desc = "Delete all saved teleport positions",
        Callback = function()
            stopTeleportLoop()
            pcall(function() LoopTeleportToggle:SetValue(false) end)
            savedPositions = {}
            selectedPositionIndex = nil
            
            -- Clear dropdown
            refreshDropdown()
            
            WindUI:Notify({ Title = "Cleared", Content = "All saved positions deleted", Duration = 2, Icon = "trash-2" })
        end
    })
end
-- ===== END FLY FEATURE =====

-- Auto Remove Horses (Performance boost)
AutoRemoveHorsesEnabled = false -- Global for keybind access
local autoRemoveConn = nil
local removeTicker = 0

local function removeHorsesOnce()
    -- Saint Petersburg: workspace["Saint Petersburg"].Modes.Holdout.HorseCarriage.Horses
    pcall(function()
        local sp = Workspace:FindFirstChild("Saint Petersburg")
        if sp and sp:FindFirstChild("Modes") then
            local modes = sp.Modes
            if modes:FindFirstChild("Holdout") and modes.Holdout:FindFirstChild("HorseCarriage") then
                local hc = modes.Holdout.HorseCarriage
                local horses = hc:FindFirstChild("Horses")
                if horses then
                    horses:Destroy()
                end
            end
        end
    end)

    -- Westminster: workspace.Westminster.Modes.Objective.SecondWagon.Wagon.Horses
    pcall(function()
        local west = Workspace:FindFirstChild("Westminster")
        if west and west:FindFirstChild("Modes") then
            local modes = west.Modes
            if modes:FindFirstChild("Objective") then
                local obj = modes.Objective

                if obj:FindFirstChild("SecondWagon") and obj.SecondWagon:FindFirstChild("Wagon") then
                    local horses = obj.SecondWagon.Wagon:FindFirstChild("Horses")
                    if horses then horses:Destroy() end
                end

                if obj:FindFirstChild("WagonEvent") and obj.WagonEvent:FindFirstChild("Wagon") then
                    local horses = obj.WagonEvent.Wagon:FindFirstChild("Horses")
                    if horses then horses:Destroy() end
                end
            end
        end
    end)
end

local AutoRemoveHorsesToggle = VisualSection:Toggle({
    Title = "Auto Remove Horses (Performance boost)",
    Flag = "Visual_AutoRemoveHorses",
    Desc = "Removes the horses to reduce lag, mainly on westminster.",
    Default = false,
    Callback = function(state)
        AutoRemoveHorsesEnabled = state
        if state then
            -- immediate attempt
            pcall(removeHorsesOnce)

            -- connect heartbeat to keep removing (runs roughly once/second)
            if autoRemoveConn then
                pcall(function() autoRemoveConn:Disconnect() end)
                autoRemoveConn = nil
            end
            removeTicker = 0
            autoRemoveConn = RunService.Heartbeat:Connect(function(dt)
                if not AutoRemoveHorsesEnabled then return end
                removeTicker = removeTicker + (dt or 0)
                if removeTicker >= 1 then
                    removeTicker = 0
                    pcall(removeHorsesOnce)
                end
            end)

            pcall(function()
                if WindUI and WindUI.Notify then
                    WindUI:Notify({ Title = "Visual", Content = "Auto Remove Horses enabled", Duration = 2, Icon = "trash" })
                end
            end)
        else
            -- disable
            if autoRemoveConn then
                pcall(function() autoRemoveConn:Disconnect() end)
                autoRemoveConn = nil
            end
            pcall(function()
                if WindUI and WindUI.Notify then
                    WindUI:Notify({ Title = "Visual", Content = "Auto Remove Horses disabled", Duration = 2, Icon = "trash-off" })
                end
            end)
        end
    end
})
_G.KatchiToggleElements = _G.KatchiToggleElements or {}
_G.KatchiToggleElements.AutoRemoveHorses = AutoRemoveHorsesToggle

-- === Simplified Visuals: Fullbright & NoFog ===
local Lighting = game:GetService("Lighting")

local fullbrightEnabled = false
local noFogEnabled = false

-- Save originals for restoration
local originalLighting = {
    Brightness = Lighting.Brightness,
    ClockTime = Lighting.ClockTime,
    FogEnd = Lighting.FogEnd,
    GlobalShadows = Lighting.GlobalShadows,
    OutdoorAmbient = Lighting.OutdoorAmbient,
}

-- Simple Fullbright - just set values once
local function applyFullbright()
    pcall(function()
        Lighting.Brightness = 2
        Lighting.ClockTime = 14
        Lighting.FogEnd = 100000
        Lighting.GlobalShadows = false
        Lighting.OutdoorAmbient = Color3.fromRGB(128, 128, 128)
    end)
end

local function restoreFullbright()
    pcall(function()
        Lighting.Brightness = originalLighting.Brightness
        Lighting.ClockTime = originalLighting.ClockTime
        if not noFogEnabled then
            Lighting.FogEnd = originalLighting.FogEnd
        end
        Lighting.GlobalShadows = originalLighting.GlobalShadows
        Lighting.OutdoorAmbient = originalLighting.OutdoorAmbient
    end)
end

-- Simple NoFog - just set FogEnd and destroy Atmospheres
local function applyNoFog()
    pcall(function()
        Lighting.FogEnd = 100000
        for _, v in pairs(Lighting:GetDescendants()) do
            if v:IsA("Atmosphere") then
                v:Destroy()
            end
        end
    end)
end

local function restoreNoFog()
    if not fullbrightEnabled then
        pcall(function()
            Lighting.FogEnd = originalLighting.FogEnd
        end)
    end
end

-- UI toggles
VisualSection:Toggle({
    Title = "Fullbright",
    Flag = "Visual_1",
    Desc = "Enable fullbright lighting",
    Default = false,
    Callback = function(state)
        fullbrightEnabled = state
        if state then
            applyFullbright()
            WindUI:Notify({ Title = "Visual", Content = "Fullbright enabled.", Duration = 2, Icon = "sun" })
        else
            restoreFullbright()
            WindUI:Notify({ Title = "Visual", Content = "Fullbright disabled.", Duration = 2, Icon = "moon" })
        end
    end
})

VisualSection:Toggle({
    Title = "No Fog",
    Flag = "Visual_2",
    Desc = "Remove fog and atmospheres",
    Default = false,
    Callback = function(state)
        noFogEnabled = state
        if state then
            applyNoFog()
            WindUI:Notify({ Title = "Visual", Content = "NoFog enabled.", Duration = 2, Icon = "cloud-off" })
        else
            restoreNoFog()
            WindUI:Notify({ Title = "Visual", Content = "NoFog disabled.", Duration = 2, Icon = "cloud" })
        end
    end
})

-- === FOV Changer ===
local originalFieldOfView = nil
local fovChangerEnabled = false
local currentFOV = 70

pcall(function()
    originalFieldOfView = workspace.CurrentCamera.FieldOfView
end)

local function applyFOV(fov)
    pcall(function()
        workspace.CurrentCamera.FieldOfView = fov
    end)
end

local function restoreFOV()
    pcall(function()
        workspace.CurrentCamera.FieldOfView = originalFieldOfView or 70
    end)
end

VisualSection:Toggle({
    Title = "FOV Changer",
    Flag = "Visual_FOVChanger",
    Desc = "Change your camera field of view",
    Default = false,
    Callback = function(state)
        fovChangerEnabled = state
        if state then
            applyFOV(currentFOV)
            WindUI:Notify({ Title = "Visual", Content = "FOV Changer enabled (" .. currentFOV .. ")", Duration = 2, Icon = "eye" })
        else
            restoreFOV()
            WindUI:Notify({ Title = "Visual", Content = "FOV Changer disabled.", Duration = 2, Icon = "eye-off" })
        end
    end
})

VisualSection:Slider({
    Title = "FOV Value",
    Flag = "Visual_FOVValue",
    Desc = "Adjust field of view (default: 70)",
    Value = { Min = 30, Max = 120, Default = 70 },
    Callback = function(value)
        currentFOV = value
        if fovChangerEnabled then
            applyFOV(value)
        end
    end
})

-- === Infinite Zoom ===
local infiniteZoomEnabled = false
local originalMinZoomDistance = nil
local originalMaxZoomDistance = nil
local zoomConnection = nil

local function applyInfiniteZoom()
    pcall(function()
        local player = Players.LocalPlayer
        if not player then return end
        
        -- Store original values
        if originalMinZoomDistance == nil then
            originalMinZoomDistance = player.CameraMinZoomDistance
        end
        if originalMaxZoomDistance == nil then
            originalMaxZoomDistance = player.CameraMaxZoomDistance
        end
        
        -- Set infinite zoom
        player.CameraMinZoomDistance = 0.5
        player.CameraMaxZoomDistance = 9999
    end)
end

local function restoreZoom()
    pcall(function()
        local player = Players.LocalPlayer
        if not player then return end
        
        player.CameraMinZoomDistance = originalMinZoomDistance or 0.5
        player.CameraMaxZoomDistance = originalMaxZoomDistance or 128
    end)
end

VisualSection:Toggle({
    Title = "Infinite Zoom",
    Flag = "Visual_InfiniteZoom",
    Desc = "Remove zoom distance limits",
    Default = false,
    Callback = function(state)
        infiniteZoomEnabled = state
        if state then
            applyInfiniteZoom()
            -- Keep applying in case game resets it
            if zoomConnection then zoomConnection:Disconnect() end
            zoomConnection = RunService.Heartbeat:Connect(function()
                if not infiniteZoomEnabled then return end
                pcall(function()
                    local player = Players.LocalPlayer
                    if player and player.CameraMaxZoomDistance < 9999 then
                        player.CameraMaxZoomDistance = 9999
                    end
                end)
            end)
            WindUI:Notify({ Title = "Visual", Content = "Infinite Zoom enabled.", Duration = 2, Icon = "zoom-in" })
        else
            if zoomConnection then zoomConnection:Disconnect() zoomConnection = nil end
            restoreZoom()
            WindUI:Notify({ Title = "Visual", Content = "Infinite Zoom disabled.", Duration = 2, Icon = "zoom-out" })
        end
    end
})

    -- === Server Modifiers ===
    noFallDamageEnabled = false -- Global for keybind access
    noFallDamageThread = nil -- Global for keybind access

    function noFallDamageLoop() -- Global for keybind access
        while noFallDamageEnabled do
            task.wait(1)

            local char = LocalPlayer and LocalPlayer.Character
            if not char then
                continue
            end

            -- Guts & BlackPowder style "Health" instance with ForceSelfDamage
            local health = char:FindFirstChild("Health")
            if not health then
                continue
            end

            local forceSelfDamage = health:FindFirstChild("ForceSelfDamage")
            if not forceSelfDamage then
                continue
            end

            -- Send 0 damage repeatedly to neutralize fall damage
            pcall(function()
                _G.SafeFireServer(forceSelfDamage, 0)
            end)
        end
    end

    local NoFallDamageToggle = ServerModifiersSection:Toggle({
        Title = "No Fall Damage",
        Flag = "ServerMods_NoFallDamage",
        Desc = "Removes fall damage",
        Default = false,
        Callback = function(state)
            noFallDamageEnabled = state

            if state then
                -- (Re)start the loop
                if noFallDamageThread then
                    pcall(task.cancel, noFallDamageThread)
                end

                noFallDamageThread = task.spawn(noFallDamageLoop)

                WindUI:Notify({
                    Title = "Server Modifiers",
                    Content = "No Fall Damage enabled.",
                    Duration = 2,
                    Icon = "shield-check",
                })
            else
                -- Stop the loop
                if noFallDamageThread then
                    pcall(task.cancel, noFallDamageThread)
                    noFallDamageThread = nil
                end

                WindUI:Notify({
                    Title = "Server Modifiers",
                    Content = "No Fall Damage disabled.",
                    Duration = 2,
                    Icon = "shield-off",
                })
            end
        end
    })
    _G.KatchiToggleElements = _G.KatchiToggleElements or {}
    _G.KatchiToggleElements.NoFallDamage = NoFallDamageToggle

    -- === Baguette Purchase ===
    ServerModifiersSection:Button({
        Title = "Get Baguette",
        Desc = "Purchase the Baguette item from the server",
        Callback = function()
            pcall(function()
                local args = {
                    [1] = "Baguette"
                }
                _G.SafeFireServer(game:GetService("ReplicatedStorage").Events.Customize.PurchaseEvent, unpack(args))
            end)
            WindUI:Notify({
                Title = "Server Modifiers",
                Content = "Baguette purchase requested!",
                Duration = 2,
                Icon = "cookie"
            })
        end
    })

    -- === Voivode Purchase ===
    ServerModifiersSection:Button({
        Title = "Get Voivode",
        Desc = "Purchase the Voivode item from the server",
        Callback = function()
            pcall(function()
                _G.SafeFireServer(game:GetService("ReplicatedStorage").Events.Customize.PurchaseEvent, "Voivode")
            end)
            WindUI:Notify({
                Title = "Server Modifiers",
                Content = "Voivode purchase requested!",
                Duration = 2,
                Icon = "crown"
            })
        end
    })

    -- === Iron Stake Purchase ===
    ServerModifiersSection:Button({
        Title = "Get Iron Stake",
        Desc = "Purchase the Iron Stake item from the server",
        Callback = function()
            pcall(function()
                _G.SafeFireServer(game:GetService("ReplicatedStorage").Events.Customize.PurchaseEvent, "Iron Stake")
            end)
            WindUI:Notify({
                Title = "Server Modifiers",
                Content = "Iron Stake purchase requested!",
                Duration = 2,
                Icon = "swords"
            })
        end
    })

    -- === Fly (Climbing-based smooth flight) ===
    FlyEnabled = false -- Global for keybind access
    FlySpeed = 25 -- Default fly speed
    local flyBodyVelocity = nil
    FlyBodyGyro = nil -- Global so Auto Look can detect flying
    local flyConnection = nil
    local flyAnimConnection = nil -- Connection to stop climb animations
    local flyStateConnection = nil -- Connection to enforce climbing state
    local flyMobileGui = nil -- Mobile UI for up/down buttons
    local flyLastMoveTime = 0 -- Track when player last moved (for anti-AFK)
    local flyMobileUp = false -- Is mobile up button held
    local flyMobileDown = false -- Is mobile down button held
    local flyAntiAfkRunning = false -- Anti-AFK loop flag
    local flyAntiAfkResetting = false -- True during anti-AFK state reset

    -- Create mobile fly controls
    local function createFlyMobileUI()
        if flyMobileGui and flyMobileGui.Parent then return end
        
        local playerGui = LocalPlayer:FindFirstChild("PlayerGui")
        if not playerGui then return end
        
        flyMobileGui = Instance.new("ScreenGui")
        flyMobileGui.ResetOnSpawn = false
        flyMobileGui.ZIndexBehavior = Enum.ZIndexBehavior.Sibling
        if _G.protectGUI then _G.protectGUI(flyMobileGui) else flyMobileGui.Parent = playerGui end -- Use stealth protection
        
        -- Container frame on the right side
        local container = Instance.new("Frame")
        -- Use randomized name for anti-detection
        container.Name = "Frame_" .. math.random(10000, 99999)
        container.Size = UDim2.new(0, 70, 0, 150)
        container.Position = UDim2.new(1, -85, 0.5, -75)
        container.BackgroundTransparency = 1
        container.Parent = flyMobileGui
        
        -- Up button
        local upBtn = Instance.new("TextButton")
        -- Use randomized name
        upBtn.Name = "Button_" .. math.random(10000, 99999)
        upBtn.Size = UDim2.new(1, 0, 0, 65)
        upBtn.Position = UDim2.new(0, 0, 0, 0)
        upBtn.BackgroundColor3 = Color3.fromRGB(50, 150, 255)
        upBtn.BackgroundTransparency = 0.3
        upBtn.Text = "▲"
        upBtn.TextColor3 = Color3.fromRGB(255, 255, 255)
        upBtn.TextSize = 32
        upBtn.Font = Enum.Font.GothamBold
        upBtn.Parent = container
        
        local upCorner = Instance.new("UICorner")
        upCorner.CornerRadius = UDim.new(0, 12)
        upCorner.Parent = upBtn
        
        local upStroke = Instance.new("UIStroke")
        upStroke.Color = Color3.fromRGB(255, 255, 255)
        upStroke.Thickness = 2
        upStroke.Transparency = 0.5
        upStroke.Parent = upBtn
        
        -- Down button
        local downBtn = Instance.new("TextButton")
        -- Use randomized name
        downBtn.Name = "Button_" .. math.random(10000, 99999)
        downBtn.Size = UDim2.new(1, 0, 0, 65)
        downBtn.Position = UDim2.new(0, 0, 0, 85)
        downBtn.BackgroundColor3 = Color3.fromRGB(255, 100, 50)
        downBtn.BackgroundTransparency = 0.3
        downBtn.Text = "▼"
        downBtn.TextColor3 = Color3.fromRGB(255, 255, 255)
        downBtn.TextSize = 32
        downBtn.Font = Enum.Font.GothamBold
        downBtn.Parent = container
        
        local downCorner = Instance.new("UICorner")
        downCorner.CornerRadius = UDim.new(0, 12)
        downCorner.Parent = downBtn
        
        local downStroke = Instance.new("UIStroke")
        downStroke.Color = Color3.fromRGB(255, 255, 255)
        downStroke.Thickness = 2
        downStroke.Transparency = 0.5
        downStroke.Parent = downBtn
        
        -- Connect button events
        upBtn.MouseButton1Down:Connect(function() flyMobileUp = true end)
        upBtn.MouseButton1Up:Connect(function() flyMobileUp = false end)
        upBtn.MouseLeave:Connect(function() flyMobileUp = false end)
        
        downBtn.MouseButton1Down:Connect(function() flyMobileDown = true end)
        downBtn.MouseButton1Up:Connect(function() flyMobileDown = false end)
        downBtn.MouseLeave:Connect(function() flyMobileDown = false end)
        
        -- Touch events for mobile
        upBtn.TouchLongPress:Connect(function() flyMobileUp = true end)
        upBtn.TouchEnded:Connect(function() flyMobileUp = false end)
        
        downBtn.TouchLongPress:Connect(function() flyMobileDown = true end)
        downBtn.TouchEnded:Connect(function() flyMobileDown = false end)
    end
    
    local function destroyFlyMobileUI()
        flyMobileUp = false
        flyMobileDown = false
        if flyMobileGui then
            flyMobileGui:Destroy()
            flyMobileGui = nil
        end
    end

    local function startFly()
        local char = LocalPlayer and LocalPlayer.Character
        if not char then return end
        
        local hrp = char:FindFirstChild("HumanoidRootPart")
        local humanoid = char:FindFirstChildOfClass("Humanoid")
        if not hrp or not humanoid then return end
        
        
        -- Use Climbing state to bypass anti-cheat
        pcall(function()
            humanoid:ChangeState(Enum.HumanoidStateType.Climbing)
        end)
        
        -- Create BodyVelocity for smooth movement
        flyBodyVelocity = Instance.new("BodyVelocity")
        -- Use randomized name for anti-detection
        flyBodyVelocity.Name = _G.getRandomInstanceName and _G.getRandomInstanceName() or ("BV_" .. math.random(10000, 99999))
        flyBodyVelocity.MaxForce = Vector3.new(math.huge, math.huge, math.huge)
        flyBodyVelocity.Velocity = Vector3.new(0, 0, 0)
        flyBodyVelocity.Parent = hrp
        
        -- Create BodyGyro for full 3D rotation following camera
        FlyBodyGyro = Instance.new("BodyGyro")
        -- Use randomized name
        FlyBodyGyro.Name = _G.getRandomInstanceName and _G.getRandomInstanceName() or ("BG_" .. math.random(10000, 99999))
        FlyBodyGyro.MaxTorque = Vector3.new(math.huge, math.huge, math.huge)
        FlyBodyGyro.P = 50000
        FlyBodyGyro.D = 1000
        FlyBodyGyro.Parent = hrp
        
        -- Enforce climbing state when it changes (except for dead/ragdoll/physics)
        -- This is the key anti-AFK mechanism - always force back to climbing immediately
        local blockList = {
            [Enum.HumanoidStateType.Dead] = true,
            [Enum.HumanoidStateType.Ragdoll] = true,
            [Enum.HumanoidStateType.Physics] = true,
        }
        
        local function tryEnforceClimb()
            if not FlyEnabled then return end
            if humanoid and humanoid.Parent and humanoid:GetState() ~= Enum.HumanoidStateType.Climbing then
                pcall(function()
                    humanoid:ChangeState(Enum.HumanoidStateType.Climbing)
                end)
            end
        end
        
        -- Immediately enforce climbing on start
        tryEnforceClimb()
        
        flyStateConnection = humanoid.StateChanged:Connect(function(_, newState)
            if not FlyEnabled then return end
            if blockList[newState] then return end
            -- Small delay to avoid rapid flip-flop, then force back to climbing
            task.defer(tryEnforceClimb)
        end)
        
        -- Mark anti-AFK as running (no separate loop needed now)
        flyAntiAfkRunning = true
        
        -- Stop climbing and falling animations when they play (so character looks still)
        local animator = humanoid:FindFirstChildOfClass("Animator")
        if animator then
            flyAnimConnection = animator.AnimationPlayed:Connect(function(track)
                if not FlyEnabled then return end
                local name = track.Name:lower()
                local animId = ""
                pcall(function() animId = track.Animation and track.Animation.AnimationId or "" end)
                animId = animId:lower()
                -- Stop climbing and falling animations
                if name:find("climb") or animId:find("climb") or name:find("fall") or animId:find("fall") then
                    pcall(function() track:Stop(0) end)
                end
            end)
            -- Stop any currently playing climb or fall animations
            for _, track in pairs(animator:GetPlayingAnimationTracks()) do
                local name = track.Name:lower()
                local animId = ""
                pcall(function() animId = track.Animation and track.Animation.AnimationId or "" end)
                animId = animId:lower()
                if name:find("climb") or animId:find("climb") or name:find("fall") or animId:find("fall") then
                    pcall(function() track:Stop(0) end)
                end
            end
        end
        
        -- Main fly loop
        -- Frame counter for aggressive state refresh
        local flyFrameCounter = 0
        local FLY_STATE_REFRESH_INTERVAL = 30 -- Force refresh every 30 frames (~0.5 sec at 60fps)
        
        flyConnection = RunService.RenderStepped:Connect(function()
            if not FlyEnabled then return end

            local char = LocalPlayer and LocalPlayer.Character
            if not char then return end
            
            local hrp = char:FindFirstChild("HumanoidRootPart")
            local humanoid = char:FindFirstChildOfClass("Humanoid")
            local camera = Workspace.CurrentCamera

            if not hrp or not humanoid or not camera then return end

            -- Aggressively battle the game's ladder detection
            -- Force climbing state every frame if not in it, and periodically refresh to reset game's timer
            if not flyAntiAfkResetting then
                flyFrameCounter = flyFrameCounter + 1
                local ok, state = pcall(function() return humanoid:GetState() end)
                
                if ok then
                    local isDead = state == Enum.HumanoidStateType.Dead
                    local isRagdoll = state == Enum.HumanoidStateType.Ragdoll
                    
                    if not isDead and not isRagdoll then
                        -- Every frame: if not climbing, force it back
                        if state ~= Enum.HumanoidStateType.Climbing then
                            pcall(function() humanoid:ChangeState(Enum.HumanoidStateType.Climbing) end)
                        end
                        
                        -- Every N frames: force a state refresh cycle to reset game's internal ladder timer
                        if flyFrameCounter >= FLY_STATE_REFRESH_INTERVAL then
                            flyFrameCounter = 0
                            pcall(function()
                                -- Quickly toggle to Running then back to Climbing to reset the timer
                                humanoid:ChangeState(Enum.HumanoidStateType.Running)
                            end)
                            task.defer(function()
                                if FlyEnabled and humanoid and humanoid.Parent and not flyAntiAfkResetting then
                                    pcall(function() humanoid:ChangeState(Enum.HumanoidStateType.Climbing) end)
                                end
                            end)
                        end
                    end
                else
                    -- Fallback: attempt to set climbing regardless
                    pcall(function() humanoid:ChangeState(Enum.HumanoidStateType.Climbing) end)
                end
            end

            -- Get camera CFrame for full 3D rotation
            local camCF = camera.CFrame
            local lookVector = camCF.LookVector
            local rightVector = camCF.RightVector
            
            -- Calculate movement based on input
            local moveDirection = Vector3.new(0, 0, 0)
            
            -- Check if we're on mobile/touch device
            local isMobile = UserInputService.TouchEnabled and not UserInputService.KeyboardEnabled
            
            if isMobile then
                -- Mobile: Use humanoid MoveDirection for horizontal movement (from joystick)
                local humMoveDir = humanoid.MoveDirection
                if humMoveDir.Magnitude > 0.1 then
                    -- Project move direction onto camera's horizontal plane
                    local flatLook = Vector3.new(lookVector.X, 0, lookVector.Z).Unit
                    local flatRight = Vector3.new(rightVector.X, 0, rightVector.Z).Unit
                    
                    -- Get forward/back and left/right components from humanoid move direction
                    local forwardAmount = humMoveDir:Dot(flatLook)
                    local rightAmount = humMoveDir:Dot(flatRight)
                    
                    -- Apply to full 3D camera vectors for proper pitch following
                    moveDirection = moveDirection + lookVector * forwardAmount
                    moveDirection = moveDirection + rightVector * rightAmount
                end
                
                -- Mobile up/down buttons
                if flyMobileUp then
                    moveDirection = moveDirection + Vector3.new(0, 1, 0)
                end
                if flyMobileDown then
                    moveDirection = moveDirection - Vector3.new(0, 1, 0)
                end
            else
                -- PC: Use keyboard input
                if UserInputService:IsKeyDown(Enum.KeyCode.W) then
                    moveDirection = moveDirection + lookVector
                end
                if UserInputService:IsKeyDown(Enum.KeyCode.S) then
                    moveDirection = moveDirection - lookVector
                end
                if UserInputService:IsKeyDown(Enum.KeyCode.A) then
                    moveDirection = moveDirection - rightVector
                end
                if UserInputService:IsKeyDown(Enum.KeyCode.D) then
                    moveDirection = moveDirection + rightVector
                end
                if UserInputService:IsKeyDown(Enum.KeyCode.E) then
                    moveDirection = moveDirection + Vector3.new(0, 1, 0)
                end
                if UserInputService:IsKeyDown(Enum.KeyCode.Q) then
                    moveDirection = moveDirection - Vector3.new(0, 1, 0)
                end
            end
            
            -- Normalize and apply speed
            if moveDirection.Magnitude > 0 then
                moveDirection = moveDirection.Unit * FlySpeed
                -- Update last move time for anti-AFK (player is actively moving)
                flyLastMoveTime = tick()
            end
            
            -- Apply smooth velocity with lerp
            if flyBodyVelocity and flyBodyVelocity.Parent then
                local currentVel = flyBodyVelocity.Velocity
                flyBodyVelocity.Velocity = currentVel:Lerp(moveDirection, 0.2)
            end
            
            -- Apply gyro to follow camera (Auto Look manages this externally when it has a target)
            -- Only apply if FlyBodyGyro has torque (Auto Look sets it to 0 when it takes over)
            if FlyBodyGyro and FlyBodyGyro.Parent and FlyBodyGyro.MaxTorque.Magnitude > 0 then
                FlyBodyGyro.CFrame = camCF
            end
        end)
    end

    local function stopFly()
        -- Stop anti-AFK loop
        flyAntiAfkRunning = false
        flyAntiAfkResetting = false
        
        -- Disconnect the fly loop
        if flyConnection then
            flyConnection:Disconnect()
            flyConnection = nil
        end
        
        -- Disconnect animation stopper
        if flyAnimConnection then
            flyAnimConnection:Disconnect()
            flyAnimConnection = nil
        end
        
        -- Disconnect state enforcer
        if flyStateConnection then
            flyStateConnection:Disconnect()
            flyStateConnection = nil
        end
        
        -- Remove BodyVelocity
        if flyBodyVelocity then
            flyBodyVelocity:Destroy()
            flyBodyVelocity = nil
        end
        
        -- Remove BodyGyro
        if FlyBodyGyro then
            FlyBodyGyro:Destroy()
            FlyBodyGyro = nil
        end
        
        -- Clean up Auto Look BodyGyro if it exists (since fly is stopping)
        local char = LocalPlayer and LocalPlayer.Character
        if char then
            local hrp = char:FindFirstChild("HumanoidRootPart")
            if hrp then
                local autoLookGyro = hrp:FindFirstChild("KatchiAutoLookGyro")
                if autoLookGyro then
                    autoLookGyro:Destroy()
                end
            end
        end
        
        -- Reset humanoid state to normal
        char = LocalPlayer and LocalPlayer.Character
        if char then
            local humanoid = char:FindFirstChildOfClass("Humanoid")
            if humanoid then
                pcall(function()
                    humanoid:ChangeState(Enum.HumanoidStateType.GettingUp)
                end)
                -- Force back to running state after a brief moment
                task.delay(0.1, function()
                    pcall(function()
                        if humanoid and humanoid.Parent then
                            humanoid:ChangeState(Enum.HumanoidStateType.Running)
                        end
                    end)
                end)
            end
        end
    end

    -- Handle character respawn
    LocalPlayer.CharacterAdded:Connect(function(newChar)
        if FlyEnabled then
            task.wait(0.5)
            startFly()
        end
    end)

    local FlyToggle = ServerModifiersSection:Toggle({
        Title = "Fly",
        Flag = "ServerMods_Fly",
        Desc = "Fly Bypass.",
        Default = false,
        Callback = function(state)
            FlyEnabled = state
            
            if state then
                startFly()
                WindUI:Notify({
                    Title = "Server Modifiers",
                    Content = "Fly enabled.",
                    Duration = 3,
                    Icon = "plane",
                })
            else
                stopFly()
                WindUI:Notify({
                    Title = "Server Modifiers",
                    Content = "Fly disabled.",
                    Duration = 2,
                    Icon = "plane-landing",
                })
            end
        end
    })
    _G.KatchiToggleElements.Fly = FlyToggle

    local FlyMobileButtonsEnabled = false
    ServerModifiersSection:Toggle({
        Title = "Fly Mobile Buttons",
        Flag = "ServerMods_FlyMobileButtons",
        Desc = "Show buttons on screen for mobile fly controls",
        Default = false,
        Callback = function(state)
            FlyMobileButtonsEnabled = state
            if state then
                createFlyMobileUI()
                WindUI:Notify({
                    Title = "Server Modifiers",
                    Content = "Mobile fly buttons enabled.",
                    Duration = 2,
                    Icon = "smartphone",
                })
            else
                destroyFlyMobileUI()
                WindUI:Notify({
                    Title = "Server Modifiers",
                    Content = "Mobile fly buttons disabled.",
                    Duration = 2,
                    Icon = "smartphone",
                })
            end
        end
    })

    ServerModifiersSection:Slider({
        Title = "Fly Speed",
        Flag = "ServerMods_FlySpeed",
        Desc = "Adjust flight speed",
        Step = 1,
        Value = { Min = 10, Max = 35, Default = 25 },
        Callback = function(v)
            FlySpeed = tonumber(v) or 25
        end
    })

    -- === Server utilities ===
    ServerSection:Button({
        Title = "Rejoin Server",
        Desc = "Leave and rejoin the same game",
        Callback = function()
            WindUI:Notify({ Title = "Server", Content = "Rejoining server...", Duration = 3, Icon = "refresh-cw" })
            pcall(function() TeleportService:Teleport(game.PlaceId, LocalPlayer) end)
        end
    })

    ServerSection:Button({
        Title = "Server Hop",
        Desc = "Switch to a different server",
        Callback = function()
            WindUI:Notify({ Title = "Server", Content = "Finding new server...", Duration = 3, Icon = "server" })
            local servers = {}
            local success, result = pcall(function()
                return game:HttpGet(string.format("https://games.roblox.com/v1/games/%d/servers/Public?sortOrder=Asc&limit=100", game.PlaceId))
            end)
            if success and result and type(result) == "string" then
                local ok, data = pcall(function() return HttpService:JSONDecode(result) end)
                if ok and data and data.data then
                    for _, v in pairs(data.data) do
                        if v.playing < v.maxPlayers and v.id ~= game.JobId then table.insert(servers, v.id) end
                    end
                end
            end
            if #servers > 0 then
                pcall(function() TeleportService:TeleportToPlaceInstance(game.PlaceId, servers[math.random(1,#servers)], LocalPlayer) end)
            else
                WindUI:Notify({ Title = "Error", Content = "No available servers found.", Duration = 5, Icon = "server-crash" })
            end
        end
    })

    -- end block
end -- end of Misc Tab

task.wait(0.1) -- Delay to prevent lag
do -- // Maps Hacks Tab
    local MapsHacksTab = Main1Section:Tab({ Title = "Maps Hacks", Icon = "map" })
    
    local BerezinaSection = MapsHacksTab:Section({
        Title = "Berezina",
        Icon = "hammer",
        Opened = false
    })
    
    -- ===== BEREZINA MAP FEATURES =====
    local Players = game:GetService("Players")
    local RunService = game:GetService("RunService")
    local Workspace = game:GetService("Workspace")
    local LocalPlayer = Players.LocalPlayer
    
    -- Auto Repair Bridge
    local autoRepairBridgeEnabled = false
    local autoRepairBridgeConn = nil
    
    -- Cache bridge reference to avoid repeated FindFirstChild calls
    local cachedBridge = nil
    local lastBridgeCheck = 0
    local BRIDGE_CACHE_INTERVAL = 2 -- Re-check bridge existence every 2 seconds
    
    local function getNearestBridgeConstruct()
        local char = LocalPlayer.Character
        if not char then return nil end
        local root = char:FindFirstChild("HumanoidRootPart")
        if not root then return nil end
        local rootPos = root.Position
        
        -- Cache bridge reference
        local now = tick()
        if now - lastBridgeCheck > BRIDGE_CACHE_INTERVAL then
            lastBridgeCheck = now
            cachedBridge = nil
            pcall(function()
                local berezina = Workspace:FindFirstChild("Berezina")
                if berezina then
                    local modes = berezina:FindFirstChild("Modes")
                    if modes then
                        local holdout = modes:FindFirstChild("Holdout")
                        if holdout then
                            cachedBridge = holdout:FindFirstChild("Bridge")
                        end
                    end
                end
            end)
        end
        
        if not cachedBridge or not cachedBridge.Parent then 
            cachedBridge = nil
            return nil 
        end
        
        local nearest, dist = nil, math.huge
        
        -- Use GetChildren once and iterate (avoids creating new table every call)
        local sections = cachedBridge:GetChildren()
        for i = 1, #sections do
            local section = sections[i]
            if not section then continue end
            
            -- Check Posts
            local posts = section:FindFirstChild("Posts")
            if posts then
                local postParts = posts:GetChildren()
                for j = 1, #postParts do
                    local part = postParts[j]
                    if part and part:IsA("BasePart") then
                        local health = part:FindFirstChild("ConstructHealth")
                        if health then
                            local d = (part.Position - rootPos).Magnitude
                            if d < dist then
                                dist = d
                                nearest = health
                            end
                        end
                    end
                end
            end
            
            -- Check Beam
            local beam = section:FindFirstChild("Beam")
            if beam then
                local beamHealth = beam:FindFirstChild("ConstructHealth")
                if beamHealth then
                    local d = (beam.Position - rootPos).Magnitude
                    if d < dist then
                        dist = d
                        nearest = beamHealth
                    end
                end
            end
            
            -- Check Joists
            local sectionChildren = section:GetChildren()
            for j = 1, #sectionChildren do
                local joists = sectionChildren[j]
                if joists and joists.Name == "Joists" then
                    local joistsHealth = joists:FindFirstChild("ConstructHealth")
                    if joistsHealth then
                        local d = (joists.Position - rootPos).Magnitude
                        if d < dist then
                            dist = d
                            nearest = joistsHealth
                        end
                    end
                end
            end
        end
        
        return nearest
    end
    
    local function doRepairBridge()
        local target = getNearestBridgeConstruct()
        if not target then return end
        
        local char = LocalPlayer.Character
        if not char then return end
        
        -- Find hammer in backpack or character
        local hammer = LocalPlayer.Backpack:FindFirstChild("Hammer") 
            or LocalPlayer.Backpack:FindFirstChild("Claw Hammer")
            or char:FindFirstChild("Hammer")
            or char:FindFirstChild("Claw Hammer")
        
        if not hammer or not hammer:FindFirstChild("RemoteEvent") then return end
        
        pcall(function()
            _G.SafeFireServer(hammer.RemoteEvent, "Repair", target)
        end)
    end
    
    local autoRepairBridgeTicker = 0
    local AutoRepairBridgeToggle = BerezinaSection:Toggle({
        Title = "Auto Repair Bridge",
        Flag = "Berezina_AutoRepairBridge",
        Desc = "Automatically repairs the bridge.",
        Default = false,
        Callback = function(state)
            autoRepairBridgeEnabled = state
            if state then
                if autoRepairBridgeConn then autoRepairBridgeConn:Disconnect() end
                autoRepairBridgeTicker = 0
                autoRepairBridgeConn = RunService.Heartbeat:Connect(function(dt)
                    if not autoRepairBridgeEnabled then return end
                    -- Throttle to once every 0.2 seconds for performance
                    autoRepairBridgeTicker = autoRepairBridgeTicker + (dt or 0)
                    if autoRepairBridgeTicker < 0.2 then return end
                    autoRepairBridgeTicker = 0
                    doRepairBridge()
                end)
                WindUI:Notify({
                    Title = "Auto Repair Bridge",
                    Content = "Enabled",
                    Duration = 3,
                    Icon = "hammer"
                })
            else
                if autoRepairBridgeConn then
                    autoRepairBridgeConn:Disconnect()
                    autoRepairBridgeConn = nil
                end
            end
        end
    })
    _G.KatchiToggleElements = _G.KatchiToggleElements or {}
    _G.KatchiToggleElements.AutoRepairBridge = AutoRepairBridgeToggle
    
    -- Auto Grab Log (finds nearest log)
    local autoGrabLogEnabled = false
    local autoGrabLogThread = nil
    
    -- Helper: Find nearest log interact remote
    local function findNearestLogInteract()
        local char = LocalPlayer.Character
        if not char or not char:FindFirstChild("HumanoidRootPart") then return nil end
        local root = char.HumanoidRootPart
        
        local holdout = Workspace:FindFirstChild("Berezina")
            and Workspace.Berezina:FindFirstChild("Modes")
            and Workspace.Berezina.Modes:FindFirstChild("Holdout")
        
        if not holdout then return nil end
        
        local nearest, nearestDist = nil, math.huge
        
        -- Search for all Log folders in Holdout
        for _, child in pairs(holdout:GetChildren()) do
            if child.Name == "Log" or child.Name:find("Log") then
                -- Check for Log model inside
                local logModel = child:FindFirstChild("Log")
                if logModel then
                    local interact = logModel:FindFirstChild("Interact")
                    if interact and interact:IsA("RemoteEvent") then
                        -- Get position of log
                        local logPart = logModel:FindFirstChildWhichIsA("BasePart")
                        if logPart then
                            local dist = (logPart.Position - root.Position).Magnitude
                            if dist < nearestDist then
                                nearestDist = dist
                                nearest = interact
                            end
                        else
                            -- No part found, just use this one
                            nearest = nearest or interact
                        end
                    end
                end
                -- Also check if child itself has Interact
                local directInteract = child:FindFirstChild("Interact")
                if directInteract and directInteract:IsA("RemoteEvent") then
                    local logPart = child:FindFirstChildWhichIsA("BasePart")
                    if logPart then
                        local dist = (logPart.Position - root.Position).Magnitude
                        if dist < nearestDist then
                            nearestDist = dist
                            nearest = directInteract
                        end
                    end
                end
            end
        end
        
        return nearest
    end
    
    local AutoGrabLogToggle = BerezinaSection:Toggle({
        Title = "Auto Grab Log",
        Flag = "Berezina_AutoGrabLog",
        Desc = "Automatically grabs the nearest log.",
        Default = false,
        Callback = function(state)
            autoGrabLogEnabled = state
            if state then
                if autoGrabLogThread then pcall(function() task.cancel(autoGrabLogThread) end) end
                autoGrabLogThread = task.spawn(function()
                    while autoGrabLogEnabled do
                        local ok = pcall(function()
                            local logInteract = findNearestLogInteract()
                            if logInteract and logInteract.Parent then
                                _G.SafeFireServer(logInteract)
                            end
                        end)
                        task.wait(0.2) -- Slower loop to prevent lag (was 0.1)
                    end
                end)
                WindUI:Notify({
                    Title = "Auto Grab Log",
                    Content = "Enabled - Grabs nearest log.",
                    Duration = 3,
                    Icon = "package"
                })
            else
                if autoGrabLogThread then
                    pcall(function() task.cancel(autoGrabLogThread) end)
                    autoGrabLogThread = nil
                end
            end
        end
    })
    _G.KatchiToggleElements.AutoGrabLog = AutoGrabLogToggle
    
    -- Auto Place Log (FIXED - no more memory leak from GetDescendants)
    local autoPlaceLogEnabled = false
    local autoPlaceLogThread = nil
    local cachedPlaceLogPrompts = {} -- Simple table, cleared on disable
    local lastPromptScan = 0
    local PROMPT_SCAN_INTERVAL = 3 -- Re-scan every 3 seconds (was 2)
    local cachedBerezinaRef = nil -- Cache Berezina reference
    
    -- Helper: Find nearest PlaceLog prompt (optimized - no GetDescendants spam)
    local function findNearestPlaceLogPrompt()
        local char = LocalPlayer.Character
        if not char then return nil end
        local root = char:FindFirstChild("HumanoidRootPart")
        if not root then return nil end
        local rootPos = root.Position
        
        local now = tick()
        
        -- Re-scan for prompts periodically (but much less aggressively)
        if now - lastPromptScan > PROMPT_SCAN_INTERVAL then
            lastPromptScan = now
            
            -- Clear old cache properly
            for i = #cachedPlaceLogPrompts, 1, -1 do
                cachedPlaceLogPrompts[i] = nil
            end
            
            -- Cache Berezina reference
            if not cachedBerezinaRef or not cachedBerezinaRef.Parent then
                cachedBerezinaRef = Workspace:FindFirstChild("Berezina")
            end
            
            -- Only scan if Berezina exists
            if cachedBerezinaRef then
                -- FIXED: Use targeted search instead of GetDescendants (which creates huge tables)
                -- Look in known locations for PlaceLogProximityPrompt
                local modes = cachedBerezinaRef:FindFirstChild("Modes")
                if modes then
                    local holdout = modes:FindFirstChild("Holdout")
                    if holdout then
                        local bridge = holdout:FindFirstChild("Bridge")
                        if bridge then
                            -- Search only bridge sections for prompts
                            local sections = bridge:GetChildren()
                            for i = 1, #sections do
                                local section = sections[i]
                                if section then
                                    -- Check direct children and one level deep
                                    local children = section:GetChildren()
                                    for j = 1, #children do
                                        local child = children[j]
                                        if child then
                                            -- Check for prompt on this child
                                            local prompt = child:FindFirstChild("PlaceLogProximityPrompt")
                                            if prompt and prompt:IsA("ProximityPrompt") then
                                                table.insert(cachedPlaceLogPrompts, prompt)
                                            end
                                            -- Check grandchildren
                                            local grandchildren = child:GetChildren()
                                            for k = 1, #grandchildren do
                                                local gc = grandchildren[k]
                                                if gc then
                                                    local gcPrompt = gc:FindFirstChild("PlaceLogProximityPrompt")
                                                    if gcPrompt and gcPrompt:IsA("ProximityPrompt") then
                                                        table.insert(cachedPlaceLogPrompts, gcPrompt)
                                                    end
                                                end
                                            end
                                        end
                                    end
                                end
                            end
                        end
                    end
                end
            end
        end
        
        -- Find nearest prompt from cache
        local nearest, nearestDist = nil, math.huge
        local cacheSize = #cachedPlaceLogPrompts
        for i = cacheSize, 1, -1 do
            local prompt = cachedPlaceLogPrompts[i]
            if prompt and prompt.Parent then
                local promptPart = prompt:FindFirstAncestorWhichIsA("BasePart")
                if promptPart then
                    local dist = (promptPart.Position - rootPos).Magnitude
                    if dist < nearestDist then
                        nearestDist = dist
                        nearest = prompt
                    end
                end
            else
                -- Prompt was destroyed, remove from cache (swap-remove for speed)
                cachedPlaceLogPrompts[i] = cachedPlaceLogPrompts[cacheSize]
                cachedPlaceLogPrompts[cacheSize] = nil
                cacheSize = cacheSize - 1
            end
        end
        
        return nearest
    end
    
    local AutoPlaceLogToggle = BerezinaSection:Toggle({
        Title = "Auto Place Log",
        Flag = "Berezina_AutoPlaceLog",
        Desc = "Automatically places logs on nearest bridge spot.",
        Default = false,
        Callback = function(state)
            autoPlaceLogEnabled = state
            if state then
                if autoPlaceLogThread then pcall(function() task.cancel(autoPlaceLogThread) end) end
                -- Reset cache on enable
                for i = #cachedPlaceLogPrompts, 1, -1 do cachedPlaceLogPrompts[i] = nil end
                lastPromptScan = 0
                cachedBerezinaRef = nil
                
                autoPlaceLogThread = task.spawn(function()
                    while autoPlaceLogEnabled do
                        local ok = pcall(function()
                            local prompt = findNearestPlaceLogPrompt()
                            if prompt and prompt.Parent and fireproximityprompt then
                                fireproximityprompt(prompt)
                            end
                        end)
                        task.wait(0.25) -- Slower loop to prevent lag (was 0.15)
                    end
                end)
                WindUI:Notify({
                    Title = "Auto Place Log",
                    Content = "Enabled - Places on nearest spot.",
                    Duration = 3,
                    Icon = "box"
                })
            else
                if autoPlaceLogThread then
                    pcall(function() task.cancel(autoPlaceLogThread) end)
                    autoPlaceLogThread = nil
                end
                -- Properly clear cache
                for i = #cachedPlaceLogPrompts, 1, -1 do cachedPlaceLogPrompts[i] = nil end
                cachedBerezinaRef = nil
            end
        end
    })
    _G.KatchiToggleElements.AutoPlaceLog = AutoPlaceLogToggle
    
    -- Character respawn cleanup
    LocalPlayer.CharacterAdded:Connect(function()
        -- Disable all features properly on respawn and clear all caches
        
        -- Clear bridge cache
        cachedBridge = nil
        lastBridgeCheck = 0
        
        if autoRepairBridgeEnabled then
            autoRepairBridgeEnabled = false
            if autoRepairBridgeConn then
                autoRepairBridgeConn:Disconnect()
                autoRepairBridgeConn = nil
            end
            if AutoRepairBridgeToggle then pcall(function() AutoRepairBridgeToggle:SetValue(false) end) end
        end
        if autoGrabLogEnabled then
            autoGrabLogEnabled = false
            if autoGrabLogThread then
                pcall(function() task.cancel(autoGrabLogThread) end)
                autoGrabLogThread = nil
            end
            if AutoGrabLogToggle then pcall(function() AutoGrabLogToggle:SetValue(false) end) end
        end
        if autoPlaceLogEnabled then
            autoPlaceLogEnabled = false
            if autoPlaceLogThread then
                pcall(function() task.cancel(autoPlaceLogThread) end)
                autoPlaceLogThread = nil
            end
            -- Properly clear all cached data
            for i = #cachedPlaceLogPrompts, 1, -1 do cachedPlaceLogPrompts[i] = nil end
            cachedBerezinaRef = nil
            lastPromptScan = 0
            if AutoPlaceLogToggle then pcall(function() AutoPlaceLogToggle:SetValue(false) end) end
        end
    end)
    
    -- ===== END BEREZINA FEATURES =====
end

task.wait(0.1) -- Delay to prevent lag
do -- // Keybinds and UI Tab
    local KeybindsTab = Others1Section:Tab({ Title = "Keybinds and UI", Icon = "keyboard" })

    -- Mobile Button UI System
    local MobileButtons = {}
    local MobileButtonSettings = {
        Transparency = 0.1,
        Size = 52
    }
    local TweenService = game:GetService("TweenService")
    local UserInputService = game:GetService("UserInputService")
    
    -- Color palette (clean, professional)
    local Colors = {
        Background = Color3.fromRGB(22, 22, 26),
        Surface = Color3.fromRGB(32, 32, 38),
        SurfaceLight = Color3.fromRGB(45, 45, 52),
        Primary = Color3.fromRGB(229, 57, 53), -- #E53935
        PrimaryDark = Color3.fromRGB(198, 40, 40),
        Text = Color3.fromRGB(255, 255, 255),
        TextMuted = Color3.fromRGB(140, 140, 150),
        Border = Color3.fromRGB(55, 55, 62),
        Success = Color3.fromRGB(76, 175, 80),
    }
    
    local function createMobileButton(name, toggleKey, getStateFunc)
        if MobileButtons[name] then
            pcall(function() MobileButtons[name].Frame:Destroy() end)
            MobileButtons[name] = nil
        end
        
        local Players = game:GetService("Players")
        local LocalPlayer = Players.LocalPlayer
        local PlayerGui = LocalPlayer:WaitForChild("PlayerGui")
        
        -- Create ScreenGui with full screen coverage
        local screenGui = Instance.new("ScreenGui")
        screenGui.ResetOnSpawn = false
        screenGui.ZIndexBehavior = Enum.ZIndexBehavior.Sibling
        screenGui.IgnoreGuiInset = true
        if _G.protectGUI then _G.protectGUI(screenGui) else screenGui.Parent = PlayerGui end -- Use stealth protection
        
        -- Create blur effect (hidden by default)
        local blur = Instance.new("BlurEffect")
        -- Use randomized name for anti-detection
        blur.Name = "Effect_" .. math.random(10000, 99999)
        blur.Size = 0
        blur.Parent = game:GetService("Lighting")
        
        -- Dark overlay
        local overlay = Instance.new("Frame")
        overlay.Name = "Overlay"
        overlay.Size = UDim2.new(1, 0, 1, 0)
        overlay.Position = UDim2.new(0, 0, 0, 0)
        overlay.BackgroundColor3 = Color3.fromRGB(0, 0, 0)
        overlay.BackgroundTransparency = 1
        overlay.BorderSizePixel = 0
        overlay.ZIndex = 99
        overlay.Parent = screenGui
        
        -- ===== SETTINGS PANEL (Clean, Professional Design) =====
        local settingsPanel = Instance.new("Frame")
        settingsPanel.Name = "SettingsPanel"
        settingsPanel.Size = UDim2.new(0, 260, 0, 195)
        settingsPanel.Position = UDim2.new(0.5, -130, 0.5, -97)
        settingsPanel.BackgroundColor3 = Colors.Background
        settingsPanel.BorderSizePixel = 0
        settingsPanel.Visible = false
        settingsPanel.ZIndex = 101
        settingsPanel.Parent = screenGui
        
        local panelCorner = Instance.new("UICorner")
        panelCorner.CornerRadius = UDim.new(0, 12)
        panelCorner.Parent = settingsPanel
        
        -- Subtle shadow (using a slightly larger dark frame behind)
        local shadow = Instance.new("Frame")
        shadow.Name = "Shadow"
        shadow.Size = UDim2.new(1, 8, 1, 8)
        shadow.Position = UDim2.new(0, -4, 0, 2)
        shadow.BackgroundColor3 = Color3.fromRGB(0, 0, 0)
        shadow.BackgroundTransparency = 0.7
        shadow.BorderSizePixel = 0
        shadow.ZIndex = 100
        shadow.Parent = settingsPanel
        
        local shadowCorner = Instance.new("UICorner")
        shadowCorner.CornerRadius = UDim.new(0, 14)
        shadowCorner.Parent = shadow
        
        -- Header section
        local header = Instance.new("Frame")
        header.Name = "Header"
        header.Size = UDim2.new(1, 0, 0, 48)
        header.BackgroundColor3 = Colors.Surface
        header.BorderSizePixel = 0
        header.ZIndex = 102
        header.Parent = settingsPanel
        
        local headerCorner = Instance.new("UICorner")
        headerCorner.CornerRadius = UDim.new(0, 12)
        headerCorner.Parent = header
        
        -- Fix bottom corners of header
        local headerBottom = Instance.new("Frame")
        headerBottom.Size = UDim2.new(1, 0, 0, 12)
        headerBottom.Position = UDim2.new(0, 0, 1, -12)
        headerBottom.BackgroundColor3 = Colors.Surface
        headerBottom.BorderSizePixel = 0
        headerBottom.ZIndex = 102
        headerBottom.Parent = header
        
        -- Red accent icon
        local iconBg = Instance.new("Frame")
        iconBg.Size = UDim2.new(0, 28, 0, 28)
        iconBg.Position = UDim2.new(0, 14, 0.5, -14)
        iconBg.BackgroundColor3 = Colors.Primary
        iconBg.BorderSizePixel = 0
        iconBg.ZIndex = 103
        iconBg.Parent = header
        
        local iconCorner = Instance.new("UICorner")
        iconCorner.CornerRadius = UDim.new(0, 6)
        iconCorner.Parent = iconBg
        
        local iconText = Instance.new("TextLabel")
        iconText.Size = UDim2.new(1, 0, 1, 0)
        iconText.BackgroundTransparency = 1
        iconText.Text = string.upper(string.sub(name, 1, 1))
        iconText.TextColor3 = Colors.Text
        iconText.TextSize = 14
        iconText.Font = Enum.Font.GothamBold
        iconText.ZIndex = 104
        iconText.Parent = iconBg
        
        -- Title
        local title = Instance.new("TextLabel")
        title.Name = "Title"
        title.Size = UDim2.new(1, -100, 1, 0)
        title.Position = UDim2.new(0, 52, 0, 0)
        title.BackgroundTransparency = 1
        title.Text = name
        title.TextColor3 = Colors.Text
        title.TextSize = 15
        title.Font = Enum.Font.GothamMedium
        title.TextXAlignment = Enum.TextXAlignment.Left
        title.ZIndex = 103
        title.Parent = header
        
        -- Content area
        local content = Instance.new("Frame")
        content.Name = "Content"
        content.Size = UDim2.new(1, -32, 0, 90)
        content.Position = UDim2.new(0, 16, 0, 56)
        content.BackgroundTransparency = 1
        content.ZIndex = 102
        content.Parent = settingsPanel
        
        -- Transparency input section
        local transpContainer = Instance.new("Frame")
        transpContainer.Size = UDim2.new(0.5, -6, 1, 0)
        transpContainer.Position = UDim2.new(0, 0, 0, 0)
        transpContainer.BackgroundTransparency = 1
        transpContainer.ZIndex = 102
        transpContainer.Parent = content
        
        local transpLabel = Instance.new("TextLabel")
        transpLabel.Size = UDim2.new(1, 0, 0, 18)
        transpLabel.Position = UDim2.new(0, 0, 0, 0)
        transpLabel.BackgroundTransparency = 1
        transpLabel.Text = "Transparency"
        transpLabel.TextColor3 = Colors.TextMuted
        transpLabel.TextSize = 12
        transpLabel.Font = Enum.Font.Gotham
        transpLabel.TextXAlignment = Enum.TextXAlignment.Left
        transpLabel.ZIndex = 102
        transpLabel.Parent = transpContainer
        
        local transpInputBg = Instance.new("Frame")
        transpInputBg.Size = UDim2.new(1, 0, 0, 40)
        transpInputBg.Position = UDim2.new(0, 0, 0, 24)
        transpInputBg.BackgroundColor3 = Colors.Surface
        transpInputBg.BorderSizePixel = 0
        transpInputBg.ZIndex = 102
        transpInputBg.Parent = transpContainer
        
        local transpInputCorner = Instance.new("UICorner")
        transpInputCorner.CornerRadius = UDim.new(0, 8)
        transpInputCorner.Parent = transpInputBg
        
        local transpInputStroke = Instance.new("UIStroke")
        transpInputStroke.Color = Colors.Border
        transpInputStroke.Thickness = 1
        transpInputStroke.Parent = transpInputBg
        
        local transpInput = Instance.new("TextBox")
        transpInput.Size = UDim2.new(1, 0, 1, 0)
        transpInput.BackgroundTransparency = 1
        transpInput.Text = tostring(MobileButtonSettings.Transparency)
        transpInput.TextColor3 = Colors.Text
        transpInput.TextSize = 14
        transpInput.Font = Enum.Font.Gotham
        transpInput.PlaceholderText = "0 - 1"
        transpInput.PlaceholderColor3 = Colors.TextMuted
        transpInput.ZIndex = 103
        transpInput.Parent = transpInputBg
        
        -- Size input section
        local sizeContainer = Instance.new("Frame")
        sizeContainer.Size = UDim2.new(0.5, -6, 1, 0)
        sizeContainer.Position = UDim2.new(0.5, 6, 0, 0)
        sizeContainer.BackgroundTransparency = 1
        sizeContainer.ZIndex = 102
        sizeContainer.Parent = content
        
        local sizeLabel = Instance.new("TextLabel")
        sizeLabel.Size = UDim2.new(1, 0, 0, 18)
        sizeLabel.Position = UDim2.new(0, 0, 0, 0)
        sizeLabel.BackgroundTransparency = 1
        sizeLabel.Text = "Button Size"
        sizeLabel.TextColor3 = Colors.TextMuted
        sizeLabel.TextSize = 12
        sizeLabel.Font = Enum.Font.Gotham
        sizeLabel.TextXAlignment = Enum.TextXAlignment.Left
        sizeLabel.ZIndex = 102
        sizeLabel.Parent = sizeContainer
        
        local sizeInputBg = Instance.new("Frame")
        sizeInputBg.Size = UDim2.new(1, 0, 0, 40)
        sizeInputBg.Position = UDim2.new(0, 0, 0, 24)
        sizeInputBg.BackgroundColor3 = Colors.Surface
        sizeInputBg.BorderSizePixel = 0
        sizeInputBg.ZIndex = 102
        sizeInputBg.Parent = sizeContainer
        
        local sizeInputCorner = Instance.new("UICorner")
        sizeInputCorner.CornerRadius = UDim.new(0, 8)
        sizeInputCorner.Parent = sizeInputBg
        
        local sizeInputStroke = Instance.new("UIStroke")
        sizeInputStroke.Color = Colors.Border
        sizeInputStroke.Thickness = 1
        sizeInputStroke.Parent = sizeInputBg
        
        local sizeInput = Instance.new("TextBox")
        sizeInput.Size = UDim2.new(1, 0, 1, 0)
        sizeInput.BackgroundTransparency = 1
        sizeInput.Text = tostring(MobileButtonSettings.Size)
        sizeInput.TextColor3 = Colors.Text
        sizeInput.TextSize = 14
        sizeInput.Font = Enum.Font.Gotham
        sizeInput.PlaceholderText = "30 - 100"
        sizeInput.PlaceholderColor3 = Colors.TextMuted
        sizeInput.ZIndex = 103
        sizeInput.Parent = sizeInputBg
        
        -- Apply & Close button
        local applyBtn = Instance.new("TextButton")
        applyBtn.Size = UDim2.new(1, -32, 0, 42)
        applyBtn.Position = UDim2.new(0, 16, 1, -58)
        applyBtn.BackgroundColor3 = Colors.Primary
        applyBtn.BorderSizePixel = 0
        applyBtn.Text = "Apply & Close"
        applyBtn.TextColor3 = Colors.Text
        applyBtn.TextSize = 14
        applyBtn.Font = Enum.Font.GothamMedium
        applyBtn.ZIndex = 102
        applyBtn.AutoButtonColor = false
        applyBtn.Parent = settingsPanel
        
        local applyCorner = Instance.new("UICorner")
        applyCorner.CornerRadius = UDim.new(0, 8)
        applyCorner.Parent = applyBtn
        
        -- ===== MOBILE BUTTON (Clean Design) =====
        local btnSize = MobileButtonSettings.Size
        local button = Instance.new("Frame")
        button.Name = "MobileButton"
        button.Size = UDim2.new(0, btnSize, 0, btnSize)
        button.Position = UDim2.new(0, 20, 0.5, -btnSize/2)
        button.BackgroundColor3 = Colors.Background
        button.BackgroundTransparency = MobileButtonSettings.Transparency
        button.BorderSizePixel = 0
        button.ZIndex = 100
        button.Active = true
        button.Parent = screenGui
        
        local buttonCorner = Instance.new("UICorner")
        buttonCorner.CornerRadius = UDim.new(0, 12)
        buttonCorner.Parent = button
        
        local buttonStroke = Instance.new("UIStroke")
        buttonStroke.Color = Colors.Primary
        buttonStroke.Thickness = 2
        buttonStroke.Transparency = 0.4
        buttonStroke.Parent = button
        
        -- Button label
        local buttonLabel = Instance.new("TextLabel")
        buttonLabel.Name = "Label"
        buttonLabel.Size = UDim2.new(1, 0, 0.55, 0)
        buttonLabel.Position = UDim2.new(0, 0, 0.08, 0)
        buttonLabel.BackgroundTransparency = 1
        buttonLabel.Text = string.upper(string.sub(name, 1, 3))
        buttonLabel.TextColor3 = Colors.Text
        buttonLabel.TextSize = 14
        buttonLabel.Font = Enum.Font.GothamBold
        buttonLabel.TextScaled = true
        buttonLabel.ZIndex = 101
        buttonLabel.Parent = button
        
        -- State indicator bar
        local stateBar = Instance.new("Frame")
        stateBar.Name = "StateBar"
        stateBar.Size = UDim2.new(0.6, 0, 0, 3)
        stateBar.Position = UDim2.new(0.2, 0, 0.72, 0)
        stateBar.BackgroundColor3 = Colors.Primary
        stateBar.BorderSizePixel = 0
        stateBar.ZIndex = 101
        stateBar.Parent = button
        
        local stateBarCorner = Instance.new("UICorner")
        stateBarCorner.CornerRadius = UDim.new(1, 0)
        stateBarCorner.Parent = stateBar
        
        -- State text
        local stateText = Instance.new("TextLabel")
        stateText.Name = "StateText"
        stateText.Size = UDim2.new(1, 0, 0, 12)
        stateText.Position = UDim2.new(0, 0, 0.82, 0)
        stateText.BackgroundTransparency = 1
        stateText.Text = "OFF"
        stateText.TextColor3 = Colors.TextMuted
        stateText.TextSize = 9
        stateText.Font = Enum.Font.GothamMedium
        stateText.ZIndex = 101
        stateText.Parent = button
        
        -- Dragging variables
        local dragging = false
        local dragInput = nil
        local dragStart = nil
        local startPos = nil
        local holdStart = nil
        local isHolding = false
        local settingsOpen = false
        local originalPos = button.Position
        
        local function updateStateIndicator()
            local state = getStateFunc and getStateFunc() or false
            local targetColor = state and Colors.Success or Colors.Primary
            local targetText = state and "ON" or "OFF"
            TweenService:Create(stateBar, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {BackgroundColor3 = targetColor}):Play()
            TweenService:Create(buttonStroke, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {Color = targetColor}):Play()
            stateText.Text = targetText
            stateText.TextColor3 = state and Colors.Success or Colors.TextMuted
        end
        
        local function updateButtonAppearance()
            local newSize = MobileButtonSettings.Size
            TweenService:Create(button, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                Size = UDim2.new(0, newSize, 0, newSize),
                BackgroundTransparency = MobileButtonSettings.Transparency
            }):Play()
        end
        
        local function updateDrag(input)
            if not dragging or not startPos then return end
            local delta = input.Position - dragStart
            local targetPos = UDim2.new(
                startPos.X.Scale, startPos.X.Offset + delta.X,
                startPos.Y.Scale, startPos.Y.Offset + delta.Y
            )
            TweenService:Create(button, TweenInfo.new(0.06, Enum.EasingStyle.Quad, Enum.EasingDirection.Out), {
                Position = targetPos
            }):Play()
        end
        
        local function openSettings()
            if settingsOpen then return end
            settingsOpen = true
            originalPos = button.Position
            
            TweenService:Create(blur, TweenInfo.new(0.3, Enum.EasingStyle.Quad, Enum.EasingDirection.Out), {Size = 20}):Play()
            TweenService:Create(overlay, TweenInfo.new(0.3, Enum.EasingStyle.Quad, Enum.EasingDirection.Out), {BackgroundTransparency = 0.5}):Play()
            
            local centerPos = UDim2.new(0.5, -MobileButtonSettings.Size/2, 0.5, -MobileButtonSettings.Size/2 - 110)
            TweenService:Create(button, TweenInfo.new(0.35, Enum.EasingStyle.Quad, Enum.EasingDirection.Out), {Position = centerPos}):Play()
            
            settingsPanel.Position = UDim2.new(0.5, -130, 0.55, 0)
            settingsPanel.Visible = true
            settingsPanel.BackgroundTransparency = 1
            TweenService:Create(settingsPanel, TweenInfo.new(0.3, Enum.EasingStyle.Quad, Enum.EasingDirection.Out), {
                Position = UDim2.new(0.5, -130, 0.5, 0),
                BackgroundTransparency = 0
            }):Play()
        end
        
        local function closeSettings()
            if not settingsOpen then return end
            settingsOpen = false
            
            TweenService:Create(blur, TweenInfo.new(0.25, Enum.EasingStyle.Quad, Enum.EasingDirection.Out), {Size = 0}):Play()
            TweenService:Create(overlay, TweenInfo.new(0.25, Enum.EasingStyle.Quad, Enum.EasingDirection.Out), {BackgroundTransparency = 1}):Play()
            
            TweenService:Create(button, TweenInfo.new(0.3, Enum.EasingStyle.Quad, Enum.EasingDirection.Out), {
                Position = originalPos,
                Size = UDim2.new(0, MobileButtonSettings.Size, 0, MobileButtonSettings.Size)
            }):Play()
            
            TweenService:Create(settingsPanel, TweenInfo.new(0.2, Enum.EasingStyle.Quad), {BackgroundTransparency = 1}):Play()
            task.delay(0.2, function()
                if not settingsOpen then settingsPanel.Visible = false end
            end)
        end
        
        -- Input handlers
        button.InputBegan:Connect(function(input)
            if input.UserInputType == Enum.UserInputType.Touch or input.UserInputType == Enum.UserInputType.MouseButton1 then
                if settingsOpen then return end
                dragging = true
                dragStart = input.Position
                startPos = button.Position
                holdStart = tick()
                isHolding = true
                
                TweenService:Create(button, TweenInfo.new(0.08, Enum.EasingStyle.Quad), {
                    Size = UDim2.new(0, MobileButtonSettings.Size * 0.94, 0, MobileButtonSettings.Size * 0.94)
                }):Play()
                
                task.spawn(function()
                    while isHolding and tick() - holdStart < 0.5 do
                        task.wait(0.02)
                    end
                    if isHolding and tick() - holdStart >= 0.5 and not settingsOpen then
                        isHolding = false
                        dragging = false
                        TweenService:Create(buttonStroke, TweenInfo.new(0.08), {Thickness = 3}):Play()
                        task.delay(0.08, function()
                            TweenService:Create(buttonStroke, TweenInfo.new(0.08), {Thickness = 2}):Play()
                        end)
                        openSettings()
                    end
                end)
                
                input.Changed:Connect(function()
                    if input.UserInputState == Enum.UserInputState.End then
                        dragging = false
                    end
                end)
            end
        end)
        
        button.InputChanged:Connect(function(input)
            if input.UserInputType == Enum.UserInputType.Touch or input.UserInputType == Enum.UserInputType.MouseMovement then
                dragInput = input
            end
        end)
        
        UserInputService.InputChanged:Connect(function(input)
            if input == dragInput and dragging then
                local delta = input.Position - dragStart
                if delta.Magnitude > 8 then
                    isHolding = false
                end
                updateDrag(input)
            end
        end)
        
        button.InputEnded:Connect(function(input)
            if input.UserInputType == Enum.UserInputType.Touch or input.UserInputType == Enum.UserInputType.MouseButton1 then
                TweenService:Create(button, TweenInfo.new(0.12, Enum.EasingStyle.Quad, Enum.EasingDirection.Out), {
                    Size = UDim2.new(0, MobileButtonSettings.Size, 0, MobileButtonSettings.Size)
                }):Play()
                
                if isHolding and not settingsOpen and tick() - holdStart < 0.5 then
                    local toggle = _G.KatchiToggleElements and _G.KatchiToggleElements[toggleKey]
                    if toggle and toggle.Set then
                        local currentState = getStateFunc and getStateFunc() or false
                        toggle:Set(not currentState)
                    end
                    task.delay(0.1, updateStateIndicator)
                end
                dragging = false
                isHolding = false
            end
        end)
        
        overlay.InputBegan:Connect(function(input)
            if input.UserInputType == Enum.UserInputType.Touch or input.UserInputType == Enum.UserInputType.MouseButton1 then
                closeSettings()
            end
        end)
        
        applyBtn.MouseButton1Click:Connect(closeSettings)
        applyBtn.TouchTap:Connect(closeSettings)
        
        -- Button hover/press effects
        applyBtn.MouseEnter:Connect(function()
            TweenService:Create(applyBtn, TweenInfo.new(0.1), {BackgroundColor3 = Colors.PrimaryDark}):Play()
        end)
        applyBtn.MouseLeave:Connect(function()
            TweenService:Create(applyBtn, TweenInfo.new(0.1), {BackgroundColor3 = Colors.Primary}):Play()
        end)
        applyBtn.MouseButton1Down:Connect(function()
            TweenService:Create(applyBtn, TweenInfo.new(0.05), {BackgroundColor3 = Color3.fromRGB(170, 35, 35)}):Play()
        end)
        applyBtn.MouseButton1Up:Connect(function()
            TweenService:Create(applyBtn, TweenInfo.new(0.1), {BackgroundColor3 = Colors.Primary}):Play()
        end)
        
        -- Input focus effects
        transpInput.Focused:Connect(function()
            TweenService:Create(transpInputStroke, TweenInfo.new(0.1), {Color = Colors.Primary}):Play()
        end)
        transpInput.FocusLost:Connect(function()
            TweenService:Create(transpInputStroke, TweenInfo.new(0.1), {Color = Colors.Border}):Play()
            local val = tonumber(transpInput.Text)
            if val and val >= 0 and val <= 1 then
                MobileButtonSettings.Transparency = val
                updateButtonAppearance()
            else
                transpInput.Text = tostring(MobileButtonSettings.Transparency)
            end
        end)
        
        sizeInput.Focused:Connect(function()
            TweenService:Create(sizeInputStroke, TweenInfo.new(0.1), {Color = Colors.Primary}):Play()
        end)
        sizeInput.FocusLost:Connect(function()
            TweenService:Create(sizeInputStroke, TweenInfo.new(0.1), {Color = Colors.Border}):Play()
            local val = tonumber(sizeInput.Text)
            if val and val >= 30 and val <= 100 then
                MobileButtonSettings.Size = val
                updateButtonAppearance()
            else
                sizeInput.Text = tostring(MobileButtonSettings.Size)
            end
        end)
        
        -- Update state periodically
        task.spawn(function()
            while button and button.Parent do
                updateStateIndicator()
                task.wait(0.5)
            end
        end)
        
        updateStateIndicator()
        
        MobileButtons[name] = {
            Frame = screenGui,
            Blur = blur,
            Update = updateStateIndicator
        }
        
        return MobileButtons[name]
    end
    
    local function destroyMobileButton(name)
        if MobileButtons[name] then
            pcall(function()
                if MobileButtons[name].Blur then
                    MobileButtons[name].Blur:Destroy()
                end
                MobileButtons[name].Frame:Destroy()
            end)
            MobileButtons[name] = nil
        end
    end

    local KeybindsSection = KeybindsTab:Section({ Title = "Toggle Keybinds", Icon = "key", Opened = true })

    KeybindsSection:Paragraph({
        Title = "How to use",
        Desc = "Click An Keybind Button And Bind A Key, On Mobile Ui Click The Toggle And A Ui Will Pop Up And You Can Use It To Toggle While Not In The Ui, Hold the button if you want to see the settings."
    })

    -- Head Hit Keybind
    KeybindsSection:Keybind({
        Title = "Head Hit",
        Flag = "Keybind_HeadHit",
        Desc = "Toggle Head Hit feature",
        Value = "",
        Callback = function()
            pcall(function()
                local toggle = _G.KatchiToggleElements and _G.KatchiToggleElements.HeadHit
                if toggle and toggle.Set then
                    toggle:Set(not HeadHitEnabled)
                end
            end)
        end
    })
    KeybindsSection:Toggle({
        Title = "Head Hit Button UI",
        Flag = "ButtonUI_HeadHit",
        Desc = "Create mobile button for Head Hit",
        Default = false,
        Callback = function(v)
            if v then
                createMobileButton("Head Hit", "HeadHit", function() return HeadHitEnabled end)
            else
                destroyMobileButton("Head Hit")
            end
        end
    })

    -- Auto Jump Keybind
    KeybindsSection:Keybind({
        Title = "Auto Jump",
        Flag = "Keybind_AutoJump",
        Desc = "Toggle Auto Jump feature",
        Value = "",
        Callback = function()
            pcall(function()
                local toggle = _G.KatchiToggleElements and _G.KatchiToggleElements.AutoJump
                if toggle and toggle.Set then
                    local LocalPlayer = game:GetService("Players").LocalPlayer
                    local currentState = LocalPlayer:GetAttribute("AutoJumpEnabled") or false
                    toggle:Set(not currentState)
                end
            end)
        end
    })
    KeybindsSection:Toggle({
        Title = "Auto Jump Button UI",
        Flag = "ButtonUI_AutoJump",
        Desc = "Create mobile button for Auto Jump",
        Default = false,
        Callback = function(v)
            if v then
                createMobileButton("Auto Jump", "AutoJump", function() 
                    return game:GetService("Players").LocalPlayer:GetAttribute("AutoJumpEnabled") or false 
                end)
            else
                destroyMobileButton("Auto Jump")
            end
        end
    })

    -- Hitbox Expander Keybind
    KeybindsSection:Keybind({
        Title = "Hitbox Expander",
        Flag = "Keybind_HitboxExpander",
        Desc = "Toggle Hitbox Expander feature",
        Value = "",
        Callback = function()
            pcall(function()
                local toggle = _G.KatchiToggleElements and _G.KatchiToggleElements.HitboxExpander
                if toggle and toggle.Set then
                    toggle:Set(not hitboxEnabled)
                end
            end)
        end
    })
    KeybindsSection:Toggle({
        Title = "Hitbox Expander Button UI",
        Flag = "ButtonUI_HitboxExpander",
        Desc = "Create mobile button for Hitbox Expander",
        Default = false,
        Callback = function(v)
            if v then
                createMobileButton("Hitbox", "HitboxExpander", function() return hitboxEnabled end)
            else
                destroyMobileButton("Hitbox")
            end
        end
    })

    -- Shove Hitbox Expander Keybind
    KeybindsSection:Keybind({
        Title = "Shove Hitbox Expander",
        Flag = "Keybind_ShoveHitbox",
        Desc = "Toggle Shove Hitbox Expander feature",
        Value = "",
        Callback = function()
            pcall(function()
                local toggle = _G.KatchiToggleElements and _G.KatchiToggleElements.ShoveHitbox
                if toggle and toggle.Set then
                    toggle:Set(not ShoveHitboxExpanderEnabled)
                end
            end)
        end
    })
    KeybindsSection:Toggle({
        Title = "Shove Hitbox Button UI",
        Flag = "ButtonUI_ShoveHitbox",
        Desc = "Create mobile button for Shove Hitbox",
        Default = false,
        Callback = function(v)
            if v then
                createMobileButton("Shove HB", "ShoveHitbox", function() return ShoveHitboxExpanderEnabled end)
            else
                destroyMobileButton("Shove HB")
            end
        end
    })

    -- Auto Parry Sapper Keybind
    KeybindsSection:Keybind({
        Title = "Auto Parry Sapper",
        Flag = "Keybind_AutoParrySapper",
        Desc = "Toggle Auto Parry Sapper feature",
        Value = "",
        Callback = function()
            pcall(function()
                local toggle = _G.KatchiToggleElements and _G.KatchiToggleElements.AutoParrySapper
                if toggle and toggle.Set then
                    toggle:Set(not AutoParrySapperMeleeEnabled)
                end
            end)
        end
    })
    KeybindsSection:Toggle({
        Title = "Auto Parry Sapper Button UI",
        Flag = "ButtonUI_AutoParrySapper",
        Desc = "Create mobile button for Auto Parry Sapper",
        Default = false,
        Callback = function(v)
            if v then
                createMobileButton("Parry", "AutoParrySapper", function() return AutoParrySapperMeleeEnabled end)
            else
                destroyMobileButton("Parry")
            end
        end
    })

    -- Enable Auto Shoot Keybind
    KeybindsSection:Keybind({
        Title = "Auto Shoot",
        Flag = "Keybind_AutoShoot",
        Desc = "Toggle Auto Shoot feature",
        Value = "",
        Callback = function()
            pcall(function()
                local toggle = _G.KatchiToggleElements and _G.KatchiToggleElements.AutoShoot
                if toggle and toggle.Set then
                    toggle:Set(not USER_AUTO_SHOOT_TOGGLE)
                end
            end)
        end
    })
    KeybindsSection:Toggle({
        Title = "Auto Shoot Button UI",
        Flag = "ButtonUI_AutoShoot",
        Desc = "Create mobile button for Auto Shoot",
        Default = false,
        Callback = function(v)
            if v then
                createMobileButton("Shoot", "AutoShoot", function() return USER_AUTO_SHOOT_TOGGLE end)
            else
                destroyMobileButton("Shoot")
            end
        end
    })

    -- Instant Shoot Keybind
    KeybindsSection:Keybind({
        Title = "Instant Shoot",
        Flag = "Keybind_InstantShoot",
        Desc = "Toggle Instant Shoot feature",
        Value = "",
        Callback = function()
            pcall(function()
                local toggle = _G.KatchiToggleElements and _G.KatchiToggleElements.InstantShoot
                if toggle and toggle.Set then
                    toggle:Set(not INSTANT_SHOOT_ENABLED)
                end
            end)
        end
    })
    KeybindsSection:Toggle({
        Title = "Instant Shoot Button UI",
        Flag = "ButtonUI_InstantShoot",
        Desc = "Create mobile button for Instant Shoot",
        Default = false,
        Callback = function(v)
            if v then
                createMobileButton("Instant", "InstantShoot", function() return INSTANT_SHOOT_ENABLED end)
            else
                destroyMobileButton("Instant")
            end
        end
    })

    -- Use FOV Keybind
    KeybindsSection:Keybind({
        Title = "Use FOV",
        Flag = "Keybind_UseFov",
        Desc = "Toggle Use FOV feature",
        Value = "",
        Callback = function()
            pcall(function()
                local toggle = _G.KatchiToggleElements and _G.KatchiToggleElements.UseFov
                if toggle and toggle.Set then
                    toggle:Set(not USE_FOV)
                end
            end)
        end
    })
    KeybindsSection:Toggle({
        Title = "Use FOV Button UI",
        Flag = "ButtonUI_UseFov",
        Desc = "Create mobile button for Use FOV",
        Default = false,
        Callback = function(v)
            if v then
                createMobileButton("FOV", "UseFov", function() return USE_FOV end)
            else
                destroyMobileButton("FOV")
            end
        end
    })

    -- Show FOV Keybind
    KeybindsSection:Keybind({
        Title = "Show FOV",
        Flag = "Keybind_ShowFov",
        Desc = "Toggle Show FOV feature",
        Value = "",
        Callback = function()
            pcall(function()
                local toggle = _G.KatchiToggleElements and _G.KatchiToggleElements.ShowFov
                if toggle and toggle.Set then
                    toggle:Set(not SHOW_FOV)
                end
            end)
        end
    })
    KeybindsSection:Toggle({
        Title = "Show FOV Button UI",
        Flag = "ButtonUI_ShowFov",
        Desc = "Create mobile button for Show FOV",
        Default = false,
        Callback = function(v)
            if v then
                createMobileButton("ShowFOV", "ShowFov", function() return SHOW_FOV end)
            else
                destroyMobileButton("ShowFOV")
            end
        end
    })

    -- Wall Check Keybind
    KeybindsSection:Keybind({
        Title = "Wall Check",
        Flag = "Keybind_WallCheck",
        Desc = "Toggle Wall Check feature",
        Value = "",
        Callback = function()
            pcall(function()
                local toggle = _G.KatchiToggleElements and _G.KatchiToggleElements.WallCheck
                if toggle and toggle.Set then
                    toggle:Set(not CHECK_WALLS)
                end
            end)
        end
    })
    KeybindsSection:Toggle({
        Title = "Wall Check Button UI",
        Flag = "ButtonUI_WallCheck",
        Desc = "Create mobile button for Wall Check",
        Default = false,
        Callback = function(v)
            if v then
                createMobileButton("Wall", "WallCheck", function() return CHECK_WALLS end)
            else
                destroyMobileButton("Wall")
            end
        end
    })

    -- Auto Reload Keybind
    KeybindsSection:Keybind({
        Title = "Auto Reload",
        Flag = "Keybind_AutoReload",
        Desc = "Toggle Auto Reload feature",
        Value = "",
        Callback = function()
            pcall(function()
                local toggle = _G.KatchiToggleElements and _G.KatchiToggleElements.AutoReload
                if toggle and toggle.Set then
                    toggle:Set(not AUTO_RELOAD_ENABLED)
                end
            end)
        end
    })
    KeybindsSection:Toggle({
        Title = "Auto Reload Button UI",
        Flag = "ButtonUI_AutoReload",
        Desc = "Create mobile button for Auto Reload",
        Default = false,
        Callback = function(v)
            if v then
                createMobileButton("Reload", "AutoReload", function() return AUTO_RELOAD_ENABLED end)
            else
                destroyMobileButton("Reload")
            end
        end
    })

    -- Auto Save Players Keybind
    KeybindsSection:Keybind({
        Title = "Auto Save Players",
        Flag = "Keybind_AutoSavePlayers",
        Desc = "Toggle Auto Save Players feature",
        Value = "",
        Callback = function()
            pcall(function()
                local toggle = _G.KatchiToggleElements and _G.KatchiToggleElements.AutoSavePlayers
                if toggle and toggle.Set then
                    toggle:Set(not AUTO_SAVE_PLAYERS_ENABLED)
                end
            end)
        end
    })
    KeybindsSection:Toggle({
        Title = "Auto Save Players Button UI",
        Flag = "ButtonUI_AutoSavePlayers",
        Desc = "Create mobile button for Auto Save Players",
        Default = false,
        Callback = function(v)
            if v then
                createMobileButton("Save", "AutoSavePlayers", function() return AUTO_SAVE_PLAYERS_ENABLED end)
            else
                destroyMobileButton("Save")
            end
        end
    })

    -- Kill Aura Keybind
    KeybindsSection:Keybind({
        Title = "Kill Aura",
        Flag = "Keybind_KillAura",
        Desc = "Toggle Kill Aura feature",
        Value = "",
        Callback = function()
            pcall(function()
                local toggle = _G.KatchiToggleElements and _G.KatchiToggleElements.KillAura
                if toggle and toggle.Set then
                    toggle:Set(not KillAuraEnabled)
                end
            end)
        end
    })
    KeybindsSection:Toggle({
        Title = "Kill Aura Button UI",
        Flag = "ButtonUI_KillAura",
        Desc = "Create mobile button for Kill Aura",
        Default = false,
        Callback = function(v)
            if v then
                createMobileButton("KillAura", "KillAura", function() return KillAuraEnabled end)
            else
                destroyMobileButton("KillAura")
            end
        end
    })

    -- Reach Keybind
    KeybindsSection:Keybind({
        Title = "Reach",
        Flag = "Keybind_Reach",
        Desc = "Toggle Reach feature",
        Value = "",
        Callback = function()
            pcall(function()
                local toggle = _G.KatchiToggleElements and _G.KatchiToggleElements.Reach
                if toggle and toggle.Set then
                    toggle:Set(not KillAura_HitboxExpanderEnabled)
                end
            end)
        end
    })
    KeybindsSection:Toggle({
        Title = "Reach Button UI",
        Flag = "ButtonUI_Reach",
        Desc = "Create mobile button for Reach",
        Default = false,
        Callback = function(v)
            if v then
                createMobileButton("Reach", "Reach", function() return KillAura_HitboxExpanderEnabled end)
            else
                destroyMobileButton("Reach")
            end
        end
    })

    -- Auto Equip Melee Keybind
    KeybindsSection:Keybind({
        Title = "Auto Equip Melee",
        Flag = "Keybind_AutoEquipMelee",
        Desc = "Toggle Auto Equip Melee feature",
        Value = "",
        Callback = function()
            pcall(function()
                local toggle = _G.KatchiToggleElements and _G.KatchiToggleElements.AutoEquipMelee
                if toggle and toggle.Set then
                    toggle:Set(not KillAura_AutoEquipMelee)
                end
            end)
        end
    })
    KeybindsSection:Toggle({
        Title = "Auto Equip Melee Button UI",
        Flag = "ButtonUI_AutoEquipMelee",
        Desc = "Create mobile button for Auto Equip Melee",
        Default = false,
        Callback = function(v)
            if v then
                createMobileButton("Equip", "AutoEquipMelee", function() return KillAura_AutoEquipMelee end)
            else
                destroyMobileButton("Equip")
            end
        end
    })

    -- Bayonet Kill Aura Keybind
    KeybindsSection:Keybind({
        Title = "Bayonet Kill Aura",
        Flag = "Keybind_BayonetKillAura",
        Desc = "Toggle Bayonet Kill Aura feature",
        Value = "",
        Callback = function()
            pcall(function()
                local toggle = _G.KatchiToggleElements and _G.KatchiToggleElements.BayonetKillAura
                if toggle and toggle.Set then
                    toggle:Set(not KillAura_EnableBayonet)
                end
            end)
        end
    })
    KeybindsSection:Toggle({
        Title = "Bayonet Kill Aura Button UI",
        Flag = "ButtonUI_BayonetKillAura",
        Desc = "Create mobile button for Bayonet Kill Aura",
        Default = false,
        Callback = function(v)
            if v then
                createMobileButton("Bayonet", "BayonetKillAura", function() return KillAura_EnableBayonet end)
            else
                destroyMobileButton("Bayonet")
            end
        end
    })

    -- Auto Look Keybind
    KeybindsSection:Keybind({
        Title = "Auto Look",
        Flag = "Keybind_AutoLook",
        Desc = "Toggle Auto Look feature",
        Value = "",
        Callback = function()
            pcall(function()
                local toggle = _G.KatchiToggleElements and _G.KatchiToggleElements.AutoLook
                if toggle and toggle.Set then
                    toggle:Set(not KillAuraAutoLook)
                end
            end)
        end
    })
    KeybindsSection:Toggle({
        Title = "Auto Look Button UI",
        Flag = "ButtonUI_AutoLook",
        Desc = "Create mobile button for Auto Look",
        Default = false,
        Callback = function(v)
            if v then
                createMobileButton("Look", "AutoLook", function() return KillAuraAutoLook end)
            else
                destroyMobileButton("Look")
            end
        end
    })

    -- Anti Grab Keybind
    KeybindsSection:Keybind({
        Title = "Anti Grab",
        Flag = "Keybind_AntiGrab",
        Desc = "Toggle Anti Grab feature",
        Value = "",
        Callback = function()
            pcall(function()
                local toggle = _G.KatchiToggleElements and _G.KatchiToggleElements.AntiGrab
                if toggle and toggle.Set then
                    toggle:Set(not AntiGrabEnabled)
                end
            end)
        end
    })
    KeybindsSection:Toggle({
        Title = "Anti Grab Button UI",
        Flag = "ButtonUI_AntiGrab",
        Desc = "Create mobile button for Anti Grab",
        Default = false,
        Callback = function(v)
            if v then
                createMobileButton("AntiGrab", "AntiGrab", function() return AntiGrabEnabled end)
            else
                destroyMobileButton("AntiGrab")
            end
        end
    })

    -- Shove Aura Keybind
    KeybindsSection:Keybind({
        Title = "Shove Aura",
        Flag = "Keybind_ShoveAura",
        Desc = "Toggle Shove Aura feature",
        Value = "",
        Callback = function()
            pcall(function()
                local toggle = _G.KatchiToggleElements and _G.KatchiToggleElements.ShoveAura
                if toggle and toggle.Set then
                    toggle:Set(not ShoveAuraEnabled)
                end
            end)
        end
    })
    KeybindsSection:Toggle({
        Title = "Shove Aura Button UI",
        Flag = "ButtonUI_ShoveAura",
        Desc = "Create mobile button for Shove Aura",
        Default = false,
        Callback = function(v)
            if v then
                createMobileButton("Shove", "ShoveAura", function() return ShoveAuraEnabled end)
            else
                destroyMobileButton("Shove")
            end
        end
    })

    -- Apply WalkSpeed Keybind
    KeybindsSection:Keybind({
        Title = "Apply WalkSpeed",
        Flag = "Keybind_ApplyWalkSpeed",
        Desc = "Toggle Apply WalkSpeed feature",
        Value = "",
        Callback = function()
            pcall(function()
                local toggle = _G.KatchiToggleElements and _G.KatchiToggleElements.ApplyWalkSpeed
                if toggle and toggle.Set then
                    toggle:Set(not walkLoopEnabled)
                end
            end)
        end
    })
    KeybindsSection:Toggle({
        Title = "Apply WalkSpeed Button UI",
        Flag = "ButtonUI_ApplyWalkSpeed",
        Desc = "Create mobile button for Apply WalkSpeed",
        Default = false,
        Callback = function(v)
            if v then
                createMobileButton("Speed", "ApplyWalkSpeed", function() return walkLoopEnabled end)
            else
                destroyMobileButton("Speed")
            end
        end
    })

    -- Auto Remove Horses Keybind
    KeybindsSection:Keybind({
        Title = "Auto Remove Horses",
        Flag = "Keybind_AutoRemoveHorses",
        Desc = "Toggle Auto Remove Horses feature",
        Value = "",
        Callback = function()
            pcall(function()
                local toggle = _G.KatchiToggleElements and _G.KatchiToggleElements.AutoRemoveHorses
                if toggle and toggle.Set then
                    toggle:Set(not AutoRemoveHorsesEnabled)
                end
            end)
        end
    })
    KeybindsSection:Toggle({
        Title = "Auto Remove Horses Button UI",
        Flag = "ButtonUI_AutoRemoveHorses",
        Desc = "Create mobile button for Auto Remove Horses",
        Default = false,
        Callback = function(v)
            if v then
                createMobileButton("Horses", "AutoRemoveHorses", function() return AutoRemoveHorsesEnabled end)
            else
                destroyMobileButton("Horses")
            end
        end
    })

    -- No Fall Damage Keybind
    KeybindsSection:Keybind({
        Title = "No Fall Damage",
        Flag = "Keybind_NoFallDamage",
        Desc = "Toggle No Fall Damage feature",
        Value = "",
        Callback = function()
            pcall(function()
                local toggle = _G.KatchiToggleElements and _G.KatchiToggleElements.NoFallDamage
                if toggle and toggle.Set then
                    toggle:Set(not noFallDamageEnabled)
                end
            end)
        end
    })
    KeybindsSection:Toggle({
        Title = "No Fall Damage Button UI",
        Flag = "ButtonUI_NoFallDamage",
        Desc = "Create mobile button for No Fall Damage",
        Default = false,
        Callback = function(v)
            if v then
                createMobileButton("NoFall", "NoFallDamage", function() return noFallDamageEnabled end)
            else
                destroyMobileButton("NoFall")
            end
        end
    })

    -- Fly Keybind
    KeybindsSection:Keybind({
        Title = "Fly",
        Flag = "Keybind_Fly",
        Desc = "Toggle Fly feature",
        Value = "",
        Callback = function()
            pcall(function()
                local toggle = _G.KatchiToggleElements and _G.KatchiToggleElements.Fly
                if toggle and toggle.Set then
                    toggle:Set(not FlyEnabled)
                end
            end)
        end
    })
    KeybindsSection:Toggle({
        Title = "Fly Button UI",
        Flag = "ButtonUI_Fly",
        Desc = "Create mobile button for Fly",
        Default = false,
        Callback = function(v)
            if v then
                createMobileButton("Fly", "Fly", function() return FlyEnabled end)
            else
                destroyMobileButton("Fly")
            end
        end
    })

end -- end of Keybinds Tab

task.wait(0.1) -- Delay to prevent lag
do -- // Feedback Tab
    local FeedbackTab = Others1Section:Tab({ Title = "Feedback", Icon = "message-circle" })

    local FeedbackSection = FeedbackTab:Section({ Title = "Send Your Feedback", Icon = "send", Opened = false })

    FeedbackSection:Paragraph({
        Title = "Why Feedback Matters",
        Desc = "Your feedback helps us improve Katchi Hub.\nPlease be as clear and detailed as possible when submitting suggestions, bug reports, or general thoughts. All feedback will be reviewed by the developer.",
    })

    local webhookUrl = "https://discord.com/api/webhooks/1441855310217089114/1eQP3UEYkndhQeQwsYgxxDfIMFbtKdY7TBQ5VJeglMtogHLsCu-7kE_k16FqKembIwA7"
    local feedbackText = ""

    FeedbackSection:Input({
        Title = "Feedback Message",
        Desc = "Enter your suggestions or issues here",
        Value = "",
        Type = "Textarea",
        Placeholder = "Write your feedback...",
        Callback = function(value)
            feedbackText = value
        end
    })

    FeedbackSection:Button({
        Title = "Submit Feedback",
        Desc = "Send feedback directly to the developer",
        Callback = function()
            if feedbackText == "" then
                WindUI:Notify({
                    Title = "Error",
                    Content = "Feedback cannot be empty.",
                    Duration = 2,
                    Icon = "alert-triangle",
                })
                return
            end

            local success, gameInfo = pcall(function()
                return MarketplaceService:GetProductInfo(game.PlaceId)
            end)

            if not success then
                gameInfo = {Name = "Unknown Game"}
            end

            local data = {
                ["username"] = "Katchi Hub Feedback",
                ["embeds"] = {{
                    ["title"] = "New Feedback Received",
                    ["description"] = string.format("**Feedback Message:**\n```\n%s\n```", feedbackText:sub(1, 2000)),
                    ["color"] = 0xFF3030,
                    ["fields"] = {
                        {["name"] = "User Info", ["value"] = string.format("**Display Name:** %s\n**Username:** %s", LocalPlayer.DisplayName, LocalPlayer.Name), ["inline"] = true},
                        {["name"] = "Technical", ["value"] = string.format("**Executor:** %s\n**Region:** %s", (identifyexecutor and identifyexecutor() or "Unknown"), LocalPlayer.LocaleId), ["inline"] = true},
                        {["name"] = "Game Info", ["value"] = string.format("**Game:** %s\n**Place ID:** %d\n**Server ID:** %s", gameInfo.Name, game.PlaceId, game.JobId), ["inline"] = false},
                    },
                    ["footer"] = {
                        ["text"] = "Katchi Hub Feedback System â€¢ "..os.date("%Y-%m-%d %H:%M:%S UTC")
                    },
                    ["timestamp"] = os.date("!%Y-%m-%dT%H:%M:%SZ")
                }}
            }

            local request = (syn and syn.request) or (http and http.request) or request
            if request then
                local success, err = pcall(function()
                    request({
                        Url = webhookUrl,
                        Method = "POST",
                        Headers = {["Content-Type"] = "application/json"},
                        Body = HttpService:JSONEncode(data)
                    })
                end)

                if success then
                    WindUI:Notify({
                        Title = "Success",
                        Content = "Your feedback has been submitted successfully!",
                        Duration = 3,
                        Icon = "check",
                    })
                    feedbackText = ""
                else
                    WindUI:Notify({
                        Title = "Error",
                        Content = "Failed to send feedback: "..tostring(err),
                        Duration = 5,
                        Icon = "alert-triangle",
                    })
                end
            else
                WindUI:Notify({
                    Title = "Error",
                    Content = "Your exploit does not support HTTP requests.",
                    Duration = 3,
                    Icon = "wifi-off",
                })
            end
        end
    })
end -- end of Feedback Tab

task.wait(0.1) -- Delay to prevent lag
do -- // Final task.spawn and connects
        WindUI:Notify({
            Title = "Katchi Hub Loaded",
            Content = "Successfully loaded Katchi Hub v4.3\nUse RightShift key to toggle the menu",
            Duration = 5,
            Icon = "zap",
        })

    print("Katchi Hub v4.3 successfully loaded!")
    print("Made by Yuki")
    print("i like dawgs!")
end -- end of Final block

task.wait(0.1) -- Delay to prevent lag
do -- // Changelog Popup UI
    -- Logo loaded via HttpGet and stored as asset (fallback to text if fails)
    local CHANGELOG_LOGO_LOADED = false
    
    -- Changelog entries (each entry is a version with its changes)
    -- Format: { version = "vX.X.X", date = "Date", changes = { {type = "fix/feature/update", text = "Description"}, ... } }
    local CHANGELOG_ENTRIES = {
                                                                 {
            version = "v4.3",
            date = "January 2026",
            changes = {
                {type = "feature", text = "Added Animation Presets!"},
                {type = "feature", text = "Added Change Fov!"},
                {type = "feature", text = "Added Infinite Zoom!"},
                {type = "fix", text = "Reduced Lag From Bypass"},
                {type = "fix", text = "Fixed Bugs"},
            }
        },
                                                                 {
            version = "v4.2",
            date = "January 2026",
            changes = {
                {type = "fix", text = "Fixed Minor Bugs"},
                {type = "fix", text = "Reduced Lag From Bypass"},
                {type = "fix", text = "Improved Bypass for Other Features"},
                {type = "fix", text = "Fixed Fullbright And No Fog Bug and issues"},
            }
        },
                                                                {
            version = "v4.1",
            date = "January 2026",
            changes = {
                {type = "fix", text = "Fixed Minor Bypass Bugs"},
                {type = "fix", text = "Improved Kill Aura"},
                {type = "fix", text = "Optimized Script"},
                {type = "fix", text = "Improved Animation Scanner (can Scan more animations now.)"},
                {type = "fix", text = "Fixed Config Bug"},
                {type = "fix", text = "Fixed Minor Bugs"},
            }
        },
                                                                {
            version = "v4",
            date = "January 2026",
            changes = {
                {type = "feature", text = "Added Copy Animation ID"},
                {type = "feature", text = "Added Animation Details (Can Copy Animation ID)"},
                {type = "feature", text = "Added Custom Animation (Paste Animations and play them)"},
                {type = "fix", text = "Fixed Minor Bypass Bugs"},
            }
        },
                                                        {
            version = "v3.9",
            date = "January 2026",
            changes = {
                {type = "feature", text = "Added Animation Player!"},
                {type = "feature", text = "Added Temporary Old Guard!"},
                {type = "feature", text = "Added Temporary ColdStream!"},
                {type = "fix", text = "Fixed Minor Bugs"},
            }
        },
                                                {
            version = "v3.8",
            date = "January 2026",
            changes = {
                {type = "feature", text = "Added Buy Voivode"},
                {type = "feature", text = "Added Buy Iron Stake"},
                {type = "fix", text = "big optimization update, yes yes"},
                {type = "fix", text = "IMPROVED BYPASS, so tuff omg son"},
            }
        },
                                        {
            version = "v3.7",
            date = "January 2026",
            changes = {
                {type = "fix", text = "Reworked Kill Aura with Presets Instead!"},
                {type = "fix", text = "Fixed Bypass Flaw!"},
                {type = "fix", text = "Fixed A Couple of bugs causing lag."},
            }
        },
                                        {
            version = "v3.6",
            date = "January 2026",
            changes = {
                {type = "feature", text = "Added Berezina in Maps Hacks"},
                {type = "fix", text = "Optimized Esp!"},
                {type = "fix", text = "Improved Bypass!"},
            }
        },
                                {
            version = "v3.5",
            date = "January 2026",
            changes = {
                {type = "feature", text = "Added Freecam Mobile Support For TP"},
            }
        },
                                {
            version = "v3.4",
            date = "January 2026",
            changes = {
                {type = "feature", text = "Added TP! (Found in Movement section - Misc Tab)"},
                {type = "feature", text = "Added Baguette! (Permanent)"},
                {type = "fix", text = "Optimized Esp!"},
                {type = "fix", text = "Made Kill Aura Safe (Not Guaranteed)"},
                {type = "fix", text = "Improved Bypass (Not Guaranteed To Be 100% Safe)"},
            }
        },
                        {
            version = "v3.3",
            date = "January 2026",
            changes = {
                {type = "feature", text = "Added Anti Cheat Bypass!"},
            }
        },
                {
            version = "v3.2",
            date = "January 2026",
            changes = {
                {type = "fix", text = "Optimized auto pick up supplies"},
                {type = "fix", text = "Optimized Silent Aim"},
            }
        },
                {
            version = "v3.1",
            date = "January 2026",
            changes = {
                {type = "fix", text = "Fixed Sapper Menu Issue"},
                {type = "fix", text = "Fixed Auto Pick Up Supplies Bug"},
            }
        },
        {
            version = "v3",
            date = "January 2026",
            changes = {
                {type = "feature", text = "Added New Fly Bypass!"},
                {type = "feature", text = "Added new Auto Mercy!"},
                {type = "feature", text = "Added new Silent Aim!"},
                {type = "fix", text = "Fixed ESP issues"},
                {type = "fix", text = "Fixed Chaplain Bug"},
                {type = "fix", text = "Fixed some minor bugs"},
            }
        },
        {
            version = "v2.6769",
            date = "December 2025",
            changes = {
                {type = "feature", text = "Added New Keybinds To Toggles!"},
                {type = "feature", text = "Added Mobile UI To Toggles!"},
            }
        },
        {
            version = "v2.6767",
            date = "December 2025",
            changes = {
                {type = "fix", text = "Head Hit Bug Not Working Is Fixed!"},
                {type = "fix", text = "Auto Jump Bug Is Fixed Too!"},
            }
        },
    }
    
    task.delay(1, function()
        local PlayerGui = LocalPlayer:WaitForChild("PlayerGui")
        
        -- Create ScreenGui with stealth protection
        local ChangelogGui = Instance.new("ScreenGui")
        ChangelogGui.ResetOnSpawn = false
        ChangelogGui.ZIndexBehavior = Enum.ZIndexBehavior.Sibling
        ChangelogGui.DisplayOrder = 999
        -- Use full stealth protection
        if _G.protectGUI then
            _G.protectGUI(ChangelogGui)
        else
            ChangelogGui.Name = _G.getRandomStealthName and _G.getRandomStealthName() or ("CoreScript_" .. math.random(10000, 99999))
            ChangelogGui.Parent = PlayerGui
        end
        
        -- Helper: Create version embed card
        local function createVersionCard(parent, entry, layoutOrder)
            local card = Instance.new("Frame")
            card.Name = "VersionCard_" .. entry.version
            card.Size = UDim2.new(1, 0, 0, 0) -- Auto size
            card.AutomaticSize = Enum.AutomaticSize.Y
            card.BackgroundColor3 = Color3.fromRGB(35, 35, 45)
            card.BorderSizePixel = 0
            card.LayoutOrder = layoutOrder
            card.Parent = parent
            
            local cardCorner = Instance.new("UICorner")
            cardCorner.CornerRadius = UDim.new(0, 10)
            cardCorner.Parent = card
            
            local cardStroke = Instance.new("UIStroke")
            cardStroke.Color = Color3.fromRGB(60, 60, 80)
            cardStroke.Thickness = 1
            cardStroke.Transparency = 0.5
            cardStroke.Parent = card
            
            local cardPadding = Instance.new("UIPadding")
            cardPadding.PaddingTop = UDim.new(0, 12)
            cardPadding.PaddingBottom = UDim.new(0, 12)
            cardPadding.PaddingLeft = UDim.new(0, 15)
            cardPadding.PaddingRight = UDim.new(0, 15)
            cardPadding.Parent = card
            
            local cardLayout = Instance.new("UIListLayout")
            cardLayout.SortOrder = Enum.SortOrder.LayoutOrder
            cardLayout.Padding = UDim.new(0, 8)
            cardLayout.Parent = card
            
            -- Version header row
            local headerRow = Instance.new("Frame")
            headerRow.Name = "Header"
            headerRow.Size = UDim2.new(1, 0, 0, 24)
            headerRow.BackgroundTransparency = 1
            headerRow.LayoutOrder = 1
            headerRow.Parent = card
            
            -- Version badge
            local versionBadge = Instance.new("Frame")
            versionBadge.Name = "VersionBadge"
            versionBadge.Size = UDim2.new(0, 70, 0, 22)
            versionBadge.Position = UDim2.new(0, 0, 0.5, 0)
            versionBadge.AnchorPoint = Vector2.new(0, 0.5)
            versionBadge.BackgroundColor3 = Color3.fromRGB(80, 200, 120)
            versionBadge.Parent = headerRow
            
            local badgeCorner = Instance.new("UICorner")
            badgeCorner.CornerRadius = UDim.new(0, 6)
            badgeCorner.Parent = versionBadge
            
            local versionText = Instance.new("TextLabel")
            versionText.Name = "Version"
            versionText.Size = UDim2.new(1, 0, 1, 0)
            versionText.BackgroundTransparency = 1
            versionText.Text = entry.version
            versionText.TextColor3 = Color3.fromRGB(255, 255, 255)
            versionText.TextSize = 12
            versionText.Font = Enum.Font.GothamBold
            versionText.Parent = versionBadge
            
            -- Date text
            local dateText = Instance.new("TextLabel")
            dateText.Name = "Date"
            dateText.Size = UDim2.new(1, -80, 1, 0)
            dateText.Position = UDim2.new(0, 80, 0, 0)
            dateText.BackgroundTransparency = 1
            dateText.Text = entry.date
            dateText.TextColor3 = Color3.fromRGB(140, 140, 140)
            dateText.TextSize = 12
            dateText.Font = Enum.Font.Gotham
            dateText.TextXAlignment = Enum.TextXAlignment.Left
            dateText.Parent = headerRow
            
            -- Changes list
            local changesFrame = Instance.new("Frame")
            changesFrame.Name = "Changes"
            changesFrame.Size = UDim2.new(1, 0, 0, 0)
            changesFrame.AutomaticSize = Enum.AutomaticSize.Y
            changesFrame.BackgroundTransparency = 1
            changesFrame.LayoutOrder = 2
            changesFrame.Parent = card
            
            local changesLayout = Instance.new("UIListLayout")
            changesLayout.SortOrder = Enum.SortOrder.LayoutOrder
            changesLayout.Padding = UDim.new(0, 4)
            changesLayout.Parent = changesFrame
            
            for i, change in ipairs(entry.changes) do
                local changeRow = Instance.new("Frame")
                changeRow.Name = "Change_" .. i
                changeRow.Size = UDim2.new(1, 0, 0, 20)
                changeRow.BackgroundTransparency = 1
                changeRow.LayoutOrder = i
                changeRow.Parent = changesFrame
                
                -- Type indicator (colored dot/icon)
                local typeIndicator = Instance.new("Frame")
                typeIndicator.Name = "TypeIndicator"
                typeIndicator.Size = UDim2.new(0, 8, 0, 8)
                typeIndicator.Position = UDim2.new(0, 0, 0.5, 0)
                typeIndicator.AnchorPoint = Vector2.new(0, 0.5)
                typeIndicator.BorderSizePixel = 0
                typeIndicator.Parent = changeRow
                
                local indicatorCorner = Instance.new("UICorner")
                indicatorCorner.CornerRadius = UDim.new(1, 0)
                indicatorCorner.Parent = typeIndicator
                
                -- Color based on type
                if change.type == "fix" then
                    typeIndicator.BackgroundColor3 = Color3.fromRGB(255, 180, 50) -- Orange for fixes
                elseif change.type == "feature" then
                    typeIndicator.BackgroundColor3 = Color3.fromRGB(100, 200, 255) -- Blue for features
                else
                    typeIndicator.BackgroundColor3 = Color3.fromRGB(180, 180, 180) -- Gray for other
                end
                
                -- Change text
                local changeText = Instance.new("TextLabel")
                changeText.Name = "Text"
                changeText.Size = UDim2.new(1, -18, 1, 0)
                changeText.Position = UDim2.new(0, 18, 0, 0)
                changeText.BackgroundTransparency = 1
                changeText.Text = change.text
                changeText.TextColor3 = Color3.fromRGB(210, 210, 210)
                changeText.TextSize = 13
                changeText.Font = Enum.Font.Gotham
                changeText.TextXAlignment = Enum.TextXAlignment.Left
                changeText.TextWrapped = true
                changeText.Parent = changeRow
            end
            
            return card
        end
        
        -- Popup Container (top right)
        local PopupFrame = Instance.new("Frame")
        PopupFrame.Name = "PopupFrame"
        PopupFrame.Size = UDim2.new(0, 300, 0, 140)
        PopupFrame.Position = UDim2.new(1, 320, 0, 20) -- Start off-screen right
        PopupFrame.AnchorPoint = Vector2.new(1, 0)
        PopupFrame.BackgroundColor3 = Color3.fromRGB(25, 25, 30)
        PopupFrame.BorderSizePixel = 0
        PopupFrame.Parent = ChangelogGui
        
        local PopupCorner = Instance.new("UICorner")
        PopupCorner.CornerRadius = UDim.new(0, 14)
        PopupCorner.Parent = PopupFrame
        
        local PopupStroke = Instance.new("UIStroke")
        PopupStroke.Color = Color3.fromRGB(80, 200, 120)
        PopupStroke.Thickness = 2
        PopupStroke.Transparency = 0.3
        PopupStroke.Parent = PopupFrame
        
        -- Gradient background
        local PopupGradient = Instance.new("UIGradient")
        PopupGradient.Color = ColorSequence.new{
            ColorSequenceKeypoint.new(0, Color3.fromRGB(38, 38, 48)),
            ColorSequenceKeypoint.new(1, Color3.fromRGB(22, 22, 28)),
        }
        PopupGradient.Rotation = 45
        PopupGradient.Parent = PopupFrame
        
        -- Logo container with fallback text
        local LogoContainer = Instance.new("Frame")
        LogoContainer.Name = "LogoContainer"
        LogoContainer.Size = UDim2.new(0, 55, 0, 55)
        LogoContainer.Position = UDim2.new(0, 15, 0, 15)
        LogoContainer.BackgroundColor3 = Color3.fromRGB(80, 200, 120)
        LogoContainer.BorderSizePixel = 0
        LogoContainer.Parent = PopupFrame
        
        local LogoContainerCorner = Instance.new("UICorner")
        LogoContainerCorner.CornerRadius = UDim.new(0, 10)
        LogoContainerCorner.Parent = LogoContainer
        
        -- Fallback text (K for Katchi)
        local LogoFallback = Instance.new("TextLabel")
        LogoFallback.Name = "LogoFallback"
        LogoFallback.Size = UDim2.new(1, 0, 1, 0)
        LogoFallback.BackgroundTransparency = 1
        LogoFallback.Text = "K"
        LogoFallback.TextColor3 = Color3.fromRGB(255, 255, 255)
        LogoFallback.TextSize = 28
        LogoFallback.Font = Enum.Font.GothamBold
        LogoFallback.Parent = LogoContainer
        
        -- Title Label
        local TitleLabel = Instance.new("TextLabel")
        TitleLabel.Name = "Title"
        TitleLabel.Size = UDim2.new(1, -90, 0, 26)
        TitleLabel.Position = UDim2.new(0, 80, 0, 15)
        TitleLabel.BackgroundTransparency = 1
        TitleLabel.Text = "What's New? 🎉"
        TitleLabel.TextColor3 = Color3.fromRGB(255, 255, 255)
        TitleLabel.TextSize = 17
        TitleLabel.Font = Enum.Font.GothamBold
        TitleLabel.TextXAlignment = Enum.TextXAlignment.Left
        TitleLabel.Parent = PopupFrame
        
        -- Subtitle Label
        local SubtitleLabel = Instance.new("TextLabel")
        SubtitleLabel.Name = "Subtitle"
        SubtitleLabel.Size = UDim2.new(1, -90, 0, 22)
        SubtitleLabel.Position = UDim2.new(0, 80, 0, 40)
        SubtitleLabel.BackgroundTransparency = 1
        SubtitleLabel.Text = "Check out the latest updates"
        SubtitleLabel.TextColor3 = Color3.fromRGB(160, 160, 160)
        SubtitleLabel.TextSize = 12
        SubtitleLabel.Font = Enum.Font.Gotham
        SubtitleLabel.TextXAlignment = Enum.TextXAlignment.Left
        SubtitleLabel.Parent = PopupFrame
        
        -- Button Container
        local ButtonContainer = Instance.new("Frame")
        ButtonContainer.Name = "Buttons"
        ButtonContainer.Size = UDim2.new(1, -30, 0, 38)
        ButtonContainer.Position = UDim2.new(0, 15, 1, -53)
        ButtonContainer.BackgroundTransparency = 1
        ButtonContainer.Parent = PopupFrame
        
        -- Open Button (Green gradient)
        local OpenButton = Instance.new("TextButton")
        OpenButton.Name = "OpenButton"
        OpenButton.Size = UDim2.new(0.48, 0, 1, 0)
        OpenButton.Position = UDim2.new(0, 0, 0, 0)
        OpenButton.BackgroundColor3 = Color3.fromRGB(50, 180, 100)
        OpenButton.Text = "View Changes"
        OpenButton.TextColor3 = Color3.fromRGB(255, 255, 255)
        OpenButton.TextSize = 13
        OpenButton.Font = Enum.Font.GothamBold
        OpenButton.BorderSizePixel = 0
        OpenButton.AutoButtonColor = false
        OpenButton.Parent = ButtonContainer
        
        local OpenCorner = Instance.new("UICorner")
        OpenCorner.CornerRadius = UDim.new(0, 8)
        OpenCorner.Parent = OpenButton
        
        local OpenGradient = Instance.new("UIGradient")
        OpenGradient.Color = ColorSequence.new{
            ColorSequenceKeypoint.new(0, Color3.fromRGB(60, 200, 120)),
            ColorSequenceKeypoint.new(1, Color3.fromRGB(40, 160, 90)),
        }
        OpenGradient.Rotation = 90
        OpenGradient.Parent = OpenButton
        
        -- Dismiss Button
        local NoButton = Instance.new("TextButton")
        NoButton.Name = "NoButton"
        NoButton.Size = UDim2.new(0.48, 0, 1, 0)
        NoButton.Position = UDim2.new(0.52, 0, 0, 0)
        NoButton.BackgroundColor3 = Color3.fromRGB(55, 55, 65)
        NoButton.Text = "Dismiss"
        NoButton.TextColor3 = Color3.fromRGB(180, 180, 180)
        NoButton.TextSize = 13
        NoButton.Font = Enum.Font.GothamBold
        NoButton.BorderSizePixel = 0
        NoButton.AutoButtonColor = false
        NoButton.Parent = ButtonContainer
        
        local NoCorner = Instance.new("UICorner")
        NoCorner.CornerRadius = UDim.new(0, 8)
        NoCorner.Parent = NoButton
        
        -- ====== EXPANDED CHANGELOG VIEW (Hidden initially) ======
        local ChangelogFrame = Instance.new("Frame")
        ChangelogFrame.Name = "ChangelogFrame"
        ChangelogFrame.Size = UDim2.new(0, 480, 0, 500)
        ChangelogFrame.Position = UDim2.new(0.5, 0, 0.5, 0)
        ChangelogFrame.AnchorPoint = Vector2.new(0.5, 0.5)
        ChangelogFrame.BackgroundColor3 = Color3.fromRGB(25, 25, 30)
        ChangelogFrame.BorderSizePixel = 0
        ChangelogFrame.Visible = false
        ChangelogFrame.Parent = ChangelogGui
        
        local ChangelogCorner = Instance.new("UICorner")
        ChangelogCorner.CornerRadius = UDim.new(0, 16)
        ChangelogCorner.Parent = ChangelogFrame
        
        local ChangelogStroke = Instance.new("UIStroke")
        ChangelogStroke.Color = Color3.fromRGB(80, 200, 120)
        ChangelogStroke.Thickness = 2
        ChangelogStroke.Transparency = 0.2
        ChangelogStroke.Parent = ChangelogFrame
        
        local ChangelogGradient = Instance.new("UIGradient")
        ChangelogGradient.Color = ColorSequence.new{
            ColorSequenceKeypoint.new(0, Color3.fromRGB(35, 35, 45)),
            ColorSequenceKeypoint.new(1, Color3.fromRGB(20, 20, 25)),
        }
        ChangelogGradient.Rotation = 135
        ChangelogGradient.Parent = ChangelogFrame
        
        -- Header with logo
        local HeaderFrame = Instance.new("Frame")
        HeaderFrame.Name = "Header"
        HeaderFrame.Size = UDim2.new(1, 0, 0, 65)
        HeaderFrame.Position = UDim2.new(0, 0, 0, 0)
        HeaderFrame.BackgroundTransparency = 1
        HeaderFrame.Parent = ChangelogFrame
        
        -- Header Logo container
        local HeaderLogoContainer = Instance.new("Frame")
        HeaderLogoContainer.Name = "LogoContainer"
        HeaderLogoContainer.Size = UDim2.new(0, 45, 0, 45)
        HeaderLogoContainer.Position = UDim2.new(0, 20, 0.5, 0)
        HeaderLogoContainer.AnchorPoint = Vector2.new(0, 0.5)
        HeaderLogoContainer.BackgroundColor3 = Color3.fromRGB(80, 200, 120)
        HeaderLogoContainer.BorderSizePixel = 0
        HeaderLogoContainer.Parent = HeaderFrame
        
        local HeaderLogoCorner = Instance.new("UICorner")
        HeaderLogoCorner.CornerRadius = UDim.new(0, 10)
        HeaderLogoCorner.Parent = HeaderLogoContainer
        
        local HeaderLogoFallback = Instance.new("TextLabel")
        HeaderLogoFallback.Name = "LogoFallback"
        HeaderLogoFallback.Size = UDim2.new(1, 0, 1, 0)
        HeaderLogoFallback.BackgroundTransparency = 1
        HeaderLogoFallback.Text = "K"
        HeaderLogoFallback.TextColor3 = Color3.fromRGB(255, 255, 255)
        HeaderLogoFallback.TextSize = 24
        HeaderLogoFallback.Font = Enum.Font.GothamBold
        HeaderLogoFallback.Parent = HeaderLogoContainer
        
        local HeaderTitle = Instance.new("TextLabel")
        HeaderTitle.Name = "Title"
        HeaderTitle.Size = UDim2.new(1, -140, 1, 0)
        HeaderTitle.Position = UDim2.new(0, 75, 0, 0)
        HeaderTitle.BackgroundTransparency = 1
        HeaderTitle.Text = "📋 Katchi Hub - Changelog"
        HeaderTitle.TextColor3 = Color3.fromRGB(255, 255, 255)
        HeaderTitle.TextSize = 18
        HeaderTitle.Font = Enum.Font.GothamBold
        HeaderTitle.TextXAlignment = Enum.TextXAlignment.Left
        HeaderTitle.Parent = HeaderFrame
        
        -- Close button
        local CloseButton = Instance.new("TextButton")
        CloseButton.Name = "CloseButton"
        CloseButton.Size = UDim2.new(0, 36, 0, 36)
        CloseButton.Position = UDim2.new(1, -52, 0.5, 0)
        CloseButton.AnchorPoint = Vector2.new(0, 0.5)
        CloseButton.BackgroundColor3 = Color3.fromRGB(180, 50, 50)
        CloseButton.Text = "x"
        CloseButton.TextColor3 = Color3.fromRGB(255, 255, 255)
        CloseButton.TextSize = 16
        CloseButton.Font = Enum.Font.GothamBold
        CloseButton.BorderSizePixel = 0
        CloseButton.AutoButtonColor = false
        CloseButton.Parent = HeaderFrame
        
        local CloseCorner = Instance.new("UICorner")
        CloseCorner.CornerRadius = UDim.new(0, 8)
        CloseCorner.Parent = CloseButton
        
        -- Divider line
        local Divider = Instance.new("Frame")
        Divider.Name = "Divider"
        Divider.Size = UDim2.new(1, -40, 0, 2)
        Divider.Position = UDim2.new(0, 20, 0, 65)
        Divider.BackgroundColor3 = Color3.fromRGB(80, 200, 120)
        Divider.BackgroundTransparency = 0.5
        Divider.BorderSizePixel = 0
        Divider.Parent = ChangelogFrame
        
        -- Legend row
        local LegendFrame = Instance.new("Frame")
        LegendFrame.Name = "Legend"
        LegendFrame.Size = UDim2.new(1, -40, 0, 25)
        LegendFrame.Position = UDim2.new(0, 20, 0, 75)
        LegendFrame.BackgroundTransparency = 1
        LegendFrame.Parent = ChangelogFrame
        
        -- Feature legend
        local FeatureDot = Instance.new("Frame")
        FeatureDot.Size = UDim2.new(0, 8, 0, 8)
        FeatureDot.Position = UDim2.new(0, 0, 0.5, 0)
        FeatureDot.AnchorPoint = Vector2.new(0, 0.5)
        FeatureDot.BackgroundColor3 = Color3.fromRGB(100, 200, 255)
        FeatureDot.BorderSizePixel = 0
        FeatureDot.Parent = LegendFrame
        Instance.new("UICorner", FeatureDot).CornerRadius = UDim.new(1, 0)
        
        local FeatureLabel = Instance.new("TextLabel")
        FeatureLabel.Size = UDim2.new(0, 50, 1, 0)
        FeatureLabel.Position = UDim2.new(0, 14, 0, 0)
        FeatureLabel.BackgroundTransparency = 1
        FeatureLabel.Text = "Feature"
        FeatureLabel.TextColor3 = Color3.fromRGB(140, 140, 140)
        FeatureLabel.TextSize = 11
        FeatureLabel.Font = Enum.Font.Gotham
        FeatureLabel.TextXAlignment = Enum.TextXAlignment.Left
        FeatureLabel.Parent = LegendFrame
        
        -- Fix legend
        local FixDot = Instance.new("Frame")
        FixDot.Size = UDim2.new(0, 8, 0, 8)
        FixDot.Position = UDim2.new(0, 80, 0.5, 0)
        FixDot.AnchorPoint = Vector2.new(0, 0.5)
        FixDot.BackgroundColor3 = Color3.fromRGB(255, 180, 50)
        FixDot.BorderSizePixel = 0
        FixDot.Parent = LegendFrame
        Instance.new("UICorner", FixDot).CornerRadius = UDim.new(1, 0)
        
        local FixLabel = Instance.new("TextLabel")
        FixLabel.Size = UDim2.new(0, 30, 1, 0)
        FixLabel.Position = UDim2.new(0, 94, 0, 0)
        FixLabel.BackgroundTransparency = 1
        FixLabel.Text = "Fix"
        FixLabel.TextColor3 = Color3.fromRGB(140, 140, 140)
        FixLabel.TextSize = 11
        FixLabel.Font = Enum.Font.Gotham
        FixLabel.TextXAlignment = Enum.TextXAlignment.Left
        FixLabel.Parent = LegendFrame
        
        -- Scrolling content area with version cards
        local ScrollFrame = Instance.new("ScrollingFrame")
        ScrollFrame.Name = "Content"
        ScrollFrame.Size = UDim2.new(1, -40, 1, -120)
        ScrollFrame.Position = UDim2.new(0, 20, 0, 105)
        ScrollFrame.BackgroundTransparency = 1
        ScrollFrame.BorderSizePixel = 0
        ScrollFrame.ScrollBarThickness = 6
        ScrollFrame.ScrollBarImageColor3 = Color3.fromRGB(80, 200, 120)
        ScrollFrame.CanvasSize = UDim2.new(0, 0, 0, 0)
        ScrollFrame.AutomaticCanvasSize = Enum.AutomaticSize.Y
        ScrollFrame.Parent = ChangelogFrame
        
        local ContentLayout = Instance.new("UIListLayout")
        ContentLayout.SortOrder = Enum.SortOrder.LayoutOrder
        ContentLayout.Padding = UDim.new(0, 12)
        ContentLayout.Parent = ScrollFrame
        
        -- Create version cards for each changelog entry
        for i, entry in ipairs(CHANGELOG_ENTRIES) do
            createVersionCard(ScrollFrame, entry, i)
        end
        
        -- ====== ANIMATIONS ======
        
        -- Slide in the popup from right
        task.wait(0.2)
        local slideIn = TweenService:Create(PopupFrame, TweenInfo.new(0.5, Enum.EasingStyle.Quint, Enum.EasingDirection.Out), {
            Position = UDim2.new(1, -20, 0, 20)
        })
        slideIn:Play()
        
        -- Close popup function
        local function closePopup()
            local slideOut = TweenService:Create(PopupFrame, TweenInfo.new(0.3, Enum.EasingStyle.Quint, Enum.EasingDirection.In), {
                Position = UDim2.new(1, 320, 0, 20)
            })
            slideOut:Play()
            slideOut.Completed:Wait()
            PopupFrame.Visible = false
        end
        
        -- Open changelog function with smooth transition
        local function openChangelog()
            -- Fade out popup content smoothly
            local fadeOutTweens = {}
            table.insert(fadeOutTweens, TweenService:Create(TitleLabel, TweenInfo.new(0.2, Enum.EasingStyle.Quad), {TextTransparency = 1}))
            table.insert(fadeOutTweens, TweenService:Create(SubtitleLabel, TweenInfo.new(0.2, Enum.EasingStyle.Quad), {TextTransparency = 1}))
            table.insert(fadeOutTweens, TweenService:Create(OpenButton, TweenInfo.new(0.2, Enum.EasingStyle.Quad), {BackgroundTransparency = 1, TextTransparency = 1}))
            table.insert(fadeOutTweens, TweenService:Create(NoButton, TweenInfo.new(0.2, Enum.EasingStyle.Quad), {BackgroundTransparency = 1, TextTransparency = 1}))
            table.insert(fadeOutTweens, TweenService:Create(LogoContainer, TweenInfo.new(0.2, Enum.EasingStyle.Quad), {BackgroundTransparency = 1}))
            table.insert(fadeOutTweens, TweenService:Create(LogoFallback, TweenInfo.new(0.2, Enum.EasingStyle.Quad), {TextTransparency = 1}))
            
            for _, tween in ipairs(fadeOutTweens) do
                tween:Play()
            end
            task.wait(0.2)
            
            -- Hide popup content
            ButtonContainer.Visible = false
            TitleLabel.Visible = false
            SubtitleLabel.Visible = false
            LogoContainer.Visible = false
            
            -- Smoothly move popup to center and expand
            local morphTween = TweenService:Create(PopupFrame, TweenInfo.new(0.4, Enum.EasingStyle.Quint, Enum.EasingDirection.Out), {
                Position = UDim2.new(0.5, 0, 0.5, 0),
                Size = UDim2.new(0, 480, 0, 500),
                AnchorPoint = Vector2.new(0.5, 0.5)
            })
            morphTween:Play()
            morphTween.Completed:Wait()
            
            -- Show changelog frame overlaying exactly on popup
            ChangelogFrame.Size = UDim2.new(0, 480, 0, 500)
            ChangelogFrame.BackgroundTransparency = 1
            ChangelogFrame.Visible = true
            
            -- Fade in changelog content
            local fadeInTween = TweenService:Create(ChangelogFrame, TweenInfo.new(0.3, Enum.EasingStyle.Quad), {
                BackgroundTransparency = 0
            })
            fadeInTween:Play()
            
            -- Hide popup after changelog is visible
            task.wait(0.15)
            PopupFrame.Visible = false
        end
        
        -- Close changelog function
        local function closeChangelog()
            -- Fade out then shrink
            local fadeOut = TweenService:Create(ChangelogFrame, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                BackgroundTransparency = 0.3
            })
            fadeOut:Play()
            fadeOut.Completed:Wait()
            
            local shrinkTween = TweenService:Create(ChangelogFrame, TweenInfo.new(0.25, Enum.EasingStyle.Quint, Enum.EasingDirection.In), {
                Size = UDim2.new(0, 0, 0, 0),
                BackgroundTransparency = 1
            })
            shrinkTween:Play()
            shrinkTween.Completed:Wait()
            ChangelogGui:Destroy()
        end
        
        -- Button connections
        OpenButton.MouseButton1Click:Connect(openChangelog)
        NoButton.MouseButton1Click:Connect(function()
            closePopup()
            task.wait(0.4)
            ChangelogGui:Destroy()
        end)
        CloseButton.MouseButton1Click:Connect(closeChangelog)
        
        -- Hover effects with smooth transitions
        OpenButton.MouseEnter:Connect(function()
            TweenService:Create(OpenButton, TweenInfo.new(0.2), {BackgroundColor3 = Color3.fromRGB(70, 220, 140)}):Play()
        end)
        OpenButton.MouseLeave:Connect(function()
            TweenService:Create(OpenButton, TweenInfo.new(0.2), {BackgroundColor3 = Color3.fromRGB(50, 180, 100)}):Play()
        end)
        
        NoButton.MouseEnter:Connect(function()
            TweenService:Create(NoButton, TweenInfo.new(0.2), {BackgroundColor3 = Color3.fromRGB(75, 75, 85)}):Play()
        end)
        NoButton.MouseLeave:Connect(function()
            TweenService:Create(NoButton, TweenInfo.new(0.2), {BackgroundColor3 = Color3.fromRGB(55, 55, 65)}):Play()
        end)
        
        CloseButton.MouseEnter:Connect(function()
            TweenService:Create(CloseButton, TweenInfo.new(0.15), {BackgroundColor3 = Color3.fromRGB(220, 70, 70)}):Play()
        end)
        CloseButton.MouseLeave:Connect(function()
            TweenService:Create(CloseButton, TweenInfo.new(0.15), {BackgroundColor3 = Color3.fromRGB(180, 50, 50)}):Play()
        end)
    end)
end -- end of Changelog Popup UI
