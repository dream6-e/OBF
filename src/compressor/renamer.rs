use std::collections::HashSet;

pub struct Renamer {
    safe_globals: HashSet<String>,
    keywords: HashSet<String>,
}

impl Renamer {
    pub fn new() -> Self {
        let safe_globals: HashSet<String> = [
            "print", "math", "string", "table", "coroutine", "debug", "os", "io", "utf8", "bit32",
            "getmetatable", "setmetatable", "tonumber", "tostring", "type", "unpack",
            "select", "pcall", "xpcall", "error", "assert", "require", "module",
            "getfenv", "setfenv", "ipairs", "pairs", "next", "rawget", "rawset",
            "rawequal", "collectgarbage", "gcinfo", "load", "loadfile", "loadstring", "_G", "_VERSION", "_ENV",
            
            "game", "workspace", "script", "shared", "warn", "delay", "spawn", "tick", "elapsedTime", 
            "settings", "stats", "typeof", "task", "UserSettings", "printidentity", "PluginManager",
            "buffer",
            
            "Instance", "Color3", "Vector3", "Vector2", "UDim2", "UDim", "CFrame", "RaycastParams", 
            "Enum", "ColorSequence", "NumberSequence", "NumberSequenceKeypoint", "Font", "TweenInfo",
            "Faces", "Axes", "BrickColor", "CatalogSearchParams", "DateTime", "FloatCurveKey", 
            "OverlapParams", "PathWaypoint", "PhysicalProperties", "Random", "Ray", "Rect", 
            "Region3", "Region3int16", "TweenSequence", "Vector2int16", "Vector3int16", "RaycastResult",
            
            "checkcaller", "hookmetamethod", "hookfunction", "newcclosure", "getnamecallmethod",
            "getrawmetatable", "setrawmetatable", "cloneref", "clonereference", "gethui", "syn",
            "getgenv", "setclipboard", "toclipboard", "identifyexecutor", "getexecutorname",
            "writefile", "readfile", "appendfile", "listfiles", "isfile", "isfolder",
            "makefolder", "delfolder", "delfile", "getconnections", "firesignal", "fireclickdetector",
            "fireproximitydetector", "getconstants", "getupvalues", "getupvalue", "setupvalue",
            "setconstant", "getreg", "getgc", "setreadonly", "isreadonly", "is_sirhurt_closure",
            "is_krnl_closure", "is_proto_closure", "is_our_closure", "is_executor_closure",
            "iscclosure", "islclosure", "getnilinstances", "getloadedmodules", "getcustomasset",
            "getscripthash", "rconsolename", "rconsoleprint", "rconsoleinfo", "rconsolewarn",
            "rconsoleerr", "rconsoleclear", "getrenv", "getrunningscripts", "hookproto",
            "request", "http_request", "HttpGet", "HttpPost", "getinstances", "getscripts",
            "getcallingscript", "getscriptclosure", "messagebox", "queue_on_teleport", "clear_teleport_queue",
            "setfpscap", "getfpscap", "isrbxactive", "iswindowactive", "keypress", "keyrelease",
            "mouse1click", "mouse1press", "mouse1release", "mouse2click", "mouse2press", "mouse2release",
            "mousescroll", "mousemoveabs", "mousemoverel",
            
            "protectGUI", "protect_gui", "protectInstance", "createProtectedScreenGui", 
            "getRandomStealthName", "getRandomInstanceName", "getRandomChildName", "isStealthName", 
            "cloakInstance", "uncloakInstance", "ProtectedGUIs", "ProtectedInstances", "CloakedInstances",
            "discordInvite"
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        let keywords: HashSet<String> = [
            "and", "break", "do", "else", "elseif", "end", "false", "for", "function",
            "if", "in", "local", "nil", "not", "or", "repeat", "return", "then",
            "true", "until", "while", "continue"
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        Self { safe_globals, keywords }
    }

    pub fn is_keyword(&self, name: &str) -> bool {
        self.keywords.contains(name)
    }

    pub fn is_safe_global(&self, name: &str) -> bool {
        self.safe_globals.contains(name)
    }
}