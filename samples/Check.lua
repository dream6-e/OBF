local apiList = {
    "firesignal", "makefolder", "rconsolehide", "getsenv",
    "clear_teleport_queue", "cansignalreplicate", "isscriptable",
    "raknet.desync", "raknet.is_enabled",
    "debug.dumpheap", "debug.getconstants", "debug.getproto",
    "debug.setmemorycategory", "debug.profilebegin", "debug.loadmodule",
    "debug.traceback", "debug.getstack", "debug.getregistry",
    "debug.setmetatable", "debug.getupvalues", "debug.getupvalue",
    "debug.getmemorycategory", "debug.resetmemorycategory",
    "debug.setupvalue", "debug.validlevel", "debug.isvalidlevel",
    "debug.dumpcodesize", "debug.setstack", "debug.getconstant",
    "debug.profileend", "debug.info", "debug.getinfo",
    "debug.getprotos", "debug.setconstant", "debug.getmetatable",
    "debug.dumprefs",
    "getfflag", "consolecreate", "queue_on_teleport", "getexecutorname",
    "get_nil_instances", "consoledestroy", "getmousepos", "isgameactive",
    "keytap", "http.request",
    "crypt.encrypt", "crypt.lz4compress", "crypt.hash", "crypt.hmac",
    "crypt.random", "crypt.lz4decompress", "crypt.base64decode",
    "crypt.generatekey", "crypt.base64encode", "crypt.generatebytes",
    "crypt.base64.encode", "crypt.base64.decode", "crypt.base64_decode",
    "crypt.base64_encode", "crypt.decrypt",
    "setthreadcontext", "getallthreads", "getrenv", "LuaStateProxy.new",
    "getobjects", "httppost", "toclipboard", "newcclosure", "httpget",
    "gethiddenproperties", "request", "is_c_closure", "getthreadcontext",
    "isfunctionhooked", "websocket.connect",
    "bit.band", "bit.extract", "bit.byteswap", "bit.bor", "bit.bnot",
    "bit.countrz", "bit.bxor", "bit.arshift", "bit.rshift", "bit.rrotate",
    "bit.replace", "bit.lshift", "bit.lrotate", "bit.btest", "bit.countlz",
    "replacefunction", "cloneref", "setproximitypromptduration",
    "setscriptable", "keyclick", "http_request",
    "getproximitypromptduration",
    "Duration.FromMonths", "Duration.FromMilliseconds",
    "Duration.FromYears", "Duration.FromMicroseconds", "Duration.FromHours",
    "Duration.FromNanoseconds", "Duration.FromSeconds", "Duration.FromMinutes",
    "Duration.FromDays", "Duration.TimeSinceEpoch",
    "Stopwatch.new", "getprotos", "Regex.Escape", "Regex.new",
    "Signal.new", "decompile", "hookfunction", "getrendersteppedlist",
    "setthreadidentity", "getproto", "getactorstates", "replicatesignal",
    "isrbxactive", "rconsoleinfo", "make_readonly", "getstack",
    "getrunningscripts", "getidentity", "setfpscap", "getsignalarguments",
    "getupvalue", "getconnections",
    "Delta.is_android", "Delta.is_ios", "Delta.is_vng",
    "Delta.roblox_version", "Delta.is_mac", "Delta.version",
    "Delta.version_num", "Delta.version_hash", "Delta.architecture_str",
    "Delta.architecture", "Delta.get_platform",
    "getfunctionhash", "iscustomcclosure", "consolesettitle", "setidentity",
    "setsimulationradius", "isexecutorthread", "getfpscap", "mouse1click",
    "run_on_actor", "setupvalue", "isfolder", "ishooked", "isparallel",
    "gethiddenproperty", "identifyexecutor", "setrbxclipboard",
    "get_comm_channel", "getscripts", "create_comm_channel", "getluastate",
    "getnilinstances", "isvalidlevel", "getallactors", "iscclosure",
    "keypress", "getproperties", "getscriptsthatrun", "getupvalues",
    "get_hidden_gui", "rconsoleclear", "mousemoveabs", "checkparallel",
    "replacefunc", "get_actors", "setstack", "messagebox",
    "getactors", "deletefolder", "getinfo", "sethiddenproperty",
    "writefile", "base64_encode", "loadfile", "is_our_closure",
    "getconstant", "isrenderobj", "filtergc", "clonefunc",
    "getcallbackmember", "cleardrawcache", "isnewcclosure",
    "make_writeable", "getscriptclosure", "makereadonly",
    "hookmetamethod", "clearteleportqueue", "checkcaller",
    "setrawmetatable", "getfenv", "isreadonly", "is_function_hooked",
    "getnamecallmethod", "setreadonly", "getrawmetatable",
    "getscriptfromthread", "isdeltafunction", "getscriptthread",
    "is_delta_closure", "setrenderproperty", "isourclosure", "checkclosure",
    "setconstant",
    "pibble.gmail", "pibble.is_detected", "pibble.washington",
    "pibble.is_pibble", "pibble.getpibbles",
    "isexecutorclosure", "getinstances", "getconstants", "firetouchinterest",
    "cache.replace", "cache.iscached", "cache.invalidate",
    "is_l_closure", "getsignalwhitelist", "isnetworkowner",
    "compareinstances", "Drawing.new", "getsignalargumentsinfo",
    "delfile", "getcallingscript", "getrenderproperty", "readfile",
    "clonefunction", "gethui", "setnamecallmethod", "consoleprint",
    "detour_function", "detourfunction", "loadstring", "replaceclosure",
    "getthreadidentity", "mouse1release", "restorefunc", "restorefunction",
    "getcustomasset", "newlclosure", "hookfunc", "rconsolewarn",
    "rconsoleerr", "rconsoleshow", "rconsolename",
    "delfolder", "listfiles", "keyrelease", "rconsolesettitle",
    "rconsoleprint", "consoleinput", "getscripthash", "get_thread_identity",
    "rconsoledestroy", "rconsolecreate", "set_thread_context", "setfflag",
    "server.has_authority", "base64_decode", "mousescroll", "mousemoverel",
    "getgamestate", "fireproximityprompt", "glooperror", "mouse2release",
    "getscriptfunction", "islclosure", "get_thread_context", "mouse2click",
    "mouse2press", "restoreclosure", "mouse1press", "dumpstring",
    "lz4decompress", "isfile", "lz4compress", "base64.encode",
    "base64.decode", "appendfile", "getscriptbytecode", "consoleclear",
    "getloadedmodules", "getcbvalue", "getgc", "gethwid",
    "getsimulationradius", "set_thread_identity", "clonereference",
    "setstackhidden", "base64decode", "is_executor_closure", "validlevel",
    "get_fps_cap", "fireclickdetector", "setclipboard", "rconsoleinput",
    "getmenv", "getreg", "queueonteleport", "getgenv",
    "clearqueueonteleport", "dofile", "iswindowactive", "base64encode",
    "set_fps_cap", "getcallbackvalue"
}

local function getGlobalEnv()
    if type(getgenv) == "function" then
        local ok, env = pcall(getgenv)
        if ok and type(env) == "table" then
            return env
        end
    end
    return _G
end

local function pathExists(root, path)
    local current = root
    for part in string.gmatch(path, "[^%.]+") do
        if type(current) ~= "table" then
            return false
        end
        local ok, val = pcall(function() return current[part] end)
        if not ok or val == nil then
            local rawOk, rawVal = pcall(rawget, current, part)
            if rawOk and rawVal ~= nil then
                current = rawVal
            else
                return false
            end
        else
            current = val
        end
    end
    return true
end

local env = getGlobalEnv()

for _, apiPath in ipairs(apiList) do
    if not pathExists(env, apiPath) then
        while true do error(0,0) end
    end
end