---乐子Yeskid

local shit=function()pcall(function()game.Players.LocalPlayer:Kick()end)pcall(game.Shutdown,game)end

local fuck=function()return"a"end
hookfunction(fuck,function()return"b"end)
if not isfunctionhooked then shit()return end
if not isfunctionhooked(fuck)then shit()return end

local bitch=game.HttpGet
hookfunction(bitch,function()end)
if not isfunctionhooked(bitch)then shit()return end
restorefunction(bitch)
if isfunctionhooked(bitch)then shit()return end

local cunt=request or http_request or(syn and syn.request)or(fluxus and fluxus.request)

spawn(function()
    while task.wait(0.5)do
        pcall(function()
            if isfunctionhooked(game.HttpGet)then shit()end
            if isfunctionhooked(game.HttpPost)then shit()end
            if isfunctionhooked(tostring)then shit()end
            if isfunctionhooked(setclipboard)then shit()end
            if cunt and isfunctionhooked(cunt)then shit()end
            if isfolder("HttpGetFolder")or isfolder("WebhookFolder")or isfolder("RequestFolder")then shit()end
        end)
    end
end)

for _,dick in pairs({"rconsoleprint","rconsolewarn","rconsoleinfo","rconsoleerr","rconsoletitle","clonefunction"})do
    getgenv()[dick]=nil
end

local Players = game:GetService("Players")
local RunService = game:GetService("RunService")
local Lighting = game:GetService("Lighting")
local TweenService = game:GetService("TweenService")
local lp = Players.LocalPlayer
local camera = workspace.CurrentCamera
local activeClone = nil
local heartbeatConnection = nil

local WindUI = loadstring(game:HttpGet("https://raw.githubusercontent.com/dream6-e/rbx/refs/heads/main/main.lua"))()

WindUI:AddTheme({
    Name = "Qcq制作",
    Accent = Color3.fromHex("#18181b"),
    Background = Color3.fromHex("#101010"),
    Outline = Color3.fromHex("#FFFFFF"),
    Text = Color3.fromHex("#FFFFFF"),
    Placeholder = Color3.fromHex("#7a7a7a"),
    Button = Color3.fromHex("#52525b"),
    Icon = Color3.fromHex("#a1a1aa"),
})

local Window = WindUI:CreateWindow({
    Title = "死冯夺舍 ",
    Folder = "dead",
    SideBarWidth = 180,
    Background = "https://raw.githubusercontent.com/dream6-e/rbx/main/pppp.png",
    BackgroundImageTransparency = 0.5,
    OpenButton = {
        Title = "OPEN UI",
        CornerRadius = UDim.new(1, 0),
        StrokeThickness = 3,
        Enabled = true,
        Draggable = true,
        OnlyMobile = false,
        Scale = 0.9,
        Color = ColorSequence.new(
            Color3.fromHex("#30FF6A"),
            Color3.fromHex("#e7ff2f")
        ),
    },
    Topbar = {
        Height = 44,
        ButtonsType = "Mac",
    },
})

Window:Tag({
    Title = "乐子Yes",
    Color = Color3.fromHex("00CED1"),
    Radius = 2,
})

Window:Tag({
    Title = "Qcq",
    Icon = "crown",
    Color = Color3.fromHex("FFD700"),
    Radius = 2,
})

local COLOR_SCHEMES = {
    ["彩虹颜色"] = {ColorSequence.new({
        ColorSequenceKeypoint.new(0,    Color3.fromHex("FF0000")),
        ColorSequenceKeypoint.new(0.16, Color3.fromHex("FFA500")),
        ColorSequenceKeypoint.new(0.33, Color3.fromHex("FFFF00")),
        ColorSequenceKeypoint.new(0.5,  Color3.fromHex("00FF00")),
        ColorSequenceKeypoint.new(0.66, Color3.fromHex("0000FF")),
        ColorSequenceKeypoint.new(0.83, Color3.fromHex("4B0082")),
        ColorSequenceKeypoint.new(1,    Color3.fromHex("EE82EE"))
    }), "palette"},

    ["绿黄渐变"] = {ColorSequence.new({
        ColorSequenceKeypoint.new(0,   Color3.fromHex("30FF6A")),
        ColorSequenceKeypoint.new(0.5, Color3.fromHex("a8ff00")),
        ColorSequenceKeypoint.new(1,   Color3.fromHex("e7ff2f"))
    }), "waves"},
}

local borderAnimation
local animationSpeed = 5

local function createRainbowBorder(window, colorScheme)
    local mainFrame = window.UIElements.Main
    if not mainFrame then return nil end

    local existingStroke = mainFrame:FindFirstChild("RainbowStroke")
    if existingStroke then existingStroke:Destroy() end

    if not mainFrame:FindFirstChildOfClass("UICorner") then
        local corner = Instance.new("UICorner")
        corner.CornerRadius = UDim.new(0, 16)
        corner.Parent = mainFrame
    end

    local rainbowStroke = Instance.new("UIStroke")
    rainbowStroke.Name = "RainbowStroke"
    rainbowStroke.Thickness = 2
    rainbowStroke.Color = Color3.new(1, 1, 1)
    rainbowStroke.ApplyStrokeMode = Enum.ApplyStrokeMode.Border
    rainbowStroke.LineJoinMode = Enum.LineJoinMode.Round
    rainbowStroke.Parent = mainFrame

    local glowEffect = Instance.new("UIGradient")
    glowEffect.Name = "GlowEffect"
    local schemeData = COLOR_SCHEMES[colorScheme or "彩虹颜色"]
    glowEffect.Color = schemeData and schemeData[1] or COLOR_SCHEMES["彩虹颜色"][1]
    glowEffect.Rotation = 0
    glowEffect.Parent = rainbowStroke

    return rainbowStroke
end

local function startBorderAnimation(window, speed)
    local mainFrame = window.UIElements.Main
    if not mainFrame then return nil end
    local rainbowStroke = mainFrame:FindFirstChild("RainbowStroke")
    if not rainbowStroke then return nil end
    local glowEffect = rainbowStroke:FindFirstChild("GlowEffect")
    if not glowEffect then return nil end

    return game:GetService("RunService").Heartbeat:Connect(function()
        if not rainbowStroke or rainbowStroke.Parent == nil then return end
        glowEffect.Rotation = (tick() * speed * 10) % 360
    end)
end

local rainbowStroke = createRainbowBorder(Window, "彩虹颜色")
if rainbowStroke then
    borderAnimation = startBorderAnimation(Window, animationSpeed)
end

local TweenServiceBlur = game:GetService("TweenService")

local blur = Lighting:FindFirstChildOfClass("BlurEffect")
if not blur then
    blur = Instance.new("BlurEffect")
    blur.Size = 0
    blur.Parent = Lighting
end

task.spawn(function()
    local wasOpen = false
    while true do
        task.wait(0.1)
        local mainFrame = Window.UIElements and Window.UIElements.Main
        local isOpen = mainFrame and mainFrame.Visible or false
        
        if isOpen ~= wasOpen then
            wasOpen = isOpen
            TweenServiceBlur:Create(blur, TweenInfo.new(0.3), {
                Size = isOpen and 20 or 0
            }):Play()
        end
    end
end)

local function resetToNormal()
    if heartbeatConnection then 
        heartbeatConnection:Disconnect()
        heartbeatConnection = nil
    end
    if activeClone then 
        activeClone:Destroy() 
        activeClone = nil 
    end
    
    local realChar = lp.Character
    if realChar then
        local realHum = realChar:FindFirstChildOfClass("Humanoid")
        local realRoot = realChar:FindFirstChild("HumanoidRootPart")
        
        if realHum then
            realHum.PlatformStand = false
        end
        if realRoot then
            realRoot.Anchored = false
        end
        
        for _, v in ipairs(realChar:GetDescendants()) do
            if v:IsA("BasePart") or v:IsA("Decal") then 
                v.Transparency = 0 
            end
        end
    end
end

local function possessTarget(targetPlayer)
    if not targetPlayer then return end
    
    local targetChar = targetPlayer.Character
    if not targetChar or not targetChar:FindFirstChild("HumanoidRootPart") then
        WindUI:Notify({Title = "错误", Content = "目标角色未加载", Type = "error"})
        return
    end

    resetToNormal()
    task.wait(0.2)

    local realChar = lp.Character
    if not realChar then
        WindUI:Notify({Title = "错误", Content = "自己的角色未加载", Type = "error"})
        return
    end
    
    local realRoot = realChar:FindFirstChild("HumanoidRootPart")
    local realHum = realChar:FindFirstChildOfClass("Humanoid")
    
    targetChar.Archivable = true
    activeClone = targetChar:Clone()
    activeClone.Name = "PossessedClone"
    activeClone.Parent = workspace
    
    local cloneHum = activeClone:FindFirstChildOfClass("Humanoid")
    local cloneRoot = activeClone:FindFirstChild("HumanoidRootPart")
    
    if realRoot and realHum then
        local frozenPosition = realRoot.Position
        
        for _, v in ipairs(realChar:GetDescendants()) do
            if v:IsA("BasePart") or v:IsA("Decal") then 
                v.Transparency = 1 
            end
        end
        realRoot.CanCollide = false
        
        realHum.PlatformStand = true
        realRoot.Anchored = true
        
        heartbeatConnection = RunService.Heartbeat:Connect(function()
            if realRoot and realRoot.Parent then
                realRoot.CFrame = CFrame.new(frozenPosition)
                realRoot.Velocity = Vector3.zero
                realRoot.RotVelocity = Vector3.zero
            end
        end)
    end
    
    lp.Character = activeClone
    camera.CameraSubject = cloneHum
    
    local animate = activeClone:FindFirstChild("Animate")
    if animate then
        animate.Disabled = true
        task.wait(0.1)
        animate.Disabled = false
    end
    
    if cloneHum then
        cloneHum.Died:Connect(function()
            if realChar then
                lp.Character = realChar
                local realHum2 = realChar:FindFirstChildOfClass("Humanoid")
                if realHum2 then
                    realHum2.PlatformStand = false
                end
                local realRoot2 = realChar:FindFirstChild("HumanoidRootPart")
                if realRoot2 then
                    realRoot2.Anchored = false
                end
            end
            if activeClone then
                activeClone:Destroy()
                activeClone = nil
            end
            if heartbeatConnection then
                heartbeatConnection:Disconnect()
                heartbeatConnection = nil
            end
        end)
    end
    
    WindUI:Notify({Title = "成功", Content = "已伪装: " .. targetPlayer.Name, Type = "success"})
end
local function randomPossess()
    local allPlayers = Players:GetPlayers()
    local others = {}
    for _, p in ipairs(allPlayers) do
        if p ~= lp and p.Character and p.Character:FindFirstChild("HumanoidRootPart") then
            table.insert(others, p)
        end
    end
    
    if #others == 0 then 
        WindUI:Notify({Title = "错误", Content = "没有其他玩家可伪装", Type = "error"})
        return 
    end
    
    local target = others[math.random(1, #others)]
    possessTarget(target)
end

local MainTab = Window:Tab({ Title = "伪装", Icon = "user-round-cog" })
Window:SelectTab(1)

MainTab:Button({
    Title = "随机伪装",
    Callback = function()
        randomPossess()
    end,
})

MainTab:Button({
    Title = "重置回本体",
    Callback = function()
        resetToNormal()
        if lp.Character then
            local realChar = lp.Character
            lp.Character = realChar
            camera.CameraSubject = realChar:FindFirstChildOfClass("Humanoid")
        end
        WindUI:Notify({Title = "提示", Content = "已重置回本体", Type = "success"})
    end,
})

MainTab:Divider()

local PlayerDropdown = MainTab:Dropdown({
    Title = "选择玩家",
    Multi = false,
    Options = {},
    Callback = function(value)
        -- 不自动执行，等按钮触发
    end,
})

local function refreshPlayerList()
    local names = {}
    for _, p in ipairs(Players:GetPlayers()) do
        if p ~= lp then
            table.insert(names, p.Name)
        end
    end
    PlayerDropdown:Refresh(names)
end

MainTab:Button({
    Title = "刷新玩家列表",
    Callback = function()
        refreshPlayerList()
        WindUI:Notify({Title = "提示", Content = "列表已刷新", Type = "success"})
    end,
})

MainTab:Button({
    Title = "伪装选中玩家",
    Callback = function()
        local selectedValue = PlayerDropdown.Value
        if selectedValue and selectedValue ~= "" then
            local target = Players:FindFirstChild(selectedValue)
            if target then
                possessTarget(target)
            else
                WindUI:Notify({Title = "错误", Content = "玩家不存在", Type = "error"})
            end
        else
            WindUI:Notify({Title = "提示", Content = "请先选择一名玩家", Type = "warning"})
        end
    end,
})

refreshPlayerList()
Players.PlayerAdded:Connect(refreshPlayerList)
Players.PlayerRemoving:Connect(refreshPlayerList)
