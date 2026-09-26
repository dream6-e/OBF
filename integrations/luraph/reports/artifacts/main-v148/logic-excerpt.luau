-- 主库 luraph14.8.lua 的可读模拟记录；不是完整静态还原源码。
-- 含试探回调、循环截断和不完整变量绑定，只供分析，不要直接运行。
-- 未真实获取远程 UI 库；if state 等结构不保证是原程序的条件。
-- 业务摘录：省略前面的探测/钩子操作；RunService 定义取自此前记录。
local RunService = game:GetService("RunService")
local Players = game:GetService("Players")
local Lighting = game:GetService("Lighting")
local TweenService = game:GetService("TweenService")
local response = game:HttpGet("https://raw.githubusercontent.com/dream6-e/rbx/refs/heads/main/main.lua")
local result = loadstring(response)()
result:AddTheme({
	Name = "Qcq制作",
	Text = Color3.fromHex("#FFFFFF"),
	Accent = Color3.fromHex("#18181b"),
	Background = Color3.fromHex("#101010"),
	Button = Color3.fromHex("#52525b"),
	Icon = Color3.fromHex("#a1a1aa"),
	Outline = Color3.fromHex("#FFFFFF"),
	Placeholder = Color3.fromHex("#7a7a7a")
})
local Window = result:CreateWindow({
	Title = "死冯夺舍 ",
	Background = "https://raw.githubusercontent.com/dream6-e/rbx/main/pppp.png",
	BackgroundImageTransparency = 0.5,
	Folder = "dead",
	OpenButton = {
		Title = "OPEN UI",
		Color = ColorSequence.new(Color3.fromHex("#30FF6A"), Color3.fromHex("#e7ff2f")),
		CornerRadius = UDim.new(1, 0),
		Draggable = true,
		Enabled = true,
		OnlyMobile = false,
		Scale = 0.9,
		StrokeThickness = 3
	},
	SideBarWidth = 180,
	Topbar = { ButtonsType = "Mac", Height = 44 }
})
Window:Tag({ Title = "乐子Yes", Color = Color3.fromHex("00CED1"), Radius = 2 })
Window:Tag({ Title = "Qcq", Color = Color3.fromHex("FFD700"), Icon = "crown", Radius = 2 })
local RainbowStroke = Window.UIElements.Main:FindFirstChild("RainbowStroke")
RainbowStroke:Destroy()
Window.UIElements.Main:FindFirstChildOfClass("UICorner")
local UIStroke = Instance.new("UIStroke")
UIStroke.Name = "RainbowStroke"
UIStroke.Thickness = 2
UIStroke.Color = Color3.new(1, 1, 1)
UIStroke.ApplyStrokeMode = Enum.ApplyStrokeMode.Border
UIStroke.LineJoinMode = Enum.LineJoinMode.Round
UIStroke.Parent = Window.UIElements.Main
local UIGradient = Instance.new("UIGradient")
UIGradient.Name = "GlowEffect"
UIGradient.Color = ColorSequence.new({ ColorSequenceKeypoint.new(0, Color3.fromHex("FF0000")), ColorSequenceKeypoint.new(0.16, Color3.fromHex("FFA500")), ColorSequenceKeypoint.new(0.33, Color3.fromHex("FFFF00")), ColorSequenceKeypoint.new(0.5, Color3.fromHex("00FF00")), ColorSequenceKeypoint.new(0.66, Color3.fromHex("0000FF")), ColorSequenceKeypoint.new(0.83, Color3.fromHex("4B0082")), ColorSequenceKeypoint.new(1, Color3.fromHex("EE82EE")) })
UIGradient.Rotation = 0
UIGradient.Parent = UIStroke
Window.UIElements.Main:FindFirstChild("RainbowStroke")
UIStroke:FindFirstChild("GlowEffect")
RunService.Heartbeat:Connect(function(deltaTime)
	UIGradient.Rotation = 218.06744384765625
end)
local BlurEffect = Lighting:FindFirstChildOfClass("BlurEffect")
task.spawn(function(...)
	task.wait(0.1)
	local tween = TweenService:Create(BlurEffect, TweenInfo.new(0.3), { Size = 20 })
	tween:Play()
	task.wait(0.1)
	task.wait(0.1)
	-- [envlog] the statements above repeat forever (loop)
end)
local Tab = Window:Tab({ Title = "伪装", Icon = "user-round-cog" })
Window:SelectTab(1)
Tab:Button({
	Title = "随机伪装",
	Callback = function(state, arg14)
		if state then
			local players = Players:GetPlayers()
			for i, v in ipairs(players) do
				v.Character:FindFirstChild("HumanoidRootPart")
			end
			v.Character:FindFirstChild("HumanoidRootPart")
			local Humanoid = Players.LocalPlayer.Character:FindFirstChildOfClass("Humanoid")
			local HumanoidRootPart = Players.LocalPlayer.Character:FindFirstChild("HumanoidRootPart")
			Humanoid.PlatformStand = false
			HumanoidRootPart.Anchored = false
			local descendants = Players.LocalPlayer.Character:GetDescendants()
			for i2, v2 in ipairs(descendants) do
				v2.Transparency = 0
			end
			task.wait(0.2)
			local HumanoidRootPart2 = Players.LocalPlayer.Character:FindFirstChild("HumanoidRootPart")
			local Humanoid2 = Players.LocalPlayer.Character:FindFirstChildOfClass("Humanoid")
			v.Character.Archivable = true
			local clone = v.Character:Clone()
			clone.Name = "PossessedClone"
			clone.Parent = workspace
			local Humanoid3 = clone:FindFirstChildOfClass("Humanoid")
			clone:FindFirstChild("HumanoidRootPart")
			local descendants2 = Players.LocalPlayer.Character:GetDescendants()
			for i3, v3 in ipairs(descendants2) do
				v3.Transparency = 1
			end
			HumanoidRootPart2.CanCollide = false
			Humanoid2.PlatformStand = true
			HumanoidRootPart2.Anchored = true
			local connection7 = RunService.Heartbeat:Connect(function(deltaTime2)
				HumanoidRootPart2.CFrame = CFrame.new(HumanoidRootPart2.Position)
				HumanoidRootPart2.Velocity = Vector3.new(0, 0, 0)
				HumanoidRootPart2.RotVelocity = Vector3.new(0, 0, 0)
			end)
			Players.LocalPlayer.Character = clone
			workspace.CurrentCamera.CameraSubject = Humanoid3
			local Animate = clone:FindFirstChild("Animate")
			Animate.Disabled = true
			task.wait(0.1)
			Animate.Disabled = false
			Humanoid3.Died:Connect(function()
				Players.LocalPlayer.Character = Players.LocalPlayer.Character
				local Humanoid17 = Players.LocalPlayer.Character:FindFirstChildOfClass("Humanoid")
				Humanoid17.PlatformStand = false
				local HumanoidRootPart11 = Players.LocalPlayer.Character:FindFirstChild("HumanoidRootPart")
				HumanoidRootPart11.Anchored = false
				clone4:Destroy()
				connection10:Disconnect()
			end)
			result:Notify({ Title = "成功", Content = "已伪装: " .. v.Name, Type = "success" })
		else
			local players2 = Players:GetPlayers()
			for i4, v4 in ipairs(players2) do
				v4.Character:FindFirstChild("HumanoidRootPart")
			end
			v4.Character:FindFirstChild("HumanoidRootPart")
			connection7:Disconnect()
			clone:Destroy()
			local Humanoid4 = clone:FindFirstChildOfClass("Humanoid")
			local HumanoidRootPart3 = clone:FindFirstChild("HumanoidRootPart")
			Humanoid4.PlatformStand = false
			HumanoidRootPart3.Anchored = false
			local descendants3 = clone:GetDescendants()
			for i5, v5 in ipairs(descendants3) do
				v5.Transparency = 0
			end
			task.wait(0.2)
			local HumanoidRootPart4 = clone:FindFirstChild("HumanoidRootPart")
			local Humanoid5 = clone:FindFirstChildOfClass("Humanoid")
			v4.Character.Archivable = true
			local clone2 = v4.Character:Clone()
			clone2.Name = "PossessedClone"
			clone2.Parent = workspace
			local Humanoid6 = clone2:FindFirstChildOfClass("Humanoid")
			clone2:FindFirstChild("HumanoidRootPart")
			local descendants4 = clone:GetDescendants()
			for i6, v6 in ipairs(descendants4) do
				v6.Transparency = 1
			end
			HumanoidRootPart4.CanCollide = false
			Humanoid5.PlatformStand = true
			HumanoidRootPart4.Anchored = true
			local connection8 = RunService.Heartbeat:Connect(function(deltaTime3)
				HumanoidRootPart4.CFrame = CFrame.new(HumanoidRootPart4.Position)
				HumanoidRootPart4.Velocity = Vector3.new(0, 0, 0)
				HumanoidRootPart4.RotVelocity = Vector3.new(0, 0, 0)
			end)
			Players.LocalPlayer.Character = clone2
			workspace.CurrentCamera.CameraSubject = Humanoid6
			local Animate2 = clone2:FindFirstChild("Animate")
			Animate2.Disabled = true
			task.wait(0.1)
			Animate2.Disabled = false
			Humanoid6.Died:Connect(function()
				Players.LocalPlayer.Character = clone
				local Humanoid18 = clone:FindFirstChildOfClass("Humanoid")
				Humanoid18.PlatformStand = false
				local HumanoidRootPart12 = clone:FindFirstChild("HumanoidRootPart")
				HumanoidRootPart12.Anchored = false
			end)
			result:Notify({ Title = "成功", Content = "已伪装: " .. v4.Name, Type = "success" })
		end
	end
})
Tab:Button({
	Title = "重置回本体",
	Callback = function(state, arg16)
		if state then
			connection8:Disconnect()
			clone2:Destroy()
			local Humanoid7 = clone2:FindFirstChildOfClass("Humanoid")
			local HumanoidRootPart5 = clone2:FindFirstChild("HumanoidRootPart")
			Humanoid7.PlatformStand = false
			HumanoidRootPart5.Anchored = false
			local descendants5 = clone2:GetDescendants()
			for i7, v7 in ipairs(descendants5) do
				v7.Transparency = 0
			end
			Players.LocalPlayer.Character = clone2
			local Humanoid8 = clone2:FindFirstChildOfClass("Humanoid")
			workspace.CurrentCamera.CameraSubject = Humanoid8
		else
			local Humanoid9 = clone2:FindFirstChildOfClass("Humanoid")
			local HumanoidRootPart6 = clone2:FindFirstChild("HumanoidRootPart")
			Humanoid9.PlatformStand = false
			HumanoidRootPart6.Anchored = false
			local descendants6 = clone2:GetDescendants()
			for i8, v8 in ipairs(descendants6) do
				v8.Transparency = 0
			end
			Players.LocalPlayer.Character = clone2
			local Humanoid10 = clone2:FindFirstChildOfClass("Humanoid")
			workspace.CurrentCamera.CameraSubject = Humanoid10
		end
		result:Notify({ Title = "提示", Content = "已重置回本体", Type = "success" })
	end
})
Tab:Divider()
local Dropdown = Tab:Dropdown({
	Title = "选择玩家",
	Multi = false,
	Options = {},
	Callback = function(state, arg18)
	end
})
Tab:Button({
	Title = "刷新玩家列表",
	Callback = function(state, arg20)
		if state then
			local players3 = Players:GetPlayers()
			for i9, v9 in ipairs(players3) do
			end
			Dropdown:Refresh({ v9.Name })
		else
			local players4 = Players:GetPlayers()
			for i10, v10 in ipairs(players4) do
			end
			Dropdown:Refresh({ v10.Name })
		end
		result:Notify({ Title = "提示", Content = "列表已刷新", Type = "success" })
	end
})
Tab:Button({
	Title = "伪装选中玩家",
	Callback = function(state, arg22)
		if state then
			local child = Players:FindFirstChild(Dropdown.Value)
			child.Character:FindFirstChild("HumanoidRootPart")
			local Humanoid11 = clone2:FindFirstChildOfClass("Humanoid")
			local HumanoidRootPart7 = clone2:FindFirstChild("HumanoidRootPart")
			Humanoid11.PlatformStand = false
			HumanoidRootPart7.Anchored = false
			local descendants7 = clone2:GetDescendants()
			for i11, v11 in ipairs(descendants7) do
				v11.Transparency = 0
			end
			task.wait(0.2)
			local HumanoidRootPart8 = clone2:FindFirstChild("HumanoidRootPart")
			local Humanoid12 = clone2:FindFirstChildOfClass("Humanoid")
			child.Character.Archivable = true
			local clone3 = child.Character:Clone()
			clone3.Name = "PossessedClone"
			clone3.Parent = workspace
			local Humanoid13 = clone3:FindFirstChildOfClass("Humanoid")
			clone3:FindFirstChild("HumanoidRootPart")
			local descendants8 = clone2:GetDescendants()
			for i12, v12 in ipairs(descendants8) do
				v12.Transparency = 1
			end
			HumanoidRootPart8.CanCollide = false
			Humanoid12.PlatformStand = true
			HumanoidRootPart8.Anchored = true
			local connection9 = RunService.Heartbeat:Connect(function(deltaTime4)
				HumanoidRootPart8.CFrame = CFrame.new(HumanoidRootPart8.Position)
				HumanoidRootPart8.Velocity = Vector3.new(0, 0, 0)
				HumanoidRootPart8.RotVelocity = Vector3.new(0, 0, 0)
			end)
			Players.LocalPlayer.Character = clone3
			workspace.CurrentCamera.CameraSubject = Humanoid13
			local Animate3 = clone3:FindFirstChild("Animate")
			Animate3.Disabled = true
			task.wait(0.1)
			Animate3.Disabled = false
			Humanoid13.Died:Connect(function()
				Players.LocalPlayer.Character = clone2
				local Humanoid19 = clone2:FindFirstChildOfClass("Humanoid")
				Humanoid19.PlatformStand = false
				local HumanoidRootPart13 = clone2:FindFirstChild("HumanoidRootPart")
				HumanoidRootPart13.Anchored = false
			end)
			result:Notify({ Title = "成功", Content = "已伪装: " .. child.Name, Type = "success" })
		else
			local child2 = Players:FindFirstChild(Dropdown.Value)
			child2.Character:FindFirstChild("HumanoidRootPart")
			connection9:Disconnect()
			clone3:Destroy()
			local Humanoid14 = clone3:FindFirstChildOfClass("Humanoid")
			local HumanoidRootPart9 = clone3:FindFirstChild("HumanoidRootPart")
			Humanoid14.PlatformStand = false
			HumanoidRootPart9.Anchored = false
			local descendants9 = clone3:GetDescendants()
			for i13, v13 in ipairs(descendants9) do
				v13.Transparency = 0
			end
			task.wait(0.2)
			local HumanoidRootPart10 = clone3:FindFirstChild("HumanoidRootPart")
			local Humanoid15 = clone3:FindFirstChildOfClass("Humanoid")
			child2.Character.Archivable = true
			local clone4 = child2.Character:Clone()
			clone4.Name = "PossessedClone"
			clone4.Parent = workspace
			local Humanoid16 = clone4:FindFirstChildOfClass("Humanoid")
			clone4:FindFirstChild("HumanoidRootPart")
			local descendants10 = clone3:GetDescendants()
			for i14, v14 in ipairs(descendants10) do
				v14.Transparency = 1
			end
			HumanoidRootPart10.CanCollide = false
			Humanoid15.PlatformStand = true
			HumanoidRootPart10.Anchored = true
			local connection10 = RunService.Heartbeat:Connect(function(deltaTime5)
				HumanoidRootPart10.CFrame = CFrame.new(HumanoidRootPart10.Position)
				HumanoidRootPart10.Velocity = Vector3.new(0, 0, 0)
				HumanoidRootPart10.RotVelocity = Vector3.new(0, 0, 0)
			end)
			Players.LocalPlayer.Character = clone4
			workspace.CurrentCamera.CameraSubject = Humanoid16
			local Animate4 = clone4:FindFirstChild("Animate")
			Animate4.Disabled = true
			task.wait(0.1)
			Animate4.Disabled = false
			Humanoid16.Died:Connect(function()
				Players.LocalPlayer.Character = clone3
				local Humanoid20 = clone3:FindFirstChildOfClass("Humanoid")
				Humanoid20.PlatformStand = false
				local HumanoidRootPart14 = clone3:FindFirstChild("HumanoidRootPart")
				HumanoidRootPart14.Anchored = false
			end)
			result:Notify({ Title = "成功", Content = "已伪装: " .. child2.Name, Type = "success" })
		end
	end
})
local players5 = Players:GetPlayers()
for i15, v15 in ipairs(players5) do
end
Dropdown:Refresh({ v15.Name })
Players.PlayerAdded:Connect(function(player)
	local players6 = Players:GetPlayers()
	for i16, v16 in ipairs(players6) do
	end
	Dropdown:Refresh({ v16.Name })
end)
Players.PlayerRemoving:Connect(function(player2)
	local players7 = Players:GetPlayers()
	for i17, v17 in ipairs(players7) do
	end
	Dropdown:Refresh({ v17.Name })
end)
