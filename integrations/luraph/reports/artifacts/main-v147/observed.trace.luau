-- 主库 Luraph14.7.lua 的模拟运行记录；分析用，不是完整还原脚本。
-- 空回调不证明原回调为空；取消的任务未执行；未覆盖白名单成功分支。
-- 网络响应由离线模拟器提供，没有实际获取白名单。
-- RESULT: behavior trace, NOT reconstructed source
-- source: input.lua
-- Only observed paths are represented.
-- run status: finished
-- 56 statements recorded in 0.47s
-- URLs requested:
--   https://raw.githubusercontent.com/GKye9178/okokok91787891kkk/refs/heads/main/gk%E8%8E%B7%E5%8F%96%E7%99%BD%E5%90%8D%E5%8D%95.lua
-- non-standard globals touched: gethwid

task.spawn(function()
end)
task.spawn(function()
end)
task.delay(370, function()
	-- [envlog] cancelled before it ran
end)
local ScreenGui = Instance.new("ScreenGui")
local Frame = Instance.new("Frame")
Frame.Position = UDim2.new(0, 0, 0, 0)
Frame.Size = UDim2.new(0, 277, 0, 126)
Frame.Parent = ScreenGui
local Path2D = Instance.new("Path2D")
Path2D.Parent = Frame
Path2D:SetControlPoints({ Path2DControlPoint.new(UDim2.new(0, 5, 0, -5), UDim2.new(0, 0, 0, 0), UDim2.new(-0.0625, 4, 0, 0)), Path2DControlPoint.new(UDim2.new(0, 7, 0.25, 0), UDim2.new(0, 0, 0, 0), UDim2.new(0, 1, -0.0625, 4)), Path2DControlPoint.new(UDim2.new(0.25, -1, 0, -3), UDim2.new(0, 0, 0, 0), UDim2.new(-0.125, -8, 0, -3)), Path2DControlPoint.new(UDim2.new(0, -8, 0.375, -10), UDim2.new(0, 0, 0, 0), UDim2.new(0, -4, 0, 3)), Path2DControlPoint.new(UDim2.new(0, 1, 0.5, -1), UDim2.new(0, 0, 0, 0), UDim2.new(0, 3, 0, -1)) })
Path2D:GetLength()
Path2D:GetPositionOnCurve(0.27272728085517883)
Path2D:GetPositionOnCurve(0.875)
Path2D:GetPositionOnCurve(0.81818181276321411)
Path2D:GetTangentOnCurve(0.625)
Path2D:GetTangentOnCurve(0.25)
Path2D:GetPositionOnCurveArcLength(0.53846156597137451)
Path2D:GetPositionOnCurveArcLength(0.1111111119389534)
Path2D:GetPositionOnCurveArcLength(0.40000000596046448)
Path2D:GetTangentOnCurveArcLength(0.80000001192092896)
Path2D:GetTangentOnCurveArcLength(0.20000000298023224)
ScreenGui:Destroy()
local connection = game.AttributeChanged:Connect(function(attribute)
end)
connection:Disconnect()
local connection2 = workspace.AttributeChanged:Connect(function(attribute2)
end)
connection2:Disconnect()
local Folder = Instance.new("Folder")
local connection3 = Folder.AttributeChanged:Connect(function(attribute3)
end)
connection3:Disconnect()
Folder:GetChildren()
Folder:Destroy()
local Folder2 = Instance.new("Folder", Folder)
local connection4 = Folder2.AttributeChanged:Connect(function(attribute4)
end)
connection4:Disconnect()
Folder2.Name = "2039492913"
Folder:WaitForChild("2039492913")
Folder:Destroy()
Folder2:Destroy()
local HttpService = game:GetService("HttpService")
local connection5 = HttpService.AttributeChanged:Connect(function(attribute5)
end)
connection5:Disconnect()
local RunService = game:GetService("RunService")
local connection6 = RunService.AttributeChanged:Connect(function(attribute6)
end)
connection6:Disconnect()
local Players = game:GetService("Players")
local StarterGui = game:GetService("StarterGui")
gethwid()
local response = game:HttpGet("https://raw.githubusercontent.com/GKye9178/okokok91787891kkk/refs/heads/main/gk%E8%8E%B7%E5%8F%96%E7%99%BD%E5%90%8D%E5%8D%95.lua")
local result = response:gsub("^﻿", "")
local result2 = result:gsub("%s*%-%-[^\n\r]*", "")
local lastResult = result2:gsub(",(%s*[%]%}])", "%1")
HttpService:JSONDecode(lastResult)
StarterGui:SetCore("SendNotification", { Text = "白名单数据格式错误，请联系管理员", Title = "Bacon head", Duration = 5 })
task.wait(1)
Players.LocalPlayer:Kick("❌ 数据解析失败")
