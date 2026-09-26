-- 业务相关已观察调用摘录：省略前面的环境探测，不补写 if/pcall/未执行分支。
-- 仅供阅读；这些语句不构成可直接运行的完整程序。
-- JSONDecode 后的通知与 Kick 是本次模拟的解析失败路径。
local HttpService = game:GetService("HttpService")
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
