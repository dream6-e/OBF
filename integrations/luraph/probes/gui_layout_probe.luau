-- Run as a LocalScript in StarterPlayerScripts of a blank Studio place (Play).
-- Also works in the command bar. No obfuscated code or network requests.
-- Creates only unparented ScreenGuis, reads their layout, then destroys them.
-- Output is calibration evidence, NOT restored source or a model implementation.
local HttpService = game:GetService("HttpService")
local RunService = game:GetService("RunService")
local cases = {}
local roots = {}

local function frame(parent, pos, size)
	local f = Instance.new("Frame")
	f.Position = pos
	f.Size = size
	f.Parent = parent
	return f
end

local function setup(name, configure)
	local gui = Instance.new("ScreenGui")
	table.insert(roots, gui)
	local parent = frame(gui, UDim2.fromOffset(31, -19), UDim2.fromOffset(321, 177))
	local child = frame(parent, UDim2.new(0.25, 11, 0.5, -7), UDim2.new(0.5, 23, 0.25, 17))
	configure(parent, child)
	table.insert(cases, {name = name, root = gui, parent = parent, child = child})
end

local function vector(v)
	return {v.X, v.Y}
end

local function dim2(v)
	return {v.X.Scale, v.X.Offset, v.Y.Scale, v.Y.Offset}
end

local function snapshot()
	local result = {}
	for _, case in cases do
		local items = {}
		for _, role in {"root", "parent", "child"} do
			local inst = case[role]
			local item = {
				class = inst.ClassName,
				absolutePosition = vector(inst.AbsolutePosition),
				absoluteSize = vector(inst.AbsoluteSize),
				absoluteRotation = inst.AbsoluteRotation,
			}
			if inst:IsA("GuiObject") then
				item.position = dim2(inst.Position)
				item.size = dim2(inst.Size)
				item.anchor = vector(inst.AnchorPoint)
				item.rotation = inst.Rotation
			end
			items[role] = item
		end
		table.insert(result, {name = case.name, items = items})
	end
	return result
end

local ok, result = xpcall(function()
	setup("scale-and-offset", function() end)
	setup("anchor", function(_, c) c.AnchorPoint = Vector2.new(0.375, 0.625) end)
	setup("rotation", function(p, c) p.Rotation = 37; c.Rotation = -83 end)
	setup("ui-scale", function(p)
		local scale = Instance.new("UIScale")
		scale.Scale = 1.25
		scale.Parent = p
	end)
	setup("size-constraint", function(_, c)
		local constraint = Instance.new("UISizeConstraint")
		constraint.MinSize = Vector2.new(41, 39)
		constraint.MaxSize = Vector2.new(113, 127)
		constraint.Parent = c
	end)
	setup("padding", function(p)
		local padding = Instance.new("UIPadding")
		padding.PaddingLeft = UDim.new(0.125, 3)
		padding.PaddingRight = UDim.new(0.25, 5)
		padding.PaddingTop = UDim.new(0, 7)
		padding.PaddingBottom = UDim.new(0, 11)
		padding.Parent = p
	end)
	setup("negative-size", function(_, c) c.Size = UDim2.fromOffset(-5, -13) end)
	setup("fractional-pixels", function(_, c)
		c.Position = UDim2.fromScale(-0.5, 0.5)
		c.Size = UDim2.fromScale(0.5, 0.5)
	end)
	local report = {
		schema = 1,
		engineVersion = version(),
		isStudio = RunService:IsStudio(),
		isRunning = RunService:IsRunning(),
		isClient = RunService:IsClient(),
		context = "unparented ScreenGui; no viewport or inset assumptions",
		immediate = snapshot(),
	}
	if RunService:IsRunning() then
		RunService.Heartbeat:Wait()
		RunService.Heartbeat:Wait()
		report.afterTwoHeartbeats = snapshot()
	end
	for _, case in cases do case.parent.Size = UDim2.fromOffset(419, 213) end
	report.afterResize = snapshot()
	if RunService:IsRunning() then
		RunService.Heartbeat:Wait()
		RunService.Heartbeat:Wait()
		report.afterResizeTwoHeartbeats = snapshot()
	end
	return HttpService:JSONEncode(report)
end, debug.traceback)

for _, root in roots do root:Destroy() end
if not ok then error(result, 0) end
-- Keep each Output entry short enough to copy without long-line truncation.
local chunkSize = 2000
local parts = math.ceil(#result / chunkSize)
print("GUI_LAYOUT_PROBE_META " .. HttpService:JSONEncode({schema = 1, bytes = #result, parts = parts}))
for i = 1, parts do
	print(string.format("GUI_LAYOUT_PROBE_PART %d/%d %s", i, parts,
		string.sub(result, (i - 1) * chunkSize + 1, i * chunkSize)))
end
print("GUI_LAYOUT_PROBE_DONE")
