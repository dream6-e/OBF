local cases = {
    {
        "initial",
        function()
            for i = "invalid", 1 do
            end
        end,
        "'for' initial value must be a number",
    },
    {
        "limit",
        function()
            for i = 1, "invalid" do
            end
        end,
        "'for' limit must be a number",
    },
    {
        "step",
        function()
            for i = 1, 2, "invalid" do
            end
        end,
        "'for' step must be a number",
    },
}

for _, case in ipairs(cases) do
    local ok, err = pcall(case[2])
    local matched = not ok and type(err) == "string" and string.find(err, case[3], 1, true) ~= nil
    print(case[1], not ok, matched)
end
