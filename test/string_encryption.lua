-- Regression fixture for chained ChaCha string constants.
-- The decoder feeds the first 8 plaintext bytes of each non-final 64-byte
-- block into the next block's counter. Compare source and generated output
-- in both ordinary and MB modes; also verify the exact HttpGet argument.

local function hex(s)
    local result = {}
    for i = 1, #s do
        result[i] = string.format("%02X", string.byte(s, i))
    end
    return table.concat(result)
end

local urls = {
    "https://raw.githubusercontent.com/dream6-e/rbx/refs/heads/main/main.lua",
    "https://raw.githubusercontent.com/dream6-e/rbx/main/pppp.png",
    "https://github.com/Footagesus/WindUI/releases/latest/download/main.lua",
    "https://raw.githubusercontent.com/katchilove81-png/dawdawdaw/refs/heads/main/ChatGPT%20Image%20Dec%2017%2C%202025%2C%2005_54_46%20PM.png",
    "https://discord.com/api/guilds/1433658537027833969/widget.json?x=1&y=%2F#frag",
}
for i = 1, #urls do
    print("URL", i, #urls[i], urls[i], hex(urls[i]))
end

local expected_lengths = { 63, 64, 65, 127, 128, 129 }
local boundary_strings = {
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ01",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ012",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRS",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRST",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTU",
}
for i = 1, #boundary_strings do
    assert(#boundary_strings[i] == expected_lengths[i], "bad boundary fixture")
    print("BOUNDARY", i, #boundary_strings[i], hex(boundary_strings[i]))
end

local all_bytes = "\000\001\002\003\004\005\006\007\008\009\010\011\012\013\014\015\016\017\018\019\020\021\022\023\024\025\026\027\028\029\030\031\032\033\034\035\036\037\038\039\040\041\042\043\044\045\046\047\048\049\050\051\052\053\054\055\056\057\058\059\060\061\062\063\064\065\066\067\068\069\070\071\072\073\074\075\076\077\078\079\080\081\082\083\084\085\086\087\088\089\090\091\092\093\094\095\096\097\098\099\100\101\102\103\104\105\106\107\108\109\110\111\112\113\114\115\116\117\118\119\120\121\122\123\124\125\126\127\128\129\130\131\132\133\134\135\136\137\138\139\140\141\142\143\144\145\146\147\148\149\150\151\152\153\154\155\156\157\158\159\160\161\162\163\164\165\166\167\168\169\170\171\172\173\174\175\176\177\178\179\180\181\182\183\184\185\186\187\188\189\190\191\192\193\194\195\196\197\198\199\200\201\202\203\204\205\206\207\208\209\210\211\212\213\214\215\216\217\218\219\220\221\222\223\224\225\226\227\228\229\230\231\232\233\234\235\236\237\238\239\240\241\242\243\244\245\246\247\248\249\250\251\252\253\254\255"
assert(#all_bytes == 256, "bad byte fixture")
print("ALL_BYTES", #all_bytes, hex(all_bytes))

-- Numeric constants use the same ChaCha key schedule, but only one 8-byte block.
local numbers = {
    0, 1, -1, 3.141592653589793, -27182818.28459045,
    9007199254740991, 1.2345678901234567, 1e100, 1e-100,
}
for i = 1, #numbers do
    print("NUMBER", i, string.format("%.17g", numbers[i]))
end

local last_httpget_url
game = {
    HttpGet = function(_, url)
        last_httpget_url = url
        return "return 17"
    end,
}
loadstring = function(source)
    assert(source == "return 17")
    return function() return 17 end
end
for i = 1, #urls do
    local result = loadstring(game:HttpGet(urls[i]))()
    assert(last_httpget_url == urls[i], "HttpGet received a changed URL")
    assert(result == 17)
    print("HTTPGET", i, #last_httpget_url, last_httpget_url, hex(last_httpget_url))
end
