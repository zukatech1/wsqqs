-- namegenerators/mangled_shuffled.lua
-- Generates short mangled variable names with shuffled character order
-- Unicode homoglyph mixing enabled and hardened.

local util = require("prometheus.util");
local chararray = util.chararray;

-- Interleaved case order makes the charset less obviously sequential
local VarDigits      = chararray("aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStTuUvVwWxXyYzZ0123456789_");
local VarStartDigits = chararray("aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStTuUvVwWxXyYzZ");

-- Expanded Unicode homoglyph table.
-- Every entry is visually indistinguishable from its ASCII counterpart in most
-- editors and terminals but produces a different byte sequence, defeating naive
-- grep/search and making manual analysis significantly harder.
--
-- Sources: Cyrillic, Greek, and Latin Extended lookalikes that are valid
-- Unicode identifier characters in Lua 5.3+ (which uses UTF-8 locale rules).
local lookalikes = {
	-- Cyrillic lookalikes
	["a"] = { "\xD0\xB0" },                          -- Cyrillic а
	["c"] = { "\xD1\x81" },                          -- Cyrillic с
	["e"] = { "\xD0\xB5" },                          -- Cyrillic е
	["o"] = { "\xD0\xBE" },                          -- Cyrillic о
	["p"] = { "\xD1\x80" },                          -- Cyrillic р
	["x"] = { "\xD1\x85" },                          -- Cyrillic х
	["y"] = { "\xD1\x83" },                          -- Cyrillic у (looks like y)
	["B"] = { "\xD0\x92" },                          -- Cyrillic В
	["H"] = { "\xD0\x9D" },                          -- Cyrillic Н
	["M"] = { "\xD0\x9C" },                          -- Cyrillic М
	["K"] = { "\xD0\x9A" },                          -- Cyrillic К
	["T"] = { "\xD0\xA2" },                          -- Cyrillic Т
	["C"] = { "\xD0\xA1" },                          -- Cyrillic С
	["A"] = { "\xD0\x90" },                          -- Cyrillic А
	["E"] = { "\xD0\x95" },                          -- Cyrillic Е
	["O"] = { "\xD0\x9E" },                          -- Cyrillic О
	["P"] = { "\xD0\xA0" },                          -- Cyrillic Р
	["X"] = { "\xD0\xA5" },                          -- Cyrillic Х
	-- Greek lookalikes
	["v"] = { "\xCE\xBD" },                          -- Greek ν (nu)
	["u"] = { "\xCF\x85" },                          -- Greek υ (upsilon)
	["n"] = { "\xCE\xB7" },                          -- Greek η (eta, looks like n)
	["i"] = { "\xCE\xB9" },                          -- Greek ι (iota)
	["o"] = { "\xD0\xBE", "\xCE\xBF" },             -- Cyrillic о OR Greek ο
	["s"] = { "\xCF\x83" },                          -- Greek σ (sigma, looks like o/s)
}

-- Probability that any given character gets substituted when a lookalike exists.
-- 0.55 means ~55% of eligible characters are replaced → heavy mixing by default.
local SUBSTITUTE_PROB = 0.55

local function maybeSubstitute(ch)
	local alts = lookalikes[ch]
	if alts and math.random() < SUBSTITUTE_PROB then
		return alts[math.random(#alts)]
	end
	return ch
end

local function generateName(id, scope)
	local name = ''
	local d = id % #VarStartDigits
	id = (id - d) / #VarStartDigits
	local startChar = VarStartDigits[d + 1]
	name = name .. maybeSubstitute(startChar)
	while id > 0 do
		local d = id % #VarDigits
		id = (id - d) / #VarDigits
		local ch = VarDigits[d + 1]
		name = name .. maybeSubstitute(ch)
	end
	return name
end

local function prepare(ast)
	util.shuffle(VarDigits)
	util.shuffle(VarStartDigits)
end

return {
	generateName = generateName,
	prepare      = prepare,
}
