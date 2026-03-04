local util = require("prometheus.util");
local MIN_LEN   = 4
local MAX_LEN   = 12
local ZW_PROB   = 0.30
local SUB_PROB  = 0.75
local ZERO_WIDTHS = {
	"\xE2\x80\x8C",
	"\xE2\x80\x8D",
}
local GLYPH_POOL = {
	{ "a", { "\xD0\xB0" } },
	{ "b", { "\xD0\xB2" } },
	{ "c", { "\xD1\x81" } },
	{ "d", { "\xD0\xB4" } },
	{ "e", { "\xD0\xB5" } },
	{ "h", { "\xD1\x85" } },
	{ "i", { "\xD1\x96", "\xCE\xB9" } },
	{ "j", { "\xD0\xB9" } },
	{ "k", { "\xD0\xBA" } },
	{ "l", { "\xD0\xBB" } },
	{ "m", { "\xD0\xBC" } },
	{ "n", { "\xD0\xBD", "\xCE\xB7" } },
	{ "o", { "\xD0\xBE", "\xCE\xBF" } },
	{ "p", { "\xD1\x80" } },
	{ "r", { "\xD0\xBF" } },
	{ "s", { "\xD1\x95", "\xCF\x83" } },
	{ "t", { "\xD1\x82" } },
	{ "u", { "\xD1\x83", "\xCF\x85" } },
	{ "v", { "\xCE\xBD" } },
	{ "w", { "\xD1\x88" } },
	{ "x", { "\xD1\x85" } },
	{ "y", { "\xD1\x83" } },
	{ "z", { "\xD0\xB7" } },
	{ "A", { "\xD0\x90" } },
	{ "B", { "\xD0\x92" } },
	{ "C", { "\xD0\xA1" } },
	{ "E", { "\xD0\x95" } },
	{ "H", { "\xD0\x9D" } },
	{ "I", { "\xD0\x98" } },
	{ "K", { "\xD0\x9A" } },
	{ "M", { "\xD0\x9C" } },
	{ "O", { "\xD0\x9E" } },
	{ "P", { "\xD0\xA0" } },
	{ "T", { "\xD0\xA2" } },
	{ "X", { "\xD0\xA5" } },
	{ "Y", { "\xD0\xA3" } },
}
local startPool = {}
local bodyPool  = {}
for _, entry in ipairs(GLYPH_POOL) do
	local base = entry[1]
	local alts = entry[2]
	table.insert(startPool, { base = base, alts = alts })
	table.insert(bodyPool,  { base = base, alts = alts })
end
local function pickGlyph(entry)
	if math.random() < SUB_PROB then
		return entry.alts[math.random(#entry.alts)]
	end
	return entry.base
end
local function maybeZeroWidth()
	if math.random() < ZW_PROB then
		return ZERO_WIDTHS[math.random(#ZERO_WIDTHS)]
	end
	return ""
end
local function generateName(id, scope)
	local length = MIN_LEN + (id % (MAX_LEN - MIN_LEN + 1))
	local si = (id % #startPool) + 1
	local name = pickGlyph(startPool[si]) .. maybeZeroWidth()
	for pos = 2, length do
		local bi = ((id + pos * 7) % #bodyPool) + 1
		name = name .. pickGlyph(bodyPool[bi]) .. maybeZeroWidth()
	end
	return name
end
local function prepare(ast)
	util.shuffle(startPool)
	util.shuffle(bodyPool)
end
return {
	generateName = generateName,
	prepare      = prepare,
}
