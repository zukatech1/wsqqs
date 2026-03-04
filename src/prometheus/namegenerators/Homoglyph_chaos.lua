-- namegenerators/homoglyph_chaos.lua
-- Pure random-length homoglyph chaos name generator.
--
-- Every name is composed of:
--   1. A visually-ASCII-looking start character drawn from Unicode lookalikes.
--   2. A variable-length body (MIN_LEN..MAX_LEN chars) of further lookalikes.
--   3. Zero-width Unicode characters (ZWJ, ZWNJ, ZWSP) randomly spliced in.
--
-- The result: names that look like ordinary short identifiers in any editor but
-- are byte-for-byte unique and completely opaque to grep, diff, and most static
-- analysis tools.
--
-- Requirements: Lua 5.3+ with UTF-8 locale (LuaJIT with LUAJIT_ENABLE_LUA52COMPAT
-- also works). The target Lua runtime must accept arbitrary Unicode codepoints in
-- identifiers (standard since Lua 5.3 on a UTF-8 system).

local util = require("prometheus.util");

-- ── Tuning ────────────────────────────────────────────────────────────────────
local MIN_LEN   = 4    -- minimum visible-character count (excluding zero-widths)
local MAX_LEN   = 12   -- maximum visible-character count
local ZW_PROB   = 0.30 -- probability of inserting a zero-width char after each visible char
local SUB_PROB  = 0.75 -- probability of using the Unicode form instead of ASCII base
-- ─────────────────────────────────────────────────────────────────────────────

-- Zero-width characters valid inside Lua identifiers on UTF-8 runtimes:
--   U+200C ZERO WIDTH NON-JOINER  (ZWNJ)
--   U+200D ZERO WIDTH JOINER      (ZWJ)
-- U+200B (ZWSP) is intentionally omitted – it breaks some parsers.
local ZERO_WIDTHS = {
	"\xE2\x80\x8C",   -- U+200C  ZWNJ
	"\xE2\x80\x8D",   -- U+200D  ZWJ
}

-- Homoglyph pools: { ascii_base, { unicode_alternative, ... } }
-- All Unicode alternatives are valid identifier characters in Lua 5.3+ UTF-8.
local GLYPH_POOL = {
	-- ── Latin / Cyrillic / Greek lookalikes ──────────────────────────────────
	{ "a", { "\xD0\xB0" } },                          -- Cyrillic а
	{ "b", { "\xD0\xB2" } },                          -- Cyrillic в  (close enough)
	{ "c", { "\xD1\x81" } },                          -- Cyrillic с
	{ "d", { "\xD0\xB4" } },                          -- Cyrillic д  (approximate)
	{ "e", { "\xD0\xB5" } },                          -- Cyrillic е
	{ "h", { "\xD1\x85" } },                          -- Cyrillic х  (looks like h/x)
	{ "i", { "\xD1\x96", "\xCE\xB9" } },             -- Cyrillic і  OR Greek ι
	{ "j", { "\xD0\xB9" } },                          -- Cyrillic й  (approximate)
	{ "k", { "\xD0\xBA" } },                          -- Cyrillic к
	{ "l", { "\xD0\xBB" } },                          -- Cyrillic л  (approximate)
	{ "m", { "\xD0\xBC" } },                          -- Cyrillic м
	{ "n", { "\xD0\xBD", "\xCE\xB7" } },             -- Cyrillic н  OR Greek η
	{ "o", { "\xD0\xBE", "\xCE\xBF" } },             -- Cyrillic о  OR Greek ο
	{ "p", { "\xD1\x80" } },                          -- Cyrillic р
	{ "r", { "\xD0\xBF" } },                          -- Cyrillic п  (approximate)
	{ "s", { "\xD1\x95", "\xCF\x83" } },             -- Cyrillic ѕ  OR Greek σ
	{ "t", { "\xD1\x82" } },                          -- Cyrillic т  (approximate)
	{ "u", { "\xD1\x83", "\xCF\x85" } },             -- Cyrillic у  OR Greek υ
	{ "v", { "\xCE\xBD" } },                          -- Greek ν
	{ "w", { "\xD1\x88" } },                          -- Cyrillic ш  (approximate)
	{ "x", { "\xD1\x85" } },                          -- Cyrillic х
	{ "y", { "\xD1\x83" } },                          -- Cyrillic у
	{ "z", { "\xD0\xB7" } },                          -- Cyrillic з  (approximate)
	-- Uppercase
	{ "A", { "\xD0\x90" } },                          -- Cyrillic А
	{ "B", { "\xD0\x92" } },                          -- Cyrillic В
	{ "C", { "\xD0\xA1" } },                          -- Cyrillic С
	{ "E", { "\xD0\x95" } },                          -- Cyrillic Е
	{ "H", { "\xD0\x9D" } },                          -- Cyrillic Н
	{ "I", { "\xD0\x98" } },                          -- Cyrillic И  (approximate)
	{ "K", { "\xD0\x9A" } },                          -- Cyrillic К
	{ "M", { "\xD0\x9C" } },                          -- Cyrillic М
	{ "O", { "\xD0\x9E" } },                          -- Cyrillic О
	{ "P", { "\xD0\xA0" } },                          -- Cyrillic Р
	{ "T", { "\xD0\xA2" } },                          -- Cyrillic Т
	{ "X", { "\xD0\xA5" } },                          -- Cyrillic Х
	{ "Y", { "\xD0\xA3" } },                          -- Cyrillic У
}

-- Pre-split into start-eligible (alpha only) and body pools
local startPool = {}
local bodyPool  = {}

for _, entry in ipairs(GLYPH_POOL) do
	local base = entry[1]
	local alts = entry[2]
	-- Start chars: ASCII letter or its Unicode form (both valid identifier starts)
	table.insert(startPool, { base = base, alts = alts })
	table.insert(bodyPool,  { base = base, alts = alts })
end

-- Body pool also includes digit-lookalike entries that are NOT valid as first char.
-- (Pure digit lookalikes are skipped here to keep the pool simple and safe.)

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
	-- Derive a deterministic-ish length from id, then randomise within range.
	-- We still use math.random for the actual character picks so each
	-- obfuscation run is different even for the same id.
	local length = MIN_LEN + (id % (MAX_LEN - MIN_LEN + 1))

	-- Start character (must be a valid identifier start)
	local si = (id % #startPool) + 1
	local name = pickGlyph(startPool[si]) .. maybeZeroWidth()

	-- Body characters
	for pos = 2, length do
		local bi = ((id + pos * 7) % #bodyPool) + 1
		name = name .. pickGlyph(bodyPool[bi]) .. maybeZeroWidth()
	end

	return name
end

local function prepare(ast)
	-- Shuffle both pools so each run maps ids to different glyphs
	util.shuffle(startPool)
	util.shuffle(bodyPool)
end

return {
	generateName = generateName,
	prepare      = prepare,
}
