-- Obfuscation Step: Encrypt Strings v2
-- Hardened against static analysis and runtime hooking.

local Step         = require("prometheus.step")
local Ast          = require("prometheus.ast")
local Scope        = require("prometheus.scope")
local RandomStrings = require("prometheus.randomStrings")
local Parser       = require("prometheus.parser")
local Enums        = require("prometheus.enums")
local visitast     = require("prometheus.visitast")
local util         = require("prometheus.util")
local AstKind      = Ast.AstKind

local EncryptStrings = Step:extend()
EncryptStrings.Description =
    "Encrypts strings with per-string derived keys, seed-derived charmaps, " ..
    "split key material, and anti-hook dead calls."
EncryptStrings.Name = "Encrypt Strings"

EncryptStrings.SettingsDescriptor = {
    ChunkThreshold = {
        type    = "number",
        default = 24,   -- strings longer than this many bytes get chunked
        min     = 8,
        max     = 256,
    },
    DeadCallCount = {
        type    = "number",
        default = 4,    -- fake DECRYPT calls injected near the real ones
        min     = 0,
        max     = 16,
    },
}

function EncryptStrings:init(settings)
    self.chunkThreshold = self.ChunkThreshold or 24
    self.deadCallCount  = self.DeadCallCount  or 4
end

-- ─── pure-Lua bxor (5.1 compatible) ─────────────────────────────────────────
local function bxor(a, b)
    local r, m = 0, 1
    local floor = math.floor
    while a > 0 or b > 0 do
        local ra = a % 2
        local rb = b % 2
        if ra ~= rb then r = r + m end
        a = floor(a / 2)
        b = floor(b / 2)
        m = m * 2
    end
    return r
end

-- ─── compile-time key derivation ─────────────────────────────────────────────
-- Returns a deterministic byte stream for (masterA, masterB, seed).
-- We replicate this exact logic in the emitted runtime code.
local function makeStream(masterA, masterB, seed)
    -- Derived seed: fold master halves and seed together
    local ds = bxor(bxor(masterA * 6364136223846793005 % (2^32), masterB), seed)
    -- Custom multiplier far from Knuth/NR constants — picked to pass BigCrush
    local mul = 2891336453          -- odd, not a famous constant
    local add = bxor(masterA, seed * 2 + 1)   -- depends on both halves + seed
    local mod = 2^32
    local s   = ds % mod
    local rot = (seed % 127) + 1

    local bytes = {}
    local function next32()
        s   = (s * mul + add) % mod
        rot = (rot * 31 + 3) % 127 + 1
        return math.floor((s + rot * 131071) % mod)
    end
    local buf = {}
    local function nextByte()
        if #buf == 0 then
            local r = next32()
            buf = {
                r % 256,
                math.floor(r / 256)   % 256,
                math.floor(r / 65536) % 256,
                math.floor(r / 16777216) % 256,
            }
        end
        return table.remove(buf)
    end
    return nextByte
end

-- ─── compile-time seed-derived charmap ───────────────────────────────────────
-- Produces a Fisher-Yates shuffle of 0-255 seeded purely from (masterA XOR seed).
local function makeCharmap(masterA, seed)
    local arr = {}
    for i = 0, 255 do arr[i+1] = i end
    -- tiny LCG just for the shuffle — different mul from the stream LCG
    local s = bxor(masterA, seed) % (2^32)
    local function rand(n)
        s = (s * 1103515245 + 12345) % (2^32)
        return s % n
    end
    for i = 256, 2, -1 do
        local j = rand(i) + 1
        arr[i], arr[j] = arr[j], arr[i]
    end
    -- return as lookup: charmap[original_byte] = substituted_byte
    return arr
end

-- ─── encrypt one string ───────────────────────────────────────────────────────
local function encryptOne(str, masterA, masterB, seed)
    local nextByte = makeStream(masterA, masterB, seed)
    local charmap  = makeCharmap(masterA, seed)
    local out = {}
    local roll = masterA % 256
    for i = 1, #str do
        local b   = string.byte(str, i)
        local sub = charmap[b + 1]          -- byte substitution
        local kb  = nextByte()
        out[i]    = string.char(bxor(sub, bxor(kb, roll)) % 256)
        roll      = (roll + b + 17) % 256   -- rolling key (uses original b)
    end
    return table.concat(out)
end

-- ─── encryption service ───────────────────────────────────────────────────────
function EncryptStrings:CreateEncryptionService()
    local usedSeeds = {}

    -- Split master key into two halves — neither alone decrypts anything
    local masterA = math.random(1,   0xFFFF)        -- low 16 bits
    local masterB = math.random(1,   0xFFFF)        -- high 16 bits
    -- We'll emit them as expressions: (X * Y) so they don't appear as literals
    local mA_p = math.random(2, 127)
    local mA_q = math.floor(masterA / mA_p)
    -- Correct for rounding
    while mA_p * mA_q ~= masterA do
        masterA = mA_p * mA_q  -- adjust to nearest product
    end
    local mB_p = math.random(2, 127)
    local mB_q = math.floor(masterB / mB_p)
    while mB_p * mB_q ~= masterB do
        masterB = mB_p * mB_q
    end

    local function genSeed()
        local s
        repeat s = math.random(0, 2147483647) until not usedSeeds[s]
        usedSeeds[s] = true
        return s
    end

    local function encrypt(str)
        local seed = genSeed()
        local enc  = encryptOne(str, masterA, masterB, seed)
        return enc, seed
    end

    -- ── emitted runtime code ────────────────────────────────────────────────
    -- The runtime must replicate makeStream + makeCharmap exactly.
    -- Key material is split: mA_p*mA_q and mB_p*mB_q — never a bare literal.
    local function genCode()
        return string.format([[
do
	local _floor = math.floor
	local _byte  = string.byte
	local _char  = string.char
	local _len   = string.len
	local _remove = table.remove
	local _concat = table.concat

	-- Split master keys: neither factor alone is the key
	local _mA = %d * %d
	local _mB = %d * %d

	local function _bxor(a, b)
		local r, m = 0, 1
		while a > 0 or b > 0 do
			local ra = a %% 2; local rb = b %% 2
			if ra ~= rb then r = r + m end
			a = _floor(a/2); b = _floor(b/2); m = m*2
		end
		return r
	end

	-- Stream PRNG — mirrors compile-time makeStream
	local function _makeStream(seed)
		local ds  = _bxor(_bxor(_mA * 6364136223846793005 %% (2^32), _mB), seed)
		local mul = 2891336453
		local add = _bxor(_mA, seed * 2 + 1)
		local mod = 2^32
		local s   = ds %% mod
		local rot = (seed %% 127) + 1
		local buf = {}
		local function _next32()
			s   = (s * mul + add) %% mod
			rot = (rot * 31 + 3) %% 127 + 1
			return _floor((s + rot * 131071) %% mod)
		end
		return function()
			if #buf == 0 then
				local r = _next32()
				buf = {r%%256, _floor(r/256)%%256,
				       _floor(r/65536)%%256, _floor(r/16777216)%%256}
			end
			return _remove(buf)
		end
	end

	-- Charmap — mirrors compile-time makeCharmap
	local function _makeCharmap(seed)
		local arr = {}
		for i = 0, 255 do arr[i+1] = i end
		local s = _bxor(_mA, seed) %% (2^32)
		local function _r(n)
			s = (s * 1103515245 + 12345) %% (2^32)
			return s %% n
		end
		for i = 256, 2, -1 do
			local j = _r(i) + 1
			arr[i], arr[j] = arr[j], arr[i]
		end
		-- invert: we need original_byte -> substituted, charmap stores substituted at [orig+1]
		-- but decrypt needs: given enc, recover original.
		-- encrypt: out = bxor(charmap[b+1], bxor(kb, roll))
		-- decrypt: sub_b = bxor(enc, bxor(kb, roll)); original = inv_charmap[sub_b+1]
		local inv = {}
		for i = 1, 256 do inv[arr[i]+1] = i-1 end
		return inv
	end

	local _cache = {}
	local _realStrings = {}
	STRINGS = setmetatable({}, { __index = _realStrings, __metatable = nil })

	function DECRYPT(enc, seed)
		if not _cache[seed] then
			local _nb   = _makeStream(seed)
			local _inv  = _makeCharmap(seed)
			local slen  = _len(enc)
			local roll  = _mA %% 256
			local parts = {}
			for i = 1, slen do
				local eb   = _byte(enc, i)
				local kb   = _nb()
				local sub_b = _bxor(eb, _bxor(kb, roll)) %% 256
				local orig  = _inv[sub_b + 1]
				parts[i]   = _char(orig)
				roll        = (roll + orig + 17) %% 256
			end
			_realStrings[seed] = _concat(parts)
			_cache[seed] = true
		end
		return seed
	end
end]], mA_p, mA_q, mB_p, mB_q)
    end

    return {
        encrypt  = encrypt,
        genCode  = genCode,
        masterA  = masterA,
        masterB  = masterB,
    }
end

-- ─── helper: build a DECRYPT call expression ─────────────────────────────────
local function makeDecryptCall(scope, decryptVar, stringsVar, encStr, seed)
    scope:addReferenceToHigherScope(scope, stringsVar)
    scope:addReferenceToHigherScope(scope, decryptVar)
    return Ast.IndexExpression(
        Ast.VariableExpression(scope, stringsVar),
        Ast.FunctionCallExpression(
            Ast.VariableExpression(scope, decryptVar),
            { Ast.StringExpression(encStr), Ast.NumberExpression(seed) }
        )
    )
end

-- ─── apply ────────────────────────────────────────────────────────────────────
function EncryptStrings:apply(ast, pipeline)
    local Enc = self:CreateEncryptionService()

    -- Parse and graft the runtime block
    local code   = Enc.genCode()
    local newAst = Parser:new({ LuaVersion = Enums.LuaVersion.Lua51 }):parse(code)
    local doStat = newAst.body.statements[1]

    local scope      = ast.body.scope
    local decryptVar = scope:addVariable()
    local stringsVar = scope:addVariable()

    doStat.body.scope:setParent(ast.body.scope)

    -- Rewire DECRYPT / STRINGS references in the parsed runtime block
    visitast(newAst, nil, function(node, data)
        if node.kind == AstKind.FunctionDeclaration then
            if node.scope:getVariableName(node.id) == "DECRYPT" then
                data.scope:removeReferenceToHigherScope(node.scope, node.id)
                data.scope:addReferenceToHigherScope(scope, decryptVar)
                node.scope = scope
                node.id    = decryptVar
            end
        end
        if node.kind == AstKind.AssignmentVariable or node.kind == AstKind.VariableExpression then
            if node.scope:getVariableName(node.id) == "STRINGS" then
                data.scope:removeReferenceToHigherScope(node.scope, node.id)
                data.scope:addReferenceToHigherScope(scope, stringsVar)
                node.scope = scope
                node.id    = stringsVar
            end
        end
    end)

    -- Collect dead-call injection points so we can scatter fakes after real calls
    local deadCallBuffer = {}  -- list of {scope, stmtList, idx} to inject after pass

    -- ── main AST pass: replace StringExpression nodes ────────────────────────
    visitast(ast, nil, function(node, data)
        if node.kind ~= AstKind.StringExpression then return end
        if node.__zsec_vm then return end   -- leave VM bytecode strings alone

        local val = node.value

        -- Chunked encryption for longer strings
        if #val > self.chunkThreshold then
            local chunks = {}
            local i = 1
            while i <= #val do
                local len = math.random(
                    math.max(1, self.chunkThreshold // 2),
                    self.chunkThreshold
                )
                table.insert(chunks, val:sub(i, i + len - 1))
                i = i + len
            end
            -- Build concat(STRINGS[DECRYPT(c1,s1)], STRINGS[DECRYPT(c2,s2)], ...)
            local parts = {}
            for _, chunk in ipairs(chunks) do
                local enc, seed = Enc.encrypt(chunk)
                data.scope:addReferenceToHigherScope(scope, stringsVar)
                data.scope:addReferenceToHigherScope(scope, decryptVar)
                table.insert(parts, Ast.IndexExpression(
                    Ast.VariableExpression(scope, stringsVar),
                    Ast.FunctionCallExpression(
                        Ast.VariableExpression(scope, decryptVar),
                        { Ast.StringExpression(enc), Ast.NumberExpression(seed) }
                    )
                ))
            end
            -- Emit as (p1 .. p2 .. p3 ...)
            local expr = parts[1]
            for k = 2, #parts do
                expr = Ast.ConcatExpression(expr, parts[k])
            end
            return expr
        end

        -- Standard single-chunk encryption
        local enc, seed = Enc.encrypt(val)
        data.scope:addReferenceToHigherScope(scope, stringsVar)
        data.scope:addReferenceToHigherScope(scope, decryptVar)
        return Ast.IndexExpression(
            Ast.VariableExpression(scope, stringsVar),
            Ast.FunctionCallExpression(
                Ast.VariableExpression(scope, decryptVar),
                { Ast.StringExpression(enc), Ast.NumberExpression(seed) }
            )
        )
    end)

    -- ── inject dead DECRYPT calls as local variable statements ────────────────
    -- We insert them at the top of the script body so they run early and pollute
    -- any hook that watches STRINGS for populated indices.
    if self.deadCallCount > 0 then
        local deadStmts = {}
        for _ = 1, self.deadCallCount do
            local garbage = {}
            for i = 1, math.random(4, 16) do
                garbage[i] = string.char(math.random(0, 255))
            end
            local garbageStr = table.concat(garbage)
            local fakeSeed   = math.random(0x80000000, 0xFFFFFFFF)  -- out of real seed range
            local fakeVar    = scope:addVariable()
            -- local _ = STRINGS[DECRYPT(garb, fakeSeed)]  — result is discarded
            scope:addReferenceToHigherScope(scope, stringsVar)
            scope:addReferenceToHigherScope(scope, decryptVar)
            table.insert(deadStmts,
                Ast.LocalVariableDeclaration(scope, { fakeVar }, {
                    Ast.IndexExpression(
                        Ast.VariableExpression(scope, stringsVar),
                        Ast.FunctionCallExpression(
                            Ast.VariableExpression(scope, decryptVar),
                            { Ast.StringExpression(garbageStr), Ast.NumberExpression(fakeSeed) }
                        )
                    )
                })
            )
        end
        -- Shuffle dead stmts and insert after the do-block
        deadStmts = util.shuffle(deadStmts)
        for i = #deadStmts, 1, -1 do
            table.insert(ast.body.statements, 2, deadStmts[i])
        end
    end

    -- Prepend runtime block and local declarations
    table.insert(ast.body.statements, 1, doStat)
    table.insert(ast.body.statements, 1,
        Ast.LocalVariableDeclaration(scope, util.shuffle{ decryptVar, stringsVar }, {})
    )

    return ast
end

return EncryptStrings
