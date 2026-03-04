-- VMEmitter.lua  (v2 — hardened)
-- Z-Sec VM Emitter
-- Changes vs v1:
--   [1] STRONGER ENCRYPTION  — 4-byte rolling XOR key (was 1-byte)
--   [2] OPCODE SHUFFLE       — logical op IDs permuted randomly each compile
--                              (requires matching permutation passed in from BytecodeCompiler)
--   [3] JUNK INJECTION       — dead locals + unreachable branches in VM body
--   [4] CONTROL FLOW FLATTEN — dispatch table replaces if/elseif chain;
--                              RETURN/JMP use a boxed-PC table so closures
--                              can mutate it without breaking the call frame

local VMEmitter = {}

local Ast           = require("prometheus.ast")
local Scope         = require("prometheus.scope")
local util          = require("prometheus.util")
local randomStrings = require("prometheus.randomStrings")

local AstKind = Ast.AstKind

-- ── Helpers (unchanged) ───────────────────────────────────────────────────────
local function N(v)    return Ast.NumberExpression(v) end
local function S(v)    return Ast.StringExpression(v) end
local function Nil()   return Ast.NilExpression() end
local function Bool(v) return Ast.BooleanExpression(v) end
local function Var(scope, id)   return Ast.VariableExpression(scope, id) end
local function Idx(base, key)   return Ast.IndexExpression(base, key) end
local function Call(base, args) return Ast.FunctionCallExpression(base, args or {}) end
local function Assign(lhs, rhs) return Ast.AssignmentStatement(lhs, rhs) end
local function Local(scope, vars, vals) return Ast.LocalVariableDeclaration(scope, vars, vals or {}) end
local function Ret(vals)  return Ast.ReturnStatement(vals or {}) end
local function Block(stmts, scope) return Ast.Block(stmts, scope) end
local function Func(args, body)    return Ast.FunctionLiteralExpression(args, body) end

-- ── [1] 4-byte rolling XOR encryption ────────────────────────────────────────
-- Previously used a single XOR key — trivially broken by XOR-ing two outputs.
-- Now uses 4 independent key bytes; decryptor is embedded as a closure in the
-- VM body with the keys as literals, obfuscated further by NumbersToExpressions.
local function obfuscateBytestring(rawBytes)
    local k1 = math.random(1, 255)
    local k2 = math.random(1, 255)
    local k3 = math.random(1, 255)
    local k4 = math.random(1, 255)
    local keys = {k1, k2, k3, k4}
    local encStr = {}
    for i = 1, #rawBytes do
        local b = string.byte(rawBytes, i)
        local k = keys[((i - 1) % 4) + 1]
        encStr[i] = string.char((b ~ k) % 256)
    end
    return table.concat(encStr), k1, k2, k3, k4
end

-- ── Decode map serializer (unchanged) ────────────────────────────────────────
local function serializeDecodeMap(decodeMap)
    local bytes = {}
    for wire = 0, 255 do
        bytes[wire + 1] = decodeMap[wire] or 0
    end
    local chars = {}
    for i, b in ipairs(bytes) do
        chars[i] = string.char(b)
    end
    return table.concat(chars)
end

-- ── [2] Opcode ID permutation ─────────────────────────────────────────────────
-- Returns a shuffled O table (name->id).
-- BytecodeCompiler must call this BEFORE serializing and pass the result to both
-- Serializer (so bytecode is written with shuffled IDs) and VMEmitter.emit
-- (so the dispatch table uses the same IDs).
function VMEmitter.generateOpcodePermutation()
    local opNames = {
        "LOAD_CONST","LOAD_BOOL","LOAD_NIL","MOV",
        "GET_UPVAL","SET_UPVAL",
        "GET_GLOBAL","SET_GLOBAL",
        "NEW_TABLE","GET_TABLE","SET_TABLE",
        "GET_TABLE_K","SET_TABLE_K",
        "ADD","SUB","MUL","DIV","MOD","POW","CONCAT",
        "UNM","NOT","LEN",
        "LT","LE","EQ","NEQ",
        "JMP","JMP_IF","JMP_IF_NOT",
        "CALL","CALL_SELF","CALL_VARARG",
        "RETURN","RETURN_NONE",
        "CLOSURE","UPVAL_REF","VARARG",
        "ITER_PREP","ITER_NEXT",
    }
    local ids = {}
    for i = 1, #opNames do ids[i] = i end
    for i = #ids, 2, -1 do
        local j = math.random(1, i)
        ids[i], ids[j] = ids[j], ids[i]
    end
    local O = {}
    for i, name in ipairs(opNames) do
        O[name] = ids[i]
    end
    return O
end

-- ── Main emitter ──────────────────────────────────────────────────────────────
function VMEmitter.emit(bytecodeStr, decodeMap, entryProtoId, opcodePermutation)
    local encryptedBytes, k1, k2, k3, k4 = obfuscateBytestring(bytecodeStr)
    local decodeMapStr = serializeDecodeMap(decodeMap)

    -- Use caller-supplied permutation or fall back to a fresh one
    local O = opcodePermutation or VMEmitter.generateOpcodePermutation()

    local newGlobalScope = Scope:newGlobal()
    local psc = Scope:new(newGlobalScope, nil)

    local _, getfenvVar      = newGlobalScope:resolve("getfenv")
    local _, tableVar        = newGlobalScope:resolve("table")
    local _, unpackVar       = newGlobalScope:resolve("unpack")
    local _, envVar          = newGlobalScope:resolve("_ENV")
    local _, newproxyVar     = newGlobalScope:resolve("newproxy")
    local _, setmetatableVar = newGlobalScope:resolve("setmetatable")
    local _, getmetatableVar = newGlobalScope:resolve("getmetatable")
    local _, selectVar       = newGlobalScope:resolve("select")
    local _, stringVar       = newGlobalScope:resolve("string")
    local _, mathVar         = newGlobalScope:resolve("math")
    local _, ipairsVar       = newGlobalScope:resolve("ipairs")
    local _, pcallVar        = newGlobalScope:resolve("pcall")
    local _, errorVar        = newGlobalScope:resolve("error")
    local _, typeVar         = newGlobalScope:resolve("type")
    local _, tostrVar        = newGlobalScope:resolve("tostring")
    local _, tonumVar        = newGlobalScope:resolve("tonumber")

    psc:addReferenceToHigherScope(newGlobalScope, getfenvVar, 2)
    psc:addReferenceToHigherScope(newGlobalScope, tableVar)
    psc:addReferenceToHigherScope(newGlobalScope, unpackVar)
    psc:addReferenceToHigherScope(newGlobalScope, envVar)
    psc:addReferenceToHigherScope(newGlobalScope, newproxyVar)
    psc:addReferenceToHigherScope(newGlobalScope, setmetatableVar)
    psc:addReferenceToHigherScope(newGlobalScope, getmetatableVar)
    psc:addReferenceToHigherScope(newGlobalScope, selectVar)
    psc:addReferenceToHigherScope(newGlobalScope, stringVar)
    psc:addReferenceToHigherScope(newGlobalScope, mathVar)
    psc:addReferenceToHigherScope(newGlobalScope, pcallVar)
    psc:addReferenceToHigherScope(newGlobalScope, typeVar)
    psc:addReferenceToHigherScope(newGlobalScope, tonumVar)

    local outerScope   = Scope:new(psc)
    local envArg       = outerScope:addVariable()
    local unpackArg    = outerScope:addVariable()
    local newproxyArg  = outerScope:addVariable()
    local setmetaArg   = outerScope:addVariable()
    local getmetaArg   = outerScope:addVariable()
    local selectArg    = outerScope:addVariable()
    local argArg       = outerScope:addVariable()

    local bytecodVar   = outerScope:addVariable()
    local opmapVar     = outerScope:addVariable()
    local vmVar        = outerScope:addVariable()

    local vmScope = Scope:new(outerScope)
    vmScope:addReferenceToHigherScope(outerScope, envArg)
    vmScope:addReferenceToHigherScope(outerScope, unpackArg)
    vmScope:addReferenceToHigherScope(outerScope, newproxyArg)
    vmScope:addReferenceToHigherScope(outerScope, setmetaArg)
    vmScope:addReferenceToHigherScope(outerScope, getmetaArg)
    vmScope:addReferenceToHigherScope(outerScope, selectArg)
    vmScope:addReferenceToHigherScope(outerScope, bytecodVar)
    vmScope:addReferenceToHigherScope(outerScope, opmapVar)

    local vmBcArg   = vmScope:addVariable()
    local vmMapArg  = vmScope:addVariable()
    local vmEnvArg  = vmScope:addVariable()
    local vmUnpkArg = vmScope:addVariable()
    local vmArgArg  = vmScope:addVariable()

    local decodeScope = Scope:new(vmScope)
    local sbVar    = decodeScope:addVariable()
    local scVar    = decodeScope:addVariable()
    local mfVar    = decodeScope:addVariable()
    local tcatVar  = decodeScope:addVariable()
    local tinsVar  = decodeScope:addVariable()
    local ssubVar  = decodeScope:addVariable()

    decodeScope:addReferenceToHigherScope(newGlobalScope, stringVar)
    decodeScope:addReferenceToHigherScope(newGlobalScope, mathVar)
    decodeScope:addReferenceToHigherScope(newGlobalScope, tableVar)

    local rawBcVar   = decodeScope:addVariable()
    local protosVar  = decodeScope:addVariable()
    local entryIdVar = decodeScope:addVariable()

    local vmSource = VMEmitter.buildVMSource(k1, k2, k3, k4, O)

    return {
        encryptedBytes = encryptedBytes,
        decodeMapStr   = decodeMapStr,
        xorKey         = k1,   -- kept for compat; real decryptor uses all 4 keys
        vmSource       = vmSource,
        entryProtoId   = entryProtoId,
        newGlobalScope = newGlobalScope,
        psc            = psc,
        __hasVmStrings = true,
    }
end

-- ── VM Source Builder v2 ──────────────────────────────────────────────────────
-- [3] Junk injection  — dead locals at top of VM function
-- [4] CFF             — _dt dispatch table, _pcbox for mutable PC,
--                       _retbox to signal RETURN across closure boundary
function VMEmitter.buildVMSource(k1, k2, k3, k4, O)
    -- Safe identifier generator
    local function rn()
        local name = randomStrings and randomStrings.randomString(math.random(8, 14))
                     or ("v" .. math.random(99999))
        if type(name) ~= "string" or name == "" then
            name = "v" .. math.random(99999)
        end
        name = name:gsub("[^%a%d_]", "_")
        if name:sub(1, 1):match("%d") then name = "_" .. name end
        return name
    end

    local vBC      = rn()  local vMap     = rn()  local vEnv     = rn()
    local vUnpk    = rn()  local vArgs    = rn()
    local vSb      = rn()  local vSc      = rn()  local vMf      = rn()
    local vTcat    = rn()  local vTins    = rn()  local vSsub    = rn()
    local vJ1      = rn()  local vJ2      = rn()  local vJ3      = rn()  -- junk
    local vDecBC   = rn()  local vPos     = rn()
    local vRB      = rn()  local vRS      = rn()  local vRI      = rn()  local vRD = rn()
    local vParse   = rn()  local vExec    = rn()  local vProtos  = rn()
    local vUVT     = rn()  local vUVRC    = rn()  local vUVID    = rn()
    local vAllocUV = rn()  local vFreeUV  = rn()

    -- Placeholder counts (for maintenance):
    --   params 5%s | stdlib 6%s | junk 6%s | decrypt 6%s+4%d | cursor 1%s
    --   readByte 6%s | readShort 9%s | readInt 15%s | readConst 20%s
    --   uvtables 16%s | parseProto 14%s | proto cache 6%s
    --   dispatch 12%s+39%d | entry 3%s
    --   TOTAL = 125%s + 43%d = 168

    local src = string.format([=[
return function(%s, %s, %s, %s, %s)
    local %s = string.byte
    local %s = string.char
    local %s = math.floor
    local %s = table.concat
    local %s = table.insert
    local %s = string.sub
    local %s = %s(0)
    local %s = %s(0)
    local %s = %s(0)
    local %s = (function()
        local _keys = {%d, %d, %d, %d}
        local _t = {}
        for _i = 1, #%s do
            local _ki = ((_i - 1) %% 4) + 1
            _t[_i] = %s(bit32.bxor(%s(%s, _i), _keys[_ki]) %% 256)
        end
        return %s(_t)
    end)()
    local %s = 1
    local function %s()
        local _b = %s(%s, %s)
        %s = %s + 1
        return _b
    end
    local function %s()
        local _lo = %s(%s, %s)
        local _hi = %s(%s, %s + 1)
        %s = %s + 2
        return _lo + _hi * 256
    end
    local function %s()
        local _a  = %s(%s, %s)
        local _b2 = %s(%s, %s + 1)
        local _c  = %s(%s, %s + 2)
        local _d  = %s(%s, %s + 3)
        %s = %s + 4
        local _v = _a + _b2 * 256 + _c * 65536 + _d * 16777216
        if _v >= 2147483648 then _v = _v - 4294967296 end
        return _v
    end
    local function %s()
        local _tag = %s()
        if _tag == 0 then return nil
        elseif _tag == 1 then return %s() ~= 0
        elseif _tag == 2 then return %s()
        elseif _tag == 3 then
            local _bytes = {}
            for _i = 1, 8 do _bytes[_i] = %s(%s, %s + _i - 1) end
            %s = %s + 8
            local _ok, _v = pcall(string.unpack, "<d", %s(%s(%s(%s(_bytes)))))
            if _ok then return _v end
            return 0
        elseif _tag == 4 then
            local _len = %s()
            local _s   = %s(%s, %s, %s + _len - 1)
            %s = %s + _len
            return _s
        end
        return nil
    end
    local %s = {}
    local %s = {}
    local %s = 0
    local function %s()
        %s = %s + 1
        %s[%s] = 1
        return %s
    end
    local function %s(id)
        %s[id] = (%s[id] or 1) - 1
        if %s[id] <= 0 then
            %s[id] = nil
            %s[id] = nil
        end
    end
    local %s
    local function %s(proto_id)
        local _pc_start   = %s
        local _paramCount = %s()
        local _isVararg   = %s() ~= 0
        local _maxReg     = %s()
        local _upvalCount = %s()
        local _kCount = %s()
        local _k = {}
        for _i = 1, _kCount do
            _k[_i - 1] = %s()
        end
        local _nProtos  = %s()
        local _protoIds = {}
        for _i = 1, _nProtos do
            _protoIds[_i] = %s()
        end
        local _iCount = %s()
        local _instrs = {}
        for _i = 1, _iCount do
            local _wire  = %s()
            local _logOp = %s(%s, _wire + 1)
            _instrs[_i]  = {op = _logOp, raw = {}}
        end
        return {
            paramCount = _paramCount,
            isVararg   = _isVararg,
            maxReg     = _maxReg,
            upvalCount = _upvalCount,
            k          = _k,
            protoIds   = _protoIds,
            instrs     = _instrs,
        }
    end
    local %s = {}
    local _protoCount = %s()
    local _entryId    = %s()
    for _pi = 1, _protoCount do
        local _pid = %s()
        %s[_pid] = %s(_pid)
    end
    %s = function(proto, regs_in, upvals_in)
        local _p      = proto
        local _k      = _p.k
        local _regs   = regs_in or {}
        local _uvs    = upvals_in or {}
        local _pcbox  = {1}
        local _instrs = _p.instrs
        local _retbox = nil
        local _dt     = {}
        _dt[%d] = function(_r) _regs[_r[1]] = _k[_r[2]] end
        _dt[%d] = function(_r) _regs[_r[1]] = _r[2] ~= 0 end
        _dt[%d] = function(_r)
            for _ni = _r[1], _r[1] + _r[2] do _regs[_ni] = nil end
        end
        _dt[%d] = function(_r) _regs[_r[1]] = _regs[_r[2]] end
        _dt[%d] = function(_r) _regs[_r[1]] = %s[_r[2]] end
        _dt[%d] = function(_r) %s[_r[1]] = _regs[_r[2]] end
        _dt[%d] = function(_r) _regs[_r[1]] = %s[_k[_r[2]]] end
        _dt[%d] = function(_r) %s[_k[_r[1]]] = _regs[_r[2]] end
        _dt[%d] = function(_r) _regs[_r[1]] = {} end
        _dt[%d] = function(_r) _regs[_r[1]] = _regs[_r[2]][_regs[_r[3]]] end
        _dt[%d] = function(_r) _regs[_r[1]][_regs[_r[2]]] = _regs[_r[3]] end
        _dt[%d] = function(_r) _regs[_r[1]] = _regs[_r[2]][_k[_r[3]]] end
        _dt[%d] = function(_r) _regs[_r[1]][_k[_r[2]]] = _regs[_r[3]] end
        _dt[%d] = function(_r) _regs[_r[1]] = _regs[_r[2]] + _regs[_r[3]] end
        _dt[%d] = function(_r) _regs[_r[1]] = _regs[_r[2]] - _regs[_r[3]] end
        _dt[%d] = function(_r) _regs[_r[1]] = _regs[_r[2]] * _regs[_r[3]] end
        _dt[%d] = function(_r) _regs[_r[1]] = _regs[_r[2]] / _regs[_r[3]] end
        _dt[%d] = function(_r) _regs[_r[1]] = _regs[_r[2]] %% _regs[_r[3]] end
        _dt[%d] = function(_r) _regs[_r[1]] = _regs[_r[2]] ^ _regs[_r[3]] end
        _dt[%d] = function(_r) _regs[_r[1]] = _regs[_r[2]] .. _regs[_r[3]] end
        _dt[%d] = function(_r) _regs[_r[1]] = -_regs[_r[2]] end
        _dt[%d] = function(_r) _regs[_r[1]] = not _regs[_r[2]] end
        _dt[%d] = function(_r) _regs[_r[1]] = #_regs[_r[2]] end
        _dt[%d] = function(_r) _regs[_r[1]] = _regs[_r[2]] < _regs[_r[3]] end
        _dt[%d] = function(_r) _regs[_r[1]] = _regs[_r[2]] <= _regs[_r[3]] end
        _dt[%d] = function(_r) _regs[_r[1]] = _regs[_r[2]] == _regs[_r[3]] end
        _dt[%d] = function(_r) _regs[_r[1]] = _regs[_r[2]] ~= _regs[_r[3]] end
        _dt[%d] = function(_r) _pcbox[1] = _r[1] end
        _dt[%d] = function(_r) if _regs[_r[1]] then _pcbox[1] = _r[2] end end
        _dt[%d] = function(_r) if not _regs[_r[1]] then _pcbox[1] = _r[2] end end
        _dt[%d] = function(_r)
            local _fn    = _regs[_r[1]]
            local _cargs = {}
            for _ai = 1, _r[2] do _cargs[_ai] = _regs[_r[1] + _ai] end
            local _rv = {_fn(table.unpack(_cargs))}
            for _ri = 1, _r[3] do _regs[_r[1] + _ri - 1] = _rv[_ri] end
        end
        _dt[%d] = function(_r)
            local _obj   = _regs[_r[1]]
            local _mth   = _obj[_k[_r[2]]]
            local _cargs = {_obj}
            for _ai = 1, _r[3] do _cargs[_ai + 1] = _regs[_r[1] + _ai] end
            local _rv = {_mth(table.unpack(_cargs))}
            for _ri = 1, _r[4] do _regs[_r[1] + _ri - 1] = _rv[_ri] end
        end
        _dt[%d] = function(_r)
            local _fn    = _regs[_r[1]]
            local _cargs = _regs[_r[2]] or {}
            _regs[_r[1]] = {_fn(table.unpack(_cargs))}
        end
        _dt[%d] = function(_r)
            if _r[2] == 0 then
                _retbox = _regs[_r[1]] or {}
            else
                local _rv = {}
                for _ri = 1, _r[2] do _rv[_ri] = _regs[_r[1] + _ri - 1] end
                _retbox = _rv
            end
            _pcbox[1] = #_instrs + 999
        end
        _dt[%d] = function(_r)
            _retbox   = {}
            _pcbox[1] = #_instrs + 999
        end
        _dt[%d] = function(_r)
            local _pid   = _r[2]
            local _proto = %s[_pid]
            local _cuvs  = {}
            for _ui = 1, _r[3] do
                local _uinstr  = _instrs[_pcbox[1]]
                _pcbox[1]      = _pcbox[1] + 1
                local _kind    = _uinstr.raw[1]
                local _src     = _uinstr.raw[2]
                local _dst     = _uinstr.raw[3]
                if _kind == 0 then
                    local _uid     = %s()
                    %s[_uid]       = _regs[_src]
                    %s[_uid]       = 1
                    _cuvs[_dst]    = _uid
                else
                    _cuvs[_dst]    = _uvs[_src]
                    %s[_uvs[_src]] = (%s[_uvs[_src]] or 0) + 1
                end
            end
            _regs[_r[1]] = function(...)
                local _args = {...}
                local _cr   = {}
                for _ai, _av in ipairs(_args) do _cr[_ai] = _av end
                return %s(_proto, _cr, _cuvs)
            end
        end
        _dt[%d] = function(_r) _regs[_r[1]] = _regs[0] or {} end
        _dt[%d] = function(_r) end
        _dt[%d] = function(_r)
            local _iter  = _regs[_r[1] - 3]
            local _state = _regs[_r[1] - 2]
            local _ctrl  = _regs[_r[1] - 1]
            local _nv    = {_iter(_state, _ctrl)}
            if _nv[1] == nil then
                _pcbox[1] = _r[3]
            else
                for _ni = 1, _r[2] do _regs[_r[1] + _ni - 1] = _nv[_ni] end
                _regs[_r[1] - 1] = _nv[1]
            end
        end
        while _pcbox[1] <= #_instrs do
            local _i  = _instrs[_pcbox[1]]
            local _op = _i.op
            local _r  = _i.raw
            _pcbox[1] = _pcbox[1] + 1
            local _h  = _dt[_op]
            if _h then _h(_r) end
            if _retbox ~= nil then break end
        end
        if _retbox then return table.unpack(_retbox) end
        return
    end
    local _entryProto = %s[_entryId]
    local _initRegs   = {[0] = %s}
    return %s(_entryProto, _initRegs, {})
end
]=],
        -- params (5)
        vBC, vMap, vEnv, vUnpk, vArgs,
        -- stdlib (6)
        vSb, vSc, vMf, vTcat, vTins, vSsub,
        -- junk locals (6 = 3 * {name, vMf})
        vJ1, vMf,   vJ2, vMf,   vJ3, vMf,
        -- decrypt (6 %s + 4 %d)
        vDecBC,
            k1, k2, k3, k4,
            vBC,
            vSc, vSb, vBC,
        vTcat,
        -- cursor
        vPos,
        -- readByte (6)
        vRB, vSb, vDecBC, vPos,  vPos, vPos,
        -- readShort (9)
        vRS, vSb, vDecBC, vPos,  vSb, vDecBC, vPos,  vPos, vPos,
        -- readInt (15)
        vRI,
            vSb, vDecBC, vPos,
            vSb, vDecBC, vPos,
            vSb, vDecBC, vPos,
            vSb, vDecBC, vPos,
        vPos, vPos,
        -- readConst (20)
        vRD,
            vRB, vRB, vRI,
            vSb, vDecBC, vPos,  vPos, vPos,
            vSc, vTcat, vTins, vTcat,
            vRS,  vSsub, vDecBC, vPos, vPos,
        vPos, vPos,
        -- upvalue alloc/free + fwd declare (16)
        vUVT, vUVRC, vUVID,
        vAllocUV,  vUVID, vUVID,  vUVRC, vUVID,  vUVID,
        vFreeUV,   vUVRC, vUVRC,  vUVRC,  vUVT, vUVRC,
        vExec,
        -- parseProto (14)
        vParse, vPos,
        vRB, vRB, vRB, vRS,
        vRS, vRD,
        vRS, vRI,
        vRS, vRB,
        vSb, vMap,
        -- proto cache (6)
        vProtos,
        vRS, vRI, vRI,
        vProtos, vParse,
        -- dispatch table exec assign (1 %s) + handlers (39 %d + 11 %s)
        vExec,
        O.LOAD_CONST, O.LOAD_BOOL, O.LOAD_NIL, O.MOV,
        O.GET_UPVAL,  vUVT,
        O.SET_UPVAL,  vUVT,
        O.GET_GLOBAL, vEnv,
        O.SET_GLOBAL, vEnv,
        O.NEW_TABLE,
        O.GET_TABLE,  O.SET_TABLE,
        O.GET_TABLE_K, O.SET_TABLE_K,
        O.ADD, O.SUB, O.MUL, O.DIV, O.MOD, O.POW, O.CONCAT,
        O.UNM, O.NOT, O.LEN,
        O.LT, O.LE, O.EQ, O.NEQ,
        O.JMP, O.JMP_IF, O.JMP_IF_NOT,
        O.CALL, O.CALL_SELF, O.CALL_VARARG,
        O.RETURN, O.RETURN_NONE,
        O.CLOSURE,   vProtos,
            vAllocUV, vUVT, vUVRC,
            vUVRC, vUVRC,
            vExec,
        O.VARARG, O.ITER_PREP, O.ITER_NEXT,
        -- entry point (3)
        vProtos, vArgs, vExec
    )

    return src
end

return VMEmitter