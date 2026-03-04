local Serializer = {}
local OP = {
    LOAD_CONST   = 1,
    LOAD_BOOL    = 2,
    LOAD_NIL     = 3,
    MOV          = 4,
    GET_UPVAL    = 5,
    SET_UPVAL    = 6,
    ALLOC_UPVAL  = 7,
    FREE_UPVAL   = 8,
    GET_GLOBAL   = 9,
    SET_GLOBAL   = 10,
    NEW_TABLE    = 11,
    GET_TABLE    = 12,
    SET_TABLE    = 13,
    GET_TABLE_K  = 14,
    SET_TABLE_K  = 15,
    SET_LIST     = 16,
    ADD          = 17,
    SUB          = 18,
    MUL          = 19,
    DIV          = 20,
    MOD          = 21,
    POW          = 22,
    CONCAT       = 23,
    ADD_K        = 24,
    SUB_K        = 25,
    MUL_K        = 26,
    DIV_K        = 27,
    UNM          = 28,
    NOT          = 29,
    LEN          = 30,
    LT           = 31,
    LE           = 32,
    EQ           = 33,
    NEQ          = 34,
    JMP          = 35,
    JMP_IF       = 36,
    JMP_IF_NOT   = 37,
    JMP_AND      = 38,
    JMP_OR       = 39,
    CALL         = 40,
    CALL_SELF    = 41,
    CALL_VARARG  = 42,
    RETURN       = 43,
    RETURN_NONE  = 44,
    CLOSURE      = 45,
    UPVAL_REF    = 46,
    VARARG       = 47,
    ITER_PREP    = 48,
    ITER_NEXT    = 49,
}
local OP_COUNT = 49
local OPERAND = {
    REG   = "r",
    CONST = "k",
    INSTR = "i",
    BYTE  = "b",
    SHORT = "s",
}
local OP_LAYOUT = {
    [OP.LOAD_CONST]  = {"r","k"},
    [OP.LOAD_BOOL]   = {"r","b"},
    [OP.LOAD_NIL]    = {"r","b"},
    [OP.MOV]         = {"r","r"},
    [OP.GET_UPVAL]   = {"r","s"},
    [OP.SET_UPVAL]   = {"s","r"},
    [OP.ALLOC_UPVAL] = {"s"},
    [OP.FREE_UPVAL]  = {"s"},
    [OP.GET_GLOBAL]  = {"r","k"},
    [OP.SET_GLOBAL]  = {"k","r"},
    [OP.NEW_TABLE]   = {"r"},
    [OP.GET_TABLE]   = {"r","r","r"},
    [OP.SET_TABLE]   = {"r","r","r"},
    [OP.GET_TABLE_K] = {"r","r","k"},
    [OP.SET_TABLE_K] = {"r","k","r"},
    [OP.SET_LIST]    = {"r","b"},
    [OP.ADD]         = {"r","r","r"},
    [OP.SUB]         = {"r","r","r"},
    [OP.MUL]         = {"r","r","r"},
    [OP.DIV]         = {"r","r","r"},
    [OP.MOD]         = {"r","r","r"},
    [OP.POW]         = {"r","r","r"},
    [OP.CONCAT]      = {"r","r","r"},
    [OP.ADD_K]       = {"r","r","k"},
    [OP.SUB_K]       = {"r","r","k"},
    [OP.MUL_K]       = {"r","r","k"},
    [OP.DIV_K]       = {"r","r","k"},
    [OP.UNM]         = {"r","r"},
    [OP.NOT]         = {"r","r"},
    [OP.LEN]         = {"r","r"},
    [OP.LT]          = {"r","r","r"},
    [OP.LE]          = {"r","r","r"},
    [OP.EQ]          = {"r","r","r"},
    [OP.NEQ]         = {"r","r","r"},
    [OP.JMP]         = {"i"},
    [OP.JMP_IF]      = {"r","i"},
    [OP.JMP_IF_NOT]  = {"r","i"},
    [OP.JMP_AND]     = {"r","r","i"},
    [OP.JMP_OR]      = {"r","r","i"},
    [OP.CALL]        = {"r","b","b"},
    [OP.CALL_SELF]   = {"r","k","b","b"},
    [OP.CALL_VARARG] = {"r","r"},
    [OP.RETURN]      = {"r","b"},
    [OP.RETURN_NONE] = {},
    [OP.CLOSURE]     = {"r","s","s"},
    [OP.UPVAL_REF]   = {"b","s","s"},
    [OP.VARARG]      = {"r"},
    [OP.ITER_PREP]   = {"r","r"},
    [OP.ITER_NEXT]   = {"r","b","i"},
}
function Serializer.generateOpcodeMap()
    local pool = {}
    for i = 0, 255 do pool[i+1] = i end
    for i = 256, 2, -1 do
        local j = math.random(1, i)
        pool[i], pool[j] = pool[j], pool[i]
    end
    local encodeMap = {}
    local decodeMap = {}
    local i = 1
    for name, logicalId in pairs(OP) do
        local wire = pool[i]
        encodeMap[logicalId] = wire
        decodeMap[wire] = logicalId
        i = i + 1
    end
    return encodeMap, decodeMap
end
function Serializer.newConstPool()
    return { values = {}, index = {} }
end
function Serializer.addConst(pool, val)
    local key = type(val) .. ":" .. tostring(val)
    if pool.index[key] then
        return pool.index[key]
    end
    table.insert(pool.values, val)
    local idx = #pool.values - 1
    pool.index[key] = idx
    return idx
end
function Serializer.newBuffer()
    return { bytes = {}, pos = 0 }
end
function Serializer.writeByte(buf, v)
    v = v % 256
    table.insert(buf.bytes, v)
    buf.pos = buf.pos + 1
end
function Serializer.writeShort(buf, v)
    v = v % 65536
    table.insert(buf.bytes, v % 256)
    table.insert(buf.bytes, math.floor(v / 256))
    buf.pos = buf.pos + 2
end
function Serializer.writeInt(buf, v)
    v = math.floor(v)
    local u = v % (2^32)
    table.insert(buf.bytes, u % 256)                         u = math.floor(u/256)
    table.insert(buf.bytes, u % 256)                         u = math.floor(u/256)
    table.insert(buf.bytes, u % 256)                         u = math.floor(u/256)
    table.insert(buf.bytes, u % 256)
    buf.pos = buf.pos + 4
end
function Serializer.writeDouble(buf, v)
    local ok, packed = pcall(string.pack, "<d", v)
    if ok then
        for i = 1, #packed do
            table.insert(buf.bytes, string.byte(packed, i))
        end
        buf.pos = buf.pos + 8
        return
    end
    local s = tostring(v)
    Serializer.writeByte(buf, #s)
    for i = 1, #s do
        Serializer.writeByte(buf, string.byte(s, i))
    end
end
function Serializer.writeString(buf, s)
    local len = #s
    Serializer.writeShort(buf, len)
    for i = 1, len do
        Serializer.writeByte(buf, string.byte(s, i))
    end
end
function Serializer.bufferToString(buf)
    local t = {}
    for i, b in ipairs(buf.bytes) do
        t[i] = string.char(b)
    end
    return table.concat(t)
end
local CONST_NIL    = 0
local CONST_BOOL   = 1
local CONST_INT    = 2
local CONST_DOUBLE = 3
local CONST_STRING = 4
function Serializer.serializeConstPool(pool, buf)
    local vals = pool.values
    Serializer.writeShort(buf, #vals)
    for _, v in ipairs(vals) do
        local t = type(v)
        if v == nil then
            Serializer.writeByte(buf, CONST_NIL)
        elseif t == "boolean" then
            Serializer.writeByte(buf, CONST_BOOL)
            Serializer.writeByte(buf, v and 1 or 0)
        elseif t == "number" then
            if math.floor(v) == v and v >= -2147483648 and v <= 2147483647 then
                Serializer.writeByte(buf, CONST_INT)
                Serializer.writeInt(buf, v)
            else
                Serializer.writeByte(buf, CONST_DOUBLE)
                Serializer.writeDouble(buf, v)
            end
        elseif t == "string" then
            Serializer.writeByte(buf, CONST_STRING)
            Serializer.writeString(buf, v)
        else
            Serializer.writeByte(buf, CONST_NIL)
        end
    end
end
function Serializer.newProto(id, paramCount, isVararg)
    return {
        id         = id,
        paramCount = paramCount or 0,
        isVararg   = isVararg or false,
        instrs     = {},
        constPool  = Serializer.newConstPool(),
        protos     = {},
        upvalCount = 0,
        maxReg     = 0,
    }
end
function Serializer.emit(proto, op, ...)
    local operands = {...}
    table.insert(proto.instrs, {op = op, operands = operands})
    return #proto.instrs
end
function Serializer.patch(proto, instrIdx, operandIdx, value)
    proto.instrs[instrIdx].operands[operandIdx] = value
end
function Serializer.konstant(proto, val)
    return Serializer.addConst(proto.constPool, val)
end
function Serializer.serializeProto(proto, buf, encodeMap)
    Serializer.writeByte(buf, proto.paramCount)
    Serializer.writeByte(buf, proto.isVararg and 1 or 0)
    Serializer.writeByte(buf, math.min(proto.maxReg, 255))
    Serializer.writeShort(buf, proto.upvalCount)
    Serializer.serializeConstPool(proto.constPool, buf)
    Serializer.writeShort(buf, #proto.protos)
    for _, pid in ipairs(proto.protos) do
        Serializer.writeInt(buf, pid)
    end
    local instrs = proto.instrs
    Serializer.writeShort(buf, #instrs)
    for _, instr in ipairs(instrs) do
        local logicalOp = instr.op
        local wireByte  = encodeMap[logicalOp]
        assert(wireByte, "No wire encoding for op " .. tostring(logicalOp))
        Serializer.writeByte(buf, wireByte)
        local layout   = OP_LAYOUT[logicalOp] or {}
        local operands = instr.operands
        for i, kind in ipairs(layout) do
            local v = operands[i] or 0
            if kind == "r" or kind == "b" then
                Serializer.writeByte(buf, v % 256)
            elseif kind == "k" or kind == "i" or kind == "s" then
                Serializer.writeShort(buf, v % 65536)
            end
        end
    end
end
function Serializer.serialize(protoTable, entryId)
    local encodeMap, decodeMap = Serializer.generateOpcodeMap()
    local buf = Serializer.newBuffer()
    local sorted = {}
    for id, proto in pairs(protoTable) do
        table.insert(sorted, proto)
    end
    table.sort(sorted, function(a, b) return a.id < b.id end)
    Serializer.writeShort(buf, #sorted)
    Serializer.writeInt(buf, entryId)
    for _, proto in ipairs(sorted) do
        Serializer.writeInt(buf, proto.id)
        Serializer.serializeProto(proto, buf, encodeMap)
    end
    return encodeMap, decodeMap, Serializer.bufferToString(buf)
end
Serializer.OP         = OP
Serializer.OP_LAYOUT  = OP_LAYOUT
Serializer.CONST_NIL  = CONST_NIL
Serializer.CONST_BOOL = CONST_BOOL
Serializer.CONST_INT  = CONST_INT
Serializer.CONST_DOUBLE = CONST_DOUBLE
Serializer.CONST_STRING = CONST_STRING
return Serializer
