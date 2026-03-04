-- Serializer.lua
-- Z-Sec Bytecode Serializer
-- Converts the compiler's internal block/instruction representation
-- into a packed binary string with a randomized opcode table.
-- The original source is NEVER present in the output — only this byte string.

local Serializer = {}

-- ── Opcode Definitions ────────────────────────────────────────────────────────
-- Logical opcodes — these are the canonical names used internally.
-- Their actual numeric values are randomized per-compile by shuffling
-- the opcode table. A decompiler targeting standard Luau opcodes gets nothing.

local OP = {
    -- Data movement
    LOAD_CONST   = 1,   -- R[A] = K[B]          (load constant by index)
    LOAD_BOOL    = 2,   -- R[A] = (B ~= 0)       (load boolean)
    LOAD_NIL     = 3,   -- R[A..A+B] = nil       (load nil range)
    MOV          = 4,   -- R[A] = R[B]           (register copy)
    -- Upvalue ops
    GET_UPVAL    = 5,   -- R[A] = UV[B]          (read upvalue slot)
    SET_UPVAL    = 6,   -- UV[B] = R[A]          (write upvalue slot)
    ALLOC_UPVAL  = 7,   -- UV[A] = alloc()       (allocate new upvalue id)
    FREE_UPVAL   = 8,   -- free(UV[A])           (decrement upvalue refcount)
    -- Global env ops
    GET_GLOBAL   = 9,   -- R[A] = ENV[K[B]]      (read global by const name)
    SET_GLOBAL   = 10,  -- ENV[K[B]] = R[A]      (write global)
    -- Table ops
    NEW_TABLE    = 11,  -- R[A] = {}             (empty table)
    GET_TABLE    = 12,  -- R[A] = R[B][R[C]]     (table index)
    SET_TABLE    = 13,  -- R[A][R[B]] = R[C]     (table newindex)
    GET_TABLE_K  = 14,  -- R[A] = R[B][K[C]]     (table index by const key)
    SET_TABLE_K  = 15,  -- R[A][K[B]] = R[C]     (table newindex by const key)
    SET_LIST     = 16,  -- R[A][B+i] = R[A+i]    (bulk sequential table set)
    -- Arithmetic
    ADD          = 17,  -- R[A] = R[B] + R[C]
    SUB          = 18,  -- R[A] = R[B] - R[C]
    MUL          = 19,  -- R[A] = R[B] * R[C]
    DIV          = 20,  -- R[A] = R[B] / R[C]
    MOD          = 21,  -- R[A] = R[B] % R[C]
    POW          = 22,  -- R[A] = R[B] ^ R[C]
    CONCAT       = 23,  -- R[A] = R[B] .. R[C]
    -- Arithmetic with constant RHS (avoids a LOAD_CONST round-trip)
    ADD_K        = 24,  -- R[A] = R[B] + K[C]
    SUB_K        = 25,  -- R[A] = R[B] - K[C]
    MUL_K        = 26,  -- R[A] = R[B] * K[C]
    DIV_K        = 27,  -- R[A] = R[B] / K[C]
    -- Unary
    UNM          = 28,  -- R[A] = -R[B]
    NOT          = 29,  -- R[A] = not R[B]
    LEN          = 30,  -- R[A] = #R[B]
    -- Comparison (set R[A] = bool result)
    LT           = 31,  -- R[A] = R[B] < R[C]
    LE           = 32,  -- R[A] = R[B] <= R[C]
    EQ           = 33,  -- R[A] = R[B] == R[C]
    NEQ          = 34,  -- R[A] = R[B] ~= R[C]
    -- Control flow
    JMP          = 35,  -- pos = B               (absolute jump to instruction index)
    JMP_IF       = 36,  -- if R[A] then pos = B  (conditional jump)
    JMP_IF_NOT   = 37,  -- if not R[A] then pos = B
    JMP_AND      = 38,  -- R[A] = R[A] and R[B]; if not R[A] then pos = C (short circuit)
    JMP_OR       = 39,  -- R[A] = R[A] or R[B];  if R[A] then pos = C
    -- Calls
    CALL         = 40,  -- R[A..A+C-1] = R[A](R[A+1..A+B])   B=argcount C=retcount
    CALL_SELF    = 41,  -- R[A..A+C-1] = R[A]:K[B](R[A+1..A+D])
    CALL_VARARG  = 42,  -- R[A] = {R[B](...)}    (vararg call, captures all returns)
    RETURN       = 43,  -- return R[A..A+B-1]    (B=0 means return all from R[A])
    RETURN_NONE  = 44,  -- return {}             (fast empty return)
    -- Closures / varargs
    CLOSURE      = 45,  -- R[A] = closure(proto=B, upvals follow as UPVAL_REF ops)
    UPVAL_REF    = 46,  -- operand for CLOSURE: marks which upvalue slot maps where
    VARARG       = 47,  -- R[A] = {...}          (capture vararg table)
    -- Iterator
    ITER_PREP    = 48,  -- R[A], R[A+1], R[A+2] = iter, state, initial  (generic for prep)
    ITER_NEXT    = 49,  -- R[A..A+C] = R[A-3](R[A-2], R[A-1]); if R[A] == nil then jmp B
}

local OP_COUNT = 49

-- ── Operand encoding sizes ────────────────────────────────────────────────────
-- Each opcode has a fixed operand layout. We encode operands as:
--   1 byte  for register IDs   (0-255, we limit MAX_REGS to 200)
--   2 bytes for instruction indices / jump targets (uint16 LE)
--   2 bytes for constant pool indices              (uint16 LE)
-- This gives us: max 65535 constants, max 65535 instructions, max 200 registers

local OPERAND = {
    REG   = "r",   -- 1 byte register
    CONST = "k",   -- 2 byte constant index
    INSTR = "i",   -- 2 byte instruction index (jump target)
    BYTE  = "b",   -- 1 byte raw value
    SHORT = "s",   -- 2 byte raw value
}

-- Layout per opcode: list of operand type strings
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
    [OP.CLOSURE]     = {"r","s","s"},   -- dst, proto_id, upval_count
    [OP.UPVAL_REF]   = {"b","s","s"},   -- kind(0=reg,1=upval), src_slot, dst_slot
    [OP.VARARG]      = {"r"},
    [OP.ITER_PREP]   = {"r","r"},
    [OP.ITER_NEXT]   = {"r","b","i"},
}

-- ── Opcode shuffler ───────────────────────────────────────────────────────────
-- Generates a random bijection from logical opcode -> wire byte value.
-- Returns: encodeMap[logicalOp] = wireByte, decodeMap[wireByte] = logicalOp
function Serializer.generateOpcodeMap()
    -- build a pool of 256 byte values, shuffle, assign first OP_COUNT to opcodes
    local pool = {}
    for i = 0, 255 do pool[i+1] = i end
    -- Fisher-Yates
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

-- ── Constant pool ─────────────────────────────────────────────────────────────
function Serializer.newConstPool()
    return { values = {}, index = {} }
end

function Serializer.addConst(pool, val)
    local key = type(val) .. ":" .. tostring(val)
    if pool.index[key] then
        return pool.index[key]
    end
    table.insert(pool.values, val)
    local idx = #pool.values - 1   -- 0-indexed
    pool.index[key] = idx
    return idx
end

-- ── Byte packer ───────────────────────────────────────────────────────────────
function Serializer.newBuffer()
    return { bytes = {}, pos = 0 }
end

function Serializer.writeByte(buf, v)
    v = v % 256
    table.insert(buf.bytes, v)
    buf.pos = buf.pos + 1
end

function Serializer.writeShort(buf, v)
    -- little-endian uint16
    v = v % 65536
    table.insert(buf.bytes, v % 256)
    table.insert(buf.bytes, math.floor(v / 256))
    buf.pos = buf.pos + 2
end

function Serializer.writeInt(buf, v)
    -- little-endian int32 (for numbers that might be negative)
    v = math.floor(v)
    local u = v % (2^32)
    table.insert(buf.bytes, u % 256)                         u = math.floor(u/256)
    table.insert(buf.bytes, u % 256)                         u = math.floor(u/256)
    table.insert(buf.bytes, u % 256)                         u = math.floor(u/256)
    table.insert(buf.bytes, u % 256)
    buf.pos = buf.pos + 4
end

function Serializer.writeDouble(buf, v)
    -- IEEE 754 double as 8 bytes LE
    -- We encode using string.pack if available, else manual IEEE754
    local ok, packed = pcall(string.pack, "<d", v)
    if ok then
        for i = 1, #packed do
            table.insert(buf.bytes, string.byte(packed, i))
        end
        buf.pos = buf.pos + 8
        return
    end
    -- fallback: encode as string representation prefixed with length
    -- (lossy but works for integer values)
    local s = tostring(v)
    Serializer.writeByte(buf, #s)
    for i = 1, #s do
        Serializer.writeByte(buf, string.byte(s, i))
    end
end

function Serializer.writeString(buf, s)
    -- 2-byte length prefix then raw bytes
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

-- ── Constant pool serializer ──────────────────────────────────────────────────
-- Format:
--   [2 bytes: count]
--   for each constant:
--     [1 byte: type tag]  0=nil, 1=bool, 2=int, 3=double, 4=string
--     [payload depends on type]

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
            -- fallback: nil
            Serializer.writeByte(buf, CONST_NIL)
        end
    end
end

-- ── Instruction emitter ───────────────────────────────────────────────────────
-- An instruction stream for a single proto (function prototype)
function Serializer.newProto(id, paramCount, isVararg)
    return {
        id         = id,
        paramCount = paramCount or 0,
        isVararg   = isVararg or false,
        instrs     = {},      -- list of {op, operands={...}}
        constPool  = Serializer.newConstPool(),
        protos     = {},      -- nested proto ids (for CLOSURE)
        upvalCount = 0,
        maxReg     = 0,
    }
end

function Serializer.emit(proto, op, ...)
    local operands = {...}
    table.insert(proto.instrs, {op = op, operands = operands})
    return #proto.instrs   -- 1-indexed instruction number
end

-- Patch a previously emitted instruction's operand (for forward jumps)
function Serializer.patch(proto, instrIdx, operandIdx, value)
    proto.instrs[instrIdx].operands[operandIdx] = value
end

-- Add a constant to this proto's pool and return its index
function Serializer.konstant(proto, val)
    return Serializer.addConst(proto.constPool, val)
end

-- ── Proto serializer ──────────────────────────────────────────────────────────
-- Format for each proto:
--   [1 byte: paramCount]
--   [1 byte: isVararg]
--   [1 byte: maxReg]
--   [2 bytes: upvalCount]
--   [const pool: see serializeConstPool]
--   [2 bytes: nested proto count]
--   [4 bytes each: nested proto IDs]
--   [2 bytes: instruction count]
--   [instructions: opcode byte + operands per OP_LAYOUT]

function Serializer.serializeProto(proto, buf, encodeMap)
    Serializer.writeByte(buf, proto.paramCount)
    Serializer.writeByte(buf, proto.isVararg and 1 or 0)
    Serializer.writeByte(buf, math.min(proto.maxReg, 255))
    Serializer.writeShort(buf, proto.upvalCount)

    Serializer.serializeConstPool(proto.constPool, buf)

    -- nested protos
    Serializer.writeShort(buf, #proto.protos)
    for _, pid in ipairs(proto.protos) do
        Serializer.writeInt(buf, pid)
    end

    -- instructions
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

-- ── Top-level serialize ───────────────────────────────────────────────────────
-- Takes the full proto table (indexed by proto id) and produces:
--   encodeMap, decodeMap, binaryString
-- The binary string format:
--   [2 bytes: proto count]
--   [4 bytes: entry proto id]
--   [protos in order of id, each preceded by 4-byte id]

function Serializer.serialize(protoTable, entryId)
    local encodeMap, decodeMap = Serializer.generateOpcodeMap()
    local buf = Serializer.newBuffer()

    -- collect and sort protos
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

-- ── Export ────────────────────────────────────────────────────────────────────
Serializer.OP         = OP
Serializer.OP_LAYOUT  = OP_LAYOUT
Serializer.CONST_NIL  = CONST_NIL
Serializer.CONST_BOOL = CONST_BOOL
Serializer.CONST_INT  = CONST_INT
Serializer.CONST_DOUBLE = CONST_DOUBLE
Serializer.CONST_STRING = CONST_STRING

return Serializer
