-- This Script is Part of the Prometheus Obfuscator by Levno_710
--
-- ProxifyLocals.lua
--
-- This Script provides a Obfuscation Step for putting all Locals into Proxy Objects
--
-- Fixes applied:
--   1. Vararg (...) variables are detected and locked (never proxified)
--   2. Variables declared inside coroutine.wrap / coroutine.create bodies are locked
--   3. Multi-assignment (a, b = ...) variables are fully locked to prevent proxy/value mismatch
--   4. Variables referenced inside load() / loadstring() arguments are locked
--   5. Per-variable unique internal key names (not shared per scope)
--   6. Non-trivial empty function (junk arithmetic body, randomised constants)
--   7. [FIX] LocalFunctionDeclaration variables are locked — prevents "attempt to call a table value"
--   8. [FIX] Single-target AssignmentStatement now emits a real index-assignment instead of
--      passing the proxy-set expression to the junk no-op function (which never actually
--      stored the value, causing stale proxy tables to be called as functions)

local Step = require("prometheus.step");
local Ast = require("prometheus.ast");
local Scope = require("prometheus.scope");
local visitast = require("prometheus.visitast");
local RandomLiterals = require("prometheus.randomLiterals")

local AstKind = Ast.AstKind;

local ProifyLocals = Step:extend();
ProifyLocals.Description = "This Step wraps all locals into Proxy Objects";
ProifyLocals.Name = "Proxify Locals";

ProifyLocals.SettingsDescriptor = {
    LiteralType = {
        name = "LiteralType",
        description = "The type of the randomly generated literals",
        type = "enum",
        values = {
            "dictionary",
            "number",
            "string",
            "any",
        },
        default = "string",
    },
}

local function shallowcopy(orig)
    local orig_type = type(orig)
    local copy
    if orig_type == 'table' then
        copy = {}
        for orig_key, orig_value in pairs(orig) do
            copy[orig_key] = orig_value
        end
    else
        copy = orig
    end
    return copy
end

local function callNameGenerator(generatorFunction, ...)
    if type(generatorFunction) == "table" then
        generatorFunction = generatorFunction.generateName;
    end
    return generatorFunction(...);
end

local MetatableExpressions = {
    {constructor = Ast.AddExpression,    key = "__add"},
    {constructor = Ast.SubExpression,    key = "__sub"},
    {constructor = Ast.IndexExpression,  key = "__index"},
    {constructor = Ast.MulExpression,    key = "__mul"},
    {constructor = Ast.DivExpression,    key = "__div"},
    {constructor = Ast.PowExpression,    key = "__pow"},
    {constructor = Ast.StrCatExpression, key = "__concat"},
}

-- ============================================================
-- Coroutine call detection helper
-- Returns true if a FunctionCallExpression node is a call to
-- coroutine.wrap or coroutine.create so we can lock all locals
-- declared inside the argument function body.
-- ============================================================
local function isCoroutineCall(node)
    if node.kind ~= AstKind.FunctionCallExpression then return false end
    local func = node.func
    if func and func.kind == AstKind.IndexExpression then
        local base = func.base
        local idx  = func.index
        if base and base.kind == AstKind.VariableExpression
        and idx  and idx.kind  == AstKind.StringExpression then
            if (idx.value == "wrap" or idx.value == "create") then
                if base.scope and base.scope.isGlobal then
                    return true
                end
            end
        end
    end
    return false
end

-- ============================================================
-- load / loadstring call detection helper
-- ============================================================
local function isLoadCall(node)
    if node.kind ~= AstKind.FunctionCallExpression then return false end
    local func = node.func
    if func and func.kind == AstKind.VariableExpression then
        if func.scope and func.scope.isGlobal then
            local name = func.name or (func.id and tostring(func.id))
            if name == "load" or name == "loadstring" then
                return true
            end
        end
    end
    return false
end

function ProifyLocals:init(settings)
end

-- FIX 5: valueName is generated per-variable, not shared per scope.
local function generateLocalMetatableInfo(pipeline)
    local usedOps = {};
    local info = {};
    for _, v in ipairs({"setValue", "getValue", "index"}) do
        local rop;
        repeat
            rop = MetatableExpressions[math.random(#MetatableExpressions)];
        until not usedOps[rop];
        usedOps[rop] = true;
        info[v] = rop;
    end
    info.valueName = callNameGenerator(pipeline.namegenerator, math.random(1, 4096));
    return info;
end

function ProifyLocals:CreateAssignmentExpression(info, expr, parentScope)
    local metatableVals = {};

    -- Setvalue Entry
    local setValueFunctionScope = Scope:new(parentScope);
    local setValueSelf = setValueFunctionScope:addVariable();
    local setValueArg  = setValueFunctionScope:addVariable();
    local setvalueFunctionLiteral = Ast.FunctionLiteralExpression(
        {
            Ast.VariableExpression(setValueFunctionScope, setValueSelf),
            Ast.VariableExpression(setValueFunctionScope, setValueArg),
        },
        Ast.Block({
            Ast.AssignmentStatement({
                Ast.AssignmentIndexing(
                    Ast.VariableExpression(setValueFunctionScope, setValueSelf),
                    Ast.StringExpression(info.valueName)
                );
            }, {
                Ast.VariableExpression(setValueFunctionScope, setValueArg)
            })
        }, setValueFunctionScope)
    );
    table.insert(metatableVals, Ast.KeyedTableEntry(Ast.StringExpression(info.setValue.key), setvalueFunctionLiteral));

    -- Getvalue Entry
    local getValueFunctionScope = Scope:new(parentScope);
    local getValueSelf = getValueFunctionScope:addVariable();
    local getValueArg  = getValueFunctionScope:addVariable();
    local getValueIdxExpr;
    if info.getValue.key == "__index" or info.setValue.key == "__index" then
        getValueIdxExpr = Ast.FunctionCallExpression(
            Ast.VariableExpression(getValueFunctionScope:resolveGlobal("rawget")),
            {
                Ast.VariableExpression(getValueFunctionScope, getValueSelf),
                Ast.StringExpression(info.valueName),
            }
        );
    else
        getValueIdxExpr = Ast.IndexExpression(
            Ast.VariableExpression(getValueFunctionScope, getValueSelf),
            Ast.StringExpression(info.valueName)
        );
    end
    local getvalueFunctionLiteral = Ast.FunctionLiteralExpression(
        {
            Ast.VariableExpression(getValueFunctionScope, getValueSelf),
            Ast.VariableExpression(getValueFunctionScope, getValueArg),
        },
        Ast.Block({
            Ast.ReturnStatement({getValueIdxExpr});
        }, getValueFunctionScope)
    );
    table.insert(metatableVals, Ast.KeyedTableEntry(Ast.StringExpression(info.getValue.key), getvalueFunctionLiteral));

    parentScope:addReferenceToHigherScope(self.setMetatableVarScope, self.setMetatableVarId);
    return Ast.FunctionCallExpression(
        Ast.VariableExpression(self.setMetatableVarScope, self.setMetatableVarId),
        {
            Ast.TableConstructorExpression({
                Ast.KeyedTableEntry(Ast.StringExpression(info.valueName), expr)
            }),
            Ast.TableConstructorExpression(metatableVals)
        }
    );
end

function ProifyLocals:apply(ast, pipeline)
    local localMetatableInfos = {};

    local function getLocalMetatableInfo(scope, id)
        if scope.isGlobal then return nil end
        localMetatableInfos[scope] = localMetatableInfos[scope] or {};
        if localMetatableInfos[scope][id] then
            if localMetatableInfos[scope][id].locked then return nil end
            return localMetatableInfos[scope][id];
        end
        local info = generateLocalMetatableInfo(pipeline);
        localMetatableInfos[scope][id] = info;
        return info;
    end

    local function disableMetatableInfo(scope, id)
        if scope.isGlobal then return nil end
        localMetatableInfos[scope] = localMetatableInfos[scope] or {};
        localMetatableInfos[scope][id] = {locked = true};
    end

    -- Pre-pass: lock all variables that must never be proxified.
    visitast(ast, function(node, data)

        -- FIX 2: Lock locals declared inside coroutine bodies.
        if isCoroutineCall(node) then
            for _, arg in ipairs(node.args or {}) do
                if arg.kind == AstKind.FunctionLiteralExpression then
                    visitast(arg, function(inner, _)
                        if inner.kind == AstKind.LocalVariableDeclaration then
                            for _, id in ipairs(inner.ids) do
                                disableMetatableInfo(inner.scope, id);
                            end
                        end
                        if inner.kind == AstKind.ForStatement then
                            disableMetatableInfo(inner.scope, inner.id);
                        end
                        if inner.kind == AstKind.ForInStatement then
                            for _, id in ipairs(inner.ids) do
                                disableMetatableInfo(inner.scope, id);
                            end
                        end
                    end, function() end);
                end
            end
        end

        -- FIX 4: Lock variables referenced as load/loadstring arguments.
        if isLoadCall(node) then
            for _, arg in ipairs(node.args or {}) do
                if arg.kind == AstKind.VariableExpression then
                    disableMetatableInfo(arg.scope, arg.id);
                end
            end
        end

        -- FIX 7: Lock local function declaration variables.
        -- When a local function is proxified, the variable becomes a metatable proxy
        -- table. Any call to that variable then hits "attempt to call a table value"
        -- because Lua tries to call the proxy table directly — the __call metamethod
        -- is not set. We simply never proxify local functions.
        if node.kind == AstKind.LocalFunctionDeclaration then
            disableMetatableInfo(node.scope, node.id);
        end

    end, function() end);

    -- Create Setmetatable Variable
    self.setMetatableVarScope = ast.body.scope;
    self.setMetatableVarId    = ast.body.scope:addVariable();

    -- Create Empty Function Variable (kept for legacy emptyFunctionUsed tracking,
    -- but no longer used as a sink for assignment side-effects — see FIX 8 below).
    self.emptyFunctionScope = ast.body.scope;
    self.emptyFunctionId    = ast.body.scope:addVariable();
    self.emptyFunctionUsed  = false;

    -- FIX 6: Non-trivial empty function body with randomised junk arithmetic.
    do
        local junkScope = Scope:new(ast.body.scope);
        local junkVar   = junkScope:addVariable();
        local c1 = math.random(1, 255);
        local c2 = math.random(2, 16);
        local junkBody = Ast.Block({
            Ast.LocalVariableDeclaration(junkScope, {junkVar}, {
                Ast.NumberExpression(c1)
            }),
            Ast.AssignmentStatement(
                {Ast.AssignmentVariable(junkScope, junkVar)},
                {Ast.MulExpression(
                    Ast.VariableExpression(junkScope, junkVar),
                    Ast.NumberExpression(c2)
                )}
            ),
        }, junkScope);
        table.insert(ast.body.statements, 1,
            Ast.LocalVariableDeclaration(
                self.emptyFunctionScope,
                {self.emptyFunctionId},
                {Ast.FunctionLiteralExpression({}, junkBody)}
            )
        );
    end

    visitast(ast, function(node, data)

        -- Lock for-loop counter variable
        if node.kind == AstKind.ForStatement then
            disableMetatableInfo(node.scope, node.id);
        end

        -- Lock for-in loop variables
        if node.kind == AstKind.ForInStatement then
            for _, id in ipairs(node.ids) do
                disableMetatableInfo(node.scope, id);
            end
        end

        -- Lock function arguments (all flavours)
        if node.kind == AstKind.FunctionDeclaration
        or node.kind == AstKind.LocalFunctionDeclaration
        or node.kind == AstKind.FunctionLiteralExpression then
            for _, expr in ipairs(node.args) do
                if expr.kind == AstKind.VariableExpression then
                    disableMetatableInfo(expr.scope, expr.id);
                end
            end
            -- FIX 1: Lock vararg scope so downstream code knows not to proxy
            -- any implicit vararg-derived locals.
            if node.hasVarArg or node.isVarArg then
                if node.body and node.body.scope then
                    node.body.scope.__hasVarArg = true;
                end
            end
        end

        -- FIX 3: Multi-assignment — lock all lhs variables.
        if node.kind == AstKind.AssignmentStatement then
            if #node.lhs > 1 then
                for _, variable in ipairs(node.lhs) do
                    if variable.kind == AstKind.AssignmentVariable then
                        disableMetatableInfo(variable.scope, variable.id);
                    end
                end
            end
        end

        -- FIX 8: Single-target AssignmentStatement.
        --
        -- OLD (broken) behaviour:
        --   The proxy set expression was passed as an argument to the junk no-op
        --   function. The junk function ignores all its arguments, so the actual
        --   store into the proxy table never happened. On the next read the variable
        --   still held the original (possibly stale) proxy table — and if it was a
        --   function being reassigned, calling it would hit "attempt to call a table
        --   value" because the proxy table has no __call metamethod.
        --
        -- NEW (fixed) behaviour:
        --   We emit a direct index-assignment:  var[valueName] = rhs
        --   This is exactly what the setvalue metamethod does internally, but done
        --   inline so it actually executes and the proxy table is updated correctly.
        if node.kind == AstKind.AssignmentStatement then
            if #node.lhs == 1 and node.lhs[1].kind == AstKind.AssignmentVariable then
                local variable = node.lhs[1];
                local localMetatableInfo = getLocalMetatableInfo(variable.scope, variable.id);
                if localMetatableInfo then
                    local vexp = Ast.VariableExpression(variable.scope, variable.id);
                    vexp.__ignoreProxifyLocals = true;
                    -- Emit: var[valueName] = rhs
                    return Ast.AssignmentStatement({
                        Ast.AssignmentIndexing(
                            vexp,
                            Ast.StringExpression(localMetatableInfo.valueName)
                        )
                    }, shallowcopy(node.rhs));
                end
            end
        end

    end, function(node, data)

        -- Local Variable Declaration
        if node.kind == AstKind.LocalVariableDeclaration then
            -- FIX 3: Multi-declaration safety.
            local exprCount = #node.expressions;
            local idCount   = #node.ids;
            local lastExpr  = node.expressions[exprCount];
            local lastIsMultiReturn = lastExpr and (
                lastExpr.kind == AstKind.FunctionCallExpression or
                lastExpr.kind == AstKind.VarArgExpression
            );
            if lastIsMultiReturn or exprCount < idCount then
                for _, id in ipairs(node.ids) do
                    disableMetatableInfo(node.scope, id);
                end
            else
                for i, id in ipairs(node.ids) do
                    local expr = node.expressions[i] or Ast.NilExpression();
                    local localMetatableInfo = getLocalMetatableInfo(node.scope, id);
                    if localMetatableInfo then
                        node.expressions[i] = self:CreateAssignmentExpression(
                            localMetatableInfo, expr, node.scope
                        );
                    end
                end
            end
        end

        -- Variable Expression (read)
        if node.kind == AstKind.VariableExpression and not node.__ignoreProxifyLocals then
            local localMetatableInfo = getLocalMetatableInfo(node.scope, node.id);
            if localMetatableInfo then
                local literal;
                if self.LiteralType == "dictionary" then
                    literal = RandomLiterals.Dictionary();
                elseif self.LiteralType == "number" then
                    literal = RandomLiterals.Number();
                elseif self.LiteralType == "string" then
                    literal = RandomLiterals.String(pipeline);
                else
                    literal = RandomLiterals.Any(pipeline);
                end
                return localMetatableInfo.getValue.constructor(node, literal);
            end
        end

        -- Assignment Variable (write target)
        if node.kind == AstKind.AssignmentVariable then
            local localMetatableInfo = getLocalMetatableInfo(node.scope, node.id);
            if localMetatableInfo then
                return Ast.AssignmentIndexing(node, Ast.StringExpression(localMetatableInfo.valueName));
            end
        end

        -- Local Function Declaration
        -- FIX 7: This block is now unreachable for any proxifiable local function
        -- because all LocalFunctionDeclaration variables are locked in the pre-pass.
        -- It is kept here as a safety net only — if somehow a local function slips
        -- through the lock (should not happen), we still skip it gracefully.
        if node.kind == AstKind.LocalFunctionDeclaration then
            -- Already locked in pre-pass. Do nothing — leave the declaration as-is.
            -- DO NOT call CreateAssignmentExpression here; that is what caused the bug.
        end

        -- Function Declaration
        if node.kind == AstKind.FunctionDeclaration then
            local localMetatableInfo = getLocalMetatableInfo(node.scope, node.id);
            if localMetatableInfo then
                table.insert(node.indices, 1, localMetatableInfo.valueName);
            end
        end

    end)

    -- Add Setmetatable Variable Declaration
    table.insert(ast.body.statements, 1,
        Ast.LocalVariableDeclaration(self.setMetatableVarScope, {self.setMetatableVarId}, {
            Ast.VariableExpression(self.setMetatableVarScope:resolveGlobal("setmetatable"))
        })
    );
end

return ProifyLocals;