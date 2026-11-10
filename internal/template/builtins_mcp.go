package template

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"

	"github.com/agardenat/clotr/internal/i18n"
)

type MCPResult struct {
	Text    string
	Data    json.RawMessage
	IsError bool
}

type MCPCaller interface {
	CallTool(ctx context.Context, tool string, args map[string]any) (*MCPResult, error)
}

func checkMCPOptions(o options) error {
	for k := range o {
		if k != "server" {
			return i18n.E("tpl.mcp.option", k)
		}
	}
	return nil
}

func (in *Instance) MCPServers() []string {
	var out []string
	for _, s := range in.mcps {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	slices.Sort(out)
	return out
}

func (in *Instance) mcpModule() *starlarkstruct.Module {
	return &starlarkstruct.Module{
		Name:    "mcp",
		Members: starlark.StringDict{"call": starlark.NewBuiltin("mcp.call", in.builtinMCPCall)},
	}
}

func (in *Instance) builtinMCPCall(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var conn, tool string
	var argsV starlark.Value
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "conn", &conn, "tool", &tool, "args?", &argsV); err != nil {
		return nil, err
	}
	if thread.Local(localLoading) != nil {
		return nil, i18n.E("tpl.mcp.at_load")
	}
	server, ok := in.mcps[conn]
	if !ok {
		return nil, i18n.E("tpl.mcp.conn", conn)
	}
	ctx := threadCtx(thread)
	if err := denyOffline(ctx); err != nil {
		return nil, err
	}
	callArgs := map[string]any{}
	if argsV != nil && argsV != starlark.None {
		v, err := fromStarlark(argsV)
		if err != nil {
			return nil, err
		}
		m, ok := v.(map[string]any)
		if !ok {
			return nil, i18n.E("tpl.mcp.args", argsV.Type())
		}
		callArgs = m
	}
	if in.MCP == nil {
		return nil, i18n.E("tpl.mcp.unavailable", server)
	}
	start := time.Now()
	audit := map[string]any{"tool": threadTool(thread), "connector": conn, "server": server, "remote_tool": tool}
	res, err := func() (*MCPResult, error) {
		c, err := in.MCP(ctx, server)
		if err != nil {
			return nil, err
		}
		return c.CallTool(ctx, tool, callArgs)
	}()
	audit["ms"] = time.Since(start).Milliseconds()
	if err != nil {
		audit["error"] = err.Error()
		in.audit("mcp_call", audit)
		return nil, fmt.Errorf("mcp.call %s %s: %w", server, tool, err)
	}
	audit["is_error"] = res.IsError
	in.audit("mcp_call", audit)
	var data starlark.Value = starlark.None
	if len(res.Data) > 0 {
		if data, err = jsonToStarlark(res.Data); err != nil {
			return nil, fmt.Errorf("mcp.call %s %s: %w", server, tool, err)
		}
	}
	return starlarkstruct.FromStringDict(starlarkstruct.Default, starlark.StringDict{
		"text":  starlark.String(res.Text),
		"data":  data,
		"error": starlark.Bool(res.IsError),
	}), nil
}
