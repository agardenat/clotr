package testutil

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/agardenat/clotr/internal/llm"
)

type ChatFunc func(ctx context.Context, provider string, req llm.Request) (*llm.Response, error)

type FakeChat struct {
	Fn    ChatFunc
	mu    sync.Mutex
	Calls []llm.Request
}

func (f *FakeChat) Chat(ctx context.Context, provider string, req llm.Request) (*llm.Response, error) {
	f.mu.Lock()
	f.Calls = append(f.Calls, req)
	f.mu.Unlock()
	return f.Fn(ctx, provider, req)
}

func Reply(content string, calls ...llm.ToolCall) *llm.Response {
	return &llm.Response{Choices: []llm.Choice{{Message: llm.Message{Role: "assistant", Content: content, ToolCalls: calls}}}}
}

func Call(name string, args any) llm.ToolCall {
	data, _ := json.Marshal(args)
	return llm.ToolCall{Function: llm.FunctionCall{Name: name, Arguments: string(data)}}
}

type FakeTool struct {
	ToolName string
	Fn       func(ctx context.Context, args json.RawMessage) (string, error)
}

func (f FakeTool) Name() string        { return f.ToolName }
func (f FakeTool) Description() string { return "fake " + f.ToolName }
func (f FakeTool) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{}}`)
}
func (f FakeTool) Call(ctx context.Context, args json.RawMessage) (string, error) {
	return f.Fn(ctx, args)
}
