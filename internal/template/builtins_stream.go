package template

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"go.starlark.net/starlark"

	"github.com/agardenat/clotr/internal/access"
	"github.com/agardenat/clotr/internal/i18n"
)

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

const (
	wsContinuation = 0x0
	wsText         = 0x1
	wsBinary       = 0x2
	wsClose        = 0x8
	wsPing         = 0x9
	wsPong         = 0xA
)

func (in *Instance) builtinHTTPStream(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var conn, p, label, timeoutS string
	var argvV *starlark.List
	var baseV, queryV, protocolsV, headersV, maxV, tlsV, proxyV starlark.Value
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "conn", &conn, "path", &p, "argv?", &argvV, "label?", &label, "query?", &queryV, "protocols?", &protocolsV, "headers?", &headersV, "base?", &baseV, "max_bytes?", &maxV, "timeout?", &timeoutS, "tls?", &tlsV, "proxy?", &proxyV); err != nil {
		return nil, err
	}
	reqTLS, err := requestTLS(tlsV)
	if err != nil {
		return nil, err
	}
	proxyOverride, err := optString("proxy", proxyV)
	if err != nil {
		return nil, err
	}
	base, err := optString("base", baseV)
	if err != nil {
		return nil, err
	}
	query, err := optDict("query", queryV)
	if err != nil {
		return nil, err
	}
	headers, err := optDict("headers", headersV)
	if err != nil {
		return nil, err
	}
	maxBytes, err := optInt("max_bytes", maxV)
	if err != nil {
		return nil, err
	}
	var protocols []string
	if protocolsV != nil && protocolsV != starlark.None {
		l, ok := protocolsV.(*starlark.List)
		if !ok {
			return nil, i18n.E("tpl.arg.list", "protocols", protocolsV.Type())
		}
		for i := 0; i < l.Len(); i++ {
			protocols = append(protocols, plain(l.Index(i)))
		}
	}
	var argv []string
	if argvV != nil {
		for i := 0; i < argvV.Len(); i++ {
			s, ok := starlark.AsString(argvV.Index(i))
			if !ok {
				return nil, i18n.E("tpl.arg.text", "argv", argvV.Index(i).Type())
			}
			argv = append(argv, s)
		}
	}
	if thread.Local(localLoading) != nil {
		return nil, i18n.E("tpl.http.at_load")
	}
	if err := denyOffline(threadCtx(thread)); err != nil {
		return nil, err
	}
	hc, ok := in.https[conn]
	if !ok {
		return nil, i18n.E("tpl.http.connector", conn, strings.Join(sortedKeys(in.https), ", "))
	}
	lvl := hc.levels[access.Exec]
	if lvl == nil {
		return nil, i18n.E("tpl.http.no_exec", conn)
	}
	clean, err := cleanRequestPath(hc, p)
	if err != nil {
		return nil, err
	}
	if !matchAny(lvl.allow, clean) {
		return nil, i18n.E("tpl.http.exec_allow", clean, conn)
	}
	if !in.access.Allows(access.Exec) {
		return nil, i18n.E("tpl.access.required", "exec "+clean, access.Exec)
	}
	switch {
	case lvl.argvParam != "" && len(argv) == 0:
		return nil, i18n.E("tpl.http.argv_required", conn)
	case lvl.argvParam == "" && len(argv) > 0:
		return nil, i18n.E("tpl.http.argv_param", conn)
	}
	ctx := threadCtx(thread)
	where := defaultStr(label, clean)
	if len(argv) > 0 {
		if err := access.CheckArgv(argv); err != nil {
			return nil, err
		}
		if in.underTracked(conn, clean) {
			in.audit("exec_decision", map[string]any{"where": where, "argv": argv, "decision": "own"})
		} else if err := in.authorizeCommand(ctx, where, argv); err != nil {
			return nil, err
		}
	}
	timeout := hc.timeout
	if timeoutS != "" {
		if timeout, err = time.ParseDuration(timeoutS); err != nil || timeout <= 0 {
			return nil, i18n.E("tpl.http.stream_timeout", timeoutS)
		}
	}
	c := &httpCall{hc: hc, method: http.MethodGet, base: base, clean: clean, tls: reqTLS, proxy: proxyOverride, headers: dictHeaders(headers), tool: threadTool(thread)}
	if c.query, err = queryValues(query); err != nil {
		return nil, err
	}
	for _, a := range argv {
		c.query.Add(lvl.argvParam, a)
	}
	limit := hc.maxBytes
	if maxBytes > 0 {
		limit = min(maxBytes, hardMaxBytes)
	}
	res, err := in.stream(ctx, c, protocols, timeout, limit, where, argv)
	if err != nil {
		return nil, err
	}
	msgs := make([]any, len(res.messages))
	for i, m := range res.messages {
		msgs[i] = m
	}
	return makeStruct(map[string]any{"status": res.status, "protocol": res.protocol, "messages": msgs, "truncated": res.truncated, "close_code": res.closeCode, "close_reason": res.closeReason, "body": res.body})
}

type wsResult struct {
	status      int
	protocol    string
	messages    [][]byte
	truncated   bool
	closeCode   int
	closeReason string
	body        string
}

func (in *Instance) stream(ctx context.Context, c *httpCall, protocols []string, timeout time.Duration, limit int, where string, argv []string) (*wsResult, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, u, err := in.newRequest(ctx, c)
	if err != nil {
		return nil, err
	}
	key := make([]byte, 16)
	_, _ = rand.Read(key)
	k := base64.StdEncoding.EncodeToString(key)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", k)
	req.Header.Del("Accept")
	if len(protocols) > 0 {
		req.Header.Set("Sec-WebSocket-Protocol", strings.Join(protocols, ", "))
	}
	client, err := in.httpClientFor(c.hc, c.tls, c.proxy)
	if err != nil {
		return nil, err
	}
	start := time.Now()
	audit := map[string]any{"tool": c.tool, "connector": c.hc.name, "url": u.Scheme + "://" + u.Host + u.Path, "where": where}
	if len(argv) > 0 {
		audit["argv"] = argv
	}
	resp, err := (&http.Client{Transport: client.Transport}).Do(req)
	if err != nil {
		audit["error"] = err.Error()
		in.audit("http_stream", audit)
		return nil, fmt.Errorf("stream %s: %w", u.Path, err)
	}
	defer resp.Body.Close()
	res := &wsResult{status: resp.StatusCode, protocol: resp.Header.Get("Sec-WebSocket-Protocol")}
	rw, ok := resp.Body.(io.ReadWriteCloser)
	if resp.StatusCode != http.StatusSwitchingProtocols || !ok {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, maxRead))
		res.body = string(data)
		audit["status"], audit["duration_ms"] = resp.StatusCode, time.Since(start).Milliseconds()
		in.audit("http_stream", audit)
		if resp.StatusCode == http.StatusSwitchingProtocols {
			return nil, i18n.E("tpl.http.stream_body", u.Path)
		}
		return res, nil
	}
	if resp.Header.Get("Sec-WebSocket-Accept") != wsAccept(k) {
		audit["error"] = "Sec-WebSocket-Accept"
		in.audit("http_stream", audit)
		return nil, i18n.E("tpl.http.stream_accept", u.Path)
	}
	stop := context.AfterFunc(ctx, func() { rw.Close() })
	defer stop()
	err = readWS(rw, limit, res)
	audit["status"], audit["bytes"], audit["messages"], audit["duration_ms"] = res.status, wsSize(res.messages), len(res.messages), time.Since(start).Milliseconds()
	if err != nil && ctx.Err() != nil {
		err = i18n.E("tpl.http.stream_timeout_hit", u.Path, timeout)
	}
	if err != nil {
		audit["error"] = err.Error()
		in.audit("http_stream", audit)
		return nil, err
	}
	in.audit("http_stream", audit)
	return res, nil
}

func wsSize(msgs [][]byte) int {
	n := 0
	for _, m := range msgs {
		n += len(m)
	}
	return n
}

func wsAccept(key string) string {
	h := sha1.Sum([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(h[:])
}

func readWS(rw io.ReadWriter, limit int, res *wsResult) error {
	r := bufio.NewReader(rw)
	var cur []byte
	inMsg := false
	total := 0
	for {
		fin, op, payload, err := readFrame(r, limit)
		if err != nil {
			if errors.Is(err, io.EOF) || (errors.Is(err, io.ErrUnexpectedEOF) && len(res.messages) > 0) {
				if inMsg {
					res.messages = append(res.messages, cur)
				}
				return nil
			}
			return err
		}
		switch op {
		case wsPing:
			if err := writeFrame(rw, wsPong, payload); err != nil {
				return err
			}
			continue
		case wsPong:
			continue
		case wsClose:
			if len(payload) >= 2 {
				res.closeCode = int(binary.BigEndian.Uint16(payload[:2]))
				res.closeReason = string(payload[2:])
			}
			_ = writeFrame(rw, wsClose, payload[:min(len(payload), 2)])
			if inMsg {
				res.messages = append(res.messages, cur)
			}
			return nil
		case wsText, wsBinary:
			cur, inMsg = nil, true
		case wsContinuation:
			if !inMsg {
				return i18n.E("tpl.http.stream_frame")
			}
		default:
			return i18n.E("tpl.http.stream_frame")
		}
		total += len(payload)
		if total > limit {
			res.truncated = true
			cur = append(cur, payload[:len(payload)-(total-limit)]...)
			res.messages = append(res.messages, cur)
			_ = writeFrame(rw, wsClose, []byte{0x03, 0xE8})
			return nil
		}
		cur = append(cur, payload...)
		if fin {
			res.messages = append(res.messages, cur)
			cur, inMsg = nil, false
		}
	}
}

func readFrame(r *bufio.Reader, limit int) (bool, byte, []byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return false, 0, nil, err
	}
	fin, op := h[0]&0x80 != 0, h[0]&0x0F
	masked := h[1]&0x80 != 0
	n := uint64(h[1] & 0x7F)
	switch n {
	case 126:
		var b [2]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return false, 0, nil, err
		}
		n = uint64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return false, 0, nil, err
		}
		n = binary.BigEndian.Uint64(b[:])
	}
	if n > uint64(limit)+(1<<16) {
		return false, 0, nil, i18n.E("tpl.http.stream_big", n)
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(r, mask[:]); err != nil {
			return false, 0, nil, err
		}
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return false, 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return fin, op, payload, nil
}

func writeFrame(w io.Writer, op byte, payload []byte) error {
	return encodeFrame(w, op, payload, true)
}

func encodeFrame(w io.Writer, op byte, payload []byte, masked bool) error {
	head := []byte{0x80 | op}
	mbit := byte(0)
	if masked {
		mbit = 0x80
	}
	switch n := len(payload); {
	case n < 126:
		head = append(head, mbit|byte(n))
	case n < 1<<16:
		head = append(head, mbit|126, byte(n>>8), byte(n))
	default:
		head = append(head, mbit|127)
		head = binary.BigEndian.AppendUint64(head, uint64(n))
	}
	body := payload
	if masked {
		var mask [4]byte
		_, _ = rand.Read(mask[:])
		head = append(head, mask[:]...)
		body = make([]byte, len(payload))
		for i := range payload {
			body[i] = payload[i] ^ mask[i%4]
		}
	}
	_, err := w.Write(append(head, body...))
	return err
}
