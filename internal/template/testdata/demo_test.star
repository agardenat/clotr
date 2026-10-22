SEED = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="

def rpc_mock(req):
    if not req.headers.get("x-demo-auth", "").startswith("k1."):
        return {"status": 403, "body": "<html><title>refusé</title></html>"}
    body = json.decode(req.body)
    if req.path == "/rpc/listNodes":
        return {"json": {"nodes": [{"name": "n1"}, {"name": "n2"}]}}
    if body["name"] == "n2":
        return {"status": 500, "body": "boom"}
    return {"json": {"node": {"state": "RUNNING", "services": ["web", "db"], "hosts": [{"fqdn": "n1-node0.example.test", "ip": "10.0.0.1"}]}}}

ROUTES = {
    "POST /rpc/listNodes": rpc_mock,
    "POST /rpc/describeNode": rpc_mock,
    "GET /api/status": {"json": {"services": [{"name": "web"}, {"name": "db"}]}},
    "GET /api/nodes/n1": {"json": {"health": "GOOD"}},
    "GET /api/nodes/n1/run": {"messages": ["\x01ok\n", "\x02warn"]},
    "POST /api/jobs": {"status": 201, "json": {}},
    "DELETE /api/jobs/j1": {"json": {}},
    "DELETE /api/jobs/j2": {"json": {}},
}

def ssh_mock(host, cmd):
    if "grep -c" in cmd:
        if "absent" in cmd:
            return {"exit": 1}
        return "/var/log/demo/app.log:1234\n" if " -r " in cmd else "1234\n"
    if "find" in cmd:
        return "1760000000.5 1234 /var/log/demo/app.log\n"
    if "tail" in cmd:
        return "ligne password=hunter2\n"
    return {"exit": 2, "stderr": "inconnu"}

def new(**kw):
    args = dict(params = {"api_url": "https://api.example.test"}, http = ROUTES, ssh = ssh_mock, env = {"DEMO_KEY": SEED}, files = {"~/.demo/credentials": "key_id = k1\n"}, now = "2026-01-02T03:04:05Z")
    args.update(kw)
    return template.instance(**args)

def test_discover():
    inst = new()
    inv = inst.discover()
    names = [t["name"] for t in inv["targets"]]
    assert.eq(names, ["main", "n1", "n2"])
    n1 = inv["targets"][1]
    assert.eq(n1["status"], "RUNNING")
    assert.eq(n1["hosts"][0]["ip"], "10.0.0.1")
    assert.contains(inv["targets"][2]["error"], "HTTP 500")
    assert.eq(inv["lines"], ["Services déclarés : web, db"])
    reqs = inst.requests()
    assert.eq(reqs[0]["headers"]["x-demo-method"], "ed25519")
    assert.eq(reqs[0]["headers"]["content-type"], "application/json")

def test_environment():
    inst = new()
    inst.discover()
    env = "\n".join(inst.environment())
    assert.contains(env, "- Instance test (template demo")
    assert.contains(env, "test_node_status")
    assert.contains(env, "  - node n1 [RUNNING] : 2 services")
    assert.contains(env, "  - node n2 : INJOIGNABLE pour ce run")
    assert.contains(env, "Consigne de démonstration.")

def test_tools():
    inst = new()
    inst.discover()
    assert.eq(inst.call("node_status", {"target": "n1"}), "GOOD 0.50 1")
    assert.contains(inst.tools()["node_status"]["description"], "n1, n2")
    assert.contains(inst.error("node_status", {"target": "main"}), "pas un nœud")
    assert.contains(inst.error("node_status", {"target": "zz"}), "cible \"zz\" inconnue")
    req = [r for r in inst.requests() if r["path"] == "/api/nodes/n1"][0]
    assert.eq(req["query"]["view"], "summary")
    assert.true(req["headers"]["authorization"].startswith("Basic "))

def test_guards():
    inst = new()
    inst.discover()
    assert.contains(inst.error("raw", {"path": "/other"}), "outside the allow list")
    assert.contains(inst.error("raw", {"path": "/api/secrets"}), "sensitive keyword")
    assert.contains(inst.error("raw", {"path": "/api/../x"}), "invalid path")
    assert.contains(inst.error("raw", {"path": "/rpc/deleteNode", "conn": "rpc", "method": "POST"}), "outside the allow list")
    assert.contains(inst.error("raw", {"path": "/api/x", "method": "DELETE"}), "method DELETE refused")
    assert.eq(inst.call("raw", {"path": "/api/missing"}), "404")

def test_ssh():
    inst = new()
    inst.discover()
    out = inst.call("node_logs", {"host": "node0"})
    assert.contains(out, "### /var/log/demo/app.log (1234)")
    assert.contains(out, "password=[REDACTED]")
    assert.not_contains(out, "hunter2")
    assert.contains(inst.error("ssh_tail", {"host": "node0", "path": "/etc/shadow"}), "")
    assert.true(inst.error("ssh_tail", {"host": "node0", "path": "/etc/shadow"}) != "")
    assert.contains(inst.error("ssh_tail", {"host": "zz", "path": "/var/log/x"}), "absent de l'inventaire")
    assert.eq(inst.call("ssh_grep", {"host": "node0", "path": "/var/log/demo/app.log", "pattern": "ERROR", "count": True}).strip(), "1234")
    assert.eq(inst.call("ssh_grep", {"host": "node0", "path": "/var/log/demo/app.log", "pattern": "absent", "count": True}), "0")
    assert.contains(inst.call("ssh_grep", {"host": "node0", "path": "/var/log/demo", "pattern": "ERROR", "count": True, "recursive": True}), "app.log:1234")
    cmds = [c["command"] for c in inst.commands()]
    assert.true(all([c.startswith("sudo -n ") for c in cmds]))
    assert.true(any(["| grep -v ':0$' |" in c for c in cmds]))

def test_missing_credentials_file():
    inst = new(files = {})
    assert.fails(lambda: inst.discover(), "file.read")

def test_access():
    inst = new()
    inst.discover()
    assert.true("node_run" not in inst.tools())
    assert.true("job" not in inst.tools())
    inst = new(access = "exec")
    inst.discover()
    assert.true("job" not in inst.tools())
    assert.eq(inst.call("node_run", {"node": "n1", "argv": ["status", "--short"]}), "1 ok\n\n2 warn")
    req = [r for r in inst.requests() if r["path"] == "/api/nodes/n1/run"][0]
    assert.eq(req["query"]["cmd"], "status,--short")
    assert.eq(req["headers"]["sec-websocket-protocol"], "demo.v1")
    assert.contains(inst.error("node_run", {"node": "n1", "argv": ["reboot"]}), "reboot")
    assert.eq(len(inst.questions()), 1)
    inst = new(access = "exec", confirm = "always")
    inst.discover()
    assert.eq(inst.call("node_run", {"node": "n1", "argv": ["uptime"]}), "1 ok\n\n2 warn")
    inst.call("node_run", {"node": "n1", "argv": ["uptime"]})
    assert.eq(len(inst.questions()), 1)
    inst = new(access = "create")
    inst.discover()
    assert.eq(inst.call("job", {"name": "j1", "remove": True}), "201")
    assert.eq(inst.call("job", {"name": "j2"}), "201")
    assert.eq(inst.tracked(), ["api /api/jobs/j2"])
    assert.eq(inst.cleanup(), [{"resource": "test api /api/jobs/j2", "error": ""}])
    assert.eq(inst.tracked(), [])
    assert.contains(inst.error("raw", {"path": "/api/jobs/j9", "method": "DELETE"}), "created by clotr")
