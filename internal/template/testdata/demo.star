load("demo_lib.star", "services_summary")

def key_id():
    for line in file.read("~/.demo/credentials").splitlines():
        k, _, v = line.partition("=")
        if k.strip() == "key_id":
            return v.strip()
    fail("key_id absent")

def rpc(op, body):
    path = "/rpc/" + op
    sig = crypto.sign(env("DEMO_KEY"), "POST\n" + path)
    headers = {"x-demo-auth": key_id() + "." + base64.encode(sig.signature, url = True), "x-demo-method": sig.method}
    r = http.request("rpc", "POST", path, json = body, headers = headers)
    if r.status != 200:
        fail("%s: HTTP %d %s" % (op, r.status, http.snippet(r.body)))
    return json.decode(r.body)

def describe(name):
    return rpc("describeNode", {"name": name})["node"]

def discover(ctx):
    targets = [dict(t) for t in ctx.targets]
    warnings = []
    names = [n["name"] for n in rpc("listNodes", {})["nodes"]]
    for name, res in zip(names, parallel(describe, names, limit = 2)):
        if res.error:
            targets.append({"name": name, "kind": "node", "error": res.error})
            continue
        n = res.value
        targets.append({
            "name": name,
            "kind": "node",
            "status": n["state"],
            "summary": services_summary(n["services"]),
            "hosts": [{"name": h["fqdn"], "ip": h["ip"], "roles": n["services"]} for h in n["hosts"]],
            "data": {"services": n["services"]},
        })
    status = http.request("api", "GET", "/api/status", jq = "[.services[].name]")
    if status.status != 200:
        warnings.append("statut indisponible")
    lines = ["Services déclarés : " + ", ".join(status.data[0])] if status.data else []
    return {"targets": targets, "lines": lines, "warnings": warnings}

def status_desc():
    return "État d'un nœud de %s (%s)" % (instance.name, ", ".join([t["name"] for t in instance.inventory()["targets"]]))

def node_status(args):
    t = instance.target(args["target"])
    if t["kind"] != "node":
        fail("cible %s : pas un nœud" % t["name"])
    r = http.request("api", "GET", "/api/nodes/" + t["name"], query = {"view": args.get("view", "summary")})
    if r.status != 200:
        fail("HTTP %d" % r.status)
    calls = instance.memo("calls/" + t["name"], lambda: 1)
    return sprintf("%s %.2f %d", json.decode(r.body)["health"], 0.5, calls)

def raw(args):
    r = http.request(args.get("conn", "api"), args.get("method", "GET"), args["path"])
    return "%d" % r.status

def node_logs(args):
    t, h = instance.find_host(args["host"])
    files = ssh.recent(h["name"], ["/var/log/demo"], minutes = 60, limit = 2).files
    out = []
    for f in files:
        res = ssh.tail(h["name"], f["path"], lines = 10, filter = args.get("filter", ""))
        out.append("### %s (%d)\n%s" % (f["path"], f["size"], ssh.format(res)))
    return redact("\n".join(out))

def loop(args):
    while True:
        pass

tool(name = "node_status", description = status_desc, schema = {"type": "object", "properties": {"target": {"type": "string"}, "view": {"type": "string"}}, "required": ["target"]}, fn = node_status)
tool(name = "raw", description = "requête brute (tests des garde-fous)", schema = {"type": "object", "properties": {"path": {"type": "string"}}}, fn = raw)
tool(name = "node_logs", description = "logs récents d'un hôte", schema = {"type": "object", "properties": {"host": {"type": "string"}}}, fn = node_logs)
tool(name = "loop", description = "boucle infinie (test d'annulation)", schema = {"type": "object"}, fn = loop)
