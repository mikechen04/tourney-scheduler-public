const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

function loadEnvFromFile() {
    const envPath = path.join(__dirname, ".env");
    if (!fs.existsSync(envPath)) {
        return;
    }

    const raw = fs.readFileSync(envPath, "utf8");
    const lines = raw.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        if (!line || line.startsWith("#")) {
            continue;
        }

        const eq = line.indexOf("=");
        if (eq === -1) {
            continue;
        }

        const key = line.slice(0, eq).trim();
        let value = line.slice(eq + 1).trim();
        if (
            (value.startsWith("\"") && value.endsWith("\"")) ||
            (value.startsWith("'") && value.endsWith("'"))
        ) {
            value = value.slice(1, -1);
        }

        // always prefer .env values so stale shell vars do not break oauth
        process.env[key] = value;
    }
}

loadEnvFromFile();

const PORT = Number(process.env.PORT || 8000);
const HOST = "0.0.0.0";

const ROOT = __dirname;
const BASE_URL = process.env.BASE_URL || ("http://localhost:" + PORT);
const OSU_CLIENT_ID = process.env.OSU_CLIENT_ID || "";
const OSU_CLIENT_SECRET = process.env.OSU_CLIENT_SECRET || "";
const OSU_REDIRECT_URI = process.env.OSU_REDIRECT_URI || (BASE_URL + "/auth/osu/callback");
const ALLOW_DEBUG_ROUTES = process.env.ALLOW_DEBUG_ROUTES === "true";

const stateStore = new Map();
const loginTicketStore = new Map();

function contentTypeFor(filePath) {
    const ext = path.extname(filePath).toLowerCase();
    if (ext === ".html") return "text/html; charset=utf-8";
    if (ext === ".js") return "text/javascript; charset=utf-8";
    if (ext === ".css") return "text/css; charset=utf-8";
    if (ext === ".json") return "application/json; charset=utf-8";
    if (ext === ".png") return "image/png";
    if (ext === ".jpg" || ext === ".jpeg") return "image/jpeg";
    if (ext === ".svg") return "image/svg+xml";
    if (ext === ".ico") return "image/x-icon";
    return "application/octet-stream";
}

function send(res, statusCode, body, type) {
    res.writeHead(statusCode, { "Content-Type": type || "text/plain; charset=utf-8" });
    res.end(body);
}

function redirect(res, location) {
    res.writeHead(302, { Location: location });
    res.end();
}

function safeFilePathFromUrl(urlObj) {
    let filePath = urlObj.pathname;
    if (filePath === "/") {
        filePath = "/index.html";
    }

    const localPath = path.resolve(ROOT, filePath.replace(/^\/+/, ""));
    const rootWithSep = ROOT.endsWith(path.sep) ? ROOT : ROOT + path.sep;
    if (localPath !== ROOT && !localPath.startsWith(rootWithSep)) {
        return null;
    }
    return localPath;
}

function parseQuery(reqUrl) {
    return new URL(reqUrl, BASE_URL);
}

function maskSecret(secret) {
    if (!secret) {
        return "";
    }
    if (secret.length <= 8) {
        return "****";
    }
    return secret.slice(0, 4) + "..." + secret.slice(-4);
}

function makeState() {
    return crypto.randomBytes(16).toString("hex");
}

function cleanupOldStates() {
    const now = Date.now();
    for (const [key, value] of stateStore.entries()) {
        if (now - value.createdAt > 10 * 60 * 1000) {
            stateStore.delete(key);
        }
    }
}

function cleanupOldLoginTickets() {
    const now = Date.now();
    for (const [key, value] of loginTicketStore.entries()) {
        if (now - value.createdAt > 2 * 60 * 1000) {
            loginTicketStore.delete(key);
        }
    }
}

async function exchangeCodeForToken(code) {
    const body = new URLSearchParams({
        client_id: OSU_CLIENT_ID,
        client_secret: OSU_CLIENT_SECRET,
        code: code,
        grant_type: "authorization_code",
        redirect_uri: OSU_REDIRECT_URI
    });

    const resp = await fetch("https://osu.ppy.sh/oauth/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: body.toString()
    });

    if (!resp.ok) {
        const text = await resp.text();
        throw new Error("token exchange failed: " + text);
    }

    return resp.json();
}

async function fetchOsuMe(accessToken) {
    const resp = await fetch("https://osu.ppy.sh/api/v2/me", {
        headers: {
            Authorization: "Bearer " + accessToken
        }
    });

    if (!resp.ok) {
        const text = await resp.text();
        throw new Error("failed getting osu user: " + text);
    }

    return resp.json();
}

async function checkClientCredentialsFlow() {
    const body = new URLSearchParams({
        client_id: OSU_CLIENT_ID,
        client_secret: OSU_CLIENT_SECRET,
        grant_type: "client_credentials",
        scope: "public"
    });

    const resp = await fetch("https://osu.ppy.sh/oauth/token", {
        method: "POST",
        headers: {
            Accept: "application/json",
            "Content-Type": "application/x-www-form-urlencoded"
        },
        body: body.toString()
    });

    const text = await resp.text();
    let parsed;
    try {
        parsed = JSON.parse(text);
    } catch (err) {
        parsed = { raw: text };
    }

    return {
        ok: resp.ok,
        status: resp.status,
        data: parsed
    };
}

async function handleAuthStart(req, res, urlObj) {
    if (!OSU_CLIENT_ID || !OSU_CLIENT_SECRET) {
        redirect(res, "/scheduler.html?id=" + encodeURIComponent(urlObj.searchParams.get("schedulerId") || "") + "&osu_error=missing+server+oauth+env");
        return;
    }

    const schedulerId = urlObj.searchParams.get("schedulerId") || "";
    const team = urlObj.searchParams.get("team") === "B" ? "B" : "A";

    if (!schedulerId) {
        send(res, 400, "missing schedulerId", "text/plain; charset=utf-8");
        return;
    }

    const state = makeState();
    stateStore.set(state, {
        schedulerId: schedulerId,
        team: team,
        createdAt: Date.now()
    });
    cleanupOldStates();

    const authorizeUrl = new URL("https://osu.ppy.sh/oauth/authorize");
    authorizeUrl.searchParams.set("client_id", OSU_CLIENT_ID);
    authorizeUrl.searchParams.set("redirect_uri", OSU_REDIRECT_URI);
    authorizeUrl.searchParams.set("response_type", "code");
    authorizeUrl.searchParams.set("scope", "identify");
    authorizeUrl.searchParams.set("state", state);

    redirect(res, authorizeUrl.toString());
}

async function handleAuthCallback(req, res, urlObj) {
    const code = urlObj.searchParams.get("code");
    const state = urlObj.searchParams.get("state");
    const oauthError = urlObj.searchParams.get("error");
    const stateDataForError = state && stateStore.has(state) ? stateStore.get(state) : null;

    if (oauthError) {
        const target = "/scheduler.html?id=" + encodeURIComponent(stateDataForError ? stateDataForError.schedulerId : "")
            + "&osu_error=" + encodeURIComponent(oauthError);
        redirect(res, target);
        return;
    }

    if (!code || !state || !stateStore.has(state)) {
        redirect(res, "/scheduler.html?osu_error=invalid+oauth+callback");
        return;
    }

    const stateData = stateStore.get(state);
    stateStore.delete(state);

    try {
        const tokenData = await exchangeCodeForToken(code);
        const me = await fetchOsuMe(tokenData.access_token);
        const username = me.username || me.name || "";

        if (!username) {
            redirect(res, "/scheduler.html?id=" + encodeURIComponent(stateData.schedulerId) + "&osu_error=missing+username");
            return;
        }

        const loginTicket = makeState() + makeState();
        loginTicketStore.set(loginTicket, {
            schedulerId: stateData.schedulerId,
            team: stateData.team,
            username: username,
            createdAt: Date.now()
        });
        cleanupOldLoginTickets();

        const target = "/scheduler.html?id=" + encodeURIComponent(stateData.schedulerId)
            + "&auth_ticket=" + encodeURIComponent(loginTicket);

        redirect(res, target);
    } catch (err) {
        const msg = err && err.message ? err.message : "oauth failed";
        const target = "/scheduler.html?id=" + encodeURIComponent(stateData.schedulerId) + "&osu_error=" + encodeURIComponent(msg);
        redirect(res, target);
    }
}

function handleConsumeTicket(req, res, urlObj) {
    const ticket = urlObj.searchParams.get("ticket") || "";
    const schedulerId = urlObj.searchParams.get("schedulerId") || "";
    if (!ticket || !schedulerId) {
        send(res, 400, JSON.stringify({ error: "missing ticket data" }), "application/json; charset=utf-8");
        return;
    }

    cleanupOldLoginTickets();

    if (!loginTicketStore.has(ticket)) {
        send(res, 400, JSON.stringify({ error: "invalid ticket" }), "application/json; charset=utf-8");
        return;
    }

    const data = loginTicketStore.get(ticket);
    loginTicketStore.delete(ticket);

    if (data.schedulerId !== schedulerId) {
        send(res, 400, JSON.stringify({ error: "ticket scheduler mismatch" }), "application/json; charset=utf-8");
        return;
    }

    const body = {
        user: data.username,
        team: data.team
    };
    send(res, 200, JSON.stringify(body), "application/json; charset=utf-8");
}

async function requestHandler(req, res) {
    const urlObj = parseQuery(req.url || "/");

    if (ALLOW_DEBUG_ROUTES && req.method === "GET" && urlObj.pathname === "/auth/osu/debug") {
        const body = {
            baseUrl: BASE_URL,
            redirectUri: OSU_REDIRECT_URI,
            hasClientId: Boolean(OSU_CLIENT_ID),
            clientId: OSU_CLIENT_ID,
            hasClientSecret: Boolean(OSU_CLIENT_SECRET),
            maskedClientSecret: maskSecret(OSU_CLIENT_SECRET)
        };
        send(res, 200, JSON.stringify(body, null, 2), "application/json; charset=utf-8");
        return;
    }

    if (ALLOW_DEBUG_ROUTES && req.method === "GET" && urlObj.pathname === "/auth/osu/check-client") {
        const result = await checkClientCredentialsFlow();
        send(res, result.ok ? 200 : 500, JSON.stringify(result, null, 2), "application/json; charset=utf-8");
        return;
    }

    if (req.method === "GET" && urlObj.pathname === "/auth/osu/start") {
        await handleAuthStart(req, res, urlObj);
        return;
    }

    if (req.method === "GET" && urlObj.pathname === "/auth/osu/callback") {
        await handleAuthCallback(req, res, urlObj);
        return;
    }

    if (req.method === "GET" && urlObj.pathname === "/auth/osu/consume-ticket") {
        handleConsumeTicket(req, res, urlObj);
        return;
    }

    const localPath = safeFilePathFromUrl(urlObj);
    if (!localPath) {
        send(res, 403, "forbidden", "text/plain; charset=utf-8");
        return;
    }

    fs.readFile(localPath, (err, data) => {
        if (err) {
            send(res, 404, "not found", "text/plain; charset=utf-8");
            return;
        }
        send(res, 200, data, contentTypeFor(localPath));
    });
}

const server = http.createServer((req, res) => {
    requestHandler(req, res).catch((err) => {
        send(res, 500, "server error: " + (err.message || "unknown"), "text/plain; charset=utf-8");
    });
});

server.listen(PORT, HOST, () => {
    console.log("osu scheduler server running on " + BASE_URL);
});
