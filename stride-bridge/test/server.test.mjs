import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { after, before, describe, it } from "node:test";
import { createApp } from "../server.mjs";

let stravaServer;
let bridgeServer;
let stravaOrigin;
let bridgeOrigin;
let registration;
let oauthTokens;
let stravaRequests = [];

function listen(server) {
  return new Promise(resolve => server.listen(0, "127.0.0.1", () => resolve(`http://127.0.0.1:${server.address().port}`)));
}

function close(server) {
  return new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
}

function send(response, body, status = 200) {
  response.writeHead(status, { "content-type": "application/json" });
  response.end(JSON.stringify(body));
}

async function jsonRequest(path, options = {}) {
  const response = await fetch(`${bridgeOrigin}${path}`, options);
  return { response, body: await response.json() };
}

function form(values) {
  return { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(values) };
}

function mcp(method, params = {}, token = oauthTokens.access_token) {
  return jsonRequest("/mcp", {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
}

before(async () => {
  stravaServer = createServer(async (request, response) => {
    const url = new URL(request.url, "http://mock.local");
    stravaRequests.push({ path: url.pathname, search: Object.fromEntries(url.searchParams), authorization: request.headers.authorization });
    if (url.pathname === "/oauth/token") {
      let text = "";
      for await (const chunk of request) text += chunk;
      const body = Object.fromEntries(new URLSearchParams(text));
      if (body.client_id !== "strava-client" || body.client_secret !== "strava-secret") return send(response, { message: "bad client" }, 401);
      if (body.grant_type === "authorization_code") {
        return send(response, { athlete: { id: 98765 }, access_token: "strava-access", refresh_token: "strava-refresh", expires_at: Math.floor(Date.now() / 1000) + 3600 });
      }
      if (body.grant_type === "refresh_token") {
        return send(response, { access_token: "strava-renewed", refresh_token: "strava-renewed-refresh", expires_at: Math.floor(Date.now() / 1000) + 3600 });
      }
    }
    if (!request.headers.authorization?.startsWith("Bearer strava-")) return send(response, { message: "not authorized" }, 401);
    if (url.pathname === "/api/v3/athlete/activities") return send(response, [{ id: 111, name: "Two-mile PR", distance: 3218.69, moving_time: 890 }]);
    if (url.pathname === "/api/v3/activities/111/streams") return send(response, { time: { data: [0, 60] }, heartrate: { data: [130, 150] } });
    if (url.pathname === "/api/v3/athlete") return send(response, { id: 98765, firstname: "Andrew" });
    if (url.pathname === "/api/v3/athletes/98765/stats") return send(response, { ytd_run_totals: { count: 42, distance: 100000 } });
    if (url.pathname === "/api/v3/gear/g123") return send(response, { id: "g123", distance: 321000 });
    if (url.pathname === "/api/v3/activities/111") return send(response, { id: 111, name: "Two-mile PR" });
    if (url.pathname === "/api/v3/activities/111/laps") return send(response, [{ id: 1, moving_time: 445 }]);
    if (url.pathname === "/api/v3/activities/111/zones") return send(response, [{ type: "heartrate" }]);
    if (url.pathname === "/api/v3/athlete/zones") return send(response, { heart_rate: { zones: [] } });
    if (url.pathname === "/api/v3/athletes/98765/routes") return send(response, [{ id: 4, name: "Logan Canyon" }]);
    return send(response, { message: "not found" }, 404);
  });
  stravaOrigin = await listen(stravaServer);
  bridgeServer = createServer();
  bridgeOrigin = await listen(bridgeServer);
  const app = createApp({
    PUBLIC_URL: bridgeOrigin,
    STRAVA_CLIENT_ID: "strava-client",
    STRAVA_CLIENT_SECRET: "strava-secret",
    STRAVA_AUTHORIZE_URL: `${stravaOrigin}/oauth/authorize`,
    STRAVA_TOKEN_URL: `${stravaOrigin}/oauth/token`,
    STRAVA_API_BASE_URL: `${stravaOrigin}/api/v3`,
  });
  bridgeServer.on("request", app.handler);
});

after(async () => {
  await close(bridgeServer);
  await close(stravaServer);
});

describe("OAuth discovery and registration", () => {
  it("advertises the required PKCE S256 support and dynamic registration", async () => {
    const { response, body } = await jsonRequest("/.well-known/oauth-authorization-server");
    assert.equal(response.status, 200);
    assert.deepEqual(body.code_challenge_methods_supported, ["S256"]);
    assert.equal(body.registration_endpoint, `${bridgeOrigin}/register`);
    assert.deepEqual(body.token_endpoint_auth_methods_supported, ["none"]);
  });

  it("advertises the protected MCP resource", async () => {
    const { response, body } = await jsonRequest("/.well-known/oauth-protected-resource/mcp");
    assert.equal(response.status, 200);
    assert.equal(body.resource, `${bridgeOrigin}/mcp`);
    assert.deepEqual(body.authorization_servers, [bridgeOrigin]);
  });

  it("rejects insecure non-loopback OAuth redirect URIs", async () => {
    const { response } = await jsonRequest("/register", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ redirect_uris: ["http://evil.example/callback"] }),
    });
    assert.equal(response.status, 400);
  });

  it("registers an OAuth client dynamically", async () => {
    const { response, body } = await jsonRequest("/register", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ client_name: "ChatGPT test", redirect_uris: ["https://chatgpt.com/connector/callback"] }),
    });
    assert.equal(response.status, 201);
    assert.ok(body.client_id);
    registration = body;
  });
});

describe("Authorization-code and PKCE flow", () => {
  let authorizationCode;
  const verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
  const challenge = createHash("sha256").update(verifier).digest("base64url");

  it("rejects authorization without PKCE S256", async () => {
    const parameters = new URLSearchParams({
      client_id: registration.client_id, redirect_uri: registration.redirect_uris[0], response_type: "code",
      code_challenge: challenge, code_challenge_method: "plain",
    });
    const { response, body } = await jsonRequest(`/authorize?${parameters}`);
    assert.equal(response.status, 400);
    assert.match(body.error_description, /PKCE/);
  });

  it("rejects unregistered redirect URIs", async () => {
    const parameters = new URLSearchParams({
      client_id: registration.client_id, redirect_uri: "https://attacker.example/callback", response_type: "code",
      code_challenge: challenge, code_challenge_method: "S256",
    });
    const { response } = await jsonRequest(`/authorize?${parameters}`);
    assert.equal(response.status, 400);
  });

  it("redirects through Strava, exchanges the Strava code, and preserves ChatGPT state", async () => {
    const parameters = new URLSearchParams({
      client_id: registration.client_id, redirect_uri: registration.redirect_uris[0], response_type: "code",
      code_challenge: challenge, code_challenge_method: "S256", state: "chatgpt-state", resource: `${bridgeOrigin}/mcp`,
    });
    const initial = await fetch(`${bridgeOrigin}/authorize?${parameters}`, { redirect: "manual" });
    assert.equal(initial.status, 302);
    const stravaRedirect = new URL(initial.headers.get("location"));
    assert.equal(stravaRedirect.origin, stravaOrigin);
    assert.equal(stravaRedirect.searchParams.get("client_id"), "strava-client");
    assert.ok(!stravaRedirect.searchParams.has("client_secret"));
    assert.equal(stravaRedirect.searchParams.get("redirect_uri"), `${bridgeOrigin}/strava/callback`);
    const callback = await fetch(`${bridgeOrigin}/strava/callback?code=strava-code&state=${stravaRedirect.searchParams.get("state")}`, { redirect: "manual" });
    assert.equal(callback.status, 302);
    const chatgptRedirect = new URL(callback.headers.get("location"));
    assert.equal(chatgptRedirect.origin, "https://chatgpt.com");
    assert.equal(chatgptRedirect.searchParams.get("state"), "chatgpt-state");
    authorizationCode = chatgptRedirect.searchParams.get("code");
    assert.ok(authorizationCode);
  });

  it("issues connector-specific tokens after verifying the PKCE verifier", async () => {
    const { response, body } = await jsonRequest("/token", form({
      grant_type: "authorization_code", client_id: registration.client_id,
      redirect_uri: registration.redirect_uris[0], code: authorizationCode,
      code_verifier: verifier, resource: `${bridgeOrigin}/mcp`,
    }));
    assert.equal(response.status, 200);
    assert.ok(body.access_token);
    assert.ok(body.refresh_token);
    assert.equal(body.token_type, "Bearer");
    assert.notEqual(body.access_token, "strava-access");
    oauthTokens = body;
  });

  it("rejects reusing an authorization code", async () => {
    const { response, body } = await jsonRequest("/token", form({
      grant_type: "authorization_code", client_id: registration.client_id,
      redirect_uri: registration.redirect_uris[0], code: authorizationCode, code_verifier: verifier,
    }));
    assert.equal(response.status, 400);
    assert.equal(body.error, "invalid_grant");
  });
});

describe("Authenticated MCP tools", () => {
  it("rejects unauthenticated requests with OAuth discovery metadata", async () => {
    const { response } = await jsonRequest("/mcp", {
      method: "POST", headers: { "content-type": "application/json" }, body: "{}",
    });
    assert.equal(response.status, 401);
    assert.match(response.headers.get("www-authenticate"), /oauth-protected-resource\/mcp/);
  });

  it("initializes the MCP protocol", async () => {
    const { response, body } = await mcp("initialize", { protocolVersion: "2025-06-18" });
    assert.equal(response.status, 200);
    assert.equal(body.result.protocolVersion, "2025-06-18");
    assert.equal(body.result.serverInfo.name, "stride-bridge");
  });

  it("exposes ten tools and marks every one read-only", async () => {
    const { body } = await mcp("tools/list");
    assert.equal(body.result.tools.length, 10);
    for (const tool of body.result.tools) {
      assert.equal(tool.annotations.readOnlyHint, true);
      assert.equal(tool.annotations.destructiveHint, false);
      assert.equal(tool.securitySchemes[0].type, "oauth2");
    }
  });

  it("lists and filters activities", async () => {
    const { body } = await mcp("tools/call", { name: "list_activities", arguments: { after: "2026-08-01", per_page: 10 } });
    assert.equal(body.result.structuredContent.count, 1);
    assert.equal(body.result.structuredContent.items[0].name, "Two-mile PR");
    const outgoing = stravaRequests.at(-1);
    assert.equal(outgoing.path, "/api/v3/athlete/activities");
    assert.equal(outgoing.search.per_page, "10");
    assert.ok(Number(outgoing.search.after) > 0);
  });

  it("fetches requested activity streams", async () => {
    const { body } = await mcp("tools/call", { name: "get_activity_streams", arguments: { activity_id: "111", keys: ["time", "heartrate"] } });
    assert.deepEqual(body.result.structuredContent.heartrate.data, [130, 150]);
    const outgoing = stravaRequests.at(-1);
    assert.equal(outgoing.search.keys, "time,heartrate");
    assert.equal(outgoing.search.key_by_type, "true");
  });

  it("fetches every remaining supported read-only resource", async () => {
    const calls = [
      ["get_activity", { activity_id: "111" }],
      ["get_activity_laps", { activity_id: "111" }],
      ["get_activity_zones", { activity_id: "111" }],
      ["get_athlete_profile", {}],
      ["get_athlete_zones", {}],
      ["get_athlete_stats", {}],
      ["get_gear", { gear_id: "g123" }],
      ["list_athlete_routes", {}],
    ];
    for (const [name, args] of calls) {
      const { body } = await mcp("tools/call", { name, arguments: args });
      assert.notEqual(body.result.isError, true, `Expected ${name} to succeed.`);
    }
  });

  it("rejects path-manipulation activity identifiers", async () => {
    const { body } = await mcp("tools/call", { name: "get_activity", arguments: { activity_id: "../athlete" } });
    assert.equal(body.result.isError, true);
    assert.match(body.result.content[0].text, /numeric identifier/);
  });

  it("rejects unsupported stream names", async () => {
    const { body } = await mcp("tools/call", { name: "get_activity_streams", arguments: { activity_id: "111", keys: ["passwords"] } });
    assert.equal(body.result.isError, true);
  });

  it("rotates connector refresh tokens", async () => {
    const oldRefreshToken = oauthTokens.refresh_token;
    const { response, body } = await jsonRequest("/token", form({
      grant_type: "refresh_token", client_id: registration.client_id, refresh_token: oldRefreshToken,
    }));
    assert.equal(response.status, 200);
    assert.notEqual(body.refresh_token, oldRefreshToken);
    const replay = await jsonRequest("/token", form({
      grant_type: "refresh_token", client_id: registration.client_id, refresh_token: oldRefreshToken,
    }));
    assert.equal(replay.response.status, 400);
  });
});
