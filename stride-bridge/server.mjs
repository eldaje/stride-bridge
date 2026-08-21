import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { createServer } from "node:http";
import { fileURLToPath } from "node:url";

const STREAM_TYPES = new Set([
  "time", "distance", "latlng", "altitude", "velocity_smooth", "heartrate",
  "cadence", "watts", "temp", "moving", "grade_smooth",
]);

const schemas = {
  none: { type: "object", properties: {}, additionalProperties: false },
  activity: {
    type: "object",
    properties: { activity_id: { type: "string", description: "Numeric Strava activity identifier." } },
    required: ["activity_id"], additionalProperties: false,
  },
};

const TOOLS = [
  {
    name: "list_activities", title: "List activities",
    description: "List your runs, rides, walks, workouts, and other activities. Supports date filtering and pagination.",
    inputSchema: {
      type: "object", properties: {
        after: { type: "string", description: "Earliest date, ISO 8601, for example 2026-08-01." },
        before: { type: "string", description: "Latest date, ISO 8601, for example 2026-09-01." },
        page: { type: "integer", minimum: 1, default: 1 },
        per_page: { type: "integer", minimum: 1, maximum: 100, default: 30 },
      }, additionalProperties: false,
    },
  },
  {
    name: "get_activity", title: "Get activity details",
    description: "Get one activity's distance, pace, elevation, heart rate, splits, laps, achievements, and segment efforts.",
    inputSchema: schemas.activity,
  },
  {
    name: "get_activity_streams", title: "Get activity streams",
    description: "Get time-series GPS coordinates, distance, elevation, pace, heart rate, cadence, power, or temperature for one activity.",
    inputSchema: {
      type: "object", properties: {
        activity_id: { type: "string", description: "Numeric Strava activity identifier." },
        keys: {
          type: "array", items: { type: "string", enum: [...STREAM_TYPES] },
          description: "Requested stream types. Defaults to time, distance, altitude, velocity_smooth, and heartrate.",
        },
      }, required: ["activity_id"], additionalProperties: false,
    },
  },
  {
    name: "get_activity_laps", title: "Get activity laps",
    description: "Get per-lap split distance, moving time, elapsed time, elevation, speed, and heart-rate data.",
    inputSchema: schemas.activity,
  },
  {
    name: "get_activity_zones", title: "Get activity training zones",
    description: "Get the time spent in heart-rate and power zones for one activity when Strava makes them available.",
    inputSchema: schemas.activity,
  },
  {
    name: "get_athlete_profile", title: "Get athlete profile",
    description: "Get your Strava athlete profile and the identifiers of your bikes and shoes.",
    inputSchema: schemas.none,
  },
  {
    name: "get_athlete_zones", title: "Get athlete training zones",
    description: "Get your configured heart-rate and power training zones when supported by your Strava account.",
    inputSchema: schemas.none,
  },
  {
    name: "get_athlete_stats", title: "Get athlete statistics",
    description: "Get year-to-date, recent, and all-time running, riding, and swimming totals.",
    inputSchema: schemas.none,
  },
  {
    name: "get_gear", title: "Get gear details",
    description: "Get a bike or shoe's accumulated distance and equipment details.",
    inputSchema: {
      type: "object", properties: {
        gear_id: { type: "string", description: "A Strava gear identifier, such as b123456 or g123456." },
      }, required: ["gear_id"], additionalProperties: false,
    },
  },
  {
    name: "list_athlete_routes", title: "List athlete routes",
    description: "List saved running and cycling routes, including distance, elevation, and map information.",
    inputSchema: {
      type: "object", properties: {
        page: { type: "integer", minimum: 1, default: 1 },
        per_page: { type: "integer", minimum: 1, maximum: 100, default: 30 },
      }, additionalProperties: false,
    },
  },
].map(tool => ({
  ...tool,
  annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  securitySchemes: [{ type: "oauth2", scopes: ["strava:read"] }],
  _meta: { securitySchemes: [{ type: "oauth2", scopes: ["strava:read"] }] },
}));

function opaqueToken() {
  return randomBytes(32).toString("base64url");
}

function challengeFor(verifier) {
  return createHash("sha256").update(verifier).digest("base64url");
}

function secureEquals(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && timingSafeEqual(a, b);
}

function parseDate(value, name) {
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) throw new RequestError(400, `Invalid ${name} date.`);
  return Math.floor(timestamp / 1000);
}

function positiveId(value, label = "activity_id") {
  if (!/^\d+$/.test(String(value))) throw new RequestError(400, `${label} must be a numeric identifier.`);
  return String(value);
}

function gearId(value) {
  if (!/^[bg]\d+$/.test(String(value))) throw new RequestError(400, "gear_id must look like b123456 or g123456.");
  return String(value);
}

function pageNumber(value, defaultValue, maximum = 100) {
  if (value === undefined) return defaultValue;
  if (!Number.isInteger(value) || value < 1 || value > maximum) {
    throw new RequestError(400, `Pagination values must be integers between 1 and ${maximum}.`);
  }
  return value;
}

class RequestError extends Error {
  constructor(status, message, oauthCode = "invalid_request") {
    super(message);
    this.status = status;
    this.oauthCode = oauthCode;
  }
}

function sendJson(response, status, body, headers = {}) {
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    ...headers,
  });
  response.end(JSON.stringify(body));
}

function redirect(response, location) {
  response.writeHead(302, { location: location.toString(), "cache-control": "no-store" });
  response.end();
}

async function readBody(request, maximumBytes = 1024 * 1024) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > maximumBytes) throw new RequestError(413, "Request body exceeds the allowed size.");
    chunks.push(chunk);
  }
  const text = Buffer.concat(chunks).toString("utf8");
  const contentType = request.headers["content-type"] || "";
  if (contentType.includes("application/x-www-form-urlencoded")) return Object.fromEntries(new URLSearchParams(text));
  if (!text) return {};
  try { return JSON.parse(text); }
  catch { throw new RequestError(400, "Request body is not valid JSON."); }
}

function normalizeConfig(overrides = {}) {
  const env = { ...process.env, ...overrides };
  const publicUrl = String(env.PUBLIC_URL || `http://127.0.0.1:${env.PORT || 3000}`).replace(/\/$/, "");
  let parsed;
  try { parsed = new URL(publicUrl); }
  catch { throw new Error("PUBLIC_URL must be a valid absolute URL."); }
  if (!/^https?:$/.test(parsed.protocol)) throw new Error("PUBLIC_URL must use http or https.");
  if (parsed.pathname !== "/" || parsed.search || parsed.hash) throw new Error("PUBLIC_URL must be an origin without a path, query, or fragment.");
  return {
    publicUrl,
    port: Number(env.PORT || 3000),
    stravaClientId: env.STRAVA_CLIENT_ID || "",
    stravaClientSecret: env.STRAVA_CLIENT_SECRET || "",
    stravaScopes: env.STRAVA_SCOPES || "read,activity:read_all,profile:read_all",
    stravaAuthorizeUrl: env.STRAVA_AUTHORIZE_URL || "https://www.strava.com/oauth/authorize",
    stravaTokenUrl: env.STRAVA_TOKEN_URL || "https://www.strava.com/oauth/token",
    stravaApiBaseUrl: (env.STRAVA_API_BASE_URL || "https://www.strava.com/api/v3").replace(/\/$/, ""),
    tokenTtlSeconds: 60 * 60,
    codeTtlMs: 10 * 60 * 1000,
  };
}

export function createApp(overrides = {}) {
  const config = normalizeConfig(overrides);
  const clients = new Map();
  const pendingAuthorizations = new Map();
  const authorizationCodes = new Map();
  const accessTokens = new Map();
  const refreshTokens = new Map();

  function oauthMetadata() {
    return {
      issuer: config.publicUrl,
      authorization_endpoint: `${config.publicUrl}/authorize`,
      token_endpoint: `${config.publicUrl}/token`,
      registration_endpoint: `${config.publicUrl}/register`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      token_endpoint_auth_methods_supported: ["none"],
      code_challenge_methods_supported: ["S256"],
      scopes_supported: ["strava:read"],
      resource_parameter_supported: true,
    };
  }

  function resourceMetadata() {
    return {
      resource: `${config.publicUrl}/mcp`,
      authorization_servers: [config.publicUrl],
      scopes_supported: ["strava:read"],
      bearer_methods_supported: ["header"],
      resource_documentation: `${config.publicUrl}/`,
    };
  }

  function authChallenge(response, message = "Authorization is required.") {
    sendJson(response, 401, { error: "invalid_token", error_description: message }, {
      "www-authenticate": `Bearer resource_metadata="${config.publicUrl}/.well-known/oauth-protected-resource/mcp", scope="strava:read"`,
    });
  }

  function cleanupExpired() {
    const now = Date.now();
    for (const [key, item] of pendingAuthorizations) if (item.expiresAt < now) pendingAuthorizations.delete(key);
    for (const [key, item] of authorizationCodes) if (item.expiresAt < now) authorizationCodes.delete(key);
    for (const [key, item] of accessTokens) if (item.expiresAt < now) accessTokens.delete(key);
  }

  function validateRedirectUri(value) {
    let parsed;
    try { parsed = new URL(value); }
    catch { throw new RequestError(400, "redirect_uri must be a valid absolute URL."); }
    const isLoopback = ["localhost", "127.0.0.1", "[::1]"].includes(parsed.hostname);
    if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && isLoopback)) {
      throw new RequestError(400, "redirect_uri must use HTTPS, except for local loopback development.");
    }
    if (parsed.hash) throw new RequestError(400, "redirect_uri must not contain a fragment.");
    return parsed.toString();
  }

  function register(body) {
    if (!Array.isArray(body.redirect_uris) || body.redirect_uris.length === 0) {
      throw new RequestError(400, "redirect_uris must contain at least one HTTPS redirect URI.");
    }
    if (body.redirect_uris.length > 20) throw new RequestError(400, "Too many redirect URIs.");
    const redirectUris = body.redirect_uris.map(validateRedirectUri);
    const clientId = opaqueToken();
    const client = {
      client_id: clientId,
      client_name: String(body.client_name || "ChatGPT") .slice(0, 100),
      redirect_uris: redirectUris,
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
    };
    clients.set(clientId, client);
    return client;
  }

  function issueTokens(session, clientId) {
    const accessToken = opaqueToken();
    const refreshToken = opaqueToken();
    accessTokens.set(accessToken, {
      session, clientId, expiresAt: Date.now() + config.tokenTtlSeconds * 1000,
    });
    refreshTokens.set(refreshToken, { session, clientId });
    return {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: config.tokenTtlSeconds,
      refresh_token: refreshToken,
      scope: "strava:read",
    };
  }

  async function exchangeStravaCode(code) {
    const body = new URLSearchParams({
      client_id: config.stravaClientId,
      client_secret: config.stravaClientSecret,
      code,
      grant_type: "authorization_code",
    });
    const result = await fetch(config.stravaTokenUrl, {
      method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body,
    });
    const payload = await result.json().catch(() => ({}));
    if (!result.ok) throw new RequestError(502, `Strava rejected authorization: ${payload.message || result.status}.`);
    if (!payload.access_token || !payload.refresh_token || !payload.athlete?.id) {
      throw new RequestError(502, "Strava returned an incomplete authorization response.");
    }
    return {
      athleteId: String(payload.athlete.id),
      accessToken: payload.access_token,
      refreshToken: payload.refresh_token,
      expiresAt: Number(payload.expires_at || Math.floor(Date.now() / 1000) + 6 * 60 * 60) * 1000,
    };
  }

  async function refreshStravaToken(session) {
    if (session.expiresAt > Date.now() + 60_000) return session.accessToken;
    const body = new URLSearchParams({
      client_id: config.stravaClientId,
      client_secret: config.stravaClientSecret,
      refresh_token: session.refreshToken,
      grant_type: "refresh_token",
    });
    const result = await fetch(config.stravaTokenUrl, {
      method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body,
    });
    const payload = await result.json().catch(() => ({}));
    if (!result.ok || !payload.access_token) {
      throw new RequestError(502, `Could not refresh Strava access: ${payload.message || result.status}.`);
    }
    session.accessToken = payload.access_token;
    session.refreshToken = payload.refresh_token || session.refreshToken;
    session.expiresAt = Number(payload.expires_at || Math.floor(Date.now() / 1000) + 6 * 60 * 60) * 1000;
    return session.accessToken;
  }

  async function stravaGet(session, path, parameters = {}) {
    const token = await refreshStravaToken(session);
    const url = new URL(`${config.stravaApiBaseUrl}${path}`);
    for (const [key, value] of Object.entries(parameters)) if (value !== undefined) url.searchParams.set(key, String(value));
    const response = await fetch(url, { headers: { authorization: `Bearer ${token}`, accept: "application/json" } });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const detail = payload.message || payload.errors?.[0]?.code || "Request failed";
      throw new RequestError(response.status === 429 ? 429 : 502, `Strava API error (${response.status}): ${detail}.`);
    }
    return payload;
  }

  async function callTool(session, name, input = {}) {
    if (input === null || typeof input !== "object" || Array.isArray(input)) {
      throw new RequestError(400, "Tool arguments must be an object.");
    }
    switch (name) {
      case "list_activities": {
        const parameters = {
          page: pageNumber(input.page, 1, 10000),
          per_page: pageNumber(input.per_page, 30),
        };
        if (input.after) parameters.after = parseDate(input.after, "after");
        if (input.before) parameters.before = parseDate(input.before, "before");
        return stravaGet(session, "/athlete/activities", parameters);
      }
      case "get_activity":
        return stravaGet(session, `/activities/${positiveId(input.activity_id)}`, { include_all_efforts: true });
      case "get_activity_streams": {
        const keys = input.keys || ["time", "distance", "altitude", "velocity_smooth", "heartrate"];
        if (!Array.isArray(keys) || keys.length === 0 || keys.some(key => !STREAM_TYPES.has(key))) {
          throw new RequestError(400, "keys must contain valid Strava stream names.");
        }
        return stravaGet(session, `/activities/${positiveId(input.activity_id)}/streams`, {
          keys: keys.join(","), key_by_type: true,
        });
      }
      case "get_activity_laps":
        return stravaGet(session, `/activities/${positiveId(input.activity_id)}/laps`);
      case "get_activity_zones":
        return stravaGet(session, `/activities/${positiveId(input.activity_id)}/zones`);
      case "get_athlete_profile":
        return stravaGet(session, "/athlete");
      case "get_athlete_zones":
        return stravaGet(session, "/athlete/zones");
      case "get_athlete_stats":
        return stravaGet(session, `/athletes/${positiveId(session.athleteId, "athlete_id")}/stats`);
      case "get_gear":
        return stravaGet(session, `/gear/${gearId(input.gear_id)}`);
      case "list_athlete_routes":
        return stravaGet(session, `/athletes/${positiveId(session.athleteId, "athlete_id")}/routes`, {
          page: pageNumber(input.page, 1, 10000), per_page: pageNumber(input.per_page, 30),
        });
      default:
        throw new RequestError(404, `Unknown tool: ${name}.`);
    }
  }

  async function handleMcp(request, response) {
    const authorization = request.headers.authorization || "";
    if (!authorization.startsWith("Bearer ")) return authChallenge(response);
    const token = accessTokens.get(authorization.slice(7));
    if (!token || token.expiresAt <= Date.now()) return authChallenge(response, "The access token is invalid or expired.");
    if (request.method === "GET") {
      response.writeHead(405, { allow: "POST", "cache-control": "no-store" });
      return response.end();
    }
    if (request.method !== "POST") throw new RequestError(405, "MCP accepts POST requests.");
    const message = await readBody(request);
    if (message.jsonrpc !== "2.0" || typeof message.method !== "string") {
      return sendJson(response, 400, { jsonrpc: "2.0", id: message.id ?? null, error: { code: -32600, message: "Invalid JSON-RPC request." } });
    }
    if (message.id === undefined) {
      response.writeHead(202, { "cache-control": "no-store" });
      return response.end();
    }
    let result;
    if (message.method === "initialize") {
      result = {
        protocolVersion: ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"].includes(message.params?.protocolVersion)
          ? message.params.protocolVersion : "2025-06-18",
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: "stride-bridge", version: "1.0.0" },
        instructions: "Read-only access to the authenticated athlete's Strava activities, GPS and biometric streams, training zones, stats, routes, and gear. Use actual activity dates when comparing workouts; distances are meters and durations are seconds.",
      };
    } else if (message.method === "ping") {
      result = {};
    } else if (message.method === "tools/list") {
      result = { tools: TOOLS };
    } else if (message.method === "tools/call") {
      try {
        const data = await callTool(token.session, message.params?.name, message.params?.arguments || {});
        result = {
          content: [{ type: "text", text: JSON.stringify(data) }],
          structuredContent: Array.isArray(data) ? { items: data, count: data.length } : data,
        };
      } catch (error) {
        result = { isError: true, content: [{ type: "text", text: error.message || "The Strava request failed." }] };
      }
    } else {
      return sendJson(response, 200, { jsonrpc: "2.0", id: message.id, error: { code: -32601, message: `Method not found: ${message.method}.` } });
    }
    return sendJson(response, 200, { jsonrpc: "2.0", id: message.id, result });
  }

  async function handler(request, response) {
    cleanupExpired();
    const url = new URL(request.url, config.publicUrl);
    try {
      if (url.pathname === "/healthz") return sendJson(response, 200, { ok: true });
      if (url.pathname === "/") {
        return sendJson(response, 200, {
          service: "Stride Bridge", read_only: true,
          mcp_endpoint: `${config.publicUrl}/mcp`,
          authentication: "OAuth 2.1 with required PKCE S256",
          setup: "Register your personal Strava developer app and configure this service's environment variables.",
        });
      }
      if (["/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"].includes(url.pathname)) {
        return sendJson(response, 200, oauthMetadata());
      }
      if (["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"].includes(url.pathname)) {
        return sendJson(response, 200, resourceMetadata());
      }
      if (url.pathname === "/register" && request.method === "POST") {
        return sendJson(response, 201, register(await readBody(request)));
      }
      if (url.pathname === "/authorize" && request.method === "GET") {
        if (!config.stravaClientId || !config.stravaClientSecret) {
          throw new RequestError(503, "The server owner must configure STRAVA_CLIENT_ID and STRAVA_CLIENT_SECRET.");
        }
        const clientId = url.searchParams.get("client_id");
        const client = clients.get(clientId);
        if (!client) throw new RequestError(400, "Unknown OAuth client.", "invalid_client");
        const redirectUri = validateRedirectUri(url.searchParams.get("redirect_uri"));
        if (!client.redirect_uris.includes(redirectUri)) throw new RequestError(400, "redirect_uri was not registered for this client.");
        if (url.searchParams.get("response_type") !== "code") throw new RequestError(400, "Only the authorization-code flow is supported.");
        if (url.searchParams.get("code_challenge_method") !== "S256") throw new RequestError(400, "PKCE with code_challenge_method=S256 is required.");
        const codeChallenge = url.searchParams.get("code_challenge");
        if (!codeChallenge || !/^[A-Za-z0-9_-]{43}$/.test(codeChallenge)) throw new RequestError(400, "A valid PKCE S256 code challenge is required.");
        const resource = url.searchParams.get("resource");
        if (resource && resource !== `${config.publicUrl}/mcp`) throw new RequestError(400, "The requested OAuth resource is not this MCP server.");
        const pendingState = opaqueToken();
        pendingAuthorizations.set(pendingState, {
          clientId, redirectUri, state: url.searchParams.get("state") || "", codeChallenge,
          resource: resource || `${config.publicUrl}/mcp`, expiresAt: Date.now() + config.codeTtlMs,
        });
        const destination = new URL(config.stravaAuthorizeUrl);
        destination.searchParams.set("client_id", config.stravaClientId);
        destination.searchParams.set("response_type", "code");
        destination.searchParams.set("redirect_uri", `${config.publicUrl}/strava/callback`);
        destination.searchParams.set("approval_prompt", "auto");
        destination.searchParams.set("scope", config.stravaScopes);
        destination.searchParams.set("state", pendingState);
        return redirect(response, destination);
      }
      if (url.pathname === "/strava/callback" && request.method === "GET") {
        const state = url.searchParams.get("state");
        const pending = pendingAuthorizations.get(state);
        pendingAuthorizations.delete(state);
        if (!pending || pending.expiresAt < Date.now()) throw new RequestError(400, "The Strava authorization state is invalid or expired.");
        const returnUrl = new URL(pending.redirectUri);
        if (url.searchParams.get("error")) {
          returnUrl.searchParams.set("error", "access_denied");
          if (pending.state) returnUrl.searchParams.set("state", pending.state);
          return redirect(response, returnUrl);
        }
        const stravaCode = url.searchParams.get("code");
        if (!stravaCode) throw new RequestError(400, "Strava did not return an authorization code.");
        const session = await exchangeStravaCode(stravaCode);
        const authorizationCode = opaqueToken();
        authorizationCodes.set(authorizationCode, { ...pending, session, expiresAt: Date.now() + config.codeTtlMs });
        returnUrl.searchParams.set("code", authorizationCode);
        if (pending.state) returnUrl.searchParams.set("state", pending.state);
        return redirect(response, returnUrl);
      }
      if (url.pathname === "/token" && request.method === "POST") {
        const body = await readBody(request);
        const client = clients.get(body.client_id);
        if (!client) throw new RequestError(400, "Unknown OAuth client.", "invalid_client");
        if (body.resource && body.resource !== `${config.publicUrl}/mcp`) {
          throw new RequestError(400, "The requested OAuth resource is not this MCP server.", "invalid_target");
        }
        if (body.grant_type === "authorization_code") {
          const grant = authorizationCodes.get(body.code);
          authorizationCodes.delete(body.code);
          if (!grant || grant.expiresAt < Date.now() || grant.clientId !== client.client_id) {
            throw new RequestError(400, "The authorization code is invalid, expired, or already used.", "invalid_grant");
          }
          if (validateRedirectUri(body.redirect_uri) !== grant.redirectUri) {
            throw new RequestError(400, "redirect_uri does not match the authorization request.", "invalid_grant");
          }
          if (!body.code_verifier || !secureEquals(challengeFor(body.code_verifier), grant.codeChallenge)) {
            throw new RequestError(400, "PKCE code_verifier does not match the authorization request.", "invalid_grant");
          }
          return sendJson(response, 200, issueTokens(grant.session, client.client_id));
        }
        if (body.grant_type === "refresh_token") {
          const grant = refreshTokens.get(body.refresh_token);
          if (!grant || grant.clientId !== client.client_id) throw new RequestError(400, "The refresh token is invalid.", "invalid_grant");
          refreshTokens.delete(body.refresh_token);
          return sendJson(response, 200, issueTokens(grant.session, client.client_id));
        }
        throw new RequestError(400, "Unsupported OAuth grant type.", "unsupported_grant_type");
      }
      if (url.pathname === "/mcp") return await handleMcp(request, response);
      return sendJson(response, 404, { error: "not_found", error_description: "No route matches this request." });
    } catch (error) {
      const status = error instanceof RequestError ? error.status : 500;
      if (!(error instanceof RequestError)) console.error("Unhandled request error:", error.message);
      return sendJson(response, status, {
        error: error instanceof RequestError ? error.oauthCode : "server_error",
        error_description: error instanceof RequestError ? error.message : "An unexpected server error occurred.",
      });
    }
  }

  return { handler, config, tools: TOOLS };
}

export function startServer(overrides = {}) {
  const app = createApp(overrides);
  const server = createServer(app.handler);
  server.listen(app.config.port, "0.0.0.0", () => {
    console.log(`Stride Bridge listening on port ${app.config.port}`);
    console.log(`Public MCP endpoint: ${app.config.publicUrl}/mcp`);
    if (!app.config.stravaClientId || !app.config.stravaClientSecret) {
      console.warn("Strava credentials are not configured; OAuth linking will be unavailable.");
    }
  });
  return server;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) startServer();
