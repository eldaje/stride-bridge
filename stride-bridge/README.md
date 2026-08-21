# Stride Bridge: your personal Strava connector for ChatGPT

Stride Bridge lets ChatGPT securely read your Strava workouts. It fixes the
specific compatibility error from Strava's own MCP server: **OAuth authorization
server metadata must advertise PKCE support**.

This service advertises and enforces PKCE `S256`, handles Strava sign-in on the
server, automatically refreshes Strava tokens, and never grants permission to
create, edit, or delete activities.

## What ChatGPT can access

- Runs, rides, walks, yoga, Pilates, strength sessions, and other activities.
- Detailed activity performance, laps, splits, and segment efforts.
- GPS, pace, distance, elevation, heart rate, cadence, power, and temperature
  streams when your device recorded them.
- Activity-specific and athlete-level training zones.
- Recent, year-to-date, and lifetime athlete statistics.
- Your saved routes, bikes, shoes, and accumulated gear mileage.

Training plans available in Strava's first-party connector are not included:
Strava's documented public API does not expose an equivalent endpoint.

## The three things you need

1. A paid Strava account, which you already have.
2. Your own Strava developer application.
3. A public HTTPS host for this project. Render is one possible option; any
   Node.js host or Docker host also works.

## Step 1: Register your Strava application

Open **https://www.strava.com/settings/api** in a browser and create an API
application.

Suggested values:

- **Application name:** `Stride Bridge`
- **Category:** `Training`
- **Website:** your eventual hosting URL, such as
  `https://stride-bridge-example.onrender.com`
- **Authorization Callback Domain:** the hostname only, such as
  `stride-bridge-example.onrender.com`

You can initially enter a temporary website and callback domain, then update
them after your hosting provider assigns your final address. The callback domain
must match your final hosting hostname exactly.

Strava will show a **Client ID** and **Client Secret**. Enter these only in your
hosting provider's private environment-variable settings. Never paste the secret
into ChatGPT, commit it to GitHub, or share screenshots containing it.

## Step 2: Deploy the connector

### Option A: Render

1. Put this project in a **private GitHub repository**.
2. In Render, create a **Web Service** from that repository.
3. Choose the Node runtime.
4. Set the build command to `node --version`.
5. Set the start command to `node server.mjs`.
6. Add these environment variables:

   | Variable | Value |
   | --- | --- |
   | `PUBLIC_URL` | Your full public service URL, with no trailing slash. |
   | `STRAVA_CLIENT_ID` | Your Strava application's Client ID. |
   | `STRAVA_CLIENT_SECRET` | Your Strava application's Client Secret. |
   | `STRAVA_SCOPES` | `read,activity:read_all,profile:read_all` |

7. Deploy the service.
8. Update your Strava application's **Authorization Callback Domain** to the
   exact hostname from `PUBLIC_URL`.
9. Visit `https://YOUR-HOSTNAME/healthz`. You should see `{"ok":true}`.

The included `render.yaml` can also be used as a Render Blueprint. Free hosting
availability, sleep behavior, and pricing are controlled by Render and may
change. Sleeping or restarting the service clears in-memory login sessions, so
you may have to reconnect ChatGPT. An always-on single-instance host avoids
most interruptions.

### Option B: Docker

Build and run with your hosting provider's secret-management interface:

```bash
docker build -t stride-bridge .
docker run --rm -p 3000:3000 \
  -e PUBLIC_URL=https://your-public-host.example \
  -e STRAVA_CLIENT_ID=YOUR_CLIENT_ID \
  -e STRAVA_CLIENT_SECRET=YOUR_CLIENT_SECRET \
  stride-bridge
```

For real deployments, prefer your platform's secrets dashboard over putting
secrets directly into a command, where they may remain in shell history.

## Step 3: Connect it to ChatGPT

Use ChatGPT **on the web** for the initial setup:

1. Open https://chatgpt.com.
2. Go to **Settings → Security and login** and enable **Developer Mode**.
3. Open the plugin/connector creation screen.
4. Name the connector `Stride Bridge`.
5. Set the MCP server URL to `https://YOUR-HOSTNAME/mcp`.
6. Select **OAuth** authentication.
7. Select **Dynamic Client Registration (DCR)** if asked.
8. Click **Create**, then sign in to Strava and approve the read permissions.

The connector intentionally advertises:

```json
"code_challenge_methods_supported": ["S256"]
```

That is the precise setting missing from the Strava server in your screenshot.

## Example prompts

- “Use Stride Bridge to compare my last five runs and tell me whether my pace
  improved.”
- “Analyze my two-mile personal record against my previous two-mile efforts.”
- “Show my running mileage and elevation gain for each of the last eight weeks.”
- “Pull the GPS and elevation streams from my Beaver Mountain run.”
- “Which heart-rate zones did I spend the most time in during my last run?”
- “How many miles are on my current running shoes?”
- “Compare my run performance on days following Pilates or yoga.”

## Security and limitations

- The connector is **read-only** and never requests Strava write scopes.
- ChatGPT receives a connector-specific access token, not your Strava client
  secret or Strava access token.
- OAuth authorization codes are single-use, expire after ten minutes, and
  require PKCE `S256` verification.
- Client redirects must be registered and use HTTPS, except local loopback
  addresses during testing.
- OAuth refresh tokens rotate when ChatGPT refreshes its connector session.
- Sessions live in memory. Restarting the service clears connected sessions and
  requires reauthorization. Use one service instance; do not run multiple
  replicas without adding a shared encrypted session store.
- A newly created Strava developer app initially supports only its owner, which
  is ideal for a personal connector.
- Your private activities are included because `activity:read_all` is
  requested. Replace it with `activity:read` if you prefer to exclude them.
- Your Strava API client secret is a server-side environment variable and must
  never appear in a browser, source code, screenshots, or chat messages.
- Some zone, gear, route, and stream data depends on your device, Strava
  account, activity privacy, and permissions.
- Strava has announced a new API base URL for 2027. This project supports the
  optional `STRAVA_API_BASE_URL` environment variable for that migration.

## Local development and tests

Requires Node.js 20 or newer and has **no npm dependencies**:

```bash
npm test
npm start
```

The automated tests use a mock Strava server and verify OAuth discovery, dynamic
client registration, PKCE enforcement, redirect safety, Strava authorization,
token refresh, authenticated MCP initialization, all read-only tool metadata,
activity fetching, stream fetching, and invalid-token handling.

## Official documentation

- ChatGPT developer mode:
  https://developers.openai.com/api/docs/guides/developer-mode
- OpenAI plugin authentication:
  https://developers.openai.com/plugins/build/auth
- Strava API getting started:
  https://developers.strava.com/docs/getting-started/
- Strava authentication:
  https://developers.strava.com/docs/authentication/
- Strava API reference:
  https://developers.strava.com/docs/reference/
