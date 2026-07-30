import type { Hooks, PluginInput } from "@opencode-ai/plugin"
import { OAUTH_DUMMY_KEY } from "../../auth"
import { OauthCallbackPage } from "@opencode-ai/core/oauth/page"

// OAuth credentials matching the Antigravity CLI (agy) binary.
// Extracted via binary analysis of /home/ops/.local/bin/agy (Go ELF, google3 monorepo build).
// The old OSS Gemini CLI client (681255809395-...) returns IneligibleTierError from
// cloudcode-pa.googleapis.com and can no longer be used for free-tier Google accounts.
// These are intentionally public for installed-app OAuth flows per Google's guidance:
// https://developers.google.com/identity/protocols/oauth2#installed
// Credential storage: agy stores tokens at ~/.gemini/antigravity-cli/antigravity-oauth-token
// Format: {"token": {"access_token":"...","refresh_token":"...","expiry":"..."}, "auth_method": "consumer"}
interface GeminiCredentials {
  clientId: string
  clientSecret: string
}

export let cachedCredentials: GeminiCredentials | null = null

export function resetCachedCredentials(): void {
  cachedCredentials = null
}

export async function getCredentials(): Promise<GeminiCredentials> {
  if (cachedCredentials) {
    return cachedCredentials
  }

  // Try to dynamically extract from the agy binary on the host system
  try {
    const fs = await import("node:fs")
    const path = await import("node:path")
    const os = await import("node:os")
    const { execSync } = await import("node:child_process")
    const { Buffer } = await import("node:buffer")

    const findAgyPath = () => {
      const envPath = process.env.OPENCODE_AGY_BINARY_PATH
      if (envPath && fs.existsSync(envPath)) return envPath

      const commonPaths = [
        path.join(os.homedir(), ".local/bin/agy"),
        "/usr/local/bin/agy",
        "/usr/bin/agy",
      ]
      for (const p of commonPaths) {
        if (fs.existsSync(p)) return p
      }
      try {
        const pathFromWhich = execSync("which agy", { encoding: "utf8" }).trim()
        if (pathFromWhich && fs.existsSync(pathFromWhich)) {
          return pathFromWhich
        }
      } catch (e) {}
      return null
    }

    const agyPath = findAgyPath()
    if (agyPath) {
      const fd = fs.openSync(agyPath, "r")
      const buffer = Buffer.alloc(1024 * 1024) // 1MB chunk
      const clientIdRegex = /1071006060591-[a-zA-Z0-9_-]+\.apps\.googleusercontent\.com/
      const clientSecretRegex = /GOCSPX-[a-zA-Z0-9_-]{28}/

      let clientId = ""
      let clientSecret = ""
      let offset = 0

      while (true) {
        const bytesRead = fs.readSync(fd, buffer, 0, buffer.length, offset)
        if (bytesRead === 0) break

        const chunkStr = buffer.toString("ascii", 0, bytesRead)

        if (!clientId) {
          const match = chunkStr.match(clientIdRegex)
          if (match) clientId = match[0]
        }

        if (!clientSecret) {
          const match = chunkStr.match(clientSecretRegex)
          if (match) clientSecret = match[0]
        }

        if (clientId && clientSecret) break

        offset += bytesRead - 100
        if (offset < 0) offset = 0
      }

      fs.closeSync(fd)

      if (clientId && clientSecret) {
        cachedCredentials = { clientId, clientSecret }
        return cachedCredentials
      }
    }
  } catch (e) {
    // Ignore and fall back
  }

  cachedCredentials = {
    clientId: "",
    clientSecret: "",
  }
  return cachedCredentials
}
const ISSUER = "https://oauth2.googleapis.com"
const AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
const OAUTH_SCOPE = [
  "https://www.googleapis.com/auth/cloud-platform",
  "https://www.googleapis.com/auth/userinfo.email",
  "https://www.googleapis.com/auth/userinfo.profile",
].join(" ")

// ------- PKCE helpers -------

interface PkceCodes {
  verifier: string
  challenge: string
}

async function generatePKCE(): Promise<PkceCodes> {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
  const verifier = Array.from(crypto.getRandomValues(new Uint8Array(43)))
    .map((b) => chars[b % chars.length])
    .join("")
  const challenge = base64UrlEncode(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)))
  return { verifier, challenge }
}

function base64UrlEncode(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer)
  const binary = String.fromCharCode(...bytes)
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

// ------- Token types -------

interface TokenResponse {
  access_token: string
  refresh_token?: string
  expires_in?: number
  token_type?: string
}

// ------- Token exchange / refresh -------

async function exchangeCodeForTokens(code: string, redirectUri: string, pkce: PkceCodes): Promise<TokenResponse> {
  const creds = await getCredentials()
  const response = await fetch(`${ISSUER}/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      client_id: creds.clientId,
      client_secret: creds.clientSecret,
      code_verifier: pkce.verifier,
    }).toString(),
  })
  if (!response.ok) {
    const body = await response.text()
    throw new Error(`Token exchange failed (${response.status}): ${body}`)
  }
  return response.json()
}

async function refreshAccessToken(refreshToken: string): Promise<TokenResponse> {
  const creds = await getCredentials()
  const response = await fetch(`${ISSUER}/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: creds.clientId,
      client_secret: creds.clientSecret,
    }).toString(),
  })
  if (!response.ok) {
    const body = await response.text()
    throw new Error(`Token refresh failed (${response.status}): ${body}`)
  }
  return response.json()
}

// ------- Shared OAuth callback registry (used by server route) -------
// Instead of spinning up a separate HTTP server on localhost:1466, we expose
// a module-level pending map that the opencode server's own
// GET /auth/gemini-callback route resolves. This way the redirect_uri can
// point at the server's externally-reachable address (e.g. 192.168.2.251:18790),
// so a Macbook browser can complete OAuth for a server running on the RPC node.

interface PendingOAuth {
  pkce: PkceCodes
  state: string
  redirectUri: string
  resolve: (tokens: TokenResponse) => void
  reject: (error: Error) => void
}

// State keyed by OAuth `state` param so multiple concurrent providers work.
const pendingOAuthMap = new Map<string, PendingOAuth>()

// Pending quota summary fetches to prevent concurrent requests for the same token.
const pendingQuotaFetches = new Set<string>()

async function fetchUserQuotaSummary(accessToken: string): Promise<any> {
  const response = await fetch("https://cloudcode-pa.googleapis.com/v1internal:retrieveUserQuotaSummary", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "User-Agent": "AntigravityCLI/1.0.16/auto (linux; amd64; terminal)",
      "Authorization": `Bearer ${accessToken}`,
    },
    body: JSON.stringify({
      project: "default-cli-project",
    }),
  })
  if (!response.ok) {
    throw new Error(`Failed to fetch quota summary: ${response.status} ${await response.text()}`)
  }
  return response.json()
}

/**
 * Returns the base URL of the opencode server for OAuth redirect_uri.
 * Google OAuth 2.0 forbids private/internal LAN IP addresses (like 192.168.2.251)
 * as redirect URIs unless they are loopback/localhost.
 * To satisfy Google's validation, we always return a localhost address with the
 * server's running port (extracted from ANTIGRAVITY_OAUTH_BASE_URL or defaulting to 18790).
 */
export function getGeminiRedirectBase(): string {
  let port = "18790"
  if (process.env.ANTIGRAVITY_OAUTH_BASE_URL) {
    try {
      const url = new URL(process.env.ANTIGRAVITY_OAUTH_BASE_URL)
      if (url.port) port = url.port
    } catch (e) {}
  }
  return `http://localhost:${port}`
}

/**
 * Called by the server's /auth/gemini-callback GET route.
 * Returns an HTML response body string.
 */
export function handleGeminiOAuthCallback(searchParams: URLSearchParams): {
  status: number
  html: string
} {
  const code = searchParams.get("code")
  const state = searchParams.get("state") || ""
  const error = searchParams.get("error")
  const errorDescription = searchParams.get("error_description")

  if (error) {
    const msg = errorDescription || error
    const pending = state ? pendingOAuthMap.get(state) : undefined
    if (pending) {
      pendingOAuthMap.delete(state)
      pending.reject(new Error(msg))
    }
    return { status: 400, html: OauthCallbackPage.error(msg, { provider: "Google" }) }
  }

  if (!code) {
    return { status: 400, html: OauthCallbackPage.error("Missing authorization code", { provider: "Google" }) }
  }

  const pending = pendingOAuthMap.get(state)
  if (!pending) {
    return { status: 400, html: OauthCallbackPage.error("Invalid or expired state — try connecting again", { provider: "Google" }) }
  }

  pendingOAuthMap.delete(state)

  exchangeCodeForTokens(code, pending.redirectUri, pending.pkce)
    .then((tokens) => pending.resolve(tokens))
    .catch((err) => pending.reject(err))

  return { status: 200, html: OauthCallbackPage.success({ provider: "Google" }) }
}

function waitForOAuthCallback(pkce: PkceCodes, state: string, redirectUri: string): Promise<TokenResponse> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(
      () => {
        if (pendingOAuthMap.has(state)) {
          pendingOAuthMap.delete(state)
          reject(new Error("OAuth callback timeout — authorization took too long"))
        }
      },
      10 * 60 * 1000, // 10 minute timeout
    )

    pendingOAuthMap.set(state, {
      pkce,
      state,
      redirectUri,
      resolve: (tokens) => {
        clearTimeout(timeout)
        resolve(tokens)
      },
      reject: (error) => {
        clearTimeout(timeout)
        reject(error)
      },
    })
  })
}
export interface AgyTokenCredentials {
  access: string
  refresh: string
  expires: number
  email?: string
  name?: string
}

export async function tryLoadAgyToken(): Promise<AgyTokenCredentials | null> {
  try {
    const fs = await import("node:fs")
    const path = await import("node:path")
    const os = await import("node:os")
    
    const tokenPath = process.env.OPENCODE_AGY_TOKEN_PATH || path.join(os.homedir(), ".gemini/antigravity-cli/antigravity-oauth-token")
    if (!fs.existsSync(tokenPath)) {
      return null
    }

    const data = JSON.parse(fs.readFileSync(tokenPath, "utf8"))
    if (!data?.token?.access_token || !data?.token?.refresh_token) {
      return null
    }

    const expires = data.token.expiry ? new Date(data.token.expiry).getTime() : Date.now() + 3600 * 1000

    // Fetch user profile information if possible
    let email = ""
    let name = ""
    try {
      const res = await fetch("https://www.googleapis.com/oauth2/v3/userinfo", {
        headers: { "Authorization": `Bearer ${data.token.access_token}` }
      })
      if (res.ok) {
        const info = await res.json() as any
        email = info.email || ""
        name = info.name || ""
      }
    } catch (e) {
      // Ignore userinfo fetch error, we still have the token
    }

    return {
      access: data.token.access_token,
      refresh: data.token.refresh_token,
      expires,
      email,
      name,
    }
  } catch (e) {
    return null
  }
}

// ------- Plugin export -------

export async function GeminiAuthPlugin(input: PluginInput, options?: Record<string, unknown>): Promise<Hooks> {
  const providerName = (typeof options?.providerName === "string" ? options.providerName : undefined) ?? "gemini"

  // Start background interval to refresh usage data every 30 seconds
  setInterval(async () => {
    try {
      let auth = await (input as any).getAuth(providerName)
      if (!auth || auth.type !== "oauth") return

      let activeAccess = auth.access
      let expires = auth.expires

      // 1. Refresh token if expired
      if (auth.refresh && (!activeAccess || expires < Date.now())) {
        try {
          const tokens = await refreshAccessToken(auth.refresh)
          activeAccess = tokens.access_token
          expires = Date.now() + (tokens.expires_in ?? 3600) * 1000
          
          await input.client.auth.set({
            path: { id: providerName },
            body: {
              type: "oauth",
              refresh: tokens.refresh_token || auth.refresh,
              access: activeAccess,
              expires,
              email: (auth as any).email || "",
              name: (auth as any).name || "",
              usage: (auth as any).usage,
            } as any,
          })
        } catch (e) {
          console.error(`[Gemini Quota Background ${providerName}] Failed to refresh token:`, e)
          return
        }
      }

      // 2. Fetch quota summary if 30s has passed since lastFetched
      const lastFetched = (auth as any).usage?.lastFetched || 0
      const now = Date.now()
      if (activeAccess && now - lastFetched > 30000 && !pendingQuotaFetches.has(activeAccess)) {
        pendingQuotaFetches.add(activeAccess)
        try {
          const summary = await fetchUserQuotaSummary(activeAccess)
          const latestAuth = await (input as any).getAuth(providerName)
          if (latestAuth && latestAuth.type === "oauth" && latestAuth.access === activeAccess) {
            await input.client.auth.set({
              path: { id: providerName },
              body: {
                type: "oauth",
                refresh: latestAuth.refresh,
                access: latestAuth.access,
                expires: latestAuth.expires,
                email: (latestAuth as any).email || "",
                name: (latestAuth as any).name || "",
                usage: {
                  lastFetched: Date.now(),
                  groups: summary.groups || [],
                },
              } as any,
            })
          }
        } catch (err) {
          console.error(`[Gemini Quota Background ${providerName}] Failed to fetch user quota summary:`, err)
        } finally {
          pendingQuotaFetches.delete(activeAccess)
        }
      }
    } catch (e) {
      // Quietly ignore background errors
    }
  }, 30000)

  return {
    auth: {
      provider: providerName,

      // Called on every request to inject the Bearer token
      async loader(getAuth) {
        let auth = await getAuth()
        if (auth.type !== "oauth" && providerName === "gemini") {
          // Try to automatically load/bridge from agy CLI token
          const agyCreds = await tryLoadAgyToken()
          if (agyCreds) {
            await input.client.auth.set({
              path: { id: providerName },
              body: {
                type: "oauth",
                refresh: agyCreds.refresh,
                access: agyCreds.access,
                expires: agyCreds.expires,
                email: agyCreds.email || "",
                name: agyCreds.name || "",
              } as any,
            })
            auth = await getAuth()
          }
        }
        if (auth.type !== "oauth") return {}

        let email = (auth as any).email
        let name = (auth as any).name
        let activeAccess = auth.access

        if (auth.refresh && (!activeAccess || auth.expires < Date.now())) {
          try {
            const tokens = await refreshAccessToken(auth.refresh)
            activeAccess = tokens.access_token
            auth.access = tokens.access_token
            auth.expires = Date.now() + (tokens.expires_in ?? 3600) * 1000
            if (tokens.refresh_token) {
              auth.refresh = tokens.refresh_token
            }
            await input.client.auth.set({
              path: { id: providerName },
              body: {
                type: "oauth",
                refresh: auth.refresh,
                access: auth.access,
                expires: auth.expires,
                email: (auth as any).email || "",
                name: (auth as any).name || "",
                usage: (auth as any).usage || undefined,
              } as any,
            })
          } catch (e) {
            console.error("Failed to refresh token during loader init:", e)
          }
        }

        if (!email && activeAccess) {
          try {
            const res = await fetch("https://www.googleapis.com/oauth2/v3/userinfo", {
              headers: { "Authorization": `Bearer ${activeAccess}` }
            })
            if (res.ok) {
              const info = await res.json() as any
              email = info.email || ""
              name = info.name || ""
              if (email) {
                await input.client.auth.set({
                  path: { id: providerName },
                  body: {
                    type: "oauth",
                    refresh: auth.refresh,
                    access: auth.access,
                    expires: auth.expires,
                    email,
                    name,
                    usage: (auth as any).usage || undefined,
                  } as any,
                })
              }
            }
          } catch (e) {
            console.error("Failed to fetch userinfo in loader init:", e)
          }
        }

        if (activeAccess && auth.refresh) {
          const lastFetched = (auth as any).usage?.lastFetched || 0
          const now = Date.now()
          if (now - lastFetched > 15000 && !pendingQuotaFetches.has(activeAccess)) {
            pendingQuotaFetches.add(activeAccess)
            fetchUserQuotaSummary(activeAccess)
              .then(async (summary) => {
                const latestAuth = await getAuth()
                if (latestAuth.type === "oauth" && latestAuth.access === activeAccess) {
                  await input.client.auth.set({
                    path: { id: providerName },
                    body: {
                      type: "oauth",
                      refresh: latestAuth.refresh,
                      access: latestAuth.access,
                      expires: latestAuth.expires,
                      email: (latestAuth as any).email || "",
                      name: (latestAuth as any).name || "",
                      usage: {
                        lastFetched: Date.now(),
                        groups: summary.groups || [],
                      },
                    } as any,
                  })
                }
              })
              .catch((err) => {
                console.error(`[Gemini Quota ${providerName}] Failed to fetch user quota summary:`, err)
              })
              .finally(() => {
                pendingQuotaFetches.delete(activeAccess)
              })
          }
        }

    let refreshPromise: Promise<{ access: string }> | undefined

    return {
      apiKey: OAUTH_DUMMY_KEY,
      email,
      name,
      usage: (auth as any).usage,
          async fetch(requestInput: RequestInfo | URL, init?: RequestInit) {
            // Clean key query parameter from URL if present
            let finalInput = requestInput
            try {
              if (typeof finalInput === "string") {
                const urlObj = new URL(finalInput)
                if (urlObj.searchParams.has("key")) {
                  urlObj.searchParams.delete("key")
                  finalInput = urlObj.toString()
                }
              } else if (finalInput instanceof URL) {
                if (finalInput.searchParams.has("key")) {
                  const urlObj = new URL(finalInput.toString())
                  urlObj.searchParams.delete("key")
                  finalInput = urlObj
                }
              }
            } catch (e) {
              // Ignore invalid URLs
            }

            // Strip any outgoing Authorization/API Key headers from init.headers
            if (init?.headers) {
              if (init.headers instanceof Headers) {
                init.headers.delete("authorization")
                init.headers.delete("Authorization")
                init.headers.delete("x-goog-api-key")
                init.headers.delete("X-Goog-Api-Key")
              } else if (Array.isArray(init.headers)) {
                init.headers = init.headers.filter(
                  ([key]) => !["authorization", "x-goog-api-key"].includes(key.toLowerCase())
                )
              } else {
                delete (init.headers as Record<string, string>)["authorization"]
                delete (init.headers as Record<string, string>)["Authorization"]
                delete (init.headers as Record<string, string>)["x-goog-api-key"]
                delete (init.headers as Record<string, string>)["X-Goog-Api-Key"]
              }
            }

            const currentAuth = await getAuth()
            if (currentAuth.type !== "oauth") return fetch(finalInput, init)

            // Refresh if expired
            if (!currentAuth.access || currentAuth.expires < Date.now()) {
              if (!refreshPromise) {
                refreshPromise = refreshAccessToken(currentAuth.refresh)
                  .then(async (tokens) => {
                    const email = (currentAuth as any).email
                    const name = (currentAuth as any).name
                    await input.client.auth.set({
                      path: { id: providerName },
                      body: {
                        type: "oauth",
                        refresh: tokens.refresh_token ?? currentAuth.refresh,
                        access: tokens.access_token,
                        expires: Date.now() + (tokens.expires_in ?? 3600) * 1000,
                        ...(email ? { email } : {}),
                        ...(name ? { name } : {}),
                      } as any,
                    })
                    return { access: tokens.access_token }
                  })
                  .finally(() => {
                    refreshPromise = undefined
                  })
              }
              const refreshed = await refreshPromise
              currentAuth.access = refreshed.access
            }

            // Build headers with Bearer token
            const headers = new Headers()
            if (init?.headers) {
              if (init.headers instanceof Headers) {
                init.headers.forEach((value, key) => headers.set(key, value))
              } else if (Array.isArray(init.headers)) {
                for (const [key, value] of init.headers) {
                  if (value !== undefined) headers.set(key, String(value))
                }
              } else {
                for (const [key, value] of Object.entries(init.headers as Record<string, string>)) {
                  if (value !== undefined) headers.set(key, value)
                }
              }
            }
            
            // Clean up copied headers to prevent conflicts
            headers.delete("authorization")
            headers.delete("Authorization")
            headers.delete("x-goog-api-key")
            headers.delete("X-Goog-Api-Key")

            headers.set("authorization", `Bearer ${currentAuth.access}`)

            // Inject GCP project header for cloud-platform authorization if explicitly set
            const quotaProjectId = process.env.GOOGLE_CLOUD_PROJECT || process.env.ANTIGRAVITY_PROJECT_ID
            if (quotaProjectId) {
              headers.set("X-Goog-User-Project", quotaProjectId)
            }

            // Intercept and proxy requests to generativelanguage.googleapis.com
            const finalInputUrl = typeof finalInput === "string" ? finalInput : (finalInput as any).url || "";
            if (typeof finalInputUrl === "string" && finalInputUrl.includes("generativelanguage.googleapis.com")) {
              try {
                const urlObj = new URL(finalInputUrl);
                const pathname = urlObj.pathname;
                
                const streamMatch = pathname.match(/\/models\/([^:]+):streamGenerateContent/);
                const normalMatch = pathname.match(/\/models\/([^:]+):generateContent/);
                
                if (streamMatch || normalMatch) {
                  const originalModel = streamMatch ? streamMatch[1] : normalMatch![1];
                  const isStream = !!streamMatch;
                  
                  // Parse request body
                  let parsedRequest: any = {};
                  if (init?.body) {
                    try {
                      parsedRequest = JSON.parse(init.body.toString());
                    } catch (e) {
                      // Ignore
                    }
                  }
                  
                  // Pass the native reasoning level name directly to the gateway model ID (defaulting to low to prevent raw model 404s)
                  let mappedModel = originalModel;
                  if (originalModel.startsWith("gemini-")) {
                    const level = parsedRequest?.thinkingConfig?.thinkingLevel || "low";
                    if (originalModel === "gemini-3.5-flash" && level === "high") {
                      mappedModel = "gemini-3-flash-agent";
                    } else {
                      mappedModel = `${originalModel}-${level}`;
                    }
                  }
                  
                  // Strip thinkingConfig from request body for gemini models, since the gateway handles reasoning levels via the model ID
                  if (originalModel.startsWith("gemini-") && parsedRequest?.thinkingConfig) {
                    delete parsedRequest.thinkingConfig;
                  }

                  // Inject functionCall and functionResponse IDs if missing (required for Anthropic translation on the gateway)
                  if (parsedRequest?.contents && Array.isArray(parsedRequest.contents)) {
                    const callIdsByName = new Map<string, string[]>();
                    for (const content of parsedRequest.contents) {
                      if (content.parts && Array.isArray(content.parts)) {
                        for (const part of content.parts) {
                          if (part.functionCall) {
                            const name = part.functionCall.name;
                            const callId = part.functionCall.id || `call_${name}_${Math.random().toString(36).substring(2, 9)}`;
                            part.functionCall.id = callId;
                            if (!callIdsByName.has(name)) {
                              callIdsByName.set(name, []);
                            }
                            callIdsByName.get(name)!.push(callId);
                          } else if (part.functionResponse) {
                            const name = part.functionResponse.name;
                            if (!part.functionResponse.id) {
                              const list = callIdsByName.get(name);
                              if (list && list.length > 0) {
                                part.functionResponse.id = list.shift()!;
                              } else {
                                part.functionResponse.id = `call_${name}_${Math.random().toString(36).substring(2, 9)}`;
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                  
                  // Wrap in CaGenerateContentRequest format
                  const newBodyObj = {
                    model: mappedModel,
                    project: "default-cli-project",
                    user_prompt_id: crypto.randomUUID ? crypto.randomUUID() : "opencode-prompt-" + Date.now(),
                    request: parsedRequest
                  };
                  
                  const endpointUrl = isStream
                    ? "https://cloudcode-pa.googleapis.com/v1internal:streamGenerateContent?alt=sse"
                    : "https://cloudcode-pa.googleapis.com/v1internal:generateContent";
                    
                  // Set necessary headers for validation bypass
                  const newHeaders = new Headers(headers);
                  newHeaders.set("Content-Type", "application/json");
                  newHeaders.set("User-Agent", "AntigravityCLI/1.0.16/auto (linux; amd64; terminal)");
                  newHeaders.delete("X-Goog-User-Project"); // Daily/production will reject user-project header if set to default-cli-project
                  
                  const backendRes = await fetch(endpointUrl, {
                    method: "POST",
                    headers: newHeaders,
                    body: JSON.stringify(newBodyObj),
                    signal: init?.signal
                  });
                  
                  if (!backendRes.ok) {
                    return backendRes;
                  }
                  
                  if (!isStream) {
                    const data = await backendRes.json() as any;
                    const unwrapped = data.response || {};
                    return new Response(JSON.stringify(unwrapped), {
                      status: backendRes.status,
                      statusText: backendRes.statusText,
                      headers: {
                        "content-type": "application/json; charset=utf-8"
                      }
                    });
                  } else {
                    const reader = backendRes.body!.getReader();
                    const decoder = new TextDecoder();
                    const encoder = new TextEncoder();
                    let streamBuffer = "";
                    
                    const customStream = new ReadableStream({
                      async start(controller) {
                        try {
                          while (true) {
                            const { done, value } = await reader.read();
                            if (done) {
                              if (streamBuffer.trim()) {
                                processLine(streamBuffer, controller);
                              }
                              controller.close();
                              break;
                            }
                            
                            streamBuffer += decoder.decode(value, { stream: true });
                            const lines = streamBuffer.split("\n");
                            streamBuffer = lines.pop() || "";
                            
                            for (const line of lines) {
                              processLine(line, controller);
                            }
                          }
                        } catch (err) {
                          controller.error(err);
                        }
                      }
                    });
                    
                    function processLine(line: string, controller: ReadableStreamDefaultController) {
                      const trimmed = line.trim();
                      if (!trimmed) {
                        controller.enqueue(encoder.encode("\n"));
                        return;
                      }
                      if (trimmed.startsWith("data:")) {
                        const dataStr = trimmed.slice(5).trim();
                        try {
                          const parsed = JSON.parse(dataStr);
                          const unwrapped = parsed.response || {};
                          controller.enqueue(encoder.encode(`data: ${JSON.stringify(unwrapped)}\n\n`));
                        } catch (e) {
                          controller.enqueue(encoder.encode(line + "\n"));
                        }
                      } else {
                        controller.enqueue(encoder.encode(line + "\n"));
                      }
                    }
                    
                    return new Response(customStream, {
                      status: backendRes.status,
                      statusText: backendRes.statusText,
                      headers: {
                        "content-type": "text/event-stream; charset=utf-8",
                        "cache-control": "no-cache",
                        "connection": "keep-alive"
                      }
                    });
                  }
                }
              } catch (err) {
                console.error("Proxy translation error:", err);
              }
            }

            return fetch(finalInput, { ...init, headers })
          },
        }
      },

      methods: [
        // ---- Browser-based PKCE flow (callback via opencode server) ----
        {
          label: "Google Account (browser)",
          type: "oauth",
          authorize: async () => {
            const creds = await getCredentials()
            if (!creds.clientId || !creds.clientSecret) {
              throw new Error("Missing OPENCODE_GEMINI_CLIENT_ID or OPENCODE_GEMINI_CLIENT_SECRET environment variables, and failed to automatically extract them from the agy binary. Please configure them before logging in.")
            }
            const baseUrl = getGeminiRedirectBase()
            const redirectUri = `${baseUrl}/auth/gemini-callback`
            const pkce = await generatePKCE()
            const state = base64UrlEncode(crypto.getRandomValues(new Uint8Array(32)).buffer as ArrayBuffer)

            const params = new URLSearchParams({
              response_type: "code",
              client_id: creds.clientId,
              redirect_uri: redirectUri,
              scope: OAUTH_SCOPE,
              code_challenge: pkce.challenge,
              code_challenge_method: "S256",
              state,
              access_type: "offline",
              prompt: "consent",
            })
            const authUrl = `${AUTH_ENDPOINT}?${params.toString()}`
            const callbackPromise = waitForOAuthCallback(pkce, state, redirectUri)

            return {
              url: authUrl,
              instructions: `Complete sign-in in your browser — Google will redirect to ${redirectUri}`,
              method: "auto" as const,
              callback: async () => {
                const tokens = await callbackPromise
                if (!tokens.refresh_token) {
                  return { type: "failed" as const }
                }

                let email = ""
                let name = ""
                try {
                  const res = await fetch("https://www.googleapis.com/oauth2/v3/userinfo", {
                    headers: { "Authorization": `Bearer ${tokens.access_token}` }
                  })
                  if (res.ok) {
                    const info = await res.json() as any
                    email = info.email || ""
                    name = info.name || ""
                  }
                } catch (e) {
                  console.error("Failed to fetch userinfo in authorize callback:", e)
                }

                return {
                  type: "success" as const,
                  refresh: tokens.refresh_token,
                  access: tokens.access_token,
                  expires: Date.now() + (tokens.expires_in ?? 3600) * 1000,
                  email,
                  name,
                }
              },
            }
          },
        },

        // ---- Headless flow — same PKCE but explicit URL for copy/paste ----
        // Uses the same server callback as browser flow so works from any device.
        // The device code flow was removed because the OAuth client ID does not
        // have the "Device Code Grant" enabled in Google Cloud Console.
        {
          label: "Google Account (headless / copy URL)",
          type: "oauth",
          authorize: async () => {
            const creds = await getCredentials()
            if (!creds.clientId || !creds.clientSecret) {
              throw new Error("Missing OPENCODE_GEMINI_CLIENT_ID or OPENCODE_GEMINI_CLIENT_SECRET environment variables, and failed to automatically extract them from the agy binary. Please configure them before logging in.")
            }
            const baseUrl = getGeminiRedirectBase()
            const redirectUri = `${baseUrl}/auth/gemini-callback`
            const pkce = await generatePKCE()
            const state = base64UrlEncode(crypto.getRandomValues(new Uint8Array(32)).buffer as ArrayBuffer)

            const params = new URLSearchParams({
              response_type: "code",
              client_id: creds.clientId,
              redirect_uri: redirectUri,
              scope: OAUTH_SCOPE,
              code_challenge: pkce.challenge,
              code_challenge_method: "S256",
              state,
              access_type: "offline",
              prompt: "consent",
            })
            const authUrl = `${AUTH_ENDPOINT}?${params.toString()}`
            const callbackPromise = waitForOAuthCallback(pkce, state, redirectUri)

            return {
              url: authUrl,
              instructions: `Open this URL in any browser. Google will redirect to ${redirectUri} which the server handles automatically.`,
              method: "auto" as const,
              callback: async () => {
                const tokens = await callbackPromise
                if (!tokens.refresh_token) {
                  return { type: "failed" as const }
                }

                let email = ""
                let name = ""
                try {
                  const res = await fetch("https://www.googleapis.com/oauth2/v3/userinfo", {
                    headers: { "Authorization": `Bearer ${tokens.access_token}` }
                  })
                  if (res.ok) {
                    const info = await res.json() as any
                    email = info.email || ""
                    name = info.name || ""
                  }
                } catch (e) {
                  console.error("Failed to fetch userinfo in headless authorize callback:", e)
                }

                return {
                  type: "success" as const,
                  refresh: tokens.refresh_token,
                  access: tokens.access_token,
                  expires: Date.now() + (tokens.expires_in ?? 3600) * 1000,
                  email,
                  name,
                }
              },
            }
          },
        },

        // ---- Manual API key fallback ----
        {
          label: "Manually enter API Key",
          type: "api",
        },
      ],
    },
  }
}
