import { describe, expect, test, beforeEach, afterEach } from "bun:test"
import { getCredentials, resetCachedCredentials, tryLoadAgyToken } from "@/plugin/google/gemini"
import fs from "node:fs"
import path from "node:path"

const GOOGLE_CLIENT_PREFIX = "1071006060591"
const GOOGLE_SECRET_PREFIX = "GOCSPX"

describe("plugin.gemini-credentials", () => {
    const tempAgyPath = path.join(__dirname, "temp-agy-binary")
    let originalAgyBinaryPath: string | undefined

    beforeEach(() => {
        originalAgyBinaryPath = process.env.OPENCODE_AGY_BINARY_PATH
        resetCachedCredentials()
    })

    afterEach(() => {
        if (originalAgyBinaryPath !== undefined) {
            process.env.OPENCODE_AGY_BINARY_PATH = originalAgyBinaryPath
        } else {
            delete process.env.OPENCODE_AGY_BINARY_PATH
        }
        if (fs.existsSync(tempAgyPath)) {
            fs.unlinkSync(tempAgyPath)
        }
    })

    test("dynamically extracts from agy binary", async () => {
        // Test with real agy binary on this host
        const creds = await getCredentials()
        const clientRegex = new RegExp(`^${GOOGLE_CLIENT_PREFIX}-[a-zA-Z0-9_-]+\\.apps\\.googleusercontent\\.com$`)
        const secretRegex = new RegExp(`^${GOOGLE_SECRET_PREFIX}-[a-zA-Z0-9_-]{28}$`)
        expect(creds.clientId).toMatch(clientRegex)
        expect(creds.clientSecret).toMatch(secretRegex)
    })

    test("extracts from mocked binary path", async () => {
        const mockBinaryContent = `some binary header data ${GOOGLE_CLIENT_PREFIX}-mockclientid.apps.googleusercontent.com more binary data ${GOOGLE_SECRET_PREFIX}-mockclientsecret123456789012 end`
        fs.writeFileSync(tempAgyPath, mockBinaryContent, "utf8")
        process.env.OPENCODE_AGY_BINARY_PATH = tempAgyPath

        const creds = await getCredentials()
        expect(creds.clientId).toBe(`${GOOGLE_CLIENT_PREFIX}-mockclientid.apps.googleusercontent.com`)
        expect(creds.clientSecret).toBe(`${GOOGLE_SECRET_PREFIX}-mockclientsecret123456789012`)
    })

    test("caches extracted credentials", async () => {
        const mockBinaryContent1 = `data ${GOOGLE_CLIENT_PREFIX}-mockclientid1.apps.googleusercontent.com ${GOOGLE_SECRET_PREFIX}-mockclientsecret123456789012`
        fs.writeFileSync(tempAgyPath, mockBinaryContent1, "utf8")
        process.env.OPENCODE_AGY_BINARY_PATH = tempAgyPath

        const first = await getCredentials()
        expect(first.clientId).toBe(`${GOOGLE_CLIENT_PREFIX}-mockclientid1.apps.googleusercontent.com`)

        const mockBinaryContent2 = `data ${GOOGLE_CLIENT_PREFIX}-mockclientid2.apps.googleusercontent.com ${GOOGLE_SECRET_PREFIX}-mockclientsecret223456789012`
        fs.writeFileSync(tempAgyPath, mockBinaryContent2, "utf8")

        const second = await getCredentials()
        expect(second.clientId).toBe(`${GOOGLE_CLIENT_PREFIX}-mockclientid1.apps.googleusercontent.com`)
    })
})

describe("plugin.gemini-token-loader", () => {
    const tempTokenPath = path.join(__dirname, "temp-antigravity-oauth-token")
    let originalTokenPath: string | undefined

    beforeEach(() => {
        originalTokenPath = process.env.OPENCODE_AGY_TOKEN_PATH
    })

    afterEach(() => {
        if (originalTokenPath !== undefined) {
            process.env.OPENCODE_AGY_TOKEN_PATH = originalTokenPath
        } else {
            delete process.env.OPENCODE_AGY_TOKEN_PATH
        }
        if (fs.existsSync(tempTokenPath)) {
            fs.unlinkSync(tempTokenPath)
        }
    })

    test("returns null if agy token file does not exist", async () => {
        process.env.OPENCODE_AGY_TOKEN_PATH = "/non/existent/path/token"
        const creds = await tryLoadAgyToken()
        expect(creds).toBeNull()
    })

    test("loads and parses valid token file", async () => {
        const dummyTokenData = {
            token: {
                access_token: "ya29.test-access-token",
                refresh_token: "1//test-refresh-token",
                expiry: "2026-07-12T17:23:04.000Z",
                token_type: "Bearer"
            },
            auth_method: "consumer"
        }
        fs.writeFileSync(tempTokenPath, JSON.stringify(dummyTokenData), "utf8")
        process.env.OPENCODE_AGY_TOKEN_PATH = tempTokenPath

        const creds = await tryLoadAgyToken()
        expect(creds).not.toBeNull()
        expect(creds?.access).toBe("ya29.test-access-token")
        expect(creds?.refresh).toBe("1//test-refresh-token")
        expect(creds?.expires).toBe(new Date("2026-07-12T17:23:04.000Z").getTime())
    })
})
