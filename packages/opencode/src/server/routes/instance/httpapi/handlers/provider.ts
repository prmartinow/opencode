import { ProviderAuth } from "@/provider/auth"
import { Config } from "@/config/config"
import { ModelsDev } from "@opencode-ai/core/models-dev"
import { Provider } from "@/provider/provider"

import { mapValues } from "remeda"
import { Effect, Schema } from "effect"
import { HttpServerRequest, HttpServerResponse } from "effect/unstable/http"
import { HttpApiBuilder } from "effect/unstable/httpapi"
import { InstanceHttpApi } from "../api"
import { ProviderAuthApiError } from "../groups/provider"
import { ProviderV2 } from "@opencode-ai/core/provider"

function mapProviderAuthError<A, R>(self: Effect.Effect<A, ProviderAuth.Error, R>) {
  return self.pipe(
    Effect.mapError((error) => {
      if (error instanceof ProviderAuth.OauthMissing) {
        return new ProviderAuthApiError({ name: error._tag, data: { providerID: error.providerID } })
      }
      if (error instanceof ProviderAuth.OauthCodeMissing) {
        return new ProviderAuthApiError({ name: error._tag, data: { providerID: error.providerID } })
      }
      if (error instanceof ProviderAuth.OauthCallbackFailed) {
        return new ProviderAuthApiError({ name: error._tag, data: {} })
      }
      if (error instanceof ProviderAuth.ValidationFailed) {
        return new ProviderAuthApiError({ name: error._tag, data: { field: error.field, message: error.message } })
      }
      return new ProviderAuthApiError({ name: "BadRequest", data: {} })
    }),
  )
}

export const providerHandlers = HttpApiBuilder.group(InstanceHttpApi, "provider", (handlers) =>
  Effect.gen(function* () {
    const cfg = yield* Config.Service
    const provider = yield* Provider.Service
    const svc = yield* ProviderAuth.Service

    const list = Effect.fn("ProviderHttpApi.list")(function* () {
      const config = yield* cfg.get()
      const all = yield* ModelsDev.Service.use((s) => s.get())
      const disabled = new Set(config.disabled_providers ?? [])
      const enabled = config.enabled_providers ? new Set(config.enabled_providers) : undefined
      const geminiBase = {
        id: "gemini",
        name: "Gemini",
        env: [],
        npm: "@ai-sdk/google",
        models: {
          "gemini-3.6-flash": {
            id: "gemini-3.6-flash",
            name: "Gemini 3.6 Flash",
            family: "gemini-3.6-flash",
            release_date: "",
            attachment: true,
            reasoning: true,
            temperature: true,
            tool_call: true,
            limit: { context: 1048576, output: 65535 },
            modalities: { input: ["text"], output: ["text"] },
            provider: { npm: "@ai-sdk/google" }
          },
          "gemini-3.5-flash": {
            id: "gemini-3.5-flash",
            name: "Gemini 3.5 Flash",
            family: "gemini-3.5-flash",
            release_date: "",
            attachment: true,
            reasoning: true,
            temperature: true,
            tool_call: true,
            limit: { context: 1048576, output: 65535 },
            modalities: { input: ["text"], output: ["text"] },
            provider: { npm: "@ai-sdk/google" }
          },
          "gemini-3.1-pro": {
            id: "gemini-3.1-pro",
            name: "Gemini 3.1 Pro",
            family: "gemini-3.1-pro",
            release_date: "",
            attachment: true,
            reasoning: true,
            temperature: true,
            tool_call: true,
            limit: { context: 1048576, output: 65535 },
            modalities: { input: ["text"], output: ["text"] },
            provider: { npm: "@ai-sdk/google" }
          },
          "claude-sonnet-4-6": {
            id: "claude-sonnet-4-6",
            name: "Claude Sonnet 4.6 (Thinking)",
            family: "claude-sonnet-4-6",
            release_date: "",
            attachment: true,
            reasoning: true,
            temperature: true,
            tool_call: true,
            limit: { context: 200000, output: 8192 },
            modalities: { input: ["text"], output: ["text"] },
            provider: { npm: "@ai-sdk/google" }
          },
          "claude-opus-4-6-thinking": {
            id: "claude-opus-4-6-thinking",
            name: "Claude Opus 4.6 (Thinking)",
            family: "claude-opus-4-6-thinking",
            release_date: "",
            attachment: true,
            reasoning: true,
            temperature: true,
            tool_call: true,
            limit: { context: 200000, output: 4096 },
            modalities: { input: ["text"], output: ["text"] },
            provider: { npm: "@ai-sdk/google" }
          },
          "gpt-oss-120b-medium": {
            id: "gpt-oss-120b-medium",
            name: "GPT-OSS 120B (Medium)",
            family: "gpt-oss-120b-medium",
            release_date: "",
            attachment: true,
            reasoning: false,
            temperature: true,
            tool_call: true,
            limit: { context: 128000, output: 4096 },
            modalities: { input: ["text"], output: ["text"] },
            provider: { npm: "@ai-sdk/google" }
          }
        }
      } as any

      const dynamicGeminiModels: Record<string, any> = {}
      const googleSourceModels = {
        ...(all.google?.models || {}),
        ...(all.gemini?.models || {})
      }
      for (const [mId, mDef] of Object.entries(googleSourceModels)) {
        if (mId.startsWith("gemini-") && !(geminiBase.models as any)[mId]) {
          dynamicGeminiModels[mId] = {
            id: mId,
            name: (mDef as any).name || mId,
            family: mId,
            release_date: (mDef as any).release_date || "",
            attachment: true,
            reasoning: true,
            temperature: true,
            tool_call: true,
            limit: (mDef as any).limit || { context: 1048576, output: 65535 },
            modalities: (mDef as any).modalities || { input: ["text"], output: ["text"] },
            provider: { npm: "@ai-sdk/google" }
          }
        }
      }
      geminiBase.models = {
        ...geminiBase.models,
        ...dynamicGeminiModels
      }

      const extendedAll: Record<string, any> = {
        ...all,
        gemini: geminiBase,
        "gemini-2": { ...geminiBase, id: "gemini-2", name: "Gemini (Account 2)" },
        "gemini-3": { ...geminiBase, id: "gemini-3", name: "Gemini (Account 3)" },
        "gemini-4": { ...geminiBase, id: "gemini-4", name: "Gemini (Account 4)" },
        "gemini-5": { ...geminiBase, id: "gemini-5", name: "Gemini (Account 5)" },
      }

      const filtered: Record<string, any> = {}
      for (const [key, value] of Object.entries(extendedAll)) {
        if ((enabled ? enabled.has(key) : true) && !disabled.has(key)) filtered[key] = value
      }
      const connected = yield* provider.list()
      const providers = Object.assign(
        mapValues(filtered, (item) => Provider.fromModelsDevProvider(item)),
        connected,
      )
      return {
        all: Object.values(providers).map(Provider.toPublicInfo),
        default: Provider.defaultModelIDs(providers),
        connected: Object.keys(connected),
      }
    })

    const auth = Effect.fn("ProviderHttpApi.auth")(function* () {
      return yield* svc.methods()
    })

    const authorize = Effect.fn("ProviderHttpApi.authorize")(function* (ctx: {
      params: { providerID: ProviderV2.ID }
      payload: ProviderAuth.AuthorizeInput
    }) {
      return yield* mapProviderAuthError(
        svc.authorize({
          providerID: ctx.params.providerID,
          method: ctx.payload.method,
          inputs: ctx.payload.inputs,
        }),
      )
    })

    const authorizeRaw = Effect.fn("ProviderHttpApi.authorizeRaw")(function* (ctx: {
      params: { providerID: ProviderV2.ID }
      request: HttpServerRequest.HttpServerRequest
    }) {
      const body = yield* Effect.orDie(ctx.request.text)
      const payload = yield* Schema.decodeUnknownEffect(Schema.fromJsonString(ProviderAuth.AuthorizeInput))(body).pipe(
        Effect.mapError(() => new ProviderAuthApiError({ name: "BadRequest", data: {} })),
      )
      // Match legacy route behavior: when authorize() resolves without a
      // result (e.g. no further redirect), serialize as JSON `null` instead
      // of an empty body so clients can `.json()` parse the response.
      const result = yield* authorize({ params: ctx.params, payload })
      return HttpServerResponse.jsonUnsafe(result ?? null)
    })

    const callback = Effect.fn("ProviderHttpApi.callback")(function* (ctx: {
      params: { providerID: ProviderV2.ID }
      payload: ProviderAuth.CallbackInput
    }) {
      yield* mapProviderAuthError(
        svc.callback({
          providerID: ctx.params.providerID,
          method: ctx.payload.method,
          code: ctx.payload.code,
        }),
      )
      return true
    })

    return handlers
      .handle("list", list)
      .handle("auth", auth)
      .handleRaw("authorize", authorizeRaw)
      .handle("callback", callback)
  }),
)
