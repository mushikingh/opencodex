import { expect, test } from "bun:test";
import { createAnthropicAdapter as createAnthropicAdapterProduction } from "../src/adapters/anthropic";
import { withTestTranslatorBudget } from "./helpers/translator-budget";
import { ANTHROPIC_OAUTH_BETA } from "../src/oauth/anthropic";
import type { OcxMessage, OcxParsedRequest, OcxProviderConfig } from "../src/types";

const createAnthropicAdapter = (...args: Parameters<typeof createAnthropicAdapterProduction>) =>
  withTestTranslatorBudget(createAnthropicAdapterProduction(...args));

/**
 * plainBearerOAuth providers (the Z.ai GLM Coding Start Plan on
 * zcode.z.ai/api/v1/zcode-plan/anthropic) are OAuth-managed but must authenticate exactly like a
 * bearer-transport key: a lone `Authorization: Bearer <token>`. The Claude-native subscription
 * OAuth fingerprint — anthropic-beta, the Claude Code headers, the forced Claude Code system
 * block, and tool-name prefixing — makes Z.ai reject the request, so none of it may appear here.
 * Ported from the request-shape the ZCode client sends (Authorization bearer only).
 */
function zaiPlanProvider(): OcxProviderConfig {
  return {
    adapter: "anthropic",
    baseUrl: "https://zcode.z.ai/api/v1/zcode-plan/anthropic",
    authMode: "oauth",
    plainBearerOAuth: true,
    apiKey: "zcode-jwt-token", // the resolved OAuth access token (the zcode JWT)
  } as OcxProviderConfig;
}

function claudeOAuthProvider(): OcxProviderConfig {
  return {
    adapter: "anthropic",
    baseUrl: "https://api.anthropic.com",
    authMode: "oauth",
    apiKey: "claude-oauth-token",
  } as OcxProviderConfig;
}

function requestWith(messages: OcxMessage[], systemPrompt?: string[]): OcxParsedRequest {
  return {
    modelId: "glm-5.3",
    stream: false,
    context: { messages, tools: [], ...(systemPrompt ? { systemPrompt } : {}) },
    options: {},
  } as OcxParsedRequest;
}

const USER_TURN: OcxMessage[] = [{ role: "user", content: "say ok" }];

test("plainBearerOAuth sends a lone Authorization: Bearer, no Anthropic OAuth fingerprint", async () => {
  const req = await createAnthropicAdapter(zaiPlanProvider()).buildRequest(requestWith(USER_TURN));
  const headers = req.headers as Record<string, string>;

  expect(headers["Authorization"]).toBe("Bearer zcode-jwt-token");
  expect(headers["x-api-key"]).toBeUndefined();
  expect(headers["anthropic-beta"]).toBeUndefined();
  expect(headers["anthropic-version"]).toBe("2023-06-01");
  // No Claude Code CLI fingerprint headers.
  expect(headers["X-Claude-Code-Session-Id"]).toBeUndefined();
  expect(headers["x-client-request-id"]).toBeUndefined();

  // The URL is the confirmed zcode-plan messages path.
  expect(req.url).toBe("https://zcode.z.ai/api/v1/zcode-plan/anthropic/v1/messages");
});

test("plainBearerOAuth does not force the Claude Code system block", async () => {
  const req = await createAnthropicAdapter(zaiPlanProvider()).buildRequest(
    requestWith(USER_TURN, ["You are terse."]),
  );
  const body = JSON.parse(req.body as string) as { system?: Array<{ text?: string }> };
  const systemText = (body.system ?? []).map(b => b.text).join("\n");
  // The caller's own system prompt survives; the Claude Code identity is NOT prepended.
  expect(systemText).toContain("You are terse.");
  expect(systemText).not.toContain("Claude Code");
});

test("api.anthropic.com OAuth still carries the Claude Code fingerprint (regression guard)", async () => {
  const req = await createAnthropicAdapter(claudeOAuthProvider()).buildRequest(requestWith(USER_TURN));
  const headers = req.headers as Record<string, string>;
  expect(headers["Authorization"]).toBe("Bearer claude-oauth-token");
  expect(headers["anthropic-beta"]).toBe(ANTHROPIC_OAUTH_BETA);
  expect(headers["X-Claude-Code-Session-Id"]).toBeDefined();
});
