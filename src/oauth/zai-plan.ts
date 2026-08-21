/**
 * Z.ai GLM Coding (Start) Plan OAuth flow.
 *
 * This is the `builtin:zai-start-plan` entitlement ZCode uses — distinct from the pay-as-you-go
 * `zai` Coding Plan key provider (api.z.ai/api/coding/paas/v4). The data plane speaks the Anthropic
 * Messages wire at https://zcode.z.ai/api/v1/zcode-plan/anthropic and authenticates with a plain
 * `Authorization: Bearer <zcode JWT>` — no captcha, device, or signature headers (ZCode's own
 * buildStartPlanRuntimeAuthorizationHeaders emits only the bearer, and strips Aliyun captcha headers
 * on this path). We therefore route it through the anthropic adapter with `plainBearerOAuth`.
 *
 * Login mirrors ZCode's ZaiProviderAdapter (recovered from the ZCode server bundle):
 *   authorize  GET  https://chat.z.ai/api/oauth/authorize
 *                     ?redirect_uri&response_type=code&client_id&state          (no PKCE, no scope)
 *   exchange   POST https://zcode.z.ai/api/v1/oauth/token   (application/json)
 *                     { provider:"zai", code, redirect_uri, state }
 *              resp { code:0, msg, data:{ token:<ZCODE_JWT>, zai:{access_token}, user, expires_in } }
 * `data.token` is the credential the data plane needs; we persist it as the OAuth access token.
 * The captcha the user may see belongs to Z.ai's own login page — solved in the browser, exactly
 * as ZCode does. No client attestation is reproduced here.
 */
import { OAuthCallbackFlow } from "./callback-server";
import type { OAuthController, OAuthCredentials } from "./types";
import { decodeJwtPayload } from "./chatgpt";

const CLIENT_ID = "client_P8X5CMWmlaRO9gyO-KSqtg"; // ZCode source: "生产 client_id 不是 secret" (public)
const AUTHORIZE_URL = "https://chat.z.ai/api/oauth/authorize";
const TOKEN_URL = "https://zcode.z.ai/api/v1/oauth/token";
const PROVIDER_ENUM = "zai"; // shared OAuth-provider enum the zcode token backend routes on
const CALLBACK_PORT = 51789;
const CALLBACK_PATH = "/callback";
// The zcode JWT observed in the wild carries no `exp`; when the token response omits `expires_in`
// we still stamp a finite far-future expiry so the refresh guardian never fires (refresh re-login).
const DEFAULT_TTL_MS = 365 * 24 * 60 * 60 * 1000;

interface ZaiTokenEnvelope {
  code?: number;
  msg?: string;
  data?: {
    token?: string;
    zai?: { access_token?: string };
    user?: { id?: unknown; email?: unknown; name?: unknown } | null;
    expires_in?: number;
  };
}

function nonEmptyString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim().length > 0 ? value : undefined;
}

type ZaiBackendUser = NonNullable<ZaiTokenEnvelope["data"]>["user"];

/** Identity for multiauth: prefer the backend user object, fall back to the zcode JWT claims. */
function identityFromEnvelope(zcodeJwt: string, user: ZaiBackendUser): {
  accountId?: string;
  email?: string;
} {
  const email = nonEmptyString(user?.email)?.toLowerCase();
  const backendId = nonEmptyString(user?.id) ?? (typeof user?.id === "number" ? String(user.id) : undefined);
  const payload = decodeJwtPayload(zcodeJwt);
  const jwtId =
    nonEmptyString(payload?.user_id) ??
    (typeof payload?.user_id === "number" ? String(payload.user_id) : undefined) ??
    nonEmptyString(payload?.sub);
  const jwtEmail = nonEmptyString(payload?.email)?.toLowerCase();
  const accountId = backendId ?? jwtId;
  return {
    ...(accountId ? { accountId } : {}),
    ...(email ?? jwtEmail ? { email: email ?? jwtEmail } : {}),
  };
}

function expiryFrom(expiresIn: number | undefined): number {
  if (typeof expiresIn === "number" && Number.isFinite(expiresIn) && expiresIn > 0) {
    const computed = Date.now() + expiresIn * 1000;
    if (Number.isFinite(computed)) return computed;
  }
  return Date.now() + DEFAULT_TTL_MS;
}

class ZaiPlanOAuthFlow extends OAuthCallbackFlow {
  constructor(ctrl: OAuthController) {
    // Dynamic loopback: the base builds http://localhost:<port>/callback and passes that exact URI
    // into both generateAuthUrl and exchangeToken, so authorize and token exchange always agree.
    super(ctrl, { preferredPort: CALLBACK_PORT, callbackPath: CALLBACK_PATH });
  }

  async generateAuthUrl(state: string, redirectUri: string): Promise<{ url: string; instructions?: string }> {
    const params = new URLSearchParams({
      redirect_uri: redirectUri,
      response_type: "code",
      client_id: CLIENT_ID,
      state,
    });
    return {
      url: `${AUTHORIZE_URL}?${params.toString()}`,
      instructions: "Complete Z.ai login in your browser (solve the captcha there if shown).",
    };
  }

  async exchangeToken(code: string, state: string, redirectUri: string): Promise<OAuthCredentials> {
    const resp = await fetch(TOKEN_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ provider: PROVIDER_ENUM, code, redirect_uri: redirectUri, state }),
    });
    const text = await resp.text().catch(() => "");
    let envelope: ZaiTokenEnvelope;
    try {
      envelope = JSON.parse(text) as ZaiTokenEnvelope;
    } catch {
      throw new Error(`Z.ai token exchange returned non-JSON (${resp.status}): ${text.slice(0, 200)}`);
    }
    if (!resp.ok) {
      throw new Error(`Z.ai token exchange failed: ${resp.status} ${envelope.msg ?? text.slice(0, 200)}`);
    }
    // Business-layer error: code !== 0. This is where a stale/replayed code surfaces (the "captcha
    // verify failed" I first hit came from replaying a token, not from this fresh-code path).
    if (envelope.code !== undefined && envelope.code !== 0) {
      throw new Error(`Z.ai token exchange rejected (code ${envelope.code}): ${envelope.msg ?? "unknown error"}`);
    }
    const zcodeJwt = nonEmptyString(envelope.data?.token);
    if (!zcodeJwt) {
      throw new Error("Z.ai token exchange succeeded but response is missing data.token (the zcode JWT)");
    }
    const identity = identityFromEnvelope(zcodeJwt, envelope.data?.user ?? null);
    return {
      access: zcodeJwt, // becomes provider.apiKey → Authorization: Bearer on the messages endpoint
      refresh: "", // Z.ai issues no refresh token on this path; re-login on expiry
      expires: expiryFrom(envelope.data?.expires_in),
      ...(identity.accountId ? { accountId: identity.accountId } : {}),
      ...(identity.email ? { email: identity.email } : {}),
      source: "oauth",
    };
  }
}

export async function loginZaiPlan(ctrl: OAuthController): Promise<OAuthCredentials> {
  return new ZaiPlanOAuthFlow(ctrl).login();
}

/**
 * Z.ai's Start Plan token path issues no refresh token, and the zcode JWT is not refreshable
 * out of band. Treat expiry as re-login. The provider's refresh policy is "disabled" so the
 * guardian never calls this proactively; it only runs if a token is ever seen past expiry.
 */
export async function refreshZaiPlanToken(_refreshToken: string): Promise<OAuthCredentials> {
  throw new Error("Z.ai Start Plan tokens cannot be refreshed — run `ocx login zai-plan` again");
}
