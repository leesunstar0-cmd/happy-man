// 네이버 간편 가입/로그인 (Supabase Edge Function)
// Supabase 는 네이버를 기본 제공하지 않아서, 이 함수가 네이버 로그인을 받아
// 같은 이메일의 Supabase 회원으로 로그인시켜요. 처음이면 일반 회원으로 가입돼요.
//
// 필요한 비밀 값 (supabase secrets set ...):
//   NAVER_CLIENT_ID, NAVER_CLIENT_SECRET  네이버 개발자센터 애플리케이션 값
//   SITE_URL                              https://leesunstar0-cmd.github.io/happy-man/
//   STATE_SECRET                          아무 긴 무작위 문자열
// SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY 는 Supabase 가 자동으로 넣어줘요.
import { createClient } from "npm:@supabase/supabase-js@2.45.4";

const env = (k: string) => {
  const v = Deno.env.get(k);
  if (!v) throw new Error("missing env " + k);
  return v;
};
const SITE_URL = env("SITE_URL");
const enc = new TextEncoder();

async function sign(data: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", enc.encode(env("STATE_SECRET")), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(data)));
  return btoa(String.fromCharCode(...mac)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
const b64url = (s: string) => btoa(unescape(encodeURIComponent(s))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64url = (s: string) => decodeURIComponent(escape(atob(s.replace(/-/g, "+").replace(/_/g, "/"))));

// 사이트 주소로만 돌려보내요. 다른 곳으로 보내는 요청은 사이트 첫 화면으로 바꿔요.
const safeRedirect = (r: string | null) => (r && r.startsWith(SITE_URL) ? r : SITE_URL);
const backWithError = (code: string) => Response.redirect(SITE_URL + "signup.html?error=" + code + "#login", 302);

Deno.serve(async (req) => {
  const url = new URL(req.url);
  // 함수 안에서는 req.url 이 내부 주소일 수 있어서, 공개 주소를 직접 만들어요.
  const self = env("SUPABASE_URL").replace(/\/$/, "") + "/functions/v1/naver-auth";

  try {
    // 1) 시작: 네이버 로그인 화면으로 보내요.
    if (!url.pathname.endsWith("/callback")) {
      const nonce = crypto.randomUUID();
      const payload = b64url(JSON.stringify({ r: safeRedirect(url.searchParams.get("redirect_to")), n: nonce, t: Date.now() }));
      const state = payload + "." + (await sign(payload));
      const naver = new URL("https://nid.naver.com/oauth2.0/authorize");
      naver.searchParams.set("response_type", "code");
      naver.searchParams.set("client_id", env("NAVER_CLIENT_ID"));
      naver.searchParams.set("redirect_uri", self + "/callback");
      naver.searchParams.set("state", state);
      return new Response(null, {
        status: 302,
        headers: {
          Location: naver.toString(),
          "Set-Cookie": `naver_nonce=${nonce}; Path=/; Max-Age=600; HttpOnly; Secure; SameSite=Lax`,
        },
      });
    }

    // 2) 돌아옴: 위조 요청인지 확인해요.
    if (url.searchParams.get("error")) return backWithError("naver_cancelled");
    const code = url.searchParams.get("code"), state = url.searchParams.get("state") || "";
    const [payload, mac] = state.split(".");
    if (!code || !payload || mac !== (await sign(payload))) return backWithError("naver_state");
    const s = JSON.parse(unb64url(payload));
    const cookieNonce = (req.headers.get("cookie") || "").match(/naver_nonce=([^;]+)/)?.[1];
    if (s.n !== cookieNonce || Date.now() - s.t > 10 * 60 * 1000) return backWithError("naver_state");

    // 3) 네이버에서 이메일과 닉네임을 받아요.
    const tokenUrl = new URL("https://nid.naver.com/oauth2.0/token");
    tokenUrl.searchParams.set("grant_type", "authorization_code");
    tokenUrl.searchParams.set("client_id", env("NAVER_CLIENT_ID"));
    tokenUrl.searchParams.set("client_secret", env("NAVER_CLIENT_SECRET"));
    tokenUrl.searchParams.set("code", code);
    tokenUrl.searchParams.set("state", state);
    const token = await (await fetch(tokenUrl)).json();
    if (!token.access_token) return backWithError("naver_token");
    const me = await (await fetch("https://openapi.naver.com/v1/nid/me", { headers: { Authorization: "Bearer " + token.access_token } })).json();
    const email: string | undefined = me?.response?.email;
    if (!email) return backWithError("naver_email");
    const nickname: string = me.response.nickname || me.response.name || email.split("@")[0];

    // 4) 같은 이메일의 회원으로 로그인시켜요. 없으면 일반 회원으로 가입시켜요.
    const admin = createClient(env("SUPABASE_URL"), env("SUPABASE_SERVICE_ROLE_KEY"), { auth: { persistSession: false } });
    const created = await admin.auth.admin.createUser({ email, email_confirm: true, user_metadata: { nickname, provider: "naver" } });
    if (created.error && !/already|registered|exists/i.test(created.error.message)) return backWithError("naver_signup");
    const link = await admin.auth.admin.generateLink({ type: "magiclink", email, options: { redirectTo: safeRedirect(s.r) } });
    if (link.error || !link.data?.properties?.action_link) return backWithError("naver_session");

    return new Response(null, {
      status: 302,
      headers: { Location: link.data.properties.action_link, "Set-Cookie": "naver_nonce=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax" },
    });
  } catch (e) {
    console.error(e);
    return backWithError("naver_server");
  }
});
