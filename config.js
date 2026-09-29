// 회원 서버(Supabase) 연결 정보
// Supabase 대시보드 → Project Settings → API 에서 복사해 넣어요.
// anon(public) 키는 공개해도 되는 키예요. service_role 키는 절대 넣지 마세요.
window.HAPPY_CONFIG = {
  supabaseUrl: "",
  supabaseAnonKey: ""
};

// 두 값이 모두 있고 Supabase 라이브러리가 불러와졌을 때만 연결해요.
window.happyAuth = (() => {
  const c = window.HAPPY_CONFIG;
  if (!c.supabaseUrl || !c.supabaseAnonKey || !window.supabase) return null;
  return window.supabase.createClient(c.supabaseUrl, c.supabaseAnonKey);
})();
