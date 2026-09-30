-- 행복을 주는 남자들: 회원 등급(일반 회원 / 관리자) 설정
-- Supabase 대시보드 → SQL Editor 에 전체를 붙여 넣고 Run 을 눌러요. 여러 번 실행해도 괜찮아요.

-- 1) 회원 프로필 표: 이메일·네이버·카카오·Google 어느 방법으로 가입해도 자동으로 '일반 회원(member)' 으로 만들어져요.
create table if not exists public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  email text,
  nickname text,
  role text not null default 'member' check (role in ('member', 'admin')),
  created_at timestamptz not null default now()
);
alter table public.profiles enable row level security;

-- 지금 로그인한 사람이 관리자인지 확인해요. (정책 안에서 표를 다시 읽을 때 무한 반복을 막으려고 security definer 로 만들어요)
create or replace function public.is_admin()
returns boolean
language sql stable security definer set search_path = public
as $$
  select exists (select 1 from public.profiles where id = auth.uid() and role = 'admin');
$$;

-- 가입하는 순간 프로필을 만들어요. 등급은 항상 member 로 시작해요.
create or replace function public.handle_new_user()
returns trigger
language plpgsql security definer set search_path = public
as $$
begin
  insert into public.profiles (id, email, nickname)
  values (new.id, new.email, coalesce(nullif(new.raw_user_meta_data ->> 'nickname', ''), nullif(new.raw_user_meta_data ->> 'name', ''), nullif(new.raw_user_meta_data ->> 'full_name', ''), split_part(new.email, '@', 1), '회원'))
  on conflict (id) do nothing;
  return new;
end;
$$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- 누가 무엇을 볼 수 있나요?
--   일반 회원: 내 프로필만 읽기. 등급은 바꿀 수 없어요.
--   관리자: 모든 회원 읽기 + 등급 바꾸기.
drop policy if exists "read own profile" on public.profiles;
create policy "read own profile" on public.profiles for select using (auth.uid() = id);
drop policy if exists "admins read all profiles" on public.profiles;
create policy "admins read all profiles" on public.profiles for select using (public.is_admin());
drop policy if exists "admins update profiles" on public.profiles;
create policy "admins update profiles" on public.profiles for update using (public.is_admin()) with check (public.is_admin());

-- 이미 가입한 회원이 있다면 프로필을 채워 넣어요.
insert into public.profiles (id, email, nickname)
select u.id, u.email, coalesce(nullif(u.raw_user_meta_data ->> 'nickname', ''), nullif(u.raw_user_meta_data ->> 'name', ''), nullif(u.raw_user_meta_data ->> 'full_name', ''), split_part(u.email, '@', 1), '회원')
from auth.users u
on conflict (id) do nothing;

-- 2) 관리자 전용 저장소: 공개되지 않는 버킷. 관리자만 파일을 내려받을 수 있어요.
insert into storage.buckets (id, name, public) values ('admin-only', 'admin-only', false)
on conflict (id) do update set public = false;
drop policy if exists "admins read admin-only" on storage.objects;
create policy "admins read admin-only" on storage.objects for select
  using (bucket_id = 'admin-only' and public.is_admin());

-- 3) 첫 관리자 지정: 사이트에서 먼저 가입하고 메일 인증까지 끝낸 뒤,
--    아래 줄의 이메일을 내 이메일로 바꾸고 앞의 -- 를 지운 다음 이 줄만 실행해요.
-- update public.profiles set role = 'admin' where email = 'you@example.com';
