
-- SafeConsent V2 : 카카오톡 단톡방 공용 링크 + 보호자 확인 + 전자 동의
-- Supabase SQL Editor에서 전체 실행
-- 실제 운영 전 기관의 개인정보/전자동의/보존정책 검토가 필요합니다.

create extension if not exists pgcrypto;

create table if not exists public.centers (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  created_at timestamptz not null default now()
);

create table if not exists public.center_members (
  center_id uuid not null references public.centers(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null default 'admin' check (role in ('admin','staff')),
  created_at timestamptz not null default now(),
  primary key(center_id,user_id)
);

create table if not exists public.children (
  id uuid primary key default gen_random_uuid(),
  center_id uuid not null references public.centers(id) on delete cascade,
  name text not null,
  grade text,
  guardian_name text,
  guardian_phone text not null,
  family_group text,
  active boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists public.consent_forms (
  id uuid primary key default gen_random_uuid(),
  center_id uuid not null references public.centers(id) on delete cascade,
  public_token text not null unique default encode(gen_random_bytes(24),'hex'),
  document_no text not null,
  document_version integer not null default 1,
  title text not null,
  event_date date,
  event_time text,
  location text,
  deadline timestamptz,
  purpose text,
  content text not null,
  precautions text,
  consent_statement text not null default '위 프로그램의 내용을 확인하였으며, 자녀의 참가 여부에 대해 아래와 같이 의사를 표시합니다.',
  status text not null default 'open' check(status in ('draft','open','closed')),
  created_by uuid references auth.users(id),
  created_at timestamptz not null default now()
);

create table if not exists public.consent_recipients (
  id uuid primary key default gen_random_uuid(),
  form_id uuid not null references public.consent_forms(id) on delete cascade,
  child_id uuid not null references public.children(id) on delete cascade,
  created_at timestamptz not null default now(),
  unique(form_id,child_id)
);

create table if not exists public.consent_responses (
  id uuid primary key default gen_random_uuid(),
  recipient_id uuid not null unique references public.consent_recipients(id) on delete cascade,
  decision text not null check(decision in ('agree','decline')),
  signer_name text not null,
  note text,
  user_agent text,
  submitted_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.centers enable row level security;
alter table public.center_members enable row level security;
alter table public.children enable row level security;
alter table public.consent_forms enable row level security;
alter table public.consent_recipients enable row level security;
alter table public.consent_responses enable row level security;

create or replace function public.is_center_member(p_center uuid)
returns boolean
language sql stable security definer
set search_path = public
as $$
  select exists(
    select 1 from public.center_members
    where center_id=p_center and user_id=auth.uid()
  );
$$;

revoke all on function public.is_center_member(uuid) from public;
grant execute on function public.is_center_member(uuid) to authenticated;

drop policy if exists center_select on public.centers;
create policy center_select on public.centers for select to authenticated
using(public.is_center_member(id));

drop policy if exists member_select on public.center_members;
create policy member_select on public.center_members for select to authenticated
using(public.is_center_member(center_id));

drop policy if exists children_member on public.children;
create policy children_member on public.children for all to authenticated
using(public.is_center_member(center_id))
with check(public.is_center_member(center_id));

drop policy if exists forms_member on public.consent_forms;
create policy forms_member on public.consent_forms for all to authenticated
using(public.is_center_member(center_id))
with check(public.is_center_member(center_id));

drop policy if exists recipients_member on public.consent_recipients;
create policy recipients_member on public.consent_recipients for all to authenticated
using(exists(
  select 1 from public.consent_forms f
  where f.id=form_id and public.is_center_member(f.center_id)
))
with check(exists(
  select 1 from public.consent_forms f
  where f.id=form_id and public.is_center_member(f.center_id)
));

drop policy if exists responses_member on public.consent_responses;
create policy responses_member on public.consent_responses for select to authenticated
using(exists(
  select 1
  from public.consent_recipients cr
  join public.consent_forms f on f.id=cr.form_id
  where cr.id=recipient_id and public.is_center_member(f.center_id)
));

-- 최초 로그인 계정의 센터 생성
create or replace function public.bootstrap_center(p_name text default '우리 지역아동센터')
returns uuid
language plpgsql security definer
set search_path=public
as $$
declare v_center uuid;
begin
  if auth.uid() is null then raise exception 'login required'; end if;

  select center_id into v_center
  from public.center_members
  where user_id=auth.uid()
  limit 1;

  if v_center is not null then return v_center; end if;

  insert into public.centers(name)
  values(coalesce(nullif(trim(p_name),''),'우리 지역아동센터'))
  returning id into v_center;

  insert into public.center_members(center_id,user_id,role)
  values(v_center,auth.uid(),'admin');

  return v_center;
end;
$$;

revoke all on function public.bootstrap_center(text) from public;
grant execute on function public.bootstrap_center(text) to authenticated;

-- 단톡방 공용 링크 접속 시: 동의서 원문만 공개
create or replace function public.get_public_consent_form(p_token text)
returns table(
  form_id uuid,
  document_no text,
  document_version integer,
  title text,
  event_date date,
  event_time text,
  location text,
  deadline timestamptz,
  purpose text,
  content text,
  precautions text,
  consent_statement text,
  form_status text,
  center_name text
)
language sql stable security definer
set search_path=public
as $$
  select
    f.id,f.document_no,f.document_version,f.title,f.event_date,f.event_time,f.location,
    f.deadline,f.purpose,f.content,f.precautions,f.consent_statement,f.status,c.name
  from public.consent_forms f
  join public.centers c on c.id=f.center_id
  where f.public_token=p_token
  limit 1;
$$;

revoke all on function public.get_public_consent_form(text) from public;
grant execute on function public.get_public_consent_form(text) to anon, authenticated;

-- 자녀 이름 + 보호자 휴대폰 뒤 4자리로 본인 대상 확인
create or replace function public.verify_public_consent_recipient(
  p_token text,
  p_child_name text,
  p_phone_last4 text
)
returns table(
  recipient_id uuid,
  child_name text,
  grade text,
  guardian_name text,
  existing_decision text,
  existing_signer text,
  existing_note text,
  existing_submitted_at timestamptz
)
language sql stable security definer
set search_path=public
as $$
  select
    cr.id,c.name,c.grade,c.guardian_name,
    r.decision,r.signer_name,r.note,r.submitted_at
  from public.consent_forms f
  join public.consent_recipients cr on cr.form_id=f.id
  join public.children c on c.id=cr.child_id
  left join public.consent_responses r on r.recipient_id=cr.id
  where f.public_token=p_token
    and f.status='open'
    and lower(trim(c.name))=lower(trim(p_child_name))
    and right(regexp_replace(c.guardian_phone,'[^0-9]','','g'),4)
        = regexp_replace(p_phone_last4,'[^0-9]','','g')
  limit 1;
$$;

revoke all on function public.verify_public_consent_recipient(text,text,text) from public;
grant execute on function public.verify_public_consent_recipient(text,text,text) to anon, authenticated;

-- 보호자 제출: 동일한 이름/뒤4자리 조건을 서버에서 다시 확인
create or replace function public.submit_public_consent(
  p_token text,
  p_child_name text,
  p_phone_last4 text,
  p_decision text,
  p_signer_name text,
  p_note text default null,
  p_user_agent text default null
)
returns boolean
language plpgsql security definer
set search_path=public
as $$
declare
  v_recipient uuid;
  v_status text;
  v_deadline timestamptz;
begin
  if p_decision not in ('agree','decline') then raise exception 'invalid decision'; end if;
  if nullif(trim(p_signer_name),'') is null then raise exception 'signer required'; end if;

  select cr.id,f.status,f.deadline
  into v_recipient,v_status,v_deadline
  from public.consent_forms f
  join public.consent_recipients cr on cr.form_id=f.id
  join public.children c on c.id=cr.child_id
  where f.public_token=p_token
    and lower(trim(c.name))=lower(trim(p_child_name))
    and right(regexp_replace(c.guardian_phone,'[^0-9]','','g'),4)
        = regexp_replace(p_phone_last4,'[^0-9]','','g')
  limit 1;

  if v_recipient is null then raise exception 'verification failed'; end if;
  if v_status <> 'open' then raise exception 'form closed'; end if;
  if v_deadline is not null and now() > v_deadline then raise exception 'deadline passed'; end if;

  insert into public.consent_responses(
    recipient_id,decision,signer_name,note,user_agent
  )
  values(
    v_recipient,p_decision,trim(p_signer_name),p_note,p_user_agent
  )
  on conflict(recipient_id) do update set
    decision=excluded.decision,
    signer_name=excluded.signer_name,
    note=excluded.note,
    user_agent=excluded.user_agent,
    submitted_at=now(),
    updated_at=now();

  return true;
end;
$$;

revoke all on function public.submit_public_consent(text,text,text,text,text,text,text) from public;
grant execute on function public.submit_public_consent(text,text,text,text,text,text,text) to anon, authenticated;

-- 30명 가상 아동
create or replace function public.seed_demo_children()
returns integer
language plpgsql security definer
set search_path=public
as $$
declare
  v_center uuid;
  v_names text[] := array[
    '김민수','이서연','박지훈','최유진','정하늘','오서준','한지우','윤도현','강하린','문지호',
    '서유나','임도윤','조아린','백시우','신예린','장현우','노지안','배서진','송지민','권도하',
    '류하은','홍지율','안서준','전유빈','고민재','유채원','남도윤','최서아','박하준','김예원'
  ];
  i int;
begin
  select center_id into v_center
  from public.center_members
  where user_id=auth.uid()
  limit 1;

  if v_center is null then raise exception 'center not found'; end if;
  if exists(select 1 from public.children where center_id=v_center) then return 0; end if;

  for i in 1..30 loop
    insert into public.children(
      center_id,name,grade,guardian_name,guardian_phone,family_group
    ) values(
      v_center,
      v_names[i],
      case ((i-1)%8)
        when 0 then '초1' when 1 then '초2' when 2 then '초3' when 3 then '초4'
        when 4 then '초5' when 5 then '초6' when 6 then '중1' else '중2' end,
      '보호자'||i,
      '010-'||lpad((3000+i)::text,4,'0')||'-'||lpad((5000+i)::text,4,'0'),
      case when i in (1,2) then '가족A'
           when i in (7,8) then '가족B'
           when i in (15,16,17) then '가족C'
           else null end
    );
  end loop;

  return 30;
end;
$$;

revoke all on function public.seed_demo_children() from public;
grant execute on function public.seed_demo_children() to authenticated;

-- anon은 테이블을 직접 못 읽고 RPC만 사용
revoke all on public.centers, public.center_members, public.children,
  public.consent_forms, public.consent_recipients, public.consent_responses from anon;

grant select on public.centers, public.center_members, public.consent_responses to authenticated;
grant select,insert,update,delete on public.children,public.consent_forms,public.consent_recipients to authenticated;
