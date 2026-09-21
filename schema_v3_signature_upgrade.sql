-- SafeConsent V3 서명 기능 업그레이드
-- 기존 V2를 사용 중인 경우 Supabase SQL Editor에서 이 파일 전체를 1회 실행합니다.

alter table public.consent_responses
  add column if not exists signature_data_url text,
  add column if not exists signature_hash text,
  add column if not exists signature_captured_at timestamptz;

create table if not exists public.consent_response_audit (
  id bigint generated always as identity primary key,
  response_id uuid not null references public.consent_responses(id) on delete cascade,
  recipient_id uuid not null references public.consent_recipients(id) on delete cascade,
  action text not null check(action in ('submitted','resubmitted','admin_updated')),
  decision text not null check(decision in ('agree','decline')),
  signer_name text not null,
  signature_hash text,
  actor_user_id uuid references auth.users(id),
  created_at timestamptz not null default now()
);

alter table public.consent_response_audit enable row level security;

drop policy if exists audit_member_select on public.consent_response_audit;
create policy audit_member_select on public.consent_response_audit for select to authenticated
using(exists(
  select 1
  from public.consent_recipients cr
  join public.consent_forms f on f.id=cr.form_id
  where cr.id=recipient_id and public.is_center_member(f.center_id)
));

grant select on public.consent_response_audit to authenticated;
revoke all on public.consent_response_audit from anon;

create or replace function public.submit_public_consent_v3(
  p_token text,
  p_child_name text,
  p_phone_last4 text,
  p_decision text,
  p_signer_name text,
  p_signature_data_url text,
  p_note text default null,
  p_user_agent text default null
)
returns boolean
language plpgsql security definer
set search_path=public,extensions
as $$
declare
  v_recipient uuid;
  v_status text;
  v_deadline timestamptz;
  v_response uuid;
  v_existed boolean;
  v_hash text;
begin
  if p_decision not in ('agree','decline') then raise exception 'invalid decision'; end if;
  if nullif(trim(p_signer_name),'') is null then raise exception 'signer required'; end if;
  if p_signature_data_url is null
     or p_signature_data_url not like 'data:image/png;base64,%'
     or char_length(p_signature_data_url) > 700000 then
    raise exception 'valid signature required';
  end if;

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

  select exists(select 1 from public.consent_responses where recipient_id=v_recipient)
  into v_existed;
  v_hash := encode(digest(convert_to(p_signature_data_url,'UTF8'),'sha256'),'hex');

  insert into public.consent_responses(
    recipient_id,decision,signer_name,note,user_agent,
    signature_data_url,signature_hash,signature_captured_at
  ) values(
    v_recipient,p_decision,trim(p_signer_name),p_note,p_user_agent,
    p_signature_data_url,v_hash,now()
  )
  on conflict(recipient_id) do update set
    decision=excluded.decision,
    signer_name=excluded.signer_name,
    note=excluded.note,
    user_agent=excluded.user_agent,
    signature_data_url=excluded.signature_data_url,
    signature_hash=excluded.signature_hash,
    signature_captured_at=excluded.signature_captured_at,
    submitted_at=now(),
    updated_at=now()
  returning id into v_response;

  insert into public.consent_response_audit(
    response_id,recipient_id,action,decision,signer_name,signature_hash
  ) values(
    v_response,v_recipient,case when v_existed then 'resubmitted' else 'submitted' end,
    p_decision,trim(p_signer_name),v_hash
  );

  return true;
end;
$$;

revoke all on function public.submit_public_consent_v3(text,text,text,text,text,text,text,text) from public;
grant execute on function public.submit_public_consent_v3(text,text,text,text,text,text,text,text) to anon, authenticated;

-- 기존 관리자 수정 함수는 보호자가 제출한 원본 서명을 보존합니다.
create or replace function public.admin_update_consent_response(
  p_recipient_id uuid,
  p_decision text,
  p_signer_name text,
  p_note text default null
)
returns boolean
language plpgsql security definer
set search_path=public
as $$
declare
  v_center uuid;
  v_response uuid;
  v_hash text;
begin
  if auth.uid() is null then raise exception 'login required'; end if;
  if p_decision not in ('agree','decline') then raise exception 'invalid decision'; end if;
  if nullif(trim(p_signer_name),'') is null then raise exception 'signer required'; end if;

  select f.center_id into v_center
  from public.consent_recipients cr
  join public.consent_forms f on f.id=cr.form_id
  where cr.id=p_recipient_id;
  if v_center is null or not public.is_center_member(v_center) then raise exception 'not allowed'; end if;

  update public.consent_responses
  set decision=p_decision, signer_name=trim(p_signer_name), note=p_note, updated_at=now()
  where recipient_id=p_recipient_id
  returning id,signature_hash into v_response,v_hash;
  if not found then raise exception 'response not found'; end if;

  insert into public.consent_response_audit(
    response_id,recipient_id,action,decision,signer_name,signature_hash,actor_user_id
  ) values(v_response,p_recipient_id,'admin_updated',p_decision,trim(p_signer_name),v_hash,auth.uid());
  return true;
end;
$$;

revoke all on function public.admin_update_consent_response(uuid,text,text,text) from public;
grant execute on function public.admin_update_consent_response(uuid,text,text,text) to authenticated;
