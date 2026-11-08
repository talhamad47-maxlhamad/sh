-- =====================================================================
--  يومية الصندوق — مخطط قاعدة البيانات (Supabase / PostgreSQL)
--  الطريقة: افتح Supabase ← SQL Editor ← New query ← الصق هذا الملف كاملاً ← Run
--  الملف آمن لإعادة التشغيل (لا يحذف بياناتك الموجودة).
-- =====================================================================

create schema if not exists extensions;
create extension if not exists pgcrypto with schema extensions;

-- ------------------------------ الجداول ------------------------------
create table if not exists public.settings (
  id      int primary key default 1 check (id = 1),
  company text not null default 'اسم المنشأة',
  tz      text not null default 'Asia/Damascus',
  cats    jsonb not null default '{
    "in":  ["مبيعات نقدية","تحصيل ذمم","إيداع / تمويل","إيرادات أخرى"],
    "out": ["مشتريات","رواتب وأجور","إيجار","كهرباء وماء واتصالات","نقل ومواصلات","مصاريف نثرية","سحب شخصي","مصاريف أخرى"]
  }'::jsonb
);
insert into public.settings (id) values (1) on conflict do nothing;

create table if not exists public.funds (
  id         uuid primary key default gen_random_uuid(),
  name       text not null,
  currency   text not null default 'ل.س',
  opening    numeric(18,2) not null default 0,
  active     boolean not null default true,
  sort       int not null default 0,
  cn_in      int not null default 0,
  cn_out     int not null default 0,
  created_at timestamptz not null default now()
);

create table if not exists public.users (
  id         uuid primary key default gen_random_uuid(),
  name       text not null,
  username   text not null unique,
  pw_hash    text not null,
  role       text not null default 'emp' check (role in ('admin','emp')),
  active     boolean not null default true,
  perms      jsonb not null default '{}'::jsonb,
  funds      uuid[] not null default '{}',
  created_at timestamptz not null default now()
);

create table if not exists public.sessions (
  token_hash text primary key,
  user_id    uuid not null references public.users(id) on delete cascade,
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);

create table if not exists public.login_attempts (
  id       bigserial primary key,
  username text not null,
  at       timestamptz not null default now()
);
create index if not exists login_attempts_idx on public.login_attempts (username, at);

create table if not exists public.entries (
  id         uuid primary key default gen_random_uuid(),
  seq        bigserial,
  fund_id    uuid not null references public.funds(id) on delete cascade,
  date       date not null,
  type       text not null check (type in ('in','out')),
  kind       text not null default 'normal' check (kind in ('normal','close')),
  num        text not null default '',
  descr      text not null default '',
  party      text not null default '',
  cat        text not null default '',
  amount     numeric(18,2) not null check (amount > 0),
  by_id      uuid,
  by_name    text not null default '',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists entries_fund_date_idx on public.entries (fund_id, date, seq);

create table if not exists public.audit (
  id        bigserial primary key,
  at        timestamptz not null default now(),
  user_name text not null default '',
  action    text not null default '',
  fund_name text not null default '',
  detail    text not null default ''
);

-- ------------------------------ الحماية ------------------------------
-- الجداول مقفلة بالكامل أمام المفتاح العام؛ كل الوصول يمر عبر الدوال أدناه
-- التي تتحقق من الجلسة والصلاحيات داخل قاعدة البيانات نفسها.
alter table public.settings       enable row level security;
alter table public.funds          enable row level security;
alter table public.users          enable row level security;
alter table public.sessions       enable row level security;
alter table public.login_attempts enable row level security;
alter table public.entries        enable row level security;
alter table public.audit          enable row level security;

revoke all on all tables    in schema public from anon, authenticated;
revoke all on all sequences in schema public from anon, authenticated;
alter default privileges in schema public revoke all on tables    from anon, authenticated;
alter default privileges in schema public revoke all on sequences from anon, authenticated;

-- ------------------------------ دوال مساعدة داخلية ------------------------------
create or replace function public._today() returns date
language sql stable security definer set search_path = public, pg_temp as $$
  select (now() at time zone coalesce((select tz from public.settings where id = 1), 'UTC'))::date
$$;

create or replace function public._me(tok text) returns public.users
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare u public.users;
begin
  select us.* into u
    from public.sessions s join public.users us on us.id = s.user_id
   where s.token_hash = encode(digest(coalesce(tok, ''), 'sha256'), 'hex')
     and s.expires_at > now() and us.active;
  if u.id is null then
    raise exception 'انتهت الجلسة، سجّل الدخول من جديد' using errcode = 'PT401';
  end if;
  return u;
end $$;

create or replace function public._can(u public.users, perm text) returns boolean
language sql immutable as $$
  select u.role = 'admin' or coalesce((u.perms ->> perm)::boolean, false)
$$;

create or replace function public._admin(u public.users) returns void
language plpgsql as $$
begin
  if u.role <> 'admin' then
    raise exception 'هذه العملية للمدير فقط' using errcode = 'PT403';
  end if;
end $$;

create or replace function public._fund(u public.users, fid uuid) returns public.funds
language plpgsql security definer set search_path = public, pg_temp as $$
declare f public.funds;
begin
  select * into f from public.funds where id = fid;
  if f.id is null then raise exception 'الصندوق غير موجود'; end if;
  if u.role <> 'admin' and (not f.active or not (fid = any (u.funds))) then
    raise exception 'لا تملك صلاحية على هذا الصندوق' using errcode = 'PT403';
  end if;
  return f;
end $$;

create or replace function public._audit(u public.users, act text, fname text, det text) returns void
language sql security definer set search_path = public, pg_temp as $$
  insert into public.audit (user_name, action, fund_name, detail) values (u.name, act, coalesce(fname, ''), coalesce(det, ''))
$$;

create or replace function public._new_session(uid uuid, remember boolean) returns text
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare t text := encode(gen_random_bytes(32), 'hex');
begin
  delete from public.sessions where expires_at < now();
  insert into public.sessions (token_hash, user_id, expires_at)
  values (encode(digest(t, 'sha256'), 'hex'), uid, now() + case when remember then interval '30 days' else interval '1 day' end);
  return t;
end $$;

-- ------------------------------ الدخول والإعداد ------------------------------
create or replace function public.needs_setup(p jsonb default '{}') returns jsonb
language sql security definer set search_path = public, pg_temp as $$
  select to_jsonb(not exists (select 1 from public.users))
$$;

create or replace function public.setup_admin(p jsonb) returns jsonb
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare nm text := trim(coalesce(p->>'name', ''));
        un text := lower(trim(coalesce(p->>'username', '')));
        pw text := coalesce(p->>'password', '');
        uid uuid;
begin
  lock table public.users in share row exclusive mode;
  if exists (select 1 from public.users) then raise exception 'تم إعداد النظام مسبقاً، سجّل الدخول'; end if;
  if nm = '' then raise exception 'اكتب الاسم الكامل'; end if;
  if un !~ '^[^[:space:]]{3,}$' then raise exception 'اسم المستخدم 3 أحرف على الأقل وبدون مسافات'; end if;
  if length(pw) < 6 then raise exception 'كلمة المرور 6 أحرف على الأقل'; end if;
  insert into public.settings (id) values (1) on conflict do nothing;
  if not exists (select 1 from public.funds) then
    insert into public.funds (name, currency, sort) values ('صندوق الليرة', 'ل.س', 1), ('صندوق الدولار', '$', 2);
  end if;
  insert into public.users (name, username, pw_hash, role)
  values (nm, un, crypt(pw, gen_salt('bf', 10)), 'admin') returning id into uid;
  return jsonb_build_object('ok', true, 'token', public._new_session(uid, false));
end $$;

create or replace function public.login(p jsonb) returns jsonb
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare un text := lower(trim(coalesce(p->>'username', '')));
        pw text := coalesce(p->>'password', '');
        u public.users; fails int;
begin
  delete from public.login_attempts where at < now() - interval '1 day';
  select count(*) into fails from public.login_attempts where username = un and at > now() - interval '5 minutes';
  if fails >= 5 then
    return jsonb_build_object('ok', false, 'error', 'محاولات خاطئة كثيرة، انتظر 5 دقائق ثم أعد المحاولة');
  end if;
  select * into u from public.users where username = un;
  if u.id is null or u.pw_hash <> crypt(pw, u.pw_hash) then
    insert into public.login_attempts (username) values (un);
    return jsonb_build_object('ok', false, 'error', 'اسم المستخدم أو كلمة المرور غير صحيحة');
  end if;
  if not u.active then
    return jsonb_build_object('ok', false, 'error', 'هذا الحساب موقوف، راجع المدير');
  end if;
  delete from public.login_attempts where username = un;
  return jsonb_build_object('ok', true, 'token', public._new_session(u.id, coalesce((p->>'remember')::boolean, false)));
end $$;

create or replace function public.logout(p jsonb) returns jsonb
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
begin
  delete from public.sessions where token_hash = encode(digest(coalesce(p->>'token', ''), 'sha256'), 'hex');
  return 'true'::jsonb;
end $$;

create or replace function public.change_password(p jsonb) returns jsonb
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare u public.users := public._me(p->>'token');
        np text := coalesce(p->>'new', '');
begin
  if u.pw_hash <> crypt(coalesce(p->>'old', ''), u.pw_hash) then raise exception 'كلمة المرور الحالية غير صحيحة'; end if;
  if length(np) < 6 then raise exception 'كلمة المرور الجديدة 6 أحرف على الأقل'; end if;
  update public.users set pw_hash = crypt(np, gen_salt('bf', 10)) where id = u.id;
  return 'true'::jsonb;
end $$;

-- ------------------------------ تحميل البيانات الأساسية ------------------------------
create or replace function public.boot(p jsonb) returns jsonb
language plpgsql security definer set search_path = public, pg_temp as $$
declare u public.users := public._me(p->>'token');
        s public.settings; fl jsonb;
begin
  select * into s from public.settings where id = 1;
  select coalesce(jsonb_agg(jsonb_build_object(
           'id', f.id, 'name', f.name, 'currency', f.currency, 'opening', f.opening,
           'active', f.active, 'sort', f.sort, 'balance', f.opening + e.bal, 'count', e.n)
         order by f.sort, f.created_at), '[]'::jsonb)
    into fl
    from public.funds f
   cross join lateral (select coalesce(sum(case when x.type = 'in' then x.amount else -x.amount end), 0) as bal, count(*) as n
                         from public.entries x where x.fund_id = f.id) e
   where u.role = 'admin' or (f.active and f.id = any (u.funds));
  return jsonb_build_object(
    'me', jsonb_build_object('id', u.id, 'name', u.name, 'username', u.username, 'role', u.role, 'perms', u.perms),
    'today', public._today(), 'company', s.company, 'tz', s.tz, 'cats', s.cats, 'funds', fl);
end $$;

-- ------------------------------ دفتر الصندوق ------------------------------
create or replace function public.ledger(p jsonb) returns jsonb
language plpgsql security definer set search_path = public, pg_temp as $$
declare u public.users := public._me(p->>'token');
        f public.funds := public._fund(public._me(p->>'token'), (p->>'fund')::uuid);
        d1 date := (p->>'from')::date;
        d2 date := (p->>'to')::date;
        t  date := public._today();
        op numeric; ents jsonb;
begin
  if d1 > d2 then raise exception 'الفترة غير صحيحة'; end if;
  if u.role <> 'admin' then
    if d1 = d2 then
      if d1 <> t and not public._can(u, 'past') and not public._can(u, 'reports') then
        raise exception 'لا تملك صلاحية عرض الأيام السابقة' using errcode = 'PT403';
      end if;
    elsif not public._can(u, 'reports') then
      raise exception 'لا تملك صلاحية عرض التقارير' using errcode = 'PT403';
    end if;
  end if;
  select f.opening + coalesce(sum(case when e.type = 'in' then e.amount else -e.amount end), 0)
    into op from public.entries e where e.fund_id = f.id and e.date < d1;
  select coalesce(jsonb_agg(jsonb_build_object(
           'id', e.id, 'date', e.date, 'type', e.type, 'kind', e.kind, 'no', e.num, 'desc', e.descr,
           'party', e.party, 'cat', e.cat, 'amount', e.amount, 'by', e.by_name) order by e.date, e.seq), '[]'::jsonb)
    into ents from public.entries e where e.fund_id = f.id and e.date between d1 and d2;
  return jsonb_build_object('opening', op, 'entries', ents);
end $$;

-- ------------------------------ السندات ------------------------------
create or replace function public.save_entry(p jsonb) returns jsonb
language plpgsql security definer set search_path = public, pg_temp as $$
declare u public.users := public._me(p->>'token');
        f public.funds; e public.entries;
        eid uuid := nullif(p->>'id', '')::uuid;
        typ text := p->>'type';
        today_ date := public._today();
        dt date;
        ds text := left(trim(coalesce(p->>'desc', '')), 500);
        amt numeric := round((p->>'amount')::numeric, 2);
        newno text;
begin
  if typ is null or typ not in ('in', 'out') then raise exception 'نوع السند غير صحيح'; end if;
  if ds = '' then raise exception 'اكتب البيان'; end if;
  if amt is null or amt <= 0 then raise exception 'أدخل مبلغاً صحيحاً أكبر من صفر'; end if;
  dt := coalesce(nullif(p->>'date', '')::date, today_);
  if u.role <> 'admin' and not public._can(u, 'past') then dt := today_; end if;

  if eid is null then
    f := public._fund(u, (p->>'fund')::uuid);
    if not public._can(u, 'add_' || typ) then
      raise exception 'لا تملك صلاحية إضافة هذا النوع من السندات' using errcode = 'PT403';
    end if;
    if typ = 'in' then
      update public.funds set cn_in = cn_in + 1 where id = f.id returning 'ق-' || lpad(cn_in::text, 4, '0') into newno;
    else
      update public.funds set cn_out = cn_out + 1 where id = f.id returning 'د-' || lpad(cn_out::text, 4, '0') into newno;
    end if;
    insert into public.entries (fund_id, date, type, num, descr, party, cat, amount, by_id, by_name)
    values (f.id, dt, typ, newno, ds, left(trim(coalesce(p->>'party', '')), 200), left(trim(coalesce(p->>'cat', '')), 200), amt, u.id, u.name)
    returning * into e;
  else
    select * into e from public.entries where id = eid for update;
    if e.id is null then raise exception 'السند غير موجود'; end if;
    f := public._fund(u, e.fund_id);
    if e.kind = 'close' then raise exception 'لا يمكن تعديل سند التصفير'; end if;
    if not public._can(u, 'edit') then raise exception 'لا تملك صلاحية تعديل السندات' using errcode = 'PT403'; end if;
    if u.role <> 'admin' and not public._can(u, 'past') and e.date <> today_ then
      raise exception 'لا تملك صلاحية تعديل سندات الأيام السابقة' using errcode = 'PT403';
    end if;
    newno := e.num;
    if e.type <> typ then
      if not public._can(u, 'add_' || typ) then
        raise exception 'لا تملك صلاحية هذا النوع من السندات' using errcode = 'PT403';
      end if;
      if typ = 'in' then
        update public.funds set cn_in = cn_in + 1 where id = f.id returning 'ق-' || lpad(cn_in::text, 4, '0') into newno;
      else
        update public.funds set cn_out = cn_out + 1 where id = f.id returning 'د-' || lpad(cn_out::text, 4, '0') into newno;
      end if;
    end if;
    perform public._audit(u, 'تعديل سند', f.name,
      e.num || ' | ' || e.descr || ' | ' || e.amount || ' ← ' || ds || ' | ' || amt || ' ' || f.currency);
    update public.entries
       set date = dt, type = typ, num = newno, descr = ds,
           party = left(trim(coalesce(p->>'party', '')), 200), cat = left(trim(coalesce(p->>'cat', '')), 200),
           amount = amt, updated_at = now()
     where id = e.id returning * into e;
  end if;
  return jsonb_build_object('id', e.id, 'no', e.num);
end $$;

create or replace function public.delete_entry(p jsonb) returns jsonb
language plpgsql security definer set search_path = public, pg_temp as $$
declare u public.users := public._me(p->>'token');
        e public.entries; f public.funds;
begin
  select * into e from public.entries where id = (p->>'id')::uuid for update;
  if e.id is null then raise exception 'السند غير موجود'; end if;
  f := public._fund(u, e.fund_id);
  if e.kind = 'close' then
    perform public._admin(u);
  else
    if not public._can(u, 'delete') then raise exception 'لا تملك صلاحية حذف السندات' using errcode = 'PT403'; end if;
    if u.role <> 'admin' and not public._can(u, 'past') and e.date <> public._today() then
      raise exception 'لا تملك صلاحية حذف سندات الأيام السابقة' using errcode = 'PT403';
    end if;
  end if;
  delete from public.entries where id = e.id;
  perform public._audit(u, case when e.kind = 'close' then 'حذف سند تصفير' else 'حذف سند' end, f.name,
    e.num || ' | ' || e.date || ' | ' || e.descr || ' | ' || e.amount || ' ' || f.currency);
  return 'true'::jsonb;
end $$;

-- ------------------------------ الصناديق (للمدير) ------------------------------
create or replace function public.save_fund(p jsonb) returns jsonb
language plpgsql security definer set search_path = public, pg_temp as $$
declare u public.users := public._me(p->>'token');
        fid uuid := nullif(p->>'id', '')::uuid;
        nm text := trim(coalesce(p->>'name', ''));
        cur text := trim(coalesce(p->>'currency', ''));
        op numeric := round(coalesce(nullif(p->>'opening', '')::numeric, 0), 2);
        act boolean := coalesce((p->>'active')::boolean, true);
        srt int := coalesce(nullif(p->>'sort', '')::int, 0);
begin
  perform public._admin(u);
  if nm = '' then raise exception 'اكتب اسم الصندوق'; end if;
  if cur = '' then raise exception 'اكتب العملة'; end if;
  if fid is null then
    insert into public.funds (name, currency, opening, active, sort)
    values (nm, cur, op, act, case when srt = 0 then (select coalesce(max(sort), 0) + 1 from public.funds) else srt end)
    returning id into fid;
    perform public._audit(u, 'إنشاء صندوق', nm, 'العملة ' || cur || ' | افتتاحي ' || op);
  else
    update public.funds set name = nm, currency = cur, opening = op, active = act, sort = srt where id = fid;
    if not found then raise exception 'الصندوق غير موجود'; end if;
    perform public._audit(u, 'تعديل صندوق', nm, 'العملة ' || cur || ' | افتتاحي ' || op || ' | ' || case when act then 'مفعّل' else 'موقوف' end);
  end if;
  return jsonb_build_object('id', fid);
end $$;

create or replace function public.delete_fund(p jsonb) returns jsonb
language plpgsql security definer set search_path = public, pg_temp as $$
declare u public.users := public._me(p->>'token');
        f public.funds := public._fund(public._me(p->>'token'), (p->>'id')::uuid);
begin
  perform public._admin(u);
  if exists (select 1 from public.entries where fund_id = f.id) then
    raise exception 'الصندوق يحتوي سندات؛ احذف سنداته أولاً ثم احذف الصندوق';
  end if;
  delete from public.funds where id = f.id;
  update public.users set funds = array_remove(funds, f.id);
  perform public._audit(u, 'حذف صندوق', f.name, '');
  return 'true'::jsonb;
end $$;

-- إقفال وتصفير الرصيد: يُسجَّل سند تصفير بقيمة الرصيد حتى التاريخ المحدد، فيصبح الرصيد صفراً والسجل القديم يبقى كما هو
create or replace function public.close_fund(p jsonb) returns jsonb
language plpgsql security definer set search_path = public, pg_temp as $$
declare u public.users := public._me(p->>'token');
        f public.funds := public._fund(public._me(p->>'token'), (p->>'fund')::uuid);
        d date := coalesce(nullif(p->>'date', '')::date, public._today());
        note text := left(trim(coalesce(p->>'note', '')), 300);
        bal numeric;
begin
  perform public._admin(u);
  perform 1 from public.funds where id = f.id for update;
  if d > public._today() then raise exception 'لا يمكن التصفير بتاريخ مستقبلي'; end if;
  select f.opening + coalesce(sum(case when e.type = 'in' then e.amount else -e.amount end), 0)
    into bal from public.entries e where e.fund_id = f.id and e.date <= d;
  if bal = 0 then raise exception 'رصيد الصندوق صفر أصلاً حتى هذا التاريخ'; end if;
  insert into public.entries (fund_id, date, type, kind, num, descr, amount, by_id, by_name)
  values (f.id, d, case when bal > 0 then 'out' else 'in' end, 'close', 'تصفير',
          'إقفال وتصفير الرصيد' || case when note <> '' then ' — ' || note else '' end,
          abs(bal), u.id, u.name);
  perform public._audit(u, 'إقفال وتصفير الرصيد', f.name, 'الرصيد قبل التصفير ' || bal || ' ' || f.currency || ' بتاريخ ' || d);
  return jsonb_build_object('balance', bal);
end $$;

-- حذف كل سندات الصندوق نهائياً وإعادة الترقيم من البداية
create or replace function public.wipe_fund(p jsonb) returns jsonb
language plpgsql security definer set search_path = public, pg_temp as $$
declare u public.users := public._me(p->>'token');
        f public.funds := public._fund(public._me(p->>'token'), (p->>'fund')::uuid);
        n int;
begin
  perform public._admin(u);
  if coalesce(p->>'confirm_name', '') <> f.name then raise exception 'اسم الصندوق المكتوب للتأكيد غير مطابق'; end if;
  delete from public.entries where fund_id = f.id;
  get diagnostics n = row_count;
  update public.funds set cn_in = 0, cn_out = 0,
         opening = case when coalesce((p->>'reset_opening')::boolean, false) then 0 else opening end
   where id = f.id;
  perform public._audit(u, 'حذف كل سندات الصندوق', f.name, 'عدد السندات المحذوفة ' || n);
  return jsonb_build_object('deleted', n);
end $$;

-- ------------------------------ المستخدمون (للمدير) ------------------------------
create or replace function public.list_users(p jsonb) returns jsonb
language plpgsql security definer set search_path = public, pg_temp as $$
declare u public.users := public._me(p->>'token');
begin
  perform public._admin(u);
  return (select coalesce(jsonb_agg(jsonb_build_object(
            'id', x.id, 'name', x.name, 'username', x.username, 'role', x.role,
            'active', x.active, 'perms', x.perms, 'funds', to_jsonb(x.funds)) order by x.created_at), '[]'::jsonb)
            from public.users x);
end $$;

create or replace function public.save_user(p jsonb) returns jsonb
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare u public.users := public._me(p->>'token');
        t public.users;
        uid uuid := nullif(p->>'id', '')::uuid;
        nm text := trim(coalesce(p->>'name', ''));
        un text := lower(trim(coalesce(p->>'username', '')));
        pw text := coalesce(p->>'password', '');
        rl text := case when p->>'role' = 'admin' then 'admin' else 'emp' end;
        act boolean := coalesce((p->>'active')::boolean, true);
        pm jsonb := '{}'::jsonb; k text; fl uuid[];
begin
  perform public._admin(u);
  if nm = '' then raise exception 'اكتب الاسم الكامل'; end if;
  if un !~ '^[^[:space:]]{3,}$' then raise exception 'اسم المستخدم 3 أحرف على الأقل وبدون مسافات'; end if;
  foreach k in array array['add_in', 'add_out', 'edit', 'delete', 'past', 'reports', 'print', 'export'] loop
    pm := pm || jsonb_build_object(k, coalesce((p->'perms'->>k)::boolean, false));
  end loop;
  select coalesce(array_agg(f.id), '{}'::uuid[]) into fl from public.funds f
   where f.id::text in (select jsonb_array_elements_text(coalesce(p->'funds', '[]'::jsonb)));
  begin
    if uid is null then
      if length(pw) < 6 then raise exception 'كلمة المرور 6 أحرف على الأقل'; end if;
      insert into public.users (name, username, pw_hash, role, active, perms, funds)
      values (nm, un, crypt(pw, gen_salt('bf', 10)), rl, act, pm, fl) returning id into uid;
      perform public._audit(u, 'إنشاء مستخدم', '', nm || ' (' || un || ') ' || rl);
    else
      select * into t from public.users where id = uid for update;
      if t.id is null then raise exception 'المستخدم غير موجود'; end if;
      if t.id = u.id and not act then raise exception 'لا يمكنك إيقاف حسابك الحالي'; end if;
      if t.role = 'admin' and t.active and (rl <> 'admin' or not act)
         and (select count(*) from public.users where role = 'admin' and active and id <> t.id) = 0 then
        raise exception 'لا بد أن يبقى مدير مفعّل واحد على الأقل';
      end if;
      if pw <> '' and length(pw) < 6 then raise exception 'كلمة المرور 6 أحرف على الأقل'; end if;
      update public.users set name = nm, username = un, role = rl, active = act, perms = pm, funds = fl where id = uid;
      if pw <> '' then update public.users set pw_hash = crypt(pw, gen_salt('bf', 10)) where id = uid; end if;
      if (pw <> '' and uid <> u.id) or not act then delete from public.sessions where user_id = uid; end if;
      perform public._audit(u, 'تعديل مستخدم', '', nm || ' (' || un || ') ' || rl || case when act then '' else ' — موقوف' end
                                                  || case when pw <> '' then ' — تغيير كلمة المرور' else '' end);
    end if;
  exception when unique_violation then
    raise exception 'اسم المستخدم مستخدم من قبل';
  end;
  return jsonb_build_object('id', uid);
end $$;

create or replace function public.set_user_active(p jsonb) returns jsonb
language plpgsql security definer set search_path = public, pg_temp as $$
declare u public.users := public._me(p->>'token');
        t public.users; act boolean := coalesce((p->>'active')::boolean, true);
begin
  perform public._admin(u);
  select * into t from public.users where id = (p->>'id')::uuid for update;
  if t.id is null then raise exception 'المستخدم غير موجود'; end if;
  if t.id = u.id then raise exception 'لا يمكنك تنفيذ هذا على حسابك الحالي'; end if;
  if not act and t.role = 'admin' and t.active
     and (select count(*) from public.users where role = 'admin' and active and id <> t.id) = 0 then
    raise exception 'لا بد أن يبقى مدير مفعّل واحد على الأقل';
  end if;
  update public.users set active = act where id = t.id;
  if not act then delete from public.sessions where user_id = t.id; end if;
  perform public._audit(u, case when act then 'تفعيل مستخدم' else 'إيقاف مستخدم' end, '', t.name || ' (' || t.username || ')');
  return 'true'::jsonb;
end $$;

create or replace function public.delete_user(p jsonb) returns jsonb
language plpgsql security definer set search_path = public, pg_temp as $$
declare u public.users := public._me(p->>'token');
        t public.users;
begin
  perform public._admin(u);
  select * into t from public.users where id = (p->>'id')::uuid for update;
  if t.id is null then raise exception 'المستخدم غير موجود'; end if;
  if t.id = u.id then raise exception 'لا يمكنك حذف حسابك الحالي'; end if;
  if t.role = 'admin' and t.active
     and (select count(*) from public.users where role = 'admin' and active and id <> t.id) = 0 then
    raise exception 'لا يمكن حذف آخر مدير';
  end if;
  delete from public.users where id = t.id;
  perform public._audit(u, 'حذف مستخدم', '', t.name || ' (' || t.username || ')');
  return 'true'::jsonb;
end $$;

-- ------------------------------ الإعدادات والسجل والاستيراد (للمدير) ------------------------------
create or replace function public.save_settings(p jsonb) returns jsonb
language plpgsql security definer set search_path = public, pg_temp as $$
declare u public.users := public._me(p->>'token');
        co text := trim(coalesce(p->>'company', ''));
        tzn text := coalesce(nullif(trim(p->>'tz'), ''), 'Asia/Damascus');
        c jsonb := p->'cats';
begin
  perform public._admin(u);
  if co = '' then co := 'اسم المنشأة'; end if;
  if not exists (select 1 from pg_timezone_names where name = tzn) then raise exception 'المنطقة الزمنية غير صحيحة'; end if;
  if c is null or jsonb_typeof(c->'in') <> 'array' or jsonb_typeof(c->'out') <> 'array' then
    select cats into c from public.settings where id = 1;
  end if;
  update public.settings set company = co, tz = tzn, cats = jsonb_build_object('in', c->'in', 'out', c->'out') where id = 1;
  return 'true'::jsonb;
end $$;

create or replace function public.audit_list(p jsonb) returns jsonb
language plpgsql security definer set search_path = public, pg_temp as $$
declare u public.users := public._me(p->>'token');
begin
  perform public._admin(u);
  return (select coalesce(jsonb_agg(jsonb_build_object('at', a.at, 'user', a.user_name, 'action', a.action,
            'fund', a.fund_name, 'detail', a.detail) order by a.id desc), '[]'::jsonb)
            from (select * from public.audit order by id desc limit 200) a);
end $$;

-- استيراد سندات من نسخة البرنامج القديم (ملف JSON) إلى صندوق محدد
create or replace function public.import_entries(p jsonb) returns jsonb
language plpgsql security definer set search_path = public, pg_temp as $$
declare u public.users := public._me(p->>'token');
        f public.funds := public._fund(public._me(p->>'token'), (p->>'fund')::uuid);
        r jsonb; n int := 0; skipped int := 0; typ text; amt numeric; dt text; no_ text;
begin
  perform public._admin(u);
  if jsonb_typeof(p->'entries') <> 'array' then raise exception 'الملف لا يحتوي سندات'; end if;
  if jsonb_array_length(p->'entries') > 20000 then raise exception 'عدد السندات كبير جداً (الحد 20000)'; end if;
  perform 1 from public.funds where id = f.id for update;
  if coalesce((p->>'set_opening')::boolean, false) then
    update public.funds set opening = round(coalesce(nullif(p->>'opening', '')::numeric, 0), 2) where id = f.id;
  end if;
  for r in select * from jsonb_array_elements(p->'entries') loop
    typ := r->>'type'; dt := r->>'date';
    begin
      amt := round((r->>'amount')::numeric, 2);
    exception when others then amt := null;
    end;
    if typ not in ('in', 'out') or dt !~ '^\d{4}-\d{2}-\d{2}$' or amt is null or amt <= 0 then
      skipped := skipped + 1; continue;
    end if;
    no_ := nullif(trim(coalesce(r->>'no', '')), '');
    if no_ is null then
      if typ = 'in' then
        update public.funds set cn_in = cn_in + 1 where id = f.id returning 'ق-' || lpad(cn_in::text, 4, '0') into no_;
      else
        update public.funds set cn_out = cn_out + 1 where id = f.id returning 'د-' || lpad(cn_out::text, 4, '0') into no_;
      end if;
    end if;
    insert into public.entries (fund_id, date, type, num, descr, party, cat, amount, by_id, by_name)
    values (f.id, dt::date, typ, left(no_, 40), left(coalesce(r->>'desc', ''), 500), left(coalesce(r->>'party', ''), 200),
            left(coalesce(r->>'cat', ''), 200), amt, u.id, coalesce(nullif(r->>'byName', ''), u.name));
    n := n + 1;
  end loop;
  update public.funds fu
     set cn_in  = greatest(fu.cn_in,  coalesce((select max(substring(e.num from '\d{1,9}$')::int) from public.entries e
                                                 where e.fund_id = fu.id and e.kind = 'normal' and e.num like 'ق-%'), 0)),
         cn_out = greatest(fu.cn_out, coalesce((select max(substring(e.num from '\d{1,9}$')::int) from public.entries e
                                                 where e.fund_id = fu.id and e.kind = 'normal' and e.num like 'د-%'), 0))
   where fu.id = f.id;
  perform public._audit(u, 'استيراد سندات', f.name, 'تم استيراد ' || n || ' سند، وتخطّي ' || skipped);
  return jsonb_build_object('imported', n, 'skipped', skipped);
end $$;

-- ------------------------------ الصلاحيات على الدوال ------------------------------
-- الدوال الداخلية (تبدأ بـ _) غير متاحة للمفتاح العام، والدوال العامة تُنفَّذ فقط عبر التحقق من الجلسة داخلها.
do $$
declare r record;
begin
  for r in
    select p.oid::regprocedure as sig, p.proname
      from pg_proc p join pg_namespace n on n.oid = p.pronamespace
     where n.nspname = 'public'
  loop
    if left(r.proname, 1) = '_' then
      execute format('revoke all on function %s from public, anon, authenticated', r.sig);
    else
      execute format('revoke all on function %s from public', r.sig);
      execute format('grant execute on function %s to anon, authenticated', r.sig);
    end if;
  end loop;
end $$;
