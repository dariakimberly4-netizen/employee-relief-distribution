-- Run in Supabase SQL Editor before using the staff portal.
create table if not exists public.staff_profiles(user_id uuid primary key references auth.users(id),role text not null check(role in ('admin','verification','release','inventory')));
create table if not exists public.employees(id text primary key,name text not null,dept text not null,eligible boolean not null default false,status text not null default 'ready' check(status in ('ready','released')));
create table if not exists public.inventory(item text primary key,quantity integer not null default 0 check(quantity>=0));
create table if not exists public.release_history(id bigint generated always as identity primary key,employee_id text not null references public.employees(id),employee_name text not null,department text not null,staff_email text not null,created_at timestamptz not null default now());
create unique index if not exists one_release_per_employee on public.release_history(employee_id);
alter table public.staff_profiles enable row level security;
alter table public.employees enable row level security;
alter table public.inventory enable row level security;
alter table public.release_history enable row level security;
create or replace function public.staff_role() returns text language sql stable security definer set search_path='' as $$select role from public.staff_profiles where user_id=auth.uid()$$;
revoke all on function public.staff_role() from public;
grant execute on function public.staff_role() to authenticated;
create policy "own role" on public.staff_profiles for select to authenticated using(user_id=auth.uid());
create policy "staff read employees" on public.employees for select to authenticated using(public.staff_role() in ('admin','verification','release','inventory'));
create policy "admin import employees" on public.employees for insert to authenticated with check(public.staff_role()='admin');
create policy "admin update employees" on public.employees for update to authenticated using(public.staff_role()='admin') with check(public.staff_role()='admin');
create policy "staff read inventory" on public.inventory for select to authenticated using(public.staff_role() in ('admin','verification','release','inventory'));
create policy "staff read history" on public.release_history for select to authenticated using(public.staff_role() in ('admin','verification','release','inventory'));
create or replace function public.release_grocery(p_employee_id text) returns void language plpgsql security definer set search_path='' as $$
declare emp public.employees%rowtype; actor text;
begin
 if public.staff_role() not in ('admin','release') then raise exception 'Not authorized';end if;
 select * into emp from public.employees where id=p_employee_id for update;
 if not found or not emp.eligible or emp.status='released' then raise exception 'Ineligible or already released';end if;
 if (select quantity from public.inventory where item='Christmas Grocery Package' for update)<1 then raise exception 'No packages left';end if;
 update public.inventory set quantity=quantity-1 where item='Christmas Grocery Package';
 update public.employees set status='released' where id=p_employee_id;
 select email into actor from auth.users where id=auth.uid();
 insert into public.release_history(employee_id,employee_name,department,staff_email) values(emp.id,emp.name,emp.dept,coalesce(actor,'staff'));
end$$;
revoke all on function public.release_grocery(text) from public;
grant execute on function public.release_grocery(text) to authenticated;
-- Seed inventory only after checking your actual approved package counts.
insert into public.inventory(item,quantity) values('Christmas Grocery Package',0) on conflict(item) do nothing;
-- Create staff accounts in Supabase Auth; then assign a role:
-- insert into public.staff_profiles(user_id,role) values('<auth-user-uuid>','admin');
-- Production hardening: avoid admin upsert overwriting released status; use a dedicated import RPC.
