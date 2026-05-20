-- =====================================================
-- Finanzas API — Schema para Supabase
-- Ejecuta esto en el SQL Editor de tu proyecto Supabase
-- =====================================================

-- USERS
create table if not exists users (
  id          uuid primary key default gen_random_uuid(),
  email       text unique not null,
  password_hash text not null,
  name        text,
  created_at  timestamptz default now()
);

-- FILES
create table if not exists files (
  id          uuid primary key default gen_random_uuid(),
  user_id     uuid not null references users(id) on delete cascade,
  name        text not null,
  rows        jsonb not null default '[]',
  "autoCount" integer not null default 0
);
create index if not exists files_user_id_idx on files(user_id);

-- BUDGETS
create table if not exists budgets (
  id          uuid primary key default gen_random_uuid(),
  user_id     uuid not null references users(id) on delete cascade,
  categoria   text not null,
  limite      numeric not null
);
create index if not exists budgets_user_id_idx on budgets(user_id);

-- GOALS
create table if not exists goals (
  id          uuid primary key default gen_random_uuid(),
  user_id     uuid not null references users(id) on delete cascade,
  nombre      text not null,
  objetivo    numeric not null,
  ahorrado    numeric not null default 0,
  fecha       text
);
create index if not exists goals_user_id_idx on goals(user_id);

-- SETTINGS (one row per user)
create table if not exists settings (
  user_id     uuid primary key references users(id) on delete cascade,
  lang        text not null default 'es',
  currency    text not null default 'EUR',
  "activeFile" text
);

-- =====================================================
-- Deshabilitar RLS en todas las tablas
-- (el backend usa la service_role key → acceso total)
-- =====================================================
alter table users    disable row level security;
alter table files    disable row level security;
alter table budgets  disable row level security;
alter table goals    disable row level security;
alter table settings disable row level security;
