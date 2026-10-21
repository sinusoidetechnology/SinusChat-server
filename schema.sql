SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

CREATE TABLE public.blocked_users (
    blocker_hash character varying(64) NOT NULL,
    blocked_hash character varying(64) NOT NULL,
    blocked_at bigint DEFAULT (EXTRACT(epoch FROM now()) * (1000)::numeric)
);

CREATE TABLE public.bug_reports (
    id bigint NOT NULL,
    user_hash character varying(64),
    email character varying(254),
    name character varying(100),
    topic character varying(16) DEFAULT 'other'::character varying NOT NULL,
    description text NOT NULL,
    app_version character varying(40),
    device character varying(120),
    android character varying(20),
    diagnostics text,
    status character varying(16) DEFAULT 'pending'::character varying NOT NULL,
    reply text,
    replied_at bigint,
    created_at bigint NOT NULL,
    updated_at bigint,
    decided_at bigint
);

CREATE SEQUENCE public.bug_reports_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.bug_reports_id_seq OWNED BY public.bug_reports.id;

CREATE TABLE public.contact_invites (
    code character varying(48) NOT NULL,
    owner_hash character varying(64) NOT NULL,
    kind character varying(8) NOT NULL,
    created_at bigint NOT NULL,
    expires_at bigint,
    used_at bigint,
    used_by character varying(64),
    revoked boolean DEFAULT false NOT NULL,
    use_count integer DEFAULT 0 NOT NULL
);

CREATE TABLE public.conversation_meta (
    conversation_id text NOT NULL,
    user_hash character varying(64) NOT NULL,
    unread_count integer DEFAULT 0,
    last_message_at bigint DEFAULT 0,
    muted_until bigint DEFAULT 0,
    delivered_up_to bigint DEFAULT 0,
    read_up_to bigint DEFAULT 0,
    disappearing_ttl bigint DEFAULT 0
);

CREATE TABLE public.conversation_participants (
    conversation_id text NOT NULL,
    user_hash character varying(64) NOT NULL,
    joined_at bigint DEFAULT (EXTRACT(epoch FROM now()) * (1000)::numeric),
    is_admin boolean DEFAULT false NOT NULL
);

CREATE TABLE public.conversations (
    id text NOT NULL,
    created_at bigint DEFAULT (EXTRACT(epoch FROM now()) * (1000)::numeric),
    disappearing_ttl_ms bigint DEFAULT 0,
    disappearing_trigger character varying(16) DEFAULT 'read'::character varying
);

CREATE TABLE public.group_bans (
    group_id character varying(64) NOT NULL,
    user_hash character varying(64) NOT NULL,
    created_at bigint NOT NULL
);

CREATE TABLE public.groups (
    id text NOT NULL,
    name text NOT NULL,
    description text DEFAULT ''::text,
    avatar_color character varying(7) DEFAULT '#5288C1'::character varying,
    created_by text NOT NULL,
    created_at bigint DEFAULT 0,
    disappearing_ttl_ms bigint DEFAULT 0 NOT NULL,
    perms jsonb DEFAULT '{"addMembers": "admin", "editSettings": "admin", "sendMessages": "all"}'::jsonb NOT NULL,
    avatar_url text,
    kind character varying(16),
    invite_code character varying(48),
    invite_created_at bigint,
    last_active_day integer
);

CREATE TABLE public.messages (
    id character varying(128) NOT NULL,
    conversation_id text NOT NULL,
    sender_hash character varying(64),
    kind character varying(32) DEFAULT 'msg'::character varying,
    payload bytea NOT NULL,
    created_at bigint DEFAULT (EXTRACT(epoch FROM now()) * (1000)::numeric),
    delivered_at bigint,
    recipient_hash character varying(64)
);

CREATE TABLE public.signal_keys (
    user_hash character varying(64) NOT NULL,
    identity_key text NOT NULL,
    registration_id integer NOT NULL,
    signed_prekey_id integer NOT NULL,
    signed_prekey text NOT NULL,
    signed_prekey_sig text NOT NULL,
    kyber_prekey_id integer NOT NULL,
    kyber_prekey text NOT NULL,
    kyber_prekey_sig text NOT NULL,
    updated_at bigint NOT NULL
);

CREATE TABLE public.signal_prekeys (
    user_hash character varying(64) NOT NULL,
    key_id integer NOT NULL,
    pub text NOT NULL
);

CREATE TABLE public.users (
    id integer NOT NULL,
    email_hash character varying(64) NOT NULL,
    display_name text DEFAULT ''::character varying NOT NULL,
    avatar_url text,
    e2e_public_key text,
    key_updated_at bigint DEFAULT 0,
    chat_privacy_mode boolean DEFAULT false,
    last_heartbeat_ms bigint DEFAULT 0,
    last_seen_ms bigint DEFAULT 0,
    created_at bigint DEFAULT (EXTRACT(epoch FROM now()) * (1000)::numeric),
    avatar_color character varying(7) DEFAULT '#5288C1'::character varying,
    ntfy_topic character varying(64),
    avatar_updated_at bigint DEFAULT 0,
    active_device_id character varying(64),
    activity_hidden boolean DEFAULT false,
    email_block boolean DEFAULT false,
    deletion_scheduled_at bigint,
    push_mode character varying(8) DEFAULT 'ntfy'::character varying,
    fcm_token text,
    auto_delete_after_sec bigint DEFAULT 0,
    last_active_day integer,
    account_kind character varying(8) DEFAULT 'email'::character varying,
    login_key text,
    ua_hash text,
    profile_key_wrap text,
    block_new boolean DEFAULT false,
    call_e2e boolean DEFAULT false
);

CREATE SEQUENCE public.users_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;

ALTER TABLE ONLY public.bug_reports ALTER COLUMN id SET DEFAULT nextval('public.bug_reports_id_seq'::regclass);

ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);

ALTER TABLE ONLY public.blocked_users
    ADD CONSTRAINT blocked_users_pkey PRIMARY KEY (blocker_hash, blocked_hash);

ALTER TABLE ONLY public.bug_reports
    ADD CONSTRAINT bug_reports_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.contact_invites
    ADD CONSTRAINT contact_invites_pkey PRIMARY KEY (code);

ALTER TABLE ONLY public.conversation_meta
    ADD CONSTRAINT conversation_meta_pkey PRIMARY KEY (conversation_id, user_hash);

ALTER TABLE ONLY public.conversation_participants
    ADD CONSTRAINT conversation_participants_pkey PRIMARY KEY (conversation_id, user_hash);

ALTER TABLE ONLY public.conversations
    ADD CONSTRAINT conversations_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.group_bans
    ADD CONSTRAINT group_bans_pkey PRIMARY KEY (group_id, user_hash);

ALTER TABLE ONLY public.groups
    ADD CONSTRAINT groups_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.messages
    ADD CONSTRAINT messages_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.signal_keys
    ADD CONSTRAINT signal_keys_pkey PRIMARY KEY (user_hash);

ALTER TABLE ONLY public.signal_prekeys
    ADD CONSTRAINT signal_prekeys_pkey PRIMARY KEY (user_hash, key_id);

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_hash_key UNIQUE (email_hash);

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);

CREATE INDEX idx_bug_reports_created ON public.bug_reports USING btree (created_at DESC);

CREATE INDEX idx_bug_reports_user ON public.bug_reports USING btree (user_hash, created_at DESC);

CREATE INDEX idx_contact_invites_owner ON public.contact_invites USING btree (owner_hash, kind);

CREATE INDEX idx_conv_participants ON public.conversation_participants USING btree (user_hash);

CREATE INDEX idx_groups_id ON public.groups USING btree (id);

CREATE UNIQUE INDEX idx_groups_invite_code ON public.groups USING btree (invite_code) WHERE (invite_code IS NOT NULL);

CREATE INDEX idx_messages_conversation ON public.messages USING btree (conversation_id, created_at);

CREATE INDEX idx_messages_delivered ON public.messages USING btree (delivered_at) WHERE (delivered_at IS NULL);

CREATE INDEX idx_messages_recipient_pending ON public.messages USING btree (recipient_hash, created_at) WHERE (delivered_at IS NULL);

CREATE INDEX idx_messages_undelivered ON public.messages USING btree (created_at) WHERE (delivered_at IS NULL);
