--
-- PostgreSQL database dump
--

-- Dumped from database version 15.18 (Debian 15.18-1.pgdg13+1)
-- Dumped by pg_dump version 16.8

-- Started on 2026-08-04 20:26:28

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- TOC entry 6 (class 2615 OID 2200)
-- Name: public; Type: SCHEMA; Schema: -; Owner: agrofusion_migration
--

-- *not* creating schema, since initdb creates it


ALTER SCHEMA public OWNER TO agrofusion_migration;

--
-- TOC entry 2 (class 3079 OID 24402)
-- Name: citext; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS citext WITH SCHEMA public;


--
-- TOC entry 4740 (class 0 OID 0)
-- Dependencies: 2
-- Name: EXTENSION citext; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION citext IS 'data type for case-insensitive character strings';


--
-- TOC entry 374 (class 1255 OID 24872)
-- Name: fn_af_kms_ca_root_audit_event(character varying, uuid, text, uuid); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_af_kms_ca_root_audit_event(event_type character varying, ca_id uuid, description text, created_by uuid) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- Cuerpo mínimo: el trigger de af_kms_ca_root llama a esta función.
    -- El registro real de auditoría se hace desde el backend (KMS_CA_CREATED en af_audit_log).
    RETURN;
END;
$$;


ALTER FUNCTION public.fn_af_kms_ca_root_audit_event(event_type character varying, ca_id uuid, description text, created_by uuid) OWNER TO postgres;

--
-- TOC entry 373 (class 1255 OID 24787)
-- Name: fn_af_kms_ca_root_audit_trigger(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_af_kms_ca_root_audit_trigger() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_event_type VARCHAR;
    v_description TEXT;
BEGIN
    IF TG_OP = 'INSERT' THEN
        v_event_type := 'KMS_CA_CREATED';
        v_description := 'Root CA creada: ' || NEW.subject;
        PERFORM fn_af_kms_ca_root_audit_event(v_event_type, NEW.ca_id, v_description, NEW.created_by);

    ELSIF TG_OP = 'UPDATE' THEN
        IF NEW.status != OLD.status THEN
            CASE NEW.status
                WHEN 'rotated' THEN
                    v_event_type := 'KMS_CA_ROTATED';
                    v_description := 'Root CA rotada: ' || OLD.subject || ' -> ' || NEW.subject;
                WHEN 'revoked' THEN
                    v_event_type := 'KMS_CA_REVOKED';
                    v_description := 'Root CA revocada: ' || NEW.subject;
                ELSE
                    v_event_type := 'KMS_CA_STATUS_CHANGED';
                    v_description := 'Estado cambiado de ' || OLD.status || ' a ' || NEW.status;
            END CASE;
            PERFORM fn_af_kms_ca_root_audit_event(v_event_type, NEW.ca_id, v_description, NULL);
        END IF;
    END IF;

    RETURN NEW;
END;
$$;


ALTER FUNCTION public.fn_af_kms_ca_root_audit_trigger() OWNER TO postgres;

--
-- TOC entry 368 (class 1255 OID 24781)
-- Name: fn_af_kms_ca_root_get_active(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_af_kms_ca_root_get_active() RETURNS TABLE(ca_id uuid, public_key text, certificate_pem text, fingerprint character varying, serial_number character varying, subject character varying, issuer character varying, valid_from timestamp with time zone, valid_to timestamp with time zone, status character varying, days_until_expiry bigint, is_expired boolean)
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN QUERY
    SELECT
        t.ca_id,
        t.public_key,
        t.certificate_pem,
        t.fingerprint,
        t.serial_number,
        t.subject,
        t.issuer,
        t.valid_from,
        t.valid_to,
        t.status,
        EXTRACT(DAY FROM (t.valid_to - NOW()))::BIGINT as days_until_expiry,
        t.valid_to <= NOW() as is_expired
    FROM af_kms_ca_root t
    WHERE t.status = 'active'
    AND t.valid_from <= NOW()
    AND t.valid_to > NOW()
    LIMIT 1;
END;
$$;


ALTER FUNCTION public.fn_af_kms_ca_root_get_active() OWNER TO postgres;

--
-- TOC entry 372 (class 1255 OID 24785)
-- Name: fn_af_kms_ca_root_get_expiring(bigint); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_af_kms_ca_root_get_expiring(p_days_threshold bigint DEFAULT 30) RETURNS TABLE(ca_id uuid, subject character varying, serial_number character varying, valid_to timestamp with time zone, days_until_expiry bigint, status character varying)
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN QUERY
    SELECT
        t.ca_id,
        t.subject,
        t.serial_number,
        t.valid_to,
        EXTRACT(DAY FROM (t.valid_to - NOW()))::BIGINT as days_until_expiry,
        t.status
    FROM af_kms_ca_root t
    WHERE t.status IN ('active', 'rotated')
    AND t.valid_to > NOW()
    AND t.valid_to <= NOW() + (p_days_threshold || ' days')::INTERVAL
    ORDER BY t.valid_to ASC;
END;
$$;


ALTER FUNCTION public.fn_af_kms_ca_root_get_expiring(p_days_threshold bigint) OWNER TO postgres;

--
-- TOC entry 367 (class 1255 OID 24780)
-- Name: fn_af_kms_ca_root_initialize(text, text, text, character varying, character varying, character varying, character varying, timestamp with time zone, timestamp with time zone, uuid); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_af_kms_ca_root_initialize(p_private_key_encrypted text, p_public_key text, p_certificate_pem text, p_fingerprint character varying, p_serial_number character varying, p_subject character varying, p_issuer character varying, p_valid_from timestamp with time zone, p_valid_to timestamp with time zone, p_created_by uuid DEFAULT NULL::uuid) RETURNS TABLE(result_code character varying, result_message text, ca_id uuid)
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_ca_id UUID;
    v_existing_active_ca UUID;
    v_error_msg TEXT;
BEGIN
    SELECT ca_id INTO v_existing_active_ca
    FROM af_kms_ca_root
    WHERE status = 'active'
    LIMIT 1;

    IF v_existing_active_ca IS NOT NULL THEN
        RETURN QUERY SELECT
            'ERROR'::VARCHAR,
            'Ya existe una Root CA activa. Use fn_af_kms_ca_root_rotate para rotarla.'::TEXT,
            NULL::UUID;
        RETURN;
    END IF;

    IF p_valid_from >= p_valid_to THEN
        RETURN QUERY SELECT
            'ERROR'::VARCHAR,
            'valid_from debe ser menor que valid_to'::TEXT,
            NULL::UUID;
        RETURN;
    END IF;

    IF p_valid_from > NOW() + INTERVAL '1 day' THEN
        RETURN QUERY SELECT
            'WARNING'::VARCHAR,
            'valid_from est  en el futuro. La CA no ser  activa hasta esa fecha.'::TEXT,
            NULL::UUID;
    END IF;

    v_ca_id := gen_random_uuid();

    INSERT INTO af_kms_ca_root (
        ca_id,
        private_key_encrypted,
        public_key,
        certificate_pem,
        fingerprint,
        serial_number,
        subject,
        issuer,
        valid_from,
        valid_to,
        status,
        created_by
    ) VALUES (
        v_ca_id,
        p_private_key_encrypted,
        p_public_key,
        p_certificate_pem,
        p_fingerprint,
        p_serial_number,
        p_subject,
        p_issuer,
        p_valid_from,
        p_valid_to,
        'active',
        p_created_by
    );

    RETURN QUERY SELECT
        'SUCCESS'::VARCHAR,
        'Root CA inicializada exitosamente'::TEXT,
        v_ca_id::UUID;

EXCEPTION WHEN OTHERS THEN
    v_error_msg := SQLERRM;
    RETURN QUERY SELECT
        'ERROR'::VARCHAR,
        'Error al inicializar Root CA: ' || v_error_msg,
        NULL::UUID;
END;
$$;


ALTER FUNCTION public.fn_af_kms_ca_root_initialize(p_private_key_encrypted text, p_public_key text, p_certificate_pem text, p_fingerprint character varying, p_serial_number character varying, p_subject character varying, p_issuer character varying, p_valid_from timestamp with time zone, p_valid_to timestamp with time zone, p_created_by uuid) OWNER TO postgres;

--
-- TOC entry 370 (class 1255 OID 24783)
-- Name: fn_af_kms_ca_root_revoke(uuid, uuid); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_af_kms_ca_root_revoke(p_ca_id uuid, p_revoked_by uuid DEFAULT NULL::uuid) RETURNS TABLE(result_code character varying, result_message text, revoked_ca_id uuid)
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_ca_status VARCHAR;
    v_error_msg TEXT;
BEGIN
    SELECT status INTO v_ca_status
    FROM af_kms_ca_root
    WHERE ca_id = p_ca_id;

    IF v_ca_status IS NULL THEN
        RETURN QUERY SELECT
            'ERROR'::VARCHAR,
            'Root CA no encontrada'::TEXT,
            NULL::UUID;
        RETURN;
    END IF;

    IF v_ca_status = 'revoked' THEN
        RETURN QUERY SELECT
            'WARNING'::VARCHAR,
            'Root CA ya est  revocada'::TEXT,
            p_ca_id;
        RETURN;
    END IF;

    BEGIN
        UPDATE af_kms_ca_root
        SET status = 'revoked'
        WHERE ca_id = p_ca_id;

        RETURN QUERY SELECT
            'SUCCESS'::VARCHAR,
            'Root CA revocada exitosamente'::TEXT,
            p_ca_id;

    EXCEPTION WHEN OTHERS THEN
        v_error_msg := SQLERRM;
        RETURN QUERY SELECT
            'ERROR'::VARCHAR,
            'Error al revocar Root CA: ' || v_error_msg,
            NULL::UUID;
    END;
END;
$$;


ALTER FUNCTION public.fn_af_kms_ca_root_revoke(p_ca_id uuid, p_revoked_by uuid) OWNER TO postgres;

--
-- TOC entry 369 (class 1255 OID 24782)
-- Name: fn_af_kms_ca_root_rotate(text, text, text, character varying, character varying, character varying, character varying, timestamp with time zone, timestamp with time zone, uuid); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_af_kms_ca_root_rotate(p_new_private_key_encrypted text, p_new_public_key text, p_new_certificate_pem text, p_new_fingerprint character varying, p_new_serial_number character varying, p_new_subject character varying, p_new_issuer character varying, p_new_valid_from timestamp with time zone, p_new_valid_to timestamp with time zone, p_rotated_by uuid DEFAULT NULL::uuid) RETURNS TABLE(result_code character varying, result_message text, old_ca_id uuid, new_ca_id uuid)
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_old_ca_id UUID;
    v_new_ca_id UUID;
    v_error_msg TEXT;
BEGIN
    SELECT ca_id INTO v_old_ca_id
    FROM af_kms_ca_root
    WHERE status = 'active'
    LIMIT 1;

    IF v_old_ca_id IS NULL THEN
        RETURN QUERY SELECT
            'ERROR'::VARCHAR,
            'No existe Root CA activa para rotar'::TEXT,
            NULL::UUID,
            NULL::UUID;
        RETURN;
    END IF;

    IF p_new_valid_from >= p_new_valid_to THEN
        RETURN QUERY SELECT
            'ERROR'::VARCHAR,
            'valid_from debe ser menor que valid_to en nueva CA'::TEXT,
            v_old_ca_id,
            NULL::UUID;
        RETURN;
    END IF;

    BEGIN
        v_new_ca_id := gen_random_uuid();

        INSERT INTO af_kms_ca_root (
            ca_id,
            private_key_encrypted,
            public_key,
            certificate_pem,
            fingerprint,
            serial_number,
            subject,
            issuer,
            valid_from,
            valid_to,
            status,
            created_by
        ) VALUES (
            v_new_ca_id,
            p_new_private_key_encrypted,
            p_new_public_key,
            p_new_certificate_pem,
            p_new_fingerprint,
            p_new_serial_number,
            p_new_subject,
            p_new_issuer,
            p_new_valid_from,
            p_new_valid_to,
            'active',
            p_rotated_by
        );

        UPDATE af_kms_ca_root
        SET status = 'rotated',
            rotated_at = NOW()
        WHERE ca_id = v_old_ca_id;

        RETURN QUERY SELECT
            'SUCCESS'::VARCHAR,
            'Root CA rotada exitosamente'::TEXT,
            v_old_ca_id,
            v_new_ca_id;

    EXCEPTION WHEN OTHERS THEN
        v_error_msg := SQLERRM;
        RETURN QUERY SELECT
            'ERROR'::VARCHAR,
            'Error al rotar Root CA: ' || v_error_msg,
            v_old_ca_id,
            NULL::UUID;
    END;
END;
$$;


ALTER FUNCTION public.fn_af_kms_ca_root_rotate(p_new_private_key_encrypted text, p_new_public_key text, p_new_certificate_pem text, p_new_fingerprint character varying, p_new_serial_number character varying, p_new_subject character varying, p_new_issuer character varying, p_new_valid_from timestamp with time zone, p_new_valid_to timestamp with time zone, p_rotated_by uuid) OWNER TO postgres;

--
-- TOC entry 371 (class 1255 OID 24784)
-- Name: fn_af_kms_ca_root_validate(uuid); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_af_kms_ca_root_validate(p_ca_id uuid) RETURNS TABLE(result_code character varying, result_message text, ca_found boolean, is_active boolean, is_valid boolean, is_expired boolean, fingerprint_exists boolean)
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_ca_id UUID;
    v_status VARCHAR;
    v_valid_from TIMESTAMPTZ;
    v_valid_to TIMESTAMPTZ;
    v_fingerprint VARCHAR;
BEGIN
    SELECT ca_id, status, valid_from, valid_to, fingerprint
    INTO v_ca_id, v_status, v_valid_from, v_valid_to, v_fingerprint
    FROM af_kms_ca_root
    WHERE ca_id = p_ca_id;

    IF v_ca_id IS NULL THEN
        RETURN QUERY SELECT
            'ERROR'::VARCHAR,
            'Root CA no encontrada'::TEXT,
            FALSE,
            FALSE,
            FALSE,
            FALSE,
            FALSE;
        RETURN;
    END IF;

    RETURN QUERY SELECT
        'SUCCESS'::VARCHAR,
        'Root CA validada'::TEXT,
        TRUE::BOOLEAN,
        (v_status = 'active')::BOOLEAN,
        (v_status = 'active' AND v_valid_from <= NOW() AND v_valid_to > NOW())::BOOLEAN,
        (v_valid_to <= NOW())::BOOLEAN,
        (v_fingerprint IS NOT NULL)::BOOLEAN;
END;
$$;


ALTER FUNCTION public.fn_af_kms_ca_root_validate(p_ca_id uuid) OWNER TO postgres;

--
-- TOC entry 366 (class 1255 OID 24753)
-- Name: fn_get_active_af_kms_ca_root(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_get_active_af_kms_ca_root() RETURNS TABLE(ca_id uuid, public_key text, certificate_pem text, fingerprint character varying, serial_number character varying, subject character varying, issuer character varying, valid_from timestamp with time zone, valid_to timestamp with time zone, status character varying)
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN QUERY
    SELECT t.ca_id, t.public_key, t.certificate_pem, t.fingerprint, t.serial_number, t.subject, t.issuer, t.valid_from, t.valid_to, t.status
    FROM af_kms_ca_root t
    WHERE t.status = 'active' AND t.valid_from <= NOW() AND t.valid_to > NOW()
    LIMIT 1;
END;
$$;


ALTER FUNCTION public.fn_get_active_af_kms_ca_root() OWNER TO postgres;

--
-- TOC entry 375 (class 1255 OID 25193)
-- Name: fn_prevent_invalid_cert_status_transition(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_prevent_invalid_cert_status_transition() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- solo validar si cambió el status
    IF OLD.status IS DISTINCT FROM NEW.status THEN

        -- si ya estaba expired o revoked, no puede cambiar jamás
        IF OLD.status IN ('expired', 'revoked', 'invalid') THEN
            RAISE EXCEPTION
                'invalid certificate status transition: cannot change status from % to %',
                OLD.status,
                NEW.status;
        END IF;

        -- active solo puede ir a expired o revoked (o quedarse active)
        IF OLD.status = 'active'
           AND NEW.status NOT IN ('active', 'expired', 'revoked', 'invalid') THEN
            RAISE EXCEPTION
                'invalid new certificate status: %',
                NEW.status;
        END IF;

    END IF;

    RETURN NEW;
END;
$$;


ALTER FUNCTION public.fn_prevent_invalid_cert_status_transition() OWNER TO postgres;

--
-- TOC entry 355 (class 1255 OID 24344)
-- Name: fn_set_updated_at_af_external_endpoint(); Type: FUNCTION; Schema: public; Owner: agrofusion_migration
--

CREATE FUNCTION public.fn_set_updated_at_af_external_endpoint() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
begin
    new.updated_at = now();
    return new;
end;
$$;


ALTER FUNCTION public.fn_set_updated_at_af_external_endpoint() OWNER TO agrofusion_migration;

--
-- TOC entry 335 (class 1255 OID 24218)
-- Name: fn_set_updated_at_af_external_projects(); Type: FUNCTION; Schema: public; Owner: agrofusion_migration
--

CREATE FUNCTION public.fn_set_updated_at_af_external_projects() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
begin
    new.updated_at = now();
    return new;
end;
$$;


ALTER FUNCTION public.fn_set_updated_at_af_external_projects() OWNER TO agrofusion_migration;

--
-- TOC entry 343 (class 1255 OID 24284)
-- Name: fn_set_updated_at_af_external_request(); Type: FUNCTION; Schema: public; Owner: agrofusion_migration
--

CREATE FUNCTION public.fn_set_updated_at_af_external_request() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
begin
    new.updated_at = now();
    return new;
end;
$$;


ALTER FUNCTION public.fn_set_updated_at_af_external_request() OWNER TO agrofusion_migration;

--
-- TOC entry 338 (class 1255 OID 24266)
-- Name: fn_set_updated_at_af_external_url(); Type: FUNCTION; Schema: public; Owner: agrofusion_migration
--

CREATE FUNCTION public.fn_set_updated_at_af_external_url() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
begin
    new.updated_at = now();
    return new;
end;
$$;


ALTER FUNCTION public.fn_set_updated_at_af_external_url() OWNER TO agrofusion_migration;

--
-- TOC entry 365 (class 1255 OID 24752)
-- Name: fn_validate_af_kms_ca_root_integrity(uuid); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.fn_validate_af_kms_ca_root_integrity(p_ca_id uuid) RETURNS boolean
    LANGUAGE plpgsql
    AS $$
DECLARE v_fingerprint VARCHAR(128);
BEGIN
    SELECT fingerprint INTO v_fingerprint FROM af_kms_ca_root WHERE ca_id = p_ca_id;
    IF v_fingerprint IS NULL THEN
        RAISE EXCEPTION 'Root CA con ID % no encontrada', p_ca_id;
    END IF;
    RETURN v_fingerprint IS NOT NULL;
END;
$$;


ALTER FUNCTION public.fn_validate_af_kms_ca_root_integrity(p_ca_id uuid) OWNER TO postgres;

--
-- TOC entry 356 (class 1255 OID 24346)
-- Name: fn_validate_external_endpoint_terms(); Type: FUNCTION; Schema: public; Owner: agrofusion_migration
--

CREATE FUNCTION public.fn_validate_external_endpoint_terms() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
begin
    if not exists (
        select 1
        from cat_terms t
        join cat_vocabularies v on v.vocabulary_id = t.vocabulary_id
        where t.term_id = new.method_term_id
          and v.vocabulary_code = 'EXTERNAL_HTTP_METHOD'
          and t.is_enabled = true
    ) then
        raise exception
            'El method_term_id % no pertenece al vocabulario EXTERNAL_HTTP_METHOD o no estÃ¡ habilitado',
            new.method_term_id;
    end if;

    if not exists (
        select 1
        from cat_terms t
        join cat_vocabularies v on v.vocabulary_id = t.vocabulary_id
        where t.term_id = new.status_term_id
          and v.vocabulary_code = 'EXTERNAL_ENDPOINT_STATUS'
          and t.is_enabled = true
    ) then
        raise exception
            'El status_term_id % no pertenece al vocabulario EXTERNAL_ENDPOINT_STATUS o no estÃ¡ habilitado',
            new.status_term_id;
    end if;

    return new;
end;
$$;


ALTER FUNCTION public.fn_validate_external_endpoint_terms() OWNER TO agrofusion_migration;

--
-- TOC entry 337 (class 1255 OID 24220)
-- Name: fn_validate_external_project_status_term(); Type: FUNCTION; Schema: public; Owner: agrofusion_migration
--

CREATE FUNCTION public.fn_validate_external_project_status_term() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
begin
    if not exists (
        select 1
        from cat_terms t
        join cat_vocabularies v on v.vocabulary_id = t.vocabulary_id
        where t.term_id = new.status_term_id
          and v.vocabulary_code = 'EXTERNAL_PROJECT_STATUS'
          and t.is_enabled = true
    ) then
        raise exception
            'El status_term_id % no pertenece al vocabulario EXTERNAL_PROJECT_STATUS o no estÃ¡ habilitado',
            new.status_term_id;
    end if;
    return new;
end;
$$;


ALTER FUNCTION public.fn_validate_external_project_status_term() OWNER TO agrofusion_migration;

--
-- TOC entry 354 (class 1255 OID 24286)
-- Name: fn_validate_external_request_status_term(); Type: FUNCTION; Schema: public; Owner: agrofusion_migration
--

CREATE FUNCTION public.fn_validate_external_request_status_term() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
begin
    if not exists (
        select 1
        from cat_terms t
        join cat_vocabularies v on v.vocabulary_id = t.vocabulary_id
        where t.term_id = new.status_term_id
          and v.vocabulary_code = 'EXTERNAL_REQUEST_STATUS'
          and t.is_enabled = true
    ) then
        raise exception
            'El status_term_id % no pertenece al vocabulario EXTERNAL_REQUEST_STATUS o no estÃ¡ habilitado',
            new.status_term_id;
    end if;
    return new;
end;
$$;


ALTER FUNCTION public.fn_validate_external_request_status_term() OWNER TO agrofusion_migration;

--
-- TOC entry 342 (class 1255 OID 24268)
-- Name: fn_validate_external_url_status_term(); Type: FUNCTION; Schema: public; Owner: agrofusion_migration
--

CREATE FUNCTION public.fn_validate_external_url_status_term() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
begin
    if not exists (
        select 1
        from cat_terms t
        join cat_vocabularies v on v.vocabulary_id = t.vocabulary_id
        where t.term_id = new.status_term_id
          and v.vocabulary_code = 'EXTERNAL_URL_STATUS'
          and t.is_enabled = true
    ) then
        raise exception
            'El status_term_id % no pertenece al vocabulario EXTERNAL_URL_STATUS o no estÃ¡ habilitado',
            new.status_term_id;
    end if;
    return new;
end;
$$;


ALTER FUNCTION public.fn_validate_external_url_status_term() OWNER TO agrofusion_migration;

--
-- TOC entry 315 (class 1255 OID 24395)
-- Name: prevent_token_revocation_revert_simple(); Type: FUNCTION; Schema: public; Owner: agrofusion_migration
--

CREATE FUNCTION public.prevent_token_revocation_revert_simple() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  -- No permitir reactivar un token ya revocado
  IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NULL THEN
    RAISE EXCEPTION 'No se permite reactivar un token revocado (%).', OLD.token_id
      USING ERRCODE = '23514';
  END IF;

  -- No permitir mover revoked_at hacia atr s si ya exist¡a
  IF OLD.revoked_at IS NOT NULL
     AND NEW.revoked_at IS NOT NULL
     AND NEW.revoked_at < OLD.revoked_at THEN
    RAISE EXCEPTION 'No se permite retroceder la fecha de revocaci¢n del token (%).', OLD.token_id
      USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END;
$$;


ALTER FUNCTION public.prevent_token_revocation_revert_simple() OWNER TO agrofusion_migration;

--
-- TOC entry 317 (class 1255 OID 24541)
-- Name: trg_assign_new_permission_to_superadmin(); Type: FUNCTION; Schema: public; Owner: agrofusion_migration
--

CREATE FUNCTION public.trg_assign_new_permission_to_superadmin() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO af_role_permissions (
        af_role_id,
        af_perm_id
    )
    VALUES (
        'a1a1a1a1-a1a1-a1a1-a1a1-a1a1a1a1a1a1',
        NEW.af_perm_id
    )
    ON CONFLICT (af_role_id, af_perm_id) DO NOTHING;

    RETURN NEW;
END;
$$;


ALTER FUNCTION public.trg_assign_new_permission_to_superadmin() OWNER TO agrofusion_migration;

--
-- TOC entry 299 (class 1255 OID 24003)
-- Name: trg_block_delete_admin_user(); Type: FUNCTION; Schema: public; Owner: agrofusion_migration
--

CREATE FUNCTION public.trg_block_delete_admin_user() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF OLD.user_id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'::uuid THEN
    RAISE EXCEPTION 'No se permite eliminar f¡sicamente el usuario administrador (%). Use soft-delete (UPDATE users SET deleted_at=now()).', OLD.user_id
      USING ERRCODE = '42501';
  END IF;

  RETURN OLD;
END;
$$;


ALTER FUNCTION public.trg_block_delete_admin_user() OWNER TO agrofusion_migration;

--
-- TOC entry 296 (class 1255 OID 24005)
-- Name: trg_block_delete_superadmin_role(); Type: FUNCTION; Schema: public; Owner: agrofusion_migration
--

CREATE FUNCTION public.trg_block_delete_superadmin_role() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF OLD.af_role_id = 'a1a1a1a1-a1a1-a1a1-a1a1-a1a1a1a1a1a1' THEN
        RAISE EXCEPTION 'No se puede eliminar el rol SUPERADMIN del sistema';
    END IF;

    RETURN OLD;
END;
$$;


ALTER FUNCTION public.trg_block_delete_superadmin_role() OWNER TO agrofusion_migration;

--
-- TOC entry 316 (class 1255 OID 24522)
-- Name: trg_block_modify_af_audit_log(); Type: FUNCTION; Schema: public; Owner: agrofusion_migration
--

CREATE FUNCTION public.trg_block_modify_af_audit_log() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  RAISE EXCEPTION 'af_audit_log es inmutable: no se permite % sobre registros de auditor¡a.', TG_OP
    USING ERRCODE = '42501';
END;
$$;


ALTER FUNCTION public.trg_block_modify_af_audit_log() OWNER TO agrofusion_migration;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- TOC entry 215 (class 1259 OID 22101)
-- Name: af_accounting_mapping_rules; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_accounting_mapping_rules (
    rule_id uuid DEFAULT gen_random_uuid() NOT NULL,
    source_project_id uuid NOT NULL,
    source_transaction_type character varying(60) NOT NULL,
    debit_account_code character varying(20) NOT NULL,
    credit_account_code character varying(20) NOT NULL,
    description_template text NOT NULL,
    amount_field_path character varying(255) NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    created_by uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone,
    updated_by uuid
);


ALTER TABLE public.af_accounting_mapping_rules OWNER TO agrofusion_migration;

--
-- TOC entry 4810 (class 0 OID 0)
-- Dependencies: 215
-- Name: TABLE af_accounting_mapping_rules; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON TABLE public.af_accounting_mapping_rules IS 'RF-INT-01: Reglas de mapeo de transacciones operativas a asientos contables (d bito/cr dito)';


--
-- TOC entry 216 (class 1259 OID 22109)
-- Name: af_accounting_queue; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_accounting_queue (
    queue_id uuid DEFAULT gen_random_uuid() NOT NULL,
    source_project_id uuid NOT NULL,
    source_module_code character varying(60) NOT NULL,
    transaction_type character varying(60) NOT NULL,
    transaction_data jsonb NOT NULL,
    accounting_date date NOT NULL,
    user_id uuid NOT NULL,
    status character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    priority integer DEFAULT 5 NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    max_attempts integer DEFAULT 3 NOT NULL,
    last_error text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    processed_at timestamp with time zone,
    sent_at timestamp with time zone,
    external_transaction_id uuid
);


ALTER TABLE public.af_accounting_queue OWNER TO agrofusion_migration;

--
-- TOC entry 4812 (class 0 OID 0)
-- Dependencies: 216
-- Name: TABLE af_accounting_queue; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON TABLE public.af_accounting_queue IS 'RF-INT-01: Cola de transacciones contables desde m dulos (DisRiego, Maquinaria, N mina) hacia el proyecto de Contabilidad';


--
-- TOC entry 217 (class 1259 OID 22120)
-- Name: af_accounting_transfers; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_accounting_transfers (
    transfer_id uuid DEFAULT gen_random_uuid() NOT NULL,
    queue_id uuid,
    source_project_id uuid NOT NULL,
    transaction_type character varying(60) NOT NULL,
    payload_json jsonb NOT NULL,
    transfer_status character varying(20) DEFAULT 'sent'::character varying NOT NULL,
    sent_at timestamp with time zone DEFAULT now() NOT NULL,
    acknowledged_at timestamp with time zone,
    accounting_entry_id character varying,
    response_json jsonb,
    error_message text,
    retry_count integer DEFAULT 0,
    external_endpoint_id uuid
);


ALTER TABLE public.af_accounting_transfers OWNER TO agrofusion_migration;

--
-- TOC entry 4814 (class 0 OID 0)
-- Dependencies: 217
-- Name: TABLE af_accounting_transfers; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON TABLE public.af_accounting_transfers IS 'RF-INT-01: Historial de transferencias contables enviadas al m dulo de Contabilidad con estado de confirmaci n';


--
-- TOC entry 218 (class 1259 OID 22129)
-- Name: af_app_redirect_uris; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_app_redirect_uris (
    app_id uuid NOT NULL,
    redirect_uri text NOT NULL
);


ALTER TABLE public.af_app_redirect_uris OWNER TO agrofusion_migration;

--
-- TOC entry 219 (class 1259 OID 22134)
-- Name: af_app_user_provisioning; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_app_user_provisioning (
    provisioning_id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    app_id uuid NOT NULL,
    provisioning_status_term_id uuid NOT NULL,
    provisioned_at timestamp with time zone,
    deprovisioned_at timestamp with time zone,
    last_sync_at timestamp with time zone,
    sync_error text,
    external_user_id character varying(255),
    metadata jsonb,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone,
    provisioning_method character varying(50),
    status_id uuid,
    provisioning_data jsonb
);


ALTER TABLE public.af_app_user_provisioning OWNER TO agrofusion_migration;

--
-- TOC entry 220 (class 1259 OID 22141)
-- Name: af_apps; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_apps (
    app_id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying(40) NOT NULL,
    namespace character varying(40) NOT NULL,
    oidc_audience character varying(120),
    provisioning_url text,
    oidc_jwks_url text,
    status_term_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone,
    sso_client_id character varying(64),
    sso_client_type character varying(16),
    redirect_uris text,
    login_url text,
    admin_rbac_url text
);


ALTER TABLE public.af_apps OWNER TO agrofusion_migration;

--
-- TOC entry 221 (class 1259 OID 22148)
-- Name: af_audit_batch_exports; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_audit_batch_exports (
    export_id uuid DEFAULT gen_random_uuid() NOT NULL,
    batch_id uuid NOT NULL,
    export_format character varying(20) NOT NULL,
    file_path text,
    file_size_bytes bigint,
    file_hash character varying(128),
    export_signature text,
    manifest_json jsonb NOT NULL,
    requested_by uuid NOT NULL,
    requested_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    downloaded_count integer DEFAULT 0,
    last_downloaded_at timestamp with time zone,
    expires_at timestamp with time zone,
    status character varying(20) DEFAULT 'pending'::character varying NOT NULL
);


ALTER TABLE public.af_audit_batch_exports OWNER TO agrofusion_migration;

--
-- TOC entry 4819 (class 0 OID 0)
-- Dependencies: 221
-- Name: TABLE af_audit_batch_exports; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON TABLE public.af_audit_batch_exports IS 'RF-INT-09: Exportaciones de lotes de auditor a firmados digitalmente';


--
-- TOC entry 222 (class 1259 OID 22157)
-- Name: af_audit_batch_records; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_audit_batch_records (
    batch_record_id uuid DEFAULT gen_random_uuid() NOT NULL,
    batch_id uuid NOT NULL,
    audit_id uuid NOT NULL,
    sequence_number integer NOT NULL,
    record_hash character varying(128) NOT NULL
);


ALTER TABLE public.af_audit_batch_records OWNER TO agrofusion_migration;

--
-- TOC entry 4821 (class 0 OID 0)
-- Dependencies: 222
-- Name: TABLE af_audit_batch_records; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON TABLE public.af_audit_batch_records IS 'RF-INT-09: Relaci n entre lotes sellados y registros individuales de auditor a';


--
-- TOC entry 223 (class 1259 OID 22161)
-- Name: af_audit_batch_seals; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_audit_batch_seals (
    batch_id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    batch_period character varying(20) NOT NULL,
    period_start timestamp with time zone NOT NULL,
    period_end timestamp with time zone NOT NULL,
    record_count integer NOT NULL,
    batch_hash character varying(128) NOT NULL,
    digital_signature text NOT NULL,
    signature_algorithm character varying(50) DEFAULT 'RSA-2048-SHA256'::character varying NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid NOT NULL,
    validated_at timestamp with time zone,
    validation_status character varying(20),
    export_count integer DEFAULT 0,
    last_exported_at timestamp with time zone,
    metadata_json jsonb
);


ALTER TABLE public.af_audit_batch_seals OWNER TO agrofusion_migration;

--
-- TOC entry 4823 (class 0 OID 0)
-- Dependencies: 223
-- Name: TABLE af_audit_batch_seals; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON TABLE public.af_audit_batch_seals IS 'RF-INT-09: Lotes de auditor a sellados con firma digital para garantizar integridad';


--
-- TOC entry 224 (class 1259 OID 22170)
-- Name: af_audit_chain; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_audit_chain (
    chain_id uuid DEFAULT gen_random_uuid() NOT NULL,
    audit_id uuid NOT NULL,
    previous_audit_id uuid,
    block_hash character varying(128) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.af_audit_chain OWNER TO agrofusion_migration;

--
-- TOC entry 4825 (class 0 OID 0)
-- Dependencies: 224
-- Name: TABLE af_audit_chain; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON TABLE public.af_audit_chain IS 'RF-INT-02: Cadena de custodia de auditor a estilo blockchain para garantizar inmutabilidad temporal';


--
-- TOC entry 225 (class 1259 OID 22175)
-- Name: af_audit_detail; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_audit_detail (
    audit_detail_id uuid DEFAULT gen_random_uuid() NOT NULL,
    audit_id uuid NOT NULL,
    entity_table character varying(64) NOT NULL,
    entity_pk_hex character varying(64) NOT NULL,
    attribute_name character varying(64) NOT NULL,
    old_value text,
    new_value text,
    pk_table regclass,
    pk_uuid uuid,
    old_value_json jsonb,
    new_value_json jsonb
);


ALTER TABLE public.af_audit_detail OWNER TO agrofusion_migration;

--
-- TOC entry 226 (class 1259 OID 22181)
-- Name: af_audit_dlq; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_audit_dlq (
    dlq_id uuid DEFAULT gen_random_uuid() NOT NULL,
    original_payload jsonb NOT NULL,
    error_code character varying(100) NOT NULL,
    error_message text NOT NULL,
    retry_attempts integer DEFAULT 0 NOT NULL,
    failed_at timestamp with time zone DEFAULT now() NOT NULL,
    trace_id character varying(255) NOT NULL,
    idempotency_key character varying(255),
    status character varying(50) DEFAULT 'pending_review'::character varying NOT NULL,
    failed_node_id character varying(100),
    retried_at timestamp with time zone,
    retried_by uuid,
    discarded_at timestamp with time zone,
    discarded_by uuid,
    discard_reason text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.af_audit_dlq OWNER TO agrofusion_migration;

--
-- TOC entry 4828 (class 0 OID 0)
-- Dependencies: 226
-- Name: TABLE af_audit_dlq; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON TABLE public.af_audit_dlq IS 'Dead Letter Queue para eventos de auditor a que fallaron tras m ltiples reintentos';


--
-- TOC entry 227 (class 1259 OID 22191)
-- Name: af_audit_exports; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_audit_exports (
    export_id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    requested_by uuid NOT NULL,
    export_format character varying(10) NOT NULL,
    filters_json jsonb NOT NULL,
    selected_fields jsonb,
    status character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    priority character varying(10) DEFAULT 'normal'::character varying,
    requested_at timestamp with time zone DEFAULT now() NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    expires_at timestamp with time zone,
    record_count integer,
    file_size_bytes bigint,
    file_hash character varying(128),
    digital_signature text,
    download_count integer DEFAULT 0,
    last_downloaded_at timestamp with time zone,
    error_message text,
    processing_time_ms integer,
    export_name character varying(255),
    file_blob bytea
);


ALTER TABLE public.af_audit_exports OWNER TO agrofusion_migration;

--
-- TOC entry 4830 (class 0 OID 0)
-- Dependencies: 227
-- Name: TABLE af_audit_exports; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON TABLE public.af_audit_exports IS 'RF-INT-06: Registro de solicitudes de exportaci n as ncrona de auditor a con firma digital';


--
-- TOC entry 228 (class 1259 OID 22201)
-- Name: af_audit_idempotency; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_audit_idempotency (
    idempotency_key character varying(255) NOT NULL,
    audit_id uuid,
    queue_message_id character varying(255),
    status character varying(50) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL
);


ALTER TABLE public.af_audit_idempotency OWNER TO agrofusion_migration;

--
-- TOC entry 4832 (class 0 OID 0)
-- Dependencies: 228
-- Name: TABLE af_audit_idempotency; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON TABLE public.af_audit_idempotency IS 'Tabla para garantizar idempotencia en eventos de auditor a. Registros se eliminan despu s de expires_at.';


--
-- TOC entry 229 (class 1259 OID 22207)
-- Name: af_audit_ingestion; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_audit_ingestion (
    ingestion_id uuid DEFAULT gen_random_uuid() NOT NULL,
    receipt_id uuid NOT NULL,
    audit_id uuid,
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    source_module character varying(60) NOT NULL,
    payload_json jsonb NOT NULL,
    schema_version character varying(20) DEFAULT '1.0'::character varying NOT NULL,
    ingestion_mode character varying(20) DEFAULT 'async'::character varying NOT NULL,
    ingestion_status character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    idempotency_key character varying(255),
    trace_id uuid,
    user_id uuid,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    processed_at timestamp with time zone,
    audit_created_at timestamp with time zone,
    processing_time_ms integer,
    ingest_node_id character varying(100),
    retry_count integer DEFAULT 0,
    max_retries integer DEFAULT 5,
    last_error text,
    dlq_at timestamp with time zone
);


ALTER TABLE public.af_audit_ingestion OWNER TO agrofusion_migration;

--
-- TOC entry 4834 (class 0 OID 0)
-- Dependencies: 229
-- Name: TABLE af_audit_ingestion; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON TABLE public.af_audit_ingestion IS 'RF-INT-03: Registro de ingesti n de eventos v a API RESTful con soporte s ncrono/as ncrono y idempotencia';


--
-- TOC entry 230 (class 1259 OID 22219)
-- Name: af_audit_log; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_audit_log (
    audit_id uuid DEFAULT gen_random_uuid() NOT NULL,
    actor_id uuid,
    action_code character varying(64) NOT NULL,
    target_json jsonb,
    diff_json jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    actor_ip inet,
    session_id uuid,
    action_term_id uuid,
    at timestamp with time zone DEFAULT now() NOT NULL,
    external_project_id uuid,
    trace_id uuid,
    module_code character varying(60),
    tenant_id uuid,
    project_id uuid,
    outcome character varying(20) DEFAULT 'success'::character varying,
    payload_hash character varying(128),
    digital_signature text,
    device_info jsonb
);


ALTER TABLE public.af_audit_log OWNER TO agrofusion_migration;

--
-- TOC entry 4836 (class 0 OID 0)
-- Dependencies: 230
-- Name: COLUMN af_audit_log.trace_id; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON COLUMN public.af_audit_log.trace_id IS 'RF-INT-03: ID de trazabilidad distribuida para seguimiento entre sistemas';


--
-- TOC entry 4837 (class 0 OID 0)
-- Dependencies: 230
-- Name: COLUMN af_audit_log.payload_hash; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON COLUMN public.af_audit_log.payload_hash IS 'RF-INT-02: Hash SHA-256 del payload para garantizar inmutabilidad';


--
-- TOC entry 4838 (class 0 OID 0)
-- Dependencies: 230
-- Name: COLUMN af_audit_log.digital_signature; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON COLUMN public.af_audit_log.digital_signature IS 'RF-INT-02: Firma digital del evento para no repudio';


--
-- TOC entry 231 (class 1259 OID 22228)
-- Name: af_audit_receipts; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_audit_receipts (
    receipt_id uuid DEFAULT gen_random_uuid() NOT NULL,
    payload jsonb NOT NULL,
    status character varying(50) NOT NULL,
    audit_id uuid,
    idempotency_key character varying(255),
    trace_id character varying(255) NOT NULL,
    queued_at timestamp with time zone DEFAULT now() NOT NULL,
    processed_at timestamp with time zone,
    failed_at timestamp with time zone,
    error_log text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    accounting_transfer_id uuid
);


ALTER TABLE public.af_audit_receipts OWNER TO agrofusion_migration;

--
-- TOC entry 232 (class 1259 OID 22236)
-- Name: af_audit_schemas; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_audit_schemas (
    schema_id uuid DEFAULT gen_random_uuid() NOT NULL,
    schema_version character varying(20) NOT NULL,
    schema_json jsonb NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    strict_mode boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    deprecated_at timestamp with time zone,
    deprecated_reason text,
    replaced_by_version character varying(20),
    author_user_id uuid,
    changelog text
);


ALTER TABLE public.af_audit_schemas OWNER TO agrofusion_migration;

--
-- TOC entry 4841 (class 0 OID 0)
-- Dependencies: 232
-- Name: TABLE af_audit_schemas; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON TABLE public.af_audit_schemas IS 'RF-INT-03: JSON Schemas versionados para validaci n de eventos de auditor a';


--
-- TOC entry 4842 (class 0 OID 0)
-- Dependencies: 232
-- Name: COLUMN af_audit_schemas.deprecated_reason; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON COLUMN public.af_audit_schemas.deprecated_reason IS 'RF-INT-07: Raz n por la cual este schema fue deprecado';


--
-- TOC entry 4843 (class 0 OID 0)
-- Dependencies: 232
-- Name: COLUMN af_audit_schemas.replaced_by_version; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON COLUMN public.af_audit_schemas.replaced_by_version IS 'RF-INT-07: Versi n que reemplaza a este schema deprecado';


--
-- TOC entry 233 (class 1259 OID 22245)
-- Name: af_auth_project_sessions; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_auth_project_sessions (
    psession_id uuid DEFAULT gen_random_uuid() NOT NULL,
    sso_session_id uuid NOT NULL,
    af_project_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    user_id uuid,
    permissions_cache jsonb,
    roles_cache jsonb,
    last_access_at timestamp with time zone DEFAULT now(),
    is_active boolean DEFAULT true NOT NULL
);


ALTER TABLE public.af_auth_project_sessions OWNER TO agrofusion_migration;

--
-- TOC entry 4845 (class 0 OID 0)
-- Dependencies: 233
-- Name: COLUMN af_auth_project_sessions.permissions_cache; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON COLUMN public.af_auth_project_sessions.permissions_cache IS 'Cach  de permisos del usuario en el proyecto';


--
-- TOC entry 4846 (class 0 OID 0)
-- Dependencies: 233
-- Name: COLUMN af_auth_project_sessions.roles_cache; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON COLUMN public.af_auth_project_sessions.roles_cache IS 'Cach  de roles del usuario en el proyecto';


--
-- TOC entry 234 (class 1259 OID 22254)
-- Name: af_auth_sessions; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_auth_sessions (
    sso_session_id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    issued_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    ip inet,
    user_agent text,
    terminated_at timestamp with time zone,
    last_activity_at timestamp with time zone DEFAULT now()
);


ALTER TABLE public.af_auth_sessions OWNER TO agrofusion_migration;

--
-- TOC entry 4848 (class 0 OID 0)
-- Dependencies: 234
-- Name: COLUMN af_auth_sessions.last_activity_at; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON COLUMN public.af_auth_sessions.last_activity_at IS 'Timestamp de  ltima actividad en la sesi n';


--
-- TOC entry 235 (class 1259 OID 22262)
-- Name: af_auth_tokens; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_auth_tokens (
    token_id uuid DEFAULT gen_random_uuid() NOT NULL,
    sso_session_id uuid NOT NULL,
    access_token text NOT NULL,
    refresh_token text NOT NULL,
    issued_at timestamp with time zone DEFAULT now() NOT NULL,
    access_expires_at timestamp with time zone NOT NULL,
    refresh_expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    revoked_reason character varying(200)
);


ALTER TABLE public.af_auth_tokens OWNER TO agrofusion_migration;

--
-- TOC entry 4850 (class 0 OID 0)
-- Dependencies: 235
-- Name: COLUMN af_auth_tokens.revoked_reason; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON COLUMN public.af_auth_tokens.revoked_reason IS 'Raz n de revocaci n del token';


--
-- TOC entry 236 (class 1259 OID 22269)
-- Name: af_connection_scopes; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_connection_scopes (
    conn_id uuid NOT NULL,
    scope text NOT NULL
);


ALTER TABLE public.af_connection_scopes OWNER TO agrofusion_migration;

--
-- TOC entry 237 (class 1259 OID 22274)
-- Name: af_connections; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_connections (
    conn_id uuid DEFAULT gen_random_uuid() NOT NULL,
    external_system_id uuid NOT NULL,
    auth_type_id uuid NOT NULL,
    encrypted_auth_payload text NOT NULL,
    scopes text,
    status_term_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone,
    enc_scheme character varying(20) DEFAULT 'aes256-gcm'::character varying,
    rotated_at timestamp with time zone,
    is_enabled boolean DEFAULT true,
    version integer DEFAULT 1,
    replaced_by uuid,
    created_by uuid,
    last_used_at timestamp with time zone
);


ALTER TABLE public.af_connections OWNER TO agrofusion_migration;

--
-- TOC entry 4853 (class 0 OID 0)
-- Dependencies: 237
-- Name: TABLE af_connections; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON TABLE public.af_connections IS 'RF-BD-06: Conexiones seguras a sistemas externos con credenciales cifradas';


--
-- TOC entry 4854 (class 0 OID 0)
-- Dependencies: 237
-- Name: COLUMN af_connections.encrypted_auth_payload; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON COLUMN public.af_connections.encrypted_auth_payload IS 'RF-BD-06: Credenciales cifradas. NUNCA texto plano';


--
-- TOC entry 4855 (class 0 OID 0)
-- Dependencies: 237
-- Name: COLUMN af_connections.enc_scheme; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON COLUMN public.af_connections.enc_scheme IS 'RF-BD-06: Esquema de cifrado utilizado (ej: AES-256-GCM)';


--
-- TOC entry 4856 (class 0 OID 0)
-- Dependencies: 237
-- Name: COLUMN af_connections.rotated_at; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON COLUMN public.af_connections.rotated_at IS 'RF-BD-06: Fecha de  ltima rotaci n de credenciales';


--
-- TOC entry 4857 (class 0 OID 0)
-- Dependencies: 237
-- Name: COLUMN af_connections.version; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON COLUMN public.af_connections.version IS 'RF-BD-06: Versi n de credenciales para rotaci n';


--
-- TOC entry 4858 (class 0 OID 0)
-- Dependencies: 237
-- Name: COLUMN af_connections.replaced_by; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON COLUMN public.af_connections.replaced_by IS 'RF-BD-06: Referencia a la nueva conexi n cuando se rota';


--
-- TOC entry 238 (class 1259 OID 22284)
-- Name: af_data_contracts; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_data_contracts (
    contract_id uuid DEFAULT gen_random_uuid() NOT NULL,
    domain_id uuid NOT NULL,
    version character varying(16) NOT NULL,
    schema_json jsonb NOT NULL,
    status_term_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    valid_from timestamp with time zone DEFAULT now() NOT NULL,
    valid_to timestamp with time zone,
    schema_checksum text,
    row_version integer DEFAULT 1
);


ALTER TABLE public.af_data_contracts OWNER TO agrofusion_migration;

--
-- TOC entry 239 (class 1259 OID 22293)
-- Name: af_data_quality_rules; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_data_quality_rules (
    dq_id uuid DEFAULT gen_random_uuid() NOT NULL,
    domain_id uuid NOT NULL,
    rule_name character varying(120) NOT NULL,
    rule_expr text NOT NULL,
    severity_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    rule_type character varying(50),
    description text,
    is_enabled boolean DEFAULT true,
    status_term_id uuid,
    created_by uuid,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone
);


ALTER TABLE public.af_data_quality_rules OWNER TO agrofusion_migration;

--
-- TOC entry 4861 (class 0 OID 0)
-- Dependencies: 239
-- Name: TABLE af_data_quality_rules; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON TABLE public.af_data_quality_rules IS 'RF-BD-09: Reglas de calidad de datos por dominio con validaciones autom ticas';


--
-- TOC entry 4862 (class 0 OID 0)
-- Dependencies: 239
-- Name: COLUMN af_data_quality_rules.rule_expr; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON COLUMN public.af_data_quality_rules.rule_expr IS 'RF-BD-09: Expresi n SQL o JSONPath para validar datos';


--
-- TOC entry 4863 (class 0 OID 0)
-- Dependencies: 239
-- Name: COLUMN af_data_quality_rules.severity_id; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON COLUMN public.af_data_quality_rules.severity_id IS 'RF-BD-09: Severidad de la regla (warn/error) del vocabulario severity';


--
-- TOC entry 240 (class 1259 OID 22301)
-- Name: af_digital_signatures; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_digital_signatures (
    signature_id uuid DEFAULT gen_random_uuid() NOT NULL,
    key_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    entity_type character varying(100) NOT NULL,
    entity_id uuid NOT NULL,
    content_hash character varying(128) NOT NULL,
    signature_value text NOT NULL,
    signature_algorithm character varying(100) NOT NULL,
    signature_format character varying(50) NOT NULL,
    timestamp_rfc3161 text,
    signed_by uuid NOT NULL,
    signed_at timestamp with time zone DEFAULT now() NOT NULL,
    validated_at timestamp with time zone,
    validation_status character varying(20),
    metadata_json jsonb
);


ALTER TABLE public.af_digital_signatures OWNER TO agrofusion_migration;

--
-- TOC entry 4865 (class 0 OID 0)
-- Dependencies: 240
-- Name: TABLE af_digital_signatures; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON TABLE public.af_digital_signatures IS 'RF-INT-10: Registro de firmas digitales aplicadas a documentos y evidencias';


--
-- TOC entry 241 (class 1259 OID 22308)
-- Name: af_email_queue; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_email_queue (
    email_queue_id uuid DEFAULT gen_random_uuid() NOT NULL,
    recipient_email character varying(255) NOT NULL,
    recipient_name character varying(200),
    subject character varying(500) NOT NULL,
    body_html text NOT NULL,
    body_text text,
    template_name character varying(100),
    template_data jsonb,
    status character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    priority integer DEFAULT 5 NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    max_attempts integer DEFAULT 3 NOT NULL,
    last_error text,
    sent_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    scheduled_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.af_email_queue OWNER TO agrofusion_migration;

--
-- TOC entry 4867 (class 0 OID 0)
-- Dependencies: 241
-- Name: TABLE af_email_queue; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON TABLE public.af_email_queue IS 'Cola de emails para procesamiento as ncrono';


--
-- TOC entry 242 (class 1259 OID 22320)
-- Name: af_email_send_log; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_email_send_log (
    log_id uuid DEFAULT gen_random_uuid() NOT NULL,
    email_queue_id uuid,
    template_code character varying(100),
    recipient_email character varying(255) NOT NULL,
    subject character varying(500) NOT NULL,
    status character varying(20) NOT NULL,
    smtp_response text,
    sent_at timestamp with time zone NOT NULL,
    delivery_time_ms integer,
    ip_address inet,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.af_email_send_log OWNER TO agrofusion_migration;

--
-- TOC entry 4869 (class 0 OID 0)
-- Dependencies: 242
-- Name: TABLE af_email_send_log; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON TABLE public.af_email_send_log IS 'Bit cora de todos los emails enviados por el sistema';


--
-- TOC entry 243 (class 1259 OID 22327)
-- Name: af_email_templates; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_email_templates (
    template_id uuid DEFAULT gen_random_uuid() NOT NULL,
    template_code character varying(100) NOT NULL,
    template_name character varying(200) NOT NULL,
    subject_template character varying(500) NOT NULL,
    body_html_template text NOT NULL,
    body_text_template text NOT NULL,
    template_variables jsonb,
    is_active boolean DEFAULT true NOT NULL,
    version character varying(20) DEFAULT '1.0.0'::character varying NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid
);


ALTER TABLE public.af_email_templates OWNER TO agrofusion_migration;

--
-- TOC entry 4871 (class 0 OID 0)
-- Dependencies: 243
-- Name: TABLE af_email_templates; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON TABLE public.af_email_templates IS 'Plantillas de correos electr nicos con variables din micas';


--
-- TOC entry 244 (class 1259 OID 22337)
-- Name: af_email_verification_tokens; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_email_verification_tokens (
    verification_token_id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    token character varying(255) NOT NULL,
    token_hash character varying(255) NOT NULL,
    purpose character varying(50) DEFAULT 'email_verification'::character varying NOT NULL,
    email character varying(255) NOT NULL,
    expires_at timestamp with time zone DEFAULT (now() + '24:00:00'::interval) NOT NULL,
    used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    ip_address inet,
    user_agent text
);


ALTER TABLE public.af_email_verification_tokens OWNER TO agrofusion_migration;

--
-- TOC entry 4873 (class 0 OID 0)
-- Dependencies: 244
-- Name: TABLE af_email_verification_tokens; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON TABLE public.af_email_verification_tokens IS 'Tokens para verificaci n de email y activaci n de cuentas';


--
-- TOC entry 245 (class 1259 OID 22346)
-- Name: af_entity_mappings; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_entity_mappings (
    map_id uuid DEFAULT gen_random_uuid() NOT NULL,
    domain_id uuid NOT NULL,
    source_system_id uuid NOT NULL,
    source_field character varying(120) NOT NULL,
    target_field character varying(120) NOT NULL,
    transform_fn text,
    is_key boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    contract_id uuid NOT NULL,
    transform_lang character varying(20),
    transform_ver character varying(16),
    transform_language character varying(20),
    transform_version character varying(20),
    status_term_id uuid,
    created_by uuid,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    description text,
    data_type character varying(50)
);


ALTER TABLE public.af_entity_mappings OWNER TO agrofusion_migration;

--
-- TOC entry 246 (class 1259 OID 22354)
-- Name: af_error_log; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_error_log (
    err_id uuid DEFAULT gen_random_uuid() NOT NULL,
    context_id uuid NOT NULL,
    source_system_id uuid,
    message text NOT NULL,
    payload_excerpt text,
    severity_id uuid NOT NULL,
    at timestamp with time zone DEFAULT now() NOT NULL,
    error_code text,
    component text
);


ALTER TABLE public.af_error_log OWNER TO agrofusion_migration;

--
-- TOC entry 247 (class 1259 OID 22361)
-- Name: af_events; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_events (
    event_id uuid DEFAULT gen_random_uuid() NOT NULL,
    event_type_id uuid NOT NULL,
    entity_reference character varying(120) NOT NULL,
    payload_json jsonb,
    at timestamp with time zone DEFAULT now() NOT NULL,
    correlation_id uuid,
    idempotency_key uuid,
    source character varying(60),
    user_id uuid,
    app_id uuid,
    processed_at timestamp with time zone,
    status character varying(50) DEFAULT 'pending'::character varying
);


ALTER TABLE public.af_events OWNER TO agrofusion_migration;

--
-- TOC entry 4877 (class 0 OID 0)
-- Dependencies: 247
-- Name: TABLE af_events; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON TABLE public.af_events IS 'RF-BD-05: Eventos del sistema para integraciones y monitoreo';


--
-- TOC entry 248 (class 1259 OID 22369)
-- Name: af_exports; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_exports (
    export_id uuid DEFAULT gen_random_uuid() NOT NULL,
    report_id uuid NOT NULL,
    run_at timestamp with time zone DEFAULT now() NOT NULL,
    export_status_id uuid NOT NULL,
    format_id uuid NOT NULL,
    file_uri text,
    row_count integer
);


ALTER TABLE public.af_exports OWNER TO agrofusion_migration;

--
-- TOC entry 293 (class 1259 OID 24288)
-- Name: af_external_endpoint; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_external_endpoint (
    external_endpoint_id uuid DEFAULT gen_random_uuid() NOT NULL,
    external_url_id uuid,
    external_request_id uuid NOT NULL,
    endpoint_name character varying(150) NOT NULL,
    path text NOT NULL,
    method_term_id uuid NOT NULL,
    description text,
    body_template jsonb,
    body_type jsonb,
    params_template jsonb,
    params_type jsonb,
    response_template jsonb,
    response_type jsonb,
    status_term_id uuid NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid NOT NULL,
    updated_by uuid,
    deleted_at timestamp with time zone,
    deleted_by uuid,
    is_protected boolean DEFAULT false,
    CONSTRAINT chk_af_external_endpoint_name_not_blank CHECK ((btrim((endpoint_name)::text) <> ''::text)),
    CONSTRAINT chk_af_external_endpoint_path_not_blank CHECK ((btrim(path) <> ''::text))
);


ALTER TABLE public.af_external_endpoint OWNER TO agrofusion_migration;

--
-- TOC entry 249 (class 1259 OID 22376)
-- Name: af_external_project_roles; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_external_project_roles (
    external_role_id uuid DEFAULT gen_random_uuid() NOT NULL,
    af_project_id uuid NOT NULL,
    external_role_uuid uuid,
    role_code character varying(100) NOT NULL,
    role_name character varying(200) NOT NULL,
    role_description text,
    permissions_snapshot jsonb,
    is_active boolean DEFAULT true,
    last_synced_at timestamp with time zone,
    sync_status character varying(20),
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone,
    created_by uuid,
    deleted_at timestamp with time zone
);


ALTER TABLE public.af_external_project_roles OWNER TO agrofusion_migration;

--
-- TOC entry 4881 (class 0 OID 0)
-- Dependencies: 249
-- Name: TABLE af_external_project_roles; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON TABLE public.af_external_project_roles IS 'RF-SEG-07: Snapshot de roles IMPORTADOS autom ticamente desde las bases de datos de proyectos externos (instancias single-tenant). Cada proyecto gestiona sus propios roles en su BD. AgroFusion SSO solo los SINCRONIZA para asignaci n, NO los crea ni edita.';


--
-- TOC entry 250 (class 1259 OID 22384)
-- Name: af_external_projects; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_external_projects (
    external_project_id uuid DEFAULT gen_random_uuid() NOT NULL,
    instance_code character varying(60) NOT NULL,
    project_name character varying(120) NOT NULL,
    client_name character varying(120) NOT NULL,
    description text,
    status_term_id uuid NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now(),
    created_by uuid NOT NULL,
    deleted_at timestamp with time zone,
    deleted_by uuid,
    project_image bytea,
    project_image_mime_type text,
    project_image_name text,
    updated_by uuid,
    CONSTRAINT chk_af_external_projects_client_name_not_blank CHECK ((btrim((client_name)::text) <> ''::text)),
    CONSTRAINT chk_af_external_projects_instance_code_not_blank CHECK ((btrim((instance_code)::text) <> ''::text)),
    CONSTRAINT chk_af_external_projects_project_name_not_blank CHECK ((btrim((project_name)::text) <> ''::text))
);


ALTER TABLE public.af_external_projects OWNER TO agrofusion_migration;

--
-- TOC entry 4883 (class 0 OID 0)
-- Dependencies: 250
-- Name: TABLE af_external_projects; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON TABLE public.af_external_projects IS '[HUB] Registro de proyectos/instancias externas gestionadas por AgroFusion';


--
-- TOC entry 292 (class 1259 OID 24270)
-- Name: af_external_request; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_external_request (
    external_request_id uuid DEFAULT gen_random_uuid() NOT NULL,
    request_name character varying(150) NOT NULL,
    description text,
    body_template jsonb,
    params_template jsonb,
    response_template jsonb,
    is_required_by_agrofusion boolean DEFAULT false NOT NULL,
    status_term_id uuid NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid NOT NULL,
    updated_by uuid,
    deleted_at timestamp with time zone,
    deleted_by uuid,
    request_code character varying(80) NOT NULL
);


ALTER TABLE public.af_external_request OWNER TO agrofusion_migration;

--
-- TOC entry 251 (class 1259 OID 22392)
-- Name: af_external_roles_cache; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_external_roles_cache (
    cache_id uuid DEFAULT gen_random_uuid() NOT NULL,
    external_project_id uuid NOT NULL,
    remote_role_id uuid NOT NULL,
    role_code character varying(60) NOT NULL,
    role_name character varying(120) NOT NULL,
    role_description text,
    permissions_snapshot jsonb,
    permissions_count integer,
    last_synced_at timestamp with time zone,
    sync_status character varying(20) DEFAULT 'pending'::character varying,
    sync_error_message text,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone
);


ALTER TABLE public.af_external_roles_cache OWNER TO agrofusion_migration;

--
-- TOC entry 4886 (class 0 OID 0)
-- Dependencies: 251
-- Name: TABLE af_external_roles_cache; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON TABLE public.af_external_roles_cache IS '[HUB] Cache de roles sincronizados desde instancias externas';


--
-- TOC entry 252 (class 1259 OID 22400)
-- Name: af_external_systems; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_external_systems (
    ext_id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying(60) NOT NULL,
    base_url text,
    status_term_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    created_by uuid,
    external_project_id uuid,
    db_host character varying(255),
    db_port integer DEFAULT 5432,
    db_name character varying(100),
    db_schema character varying(100) DEFAULT 'public'::character varying,
    db_user character varying(100),
    db_password_encrypted text,
    ssl_enabled boolean DEFAULT true,
    is_active boolean DEFAULT true,
    last_test_at timestamp with time zone,
    last_test_status character varying(20),
    last_test_error text,
    module_icon character varying,
    description character varying
);


ALTER TABLE public.af_external_systems OWNER TO agrofusion_migration;

--
-- TOC entry 4888 (class 0 OID 0)
-- Dependencies: 252
-- Name: TABLE af_external_systems; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON TABLE public.af_external_systems IS '[HUB] Configuraci n de conexiones a bases de datos de instancias externas';


--
-- TOC entry 291 (class 1259 OID 24222)
-- Name: af_external_url; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_external_url (
    external_url_id uuid DEFAULT gen_random_uuid() NOT NULL,
    external_project_id uuid NOT NULL,
    url_name character varying(100) NOT NULL,
    client_url text,
    base_url text NOT NULL,
    status_term_id uuid NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid NOT NULL,
    updated_by uuid,
    deleted_at timestamp with time zone,
    deleted_by uuid,
    CONSTRAINT chk_af_external_url_base_url_not_blank CHECK ((btrim(base_url) <> ''::text)),
    CONSTRAINT chk_af_external_url_url_name_not_blank CHECK ((btrim((url_name)::text) <> ''::text))
);


ALTER TABLE public.af_external_url OWNER TO agrofusion_migration;

--
-- TOC entry 253 (class 1259 OID 22411)
-- Name: af_feature_flags; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_feature_flags (
    flag_key character varying(100) NOT NULL,
    description text,
    status_term_id uuid NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    environment character varying(24) DEFAULT 'default'::character varying NOT NULL
);


ALTER TABLE public.af_feature_flags OWNER TO agrofusion_migration;

--
-- TOC entry 254 (class 1259 OID 22418)
-- Name: af_instance_domains; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_instance_domains (
    domain_id uuid DEFAULT gen_random_uuid() NOT NULL,
    fqdn character varying(255) NOT NULL,
    is_primary boolean DEFAULT true NOT NULL,
    dns_type_term_id uuid NOT NULL,
    dns_target character varying(255) NOT NULL,
    ssl_provider character varying(60),
    ssl_status_term_id uuid,
    ssl_expires_at timestamp with time zone,
    ssl_secret_ref text,
    last_checked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.af_instance_domains OWNER TO agrofusion_migration;

--
-- TOC entry 294 (class 1259 OID 24755)
-- Name: af_kms_ca_root; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.af_kms_ca_root (
    ca_id uuid DEFAULT gen_random_uuid() NOT NULL,
    private_key_encrypted text NOT NULL,
    public_key text NOT NULL,
    certificate_pem text NOT NULL,
    fingerprint character varying(128) NOT NULL,
    serial_number character varying(100) NOT NULL,
    subject character varying(500) NOT NULL,
    issuer character varying(500) NOT NULL,
    valid_from timestamp with time zone NOT NULL,
    valid_to timestamp with time zone NOT NULL,
    status character varying(50) DEFAULT 'active'::character varying NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    rotated_at timestamp with time zone,
    created_by uuid,
    CONSTRAINT status_check CHECK (((status)::text = ANY ((ARRAY['active'::character varying, 'rotated'::character varying, 'revoked'::character varying])::text[]))),
    CONSTRAINT valid_dates_check CHECK ((valid_from < valid_to))
);


ALTER TABLE public.af_kms_ca_root OWNER TO postgres;

--
-- TOC entry 255 (class 1259 OID 22426)
-- Name: af_kms_certificates; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_kms_certificates (
    certificate_id uuid DEFAULT gen_random_uuid() NOT NULL,
    key_id uuid NOT NULL,
    certificate_pem text NOT NULL,
    serial_number character varying(100) NOT NULL,
    subject character varying(500) NOT NULL,
    issuer character varying(500) NOT NULL,
    valid_from timestamp with time zone NOT NULL,
    valid_to timestamp with time zone NOT NULL,
    fingerprint character varying(64) NOT NULL,
    issued_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at timestamp with time zone,
    revocation_reason text,
    " signature_algorithm" text,
    status character varying,
    signature_algorithm character varying(64),
    CONSTRAINT chk_kms_cert_status_valid CHECK (((status)::text = ANY ((ARRAY['active'::character varying, 'expired'::character varying, 'revoked'::character varying, 'invalid'::character varying])::text[])))
);


ALTER TABLE public.af_kms_certificates OWNER TO agrofusion_migration;

--
-- TOC entry 4894 (class 0 OID 0)
-- Dependencies: 255
-- Name: TABLE af_kms_certificates; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON TABLE public.af_kms_certificates IS 'Certificados X.509 asociados a claves criptogr ficas';


--
-- TOC entry 4895 (class 0 OID 0)
-- Dependencies: 255
-- Name: COLUMN af_kms_certificates.revoked_at; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON COLUMN public.af_kms_certificates.revoked_at IS 'Fecha de revocación del certificado (NULL si no ha sido revocado). RF-INT-14.';


--
-- TOC entry 4896 (class 0 OID 0)
-- Dependencies: 255
-- Name: COLUMN af_kms_certificates.status; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON COLUMN public.af_kms_certificates.status IS 'Estado del certificado: active | expired | revoked. RF-INT-14.';


--
-- TOC entry 4897 (class 0 OID 0)
-- Dependencies: 255
-- Name: COLUMN af_kms_certificates.signature_algorithm; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON COLUMN public.af_kms_certificates.signature_algorithm IS 'Algoritmo de firma con el que la Root CA firmó este certificado (ej. SHA256withRSA, SHA256withECDSA). RF-INT-14.';


--
-- TOC entry 256 (class 1259 OID 22433)
-- Name: af_kms_key_rotations; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_kms_key_rotations (
    rotation_id uuid DEFAULT gen_random_uuid() NOT NULL,
    old_key_id uuid NOT NULL,
    new_key_id uuid NOT NULL,
    rotation_reason character varying(200) NOT NULL,
    grace_period_days integer DEFAULT 30 NOT NULL,
    rotated_by uuid,
    rotated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.af_kms_key_rotations OWNER TO agrofusion_migration;

--
-- TOC entry 4899 (class 0 OID 0)
-- Dependencies: 256
-- Name: TABLE af_kms_key_rotations; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON TABLE public.af_kms_key_rotations IS 'Historial de rotaciones de claves criptogr ficas';


--
-- TOC entry 257 (class 1259 OID 22439)
-- Name: af_kms_keys; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_kms_keys (
    key_id uuid DEFAULT gen_random_uuid() NOT NULL,
    project_id uuid NOT NULL,
    key_alias character varying(200) NOT NULL,
    algorithm character varying(50) NOT NULL,
    key_length integer NOT NULL,
    key_purpose character varying(50) NOT NULL,
    public_key text NOT NULL,
    key_fingerprint character varying(64) NOT NULL,
    kms_key_reference character varying(500),
    status character varying(50) DEFAULT 'active'::character varying NOT NULL,
    key_version integer DEFAULT 1 NOT NULL,
    valid_from timestamp with time zone DEFAULT now() NOT NULL,
    valid_to timestamp with time zone NOT NULL,
    created_by uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    rotated_at timestamp with time zone,
    grace_period_end timestamp with time zone,
    supersedes_key_id uuid,
    private_key_encrypted text
);


ALTER TABLE public.af_kms_keys OWNER TO agrofusion_migration;

--
-- TOC entry 4901 (class 0 OID 0)
-- Dependencies: 257
-- Name: TABLE af_kms_keys; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON TABLE public.af_kms_keys IS 'Gesti n de claves criptogr ficas por proyecto para firma digital';


--
-- TOC entry 4902 (class 0 OID 0)
-- Dependencies: 257
-- Name: COLUMN af_kms_keys.private_key_encrypted; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON COLUMN public.af_kms_keys.private_key_encrypted IS 'Clave privada cifrada con AES-256-GCM usando KMS_MASTER_KEY. Formato: AESGCM256:v1:<base64(iv||ciphertext||tag)>. RF-INT-12.';


--
-- TOC entry 258 (class 1259 OID 22449)
-- Name: af_kms_operations; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_kms_operations (
    operation_id uuid DEFAULT gen_random_uuid() NOT NULL,
    key_id uuid,
    tenant_id uuid NOT NULL,
    operation_type character varying(50) NOT NULL,
    operation_status character varying(20) NOT NULL,
    performed_by uuid NOT NULL,
    performed_at timestamp with time zone DEFAULT now() NOT NULL,
    ip_address inet,
    operation_metadata jsonb,
    error_message text
);


ALTER TABLE public.af_kms_operations OWNER TO agrofusion_migration;

--
-- TOC entry 4904 (class 0 OID 0)
-- Dependencies: 258
-- Name: TABLE af_kms_operations; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON TABLE public.af_kms_operations IS 'RF-INT-10: Auditor a completa de operaciones criptogr ficas del KMS';


--
-- TOC entry 259 (class 1259 OID 22456)
-- Name: af_kms_operations_audit; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_kms_operations_audit (
    operation_id uuid DEFAULT gen_random_uuid() NOT NULL,
    key_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    operation_type character varying(50) NOT NULL,
    operation_status character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    performed_by uuid NOT NULL,
    performed_at timestamp with time zone DEFAULT now() NOT NULL,
    ip_address inet,
    operation_metadata jsonb,
    error_message text,
    created_at timestamp with time zone DEFAULT now()
);


ALTER TABLE public.af_kms_operations_audit OWNER TO agrofusion_migration;

--
-- TOC entry 260 (class 1259 OID 22465)
-- Name: af_kms_signature_validations; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_kms_signature_validations (
    validation_id uuid DEFAULT gen_random_uuid() NOT NULL,
    signature_id uuid NOT NULL,
    validation_result character varying(50) NOT NULL,
    validation_reason text,
    validated_by uuid,
    validated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.af_kms_signature_validations OWNER TO agrofusion_migration;

--
-- TOC entry 4907 (class 0 OID 0)
-- Dependencies: 260
-- Name: TABLE af_kms_signature_validations; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON TABLE public.af_kms_signature_validations IS 'Historial de validaciones de firmas digitales';


--
-- TOC entry 261 (class 1259 OID 22472)
-- Name: af_kms_signatures; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_kms_signatures (
    signature_id uuid DEFAULT gen_random_uuid() NOT NULL,
    key_id uuid NOT NULL,
    document_hash character varying(128) NOT NULL,
    hash_algorithm character varying(20) NOT NULL,
    digital_signature text NOT NULL,
    signature_format character varying(50) NOT NULL,
    signed_at timestamp with time zone DEFAULT now() NOT NULL,
    rfc3161_timestamp text,
    document_id character varying(255),
    document_type character varying(100),
    signer_user_id uuid,
    signing_reason character varying(500),
    project_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    certificate_id uuid
);


ALTER TABLE public.af_kms_signatures OWNER TO agrofusion_migration;

--
-- TOC entry 4909 (class 0 OID 0)
-- Dependencies: 261
-- Name: TABLE af_kms_signatures; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON TABLE public.af_kms_signatures IS 'Registro de todas las firmas digitales generadas por el sistema';


--
-- TOC entry 4910 (class 0 OID 0)
-- Dependencies: 261
-- Name: COLUMN af_kms_signatures.certificate_id; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON COLUMN public.af_kms_signatures.certificate_id IS 'FK al certificado X.509 asociado a la firma (RF-INT-16).';


--
-- TOC entry 262 (class 1259 OID 22480)
-- Name: af_login_attempts; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_login_attempts (
    attempt_id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid,
    email text,
    success boolean NOT NULL,
    reason text,
    ip inet,
    at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.af_login_attempts OWNER TO agrofusion_migration;

--
-- TOC entry 263 (class 1259 OID 22487)
-- Name: af_modules; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_modules (
    af_module_id uuid DEFAULT gen_random_uuid() NOT NULL,
    code character varying(60) NOT NULL,
    name character varying(120) NOT NULL,
    status_term_id uuid NOT NULL,
    deleted_at timestamp with time zone,
    created_by uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone,
    af_project_id uuid,
    disabled_at timestamp with time zone,
    description text,
    row_version integer DEFAULT 1
);


ALTER TABLE public.af_modules OWNER TO agrofusion_migration;

--
-- TOC entry 264 (class 1259 OID 22495)
-- Name: af_otp_codes; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_otp_codes (
    otp_id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    otp_code character varying(10),
    otp_hash text,
    purpose character varying(50) NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    used_at timestamp with time zone,
    failed_attempts integer DEFAULT 0 NOT NULL,
    ip_address inet,
    user_agent text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.af_otp_codes OWNER TO agrofusion_migration;

--
-- TOC entry 4914 (class 0 OID 0)
-- Dependencies: 264
-- Name: TABLE af_otp_codes; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON TABLE public.af_otp_codes IS 'Códigos OTP para autenticación multifactor (MFA)';


--
-- TOC entry 4915 (class 0 OID 0)
-- Dependencies: 264
-- Name: COLUMN af_otp_codes.otp_hash; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON COLUMN public.af_otp_codes.otp_hash IS 'Hash del código OTP (recomendado para seguridad)';


--
-- TOC entry 4916 (class 0 OID 0)
-- Dependencies: 264
-- Name: COLUMN af_otp_codes.purpose; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON COLUMN public.af_otp_codes.purpose IS 'Propósito del OTP: login_2fa, password_reset, etc';


--
-- TOC entry 265 (class 1259 OID 22503)
-- Name: af_password_history; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_password_history (
    history_id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    password_hash text NOT NULL,
    changed_at timestamp with time zone DEFAULT now() NOT NULL,
    changed_by uuid,
    change_reason character varying(50) NOT NULL,
    ip_address inet,
    user_agent text
);


ALTER TABLE public.af_password_history OWNER TO agrofusion_migration;

--
-- TOC entry 4918 (class 0 OID 0)
-- Dependencies: 265
-- Name: TABLE af_password_history; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON TABLE public.af_password_history IS 'Historial de cambios de contrase a para prevenir reuso';


--
-- TOC entry 266 (class 1259 OID 22510)
-- Name: af_password_policies; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_password_policies (
    policy_id uuid DEFAULT gen_random_uuid() NOT NULL,
    policy_name character varying(100) NOT NULL,
    min_length integer DEFAULT 8 NOT NULL,
    max_length integer DEFAULT 128 NOT NULL,
    require_uppercase boolean DEFAULT true NOT NULL,
    require_lowercase boolean DEFAULT true NOT NULL,
    require_numbers boolean DEFAULT true NOT NULL,
    require_special_chars boolean DEFAULT true NOT NULL,
    special_chars_allowed character varying(50) DEFAULT '!@#$%^&*()_+-=[]{}|;:,.<>?'::character varying,
    password_history_count integer DEFAULT 5 NOT NULL,
    password_expiration_days integer,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.af_password_policies OWNER TO agrofusion_migration;

--
-- TOC entry 4920 (class 0 OID 0)
-- Dependencies: 266
-- Name: TABLE af_password_policies; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON TABLE public.af_password_policies IS 'Pol ticas de seguridad para contrase as del sistema';


--
-- TOC entry 267 (class 1259 OID 22525)
-- Name: af_password_reset_tokens; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_password_reset_tokens (
    reset_token_id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    token character varying(255) NOT NULL,
    token_hash character varying(255) NOT NULL,
    email character varying(255) NOT NULL,
    reset_code character varying(10),
    expires_at timestamp with time zone DEFAULT (now() + '01:00:00'::interval) NOT NULL,
    used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    ip_address inet,
    user_agent text,
    invalidated_at timestamp with time zone,
    invalidation_reason character varying(200)
);


ALTER TABLE public.af_password_reset_tokens OWNER TO agrofusion_migration;

--
-- TOC entry 4922 (class 0 OID 0)
-- Dependencies: 267
-- Name: TABLE af_password_reset_tokens; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON TABLE public.af_password_reset_tokens IS 'Tokens para proceso de restablecimiento de contrase a';


--
-- TOC entry 268 (class 1259 OID 22533)
-- Name: af_permissions; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_permissions (
    af_perm_id uuid DEFAULT gen_random_uuid() NOT NULL,
    namespace_id uuid NOT NULL,
    resource_id uuid NOT NULL,
    action_id uuid NOT NULL,
    description text,
    status_term_id uuid NOT NULL,
    deleted_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone,
    af_project_id uuid,
    af_module_id uuid,
    af_submodule_id uuid,
    perm_type_term_id uuid,
    perm_state_term_id uuid,
    code character varying(80) NOT NULL,
    name character varying(120) NOT NULL
);


ALTER TABLE public.af_permissions OWNER TO agrofusion_migration;

--
-- TOC entry 269 (class 1259 OID 22540)
-- Name: af_project_connections; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_project_connections (
    connection_id uuid DEFAULT gen_random_uuid() NOT NULL,
    af_project_id uuid NOT NULL,
    db_host character varying(255) NOT NULL,
    db_port integer DEFAULT 5432 NOT NULL,
    db_name character varying(100) NOT NULL,
    db_user character varying(100) NOT NULL,
    db_password_encrypted text NOT NULL,
    db_schema character varying(100) DEFAULT 'public'::character varying,
    sync_enabled boolean DEFAULT true,
    sync_frequency_minutes integer DEFAULT 60,
    last_sync_at timestamp with time zone,
    last_sync_status character varying(20),
    last_sync_error text,
    external_roles_table character varying(100) DEFAULT 'roles'::character varying,
    external_permissions_table character varying(100) DEFAULT 'permissions'::character varying,
    external_role_permissions_table character varying(100) DEFAULT 'role_permissions'::character varying,
    is_active boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone,
    created_by uuid
);


ALTER TABLE public.af_project_connections OWNER TO agrofusion_migration;

--
-- TOC entry 4925 (class 0 OID 0)
-- Dependencies: 269
-- Name: TABLE af_project_connections; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON TABLE public.af_project_connections IS 'Configuracion de conexiones a bases de datos de proyectos externos para sincronizacion de roles';


--
-- TOC entry 4926 (class 0 OID 0)
-- Dependencies: 269
-- Name: COLUMN af_project_connections.db_password_encrypted; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON COLUMN public.af_project_connections.db_password_encrypted IS 'Password cifrada usando pgcrypto extension';


--
-- TOC entry 270 (class 1259 OID 22555)
-- Name: af_projects; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_projects (
    af_project_id uuid DEFAULT gen_random_uuid() NOT NULL,
    code character varying(40) NOT NULL,
    name character varying(120) NOT NULL,
    status_term_id uuid NOT NULL,
    disabled_at timestamp with time zone,
    created_by uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    description text,
    row_version integer DEFAULT 1
);


ALTER TABLE public.af_projects OWNER TO agrofusion_migration;

--
-- TOC entry 271 (class 1259 OID 22563)
-- Name: af_report_runs; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_report_runs (
    run_id uuid DEFAULT gen_random_uuid() NOT NULL,
    report_id uuid NOT NULL,
    user_id uuid NOT NULL,
    params_json jsonb,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    ended_at timestamp with time zone,
    status character varying(20) DEFAULT 'running'::character varying NOT NULL,
    execution_time_ms integer,
    row_count integer,
    result_format character varying(20),
    result_size_bytes bigint,
    result_uri text,
    error_message text
);


ALTER TABLE public.af_report_runs OWNER TO agrofusion_migration;

--
-- TOC entry 4929 (class 0 OID 0)
-- Dependencies: 271
-- Name: TABLE af_report_runs; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON TABLE public.af_report_runs IS 'RF-BD-19: Registro de ejecuciones de reportes din micos con m tricas de rendimiento';


--
-- TOC entry 272 (class 1259 OID 22571)
-- Name: af_report_schedules; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_report_schedules (
    sched_id uuid DEFAULT gen_random_uuid() NOT NULL,
    report_id uuid NOT NULL,
    cron character varying(80) NOT NULL,
    format_id uuid NOT NULL,
    delivery_method_id uuid NOT NULL,
    delivery_target text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.af_report_schedules OWNER TO agrofusion_migration;

--
-- TOC entry 273 (class 1259 OID 22578)
-- Name: af_reports; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_reports (
    report_id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying(120) NOT NULL,
    domain_id uuid,
    query_definition text NOT NULL,
    created_by uuid NOT NULL,
    status_term_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.af_reports OWNER TO agrofusion_migration;

--
-- TOC entry 274 (class 1259 OID 22585)
-- Name: af_role_permissions; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_role_permissions (
    af_role_id uuid NOT NULL,
    af_perm_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone
);


ALTER TABLE public.af_role_permissions OWNER TO agrofusion_migration;

--
-- TOC entry 275 (class 1259 OID 22589)
-- Name: af_roles; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_roles (
    af_role_id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying(80) NOT NULL,
    description text,
    deleted_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone,
    af_project_id uuid NOT NULL,
    role_type_term_id uuid,
    code character varying(60),
    role_state_term_id uuid,
    is_system boolean DEFAULT false,
    status_term_id uuid,
    is_system_role boolean DEFAULT false,
    is_active boolean DEFAULT true,
    CONSTRAINT chk_af_roles_system_flags_consistent CHECK ((COALESCE(is_system, false) = COALESCE(is_system_role, false)))
);


ALTER TABLE public.af_roles OWNER TO agrofusion_migration;

--
-- TOC entry 276 (class 1259 OID 22599)
-- Name: af_security_events; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_security_events (
    event_id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid,
    event_type character varying(50) NOT NULL,
    event_description text,
    severity character varying(20) DEFAULT 'info'::character varying NOT NULL,
    ip_address inet,
    user_agent text,
    metadata jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_severity CHECK (((severity)::text = ANY ((ARRAY['info'::character varying, 'warning'::character varying, 'error'::character varying, 'critical'::character varying])::text[])))
);


ALTER TABLE public.af_security_events OWNER TO agrofusion_migration;

--
-- TOC entry 4935 (class 0 OID 0)
-- Dependencies: 276
-- Name: TABLE af_security_events; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON TABLE public.af_security_events IS 'Registro de eventos de seguridad del sistema';


--
-- TOC entry 277 (class 1259 OID 22607)
-- Name: af_settings; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_settings (
    key character varying(100) NOT NULL,
    value jsonb NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    environment character varying(24) DEFAULT 'default'::character varying NOT NULL
);


ALTER TABLE public.af_settings OWNER TO agrofusion_migration;

--
-- TOC entry 278 (class 1259 OID 22614)
-- Name: af_smtp_config; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_smtp_config (
    smtp_config_id uuid DEFAULT gen_random_uuid() NOT NULL,
    config_name character varying(100) NOT NULL,
    smtp_host character varying(255) NOT NULL,
    smtp_port integer NOT NULL,
    smtp_username character varying(255),
    smtp_password_encrypted text,
    encryption_type character varying(20) NOT NULL,
    from_email character varying(255) NOT NULL,
    from_name character varying(200) NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    is_default boolean DEFAULT false NOT NULL,
    max_emails_per_hour integer DEFAULT 100,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.af_smtp_config OWNER TO agrofusion_migration;

--
-- TOC entry 4938 (class 0 OID 0)
-- Dependencies: 278
-- Name: TABLE af_smtp_config; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON TABLE public.af_smtp_config IS 'Configuraciones de servidores SMTP para env o de correos';


--
-- TOC entry 279 (class 1259 OID 22625)
-- Name: af_sso_sessions; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_sso_sessions (
    sso_session_id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    last_seen_at timestamp with time zone,
    ip inet,
    user_agent text
);


ALTER TABLE public.af_sso_sessions OWNER TO agrofusion_migration;

--
-- TOC entry 280 (class 1259 OID 22632)
-- Name: af_sso_tokens; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_sso_tokens (
    token_id uuid DEFAULT gen_random_uuid() NOT NULL,
    sso_session_id uuid NOT NULL,
    app_id uuid,
    scope text,
    issued_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    idp_jti uuid
);


ALTER TABLE public.af_sso_tokens OWNER TO agrofusion_migration;

--
-- TOC entry 281 (class 1259 OID 22639)
-- Name: af_submodules; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_submodules (
    af_submodule_id uuid DEFAULT gen_random_uuid() NOT NULL,
    module_id uuid NOT NULL,
    code character varying(60) NOT NULL,
    name character varying(120) NOT NULL,
    status_term_id uuid NOT NULL,
    deleted_at timestamp with time zone,
    created_by uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone,
    disabled_at timestamp with time zone,
    description text,
    is_editable boolean DEFAULT true
);


ALTER TABLE public.af_submodules OWNER TO agrofusion_migration;

--
-- TOC entry 282 (class 1259 OID 22646)
-- Name: af_sync_jobs; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_sync_jobs (
    job_id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying(120) NOT NULL,
    domain_id uuid NOT NULL,
    source_system_id uuid NOT NULL,
    job_status_id uuid NOT NULL,
    cron_expr character varying(80),
    retries integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone
);


ALTER TABLE public.af_sync_jobs OWNER TO agrofusion_migration;

--
-- TOC entry 283 (class 1259 OID 22652)
-- Name: af_sync_runs; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_sync_runs (
    run_id uuid DEFAULT gen_random_uuid() NOT NULL,
    job_id uuid NOT NULL,
    run_status_id uuid NOT NULL,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    ended_at timestamp with time zone,
    fetched integer DEFAULT 0 NOT NULL,
    processed integer DEFAULT 0 NOT NULL,
    upserts integer DEFAULT 0 NOT NULL,
    errors integer DEFAULT 0 NOT NULL,
    log_uri text,
    correlation_id uuid,
    idempotency_key uuid
);


ALTER TABLE public.af_sync_runs OWNER TO agrofusion_migration;

--
-- TOC entry 284 (class 1259 OID 22663)
-- Name: af_user_app_access; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_user_app_access (
    user_id uuid NOT NULL,
    app_id uuid NOT NULL,
    access_level_term_id uuid,
    granted_by uuid,
    granted_at timestamp with time zone DEFAULT now() NOT NULL,
    valid_from timestamp with time zone DEFAULT now() NOT NULL,
    valid_to timestamp with time zone,
    access_token_hash character varying(64),
    refresh_token_hash character varying(64),
    scopes_granted jsonb,
    expires_at timestamp with time zone,
    revoked_at timestamp with time zone,
    last_used_at timestamp with time zone
);


ALTER TABLE public.af_user_app_access OWNER TO agrofusion_migration;

--
-- TOC entry 285 (class 1259 OID 22670)
-- Name: af_user_project_roles; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.af_user_project_roles (
    upr_id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    af_project_id uuid NOT NULL,
    af_role_id uuid NOT NULL,
    assigned_at timestamp with time zone DEFAULT now() NOT NULL,
    valid_from timestamp with time zone DEFAULT now() NOT NULL,
    valid_to timestamp with time zone,
    created_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone,
    valid_range tstzrange GENERATED ALWAYS AS (tstzrange(valid_from, valid_to, '[]'::text)) STORED,
    assignment_status_term_id uuid,
    suspension_reason text,
    suspended_at timestamp with time zone,
    suspended_by uuid,
    suspension_until timestamp with time zone,
    updated_by uuid
);


ALTER TABLE public.af_user_project_roles OWNER TO agrofusion_migration;

--
-- TOC entry 286 (class 1259 OID 22680)
-- Name: cat_terms; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.cat_terms (
    term_id uuid DEFAULT gen_random_uuid() NOT NULL,
    vocabulary_id uuid NOT NULL,
    code character varying(80) NOT NULL,
    label character varying(120),
    description text,
    parent_term_id uuid,
    extra jsonb,
    is_enabled boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.cat_terms OWNER TO agrofusion_migration;

--
-- TOC entry 287 (class 1259 OID 22688)
-- Name: cat_vocabularies; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.cat_vocabularies (
    vocabulary_id uuid DEFAULT gen_random_uuid() NOT NULL,
    vocabulary_code character varying(50) NOT NULL,
    name character varying(120),
    description text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.cat_vocabularies OWNER TO agrofusion_migration;

--
-- TOC entry 288 (class 1259 OID 22695)
-- Name: mfa_methods; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.mfa_methods (
    mfa_id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    method_type character varying(40) NOT NULL,
    secret_encrypted text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at timestamp with time zone
);


ALTER TABLE public.mfa_methods OWNER TO agrofusion_migration;

--
-- TOC entry 4949 (class 0 OID 0)
-- Dependencies: 288
-- Name: COLUMN mfa_methods.secret_encrypted; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON COLUMN public.mfa_methods.secret_encrypted IS 'Secreto cifrado del m todo MFA. Debe almacenarse usando pgcrypto.encrypt() o bcrypt para TOTP seeds.';


--
-- TOC entry 289 (class 1259 OID 22702)
-- Name: provisioning_status; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.provisioning_status (
    user_id uuid NOT NULL,
    app_id uuid NOT NULL,
    provisioning_status_term_id uuid NOT NULL,
    last_sync_at timestamp with time zone,
    retries integer DEFAULT 0 NOT NULL,
    last_error text,
    external_subject character varying(120),
    can_sync_roles boolean DEFAULT false NOT NULL,
    can_sync_groups boolean DEFAULT false NOT NULL,
    row_version integer DEFAULT 1,
    status_code character varying(50) NOT NULL,
    status_name character varying(100) NOT NULL,
    description text,
    is_final_state boolean DEFAULT false,
    created_at timestamp with time zone DEFAULT now()
);


ALTER TABLE public.provisioning_status OWNER TO agrofusion_migration;

--
-- TOC entry 290 (class 1259 OID 22713)
-- Name: users; Type: TABLE; Schema: public; Owner: agrofusion_migration
--

CREATE TABLE public.users (
    user_id uuid DEFAULT gen_random_uuid() NOT NULL,
    email public.citext NOT NULL,
    name character varying(120) NOT NULL,
    password_hash text NOT NULL,
    status_term_id uuid NOT NULL,
    is_mfa_enabled boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone,
    failed_attempts integer DEFAULT 0 NOT NULL,
    locked_at timestamp with time zone,
    last_login_at timestamp with time zone,
    last_login_ip inet,
    deleted_at timestamp with time zone,
    created_by uuid,
    updated_by uuid,
    email_verified_at timestamp with time zone,
    password_changed_at timestamp with time zone DEFAULT now(),
    row_version integer DEFAULT 1,
    identity_number character varying(20) NOT NULL,
    blocked_until timestamp with time zone
);


ALTER TABLE public.users OWNER TO agrofusion_migration;

--
-- TOC entry 4952 (class 0 OID 0)
-- Dependencies: 290
-- Name: COLUMN users.email_verified_at; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON COLUMN public.users.email_verified_at IS 'Timestamp de verificaci n de email';


--
-- TOC entry 4953 (class 0 OID 0)
-- Dependencies: 290
-- Name: COLUMN users.password_changed_at; Type: COMMENT; Schema: public; Owner: agrofusion_migration
--

COMMENT ON COLUMN public.users.password_changed_at IS 'Timestamp de  ltimo cambio de contrase a';


--
-- TOC entry 295 (class 1259 OID 24776)
-- Name: vw_af_kms_ca_root_active; Type: VIEW; Schema: public; Owner: postgres
--

CREATE VIEW public.vw_af_kms_ca_root_active AS
 SELECT af_kms_ca_root.ca_id,
    af_kms_ca_root.public_key,
    af_kms_ca_root.certificate_pem,
    af_kms_ca_root.fingerprint,
    af_kms_ca_root.serial_number,
    af_kms_ca_root.subject,
    af_kms_ca_root.issuer,
    af_kms_ca_root.valid_from,
    af_kms_ca_root.valid_to,
    af_kms_ca_root.created_at,
    af_kms_ca_root.created_by
   FROM public.af_kms_ca_root
  WHERE (((af_kms_ca_root.status)::text = 'active'::text) AND (af_kms_ca_root.valid_from <= now()) AND (af_kms_ca_root.valid_to > now()));


ALTER VIEW public.vw_af_kms_ca_root_active OWNER TO postgres;

--
-- TOC entry 4654 (class 0 OID 22101)
-- Dependencies: 215
-- Data for Name: af_accounting_mapping_rules; Type: TABLE DATA; Schema: public; Owner: agrofusion_migration
--

COPY public.af_accounting_mapping_rules (rule_id, source_project_id, source_transaction_type, debit_account_code, credit_account_code, description_template, amount_field_path, is_active, created_by, created_at, updated_at, updated_by) FROM stdin;
\.


--
-- TOC entry 4655 (class 0 OID 22109)
-- Dependencies: 216
-- Data for Name: af_accounting_queue; Type: TABLE DATA; Schema: public; Owner: agrofusion_migration
--

COPY public.af_accounting_queue (queue_id, source_project_id, source_module_code, transaction_type, transaction_data, accounting_date, user_id, status, priority, attempts, max_attempts, last_error, created_at, processed_at, sent_at, external_transaction_id) FROM stdin;
e3348e35-58d1-477b-adb5-81abbd861ff1	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"Currency": "COP", "TotalNet": 173.4, "TotalInvoices": 3, "TotalDocuments": 5, "TotalGrossAmount": 166.2, "TotalTransactions": 2}, "invoices": [{"Lines": [{"Code": "SVC-2025-0011", "Name": "Prueba 333", "Taxes": [{"Rate": "12.00", "Amount": "7.20", "TaxType": "01"}], "Value": 67.2, "LineType": "Prueba 333", "Quantity": 5, "UnitPrice": 12, "Description": "Prueba 333", "accounting_account": ["4310"]}], "Header": {"Type": {"Code": "01", "Name": "Factura de Venta"}, "Prefix": "SIGMA-FACT", "Serial": "SETP990021973", "Status": "PAID", "DueDate": "10-02-2026 07:34:34 AM", "IssueDate": "10-02-2026 07:34:33 AM", "UpdatedAt": "10-02-2026 07:34:34 AM", "DocumentId": "sigma-fact-E031E1BC"}, "Totals": {"Subtotal": 60, "TotalVAT": 7.2, "TotalPayment": 67.2, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 67.2}, "ThirdParty": {"NIT": "", "City": null, "Name": "Fabian Ramos Semanate", "Email": "u20212199794@usco.edu.co", "Address": "Calle 21 # 83-35", "Country": null}}, {"Lines": [{"Code": "SVC-2025-0012", "Name": "taller don Andress", "Taxes": [], "Value": 36, "LineType": "taller don Andress", "Quantity": 3, "UnitPrice": 12, "Description": "taller don Andress", "accounting_account": ["4310"]}], "Header": {"Type": {"Code": "INVOICE", "Name": "Factura de Venta"}, "Prefix": "SIGMA-FACT", "Serial": "sigma-fact-AAF0AB55", "Status": "PENDING", "DueDate": "2026-03-07", "IssueDate": "2026-03-07", "UpdatedAt": "2026-03-07", "DocumentId": "sigma-fact-AAF0AB55"}, "Totals": {"Subtotal": 35.28, "TotalVAT": 4.23, "TotalPayment": 39, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 39}, "ThirdParty": {"NIT": "", "City": null, "Name": "Roberto Carlos Silva Mendoza", "Email": "roberto.silva@email.com", "Address": "Carrera 50 #78-23", "Country": null}}, {"Lines": [], "Header": {"Type": {"Code": "INVOICE", "Name": "Factura de Venta"}, "Prefix": "SIGMA-FACT", "Serial": "sigma-fact-78496A7B", "Status": "PENDING", "DueDate": "2026-03-07", "IssueDate": "2026-03-07", "UpdatedAt": "2026-03-07", "DocumentId": "sigma-fact-78496A7B"}, "Totals": {"Subtotal": 0, "TotalVAT": 0, "TotalPayment": 0, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 0}, "ThirdParty": {"NIT": "", "City": null, "Name": "RAMIREZ SAS", "Email": "ramirezcollazos@gmail.com", "Address": "Cra 30 #29-31", "Country": null}}], "metadata": {"ExchangeId": "AF-2026-05-1365460", "GeneratedAt": "2026-05-23T04:06:10.669828Z", "GeneratedBy": "sigma-integration-service", "SourceSystem": {"SystemId": "sigma-prod-01", "SystemNIT": "9001766666", "SystemName": "Sigma", "Environment": "production"}, "RequestedPeriod": {"To": "2026-12-31", "From": "2026-01-01"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "10-02-2026 07:34:34 AM", "Type": {"Code": "PAY", "Name": "Pago de Factura"}, "Notes": "Pago asociado a factura sigma-fact-E031E1BC", "Amount": 67.2, "Status": "COMPLETED", "Currency": "COP", "UpdatedAt": "2025-11-06 15:07:17.010993+00:00", "DocumentId": "PAY-sigma-fact-E031E1BC-10-02-2026", "ThirdParty": {"NIT": "", "City": null, "Name": "Fabian Ramos Semanate", "Email": null, "Address": null, "Country": null}, "PaymentMethod": {"Code": "CHECK"}, "RelatedInvoiceId": "sigma-fact-E031E1BC"}, {"Date": "2026-03-07", "Type": {"Code": "PAY", "Name": "Pago de Factura"}, "Notes": "Pago asociado a factura sigma-fact-78496A7B", "Amount": 0, "Status": "COMPLETED", "Currency": "COP", "UpdatedAt": "2025-11-06 15:07:17.010993+00:00", "DocumentId": "PAY-sigma-fact-78496A7B-2026-03-07", "ThirdParty": {"NIT": "", "City": null, "Name": "RAMIREZ SAS", "Email": null, "Address": null, "Country": null}, "PaymentMethod": {"Code": "CASH"}, "RelatedInvoiceId": "sigma-fact-78496A7B"}]}	2026-05-23	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	rejected	1	1	2	\N	2026-05-23 04:06:12.303638+00	2026-05-23 04:06:12.494649+00	2026-05-23 04:06:12.303638+00	\N
7cd04eae-2c34-44dc-ad40-903debe24788	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 2, "TotalTransactions": 1}, "invoices": [{"Lines": [{"Code": "FERT-001", "Name": "Fertilizante Premium", "Taxes": [{"Rate": 19, "Amount": 95000, "TaxType": "IVA"}], "Value": 500000, "LineType": "PRODUCT", "Quantity": 10, "UnitPrice": 50000, "Description": "Compra de fertilizante agrícola"}], "Header": {"Type": {"Code": "03", "Name": "Compra"}, "Status": "PAID", "DueDate": "2026-05-30", "IssueDate": "2026-05-01", "DocumentId": "FC-2026-0001"}, "Totals": {"Subtotal": 500000, "TotalVAT": 95000, "TotalPayment": 595000, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 0}, "ThirdParty": {"NIT": "9012345678", "Name": "Proveedor Insumos Agro SAS"}}], "metadata": {"ExchangeId": "AF-2026-05-020232", "GeneratedAt": "2026-05-01T11:00:00Z", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "9001766666"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-02", "Type": {"Code": "PAYMENT", "Name": "Pago Factura Compra"}, "Amount": 595000, "Status": "COMPLETED", "Currency": "COP", "ThirdParty": {"NIT": "9012345678", "Name": "Proveedor Insumos Agro SAS"}, "Description": "Pago total factura de compra FC-2026-0001", "PaymentMethod": {"Code": "BANK_TRANSFER", "Name": "Transferencia Bancaria"}, "TransactionId": "PAY-SUP-2026-0001", "ReferenceDocument": {"DocumentId": "FC-2026-0001"}}]}	2026-05-24	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	partial	1	1	2	\N	2026-05-24 03:17:57.032741+00	2026-05-24 03:17:57.784368+00	2026-05-24 03:17:57.032741+00	\N
21ae6e0a-0e45-4744-9bd6-2af89652dae4	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 2, "TotalTransactions": 1}, "invoices": [{"Lines": [{"Code": "FERT-001", "Name": "Fertilizante Premium", "Taxes": [{"Rate": 19, "Amount": 95000, "TaxType": "IVA"}], "Value": 500000, "LineType": "PRODUCT", "Quantity": 10, "UnitPrice": 50000, "Description": "Compra de fertilizante agrícola"}], "Header": {"Type": {"Code": "03", "Name": "Compra"}, "Status": "PAID", "DueDate": "2026-05-30", "IssueDate": "2026-05-01", "DocumentId": "FC-2026-0001"}, "Totals": {"Subtotal": 500000, "TotalVAT": 95000, "TotalPayment": 595000, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 0}, "ThirdParty": {"NIT": "9012345678", "Name": "Proveedor Insumos Agro SAS"}}], "metadata": {"ExchangeId": "AF-2026-05-020292", "GeneratedAt": "2026-05-01T11:00:00Z", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "9001766666"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-02", "Type": {"Code": "PAY", "Name": "Pago Factura Compra"}, "Amount": 595000, "Status": "COMPLETED", "Currency": "COP", "ThirdParty": {"NIT": "9012345678", "Name": "Proveedor Insumos Agro SAS"}, "Description": "Pago total factura de compra FC-2026-0001", "PaymentMethod": {"Code": "BANK_TRANSFER", "Name": "Transferencia Bancaria"}, "TransactionId": "PAY-SUP-2026-0001", "ReferenceDocument": {"DocumentId": "FC-2026-0001"}}]}	2026-05-24	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	rejected	1	1	2	\N	2026-05-24 03:21:54.420518+00	2026-05-24 03:21:54.709738+00	2026-05-24 03:21:54.420518+00	\N
37ae7d53-d672-4482-a1d4-52a6eee8a1db	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 2, "TotalTransactions": 1}, "invoices": [{"Lines": [{"Code": "FERT-0093", "Name": "Fertilizante Premium", "Taxes": [{"Rate": 19, "Amount": 123500, "TaxType": "IVA"}], "Value": 650000, "LineType": "PRODUCT", "Quantity": 13, "UnitPrice": 50000, "Description": "Compra nueva mayo"}], "Header": {"Type": {"Code": "02", "Name": "Compra"}, "Status": "PAID", "DueDate": "2026-06-07", "IssueDate": "2026-05-23", "DocumentId": "FC-2026-0093"}, "Totals": {"Subtotal": 650000, "TotalVAT": 123500, "TotalPayment": 773500, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 0}, "ThirdParty": {"NIT": "9012345678", "Name": "Proveedor Insumos Agro SAS"}}], "metadata": {"ExchangeId": "AF-2026-05-9393", "GeneratedAt": "2026-05-23", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "9001766666"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-23", "Type": {"Code": "PAY", "Name": "Pago Factura Compra"}, "Notes": "Pago total factura FC-2026-0093", "Amount": 773500, "Status": "COMPLETED", "Currency": "COP", "UpdatedAt": "2026-05-23", "DocumentId": "PAY-SUP-2026-0093", "ThirdParty": {"NIT": "9012345678", "Name": "Proveedor Insumos Agro SAS"}, "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia Bancaria"}, "RelatedInvoiceId": "FC-2026-0093"}]}	2026-05-24	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	partial	1	1	2	\N	2026-05-24 03:24:34.361865+00	2026-05-24 03:24:34.850333+00	2026-05-24 03:24:34.361865+00	\N
e739de24-f1a3-45a7-83ea-8269bedf2116	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 1, "TotalTransactions": 0}, "invoices": [{"Lines": [{"Code": "PROD-0094", "Name": "Kit Riego Premium", "Taxes": [{"Rate": 19, "Amount": 79800, "TaxType": "IVA"}], "Value": 420000, "LineType": "PRODUCT", "Quantity": 6, "UnitPrice": 70000, "Description": "Venta nueva mayo"}], "Header": {"Type": {"Code": "01", "Name": "Venta"}, "Status": "PAID", "DueDate": "2026-06-07", "IssueDate": "2026-05-23", "DocumentId": "FV-2026-0095"}, "Totals": {"Subtotal": 420000, "TotalVAT": 79800, "TotalPayment": 499800, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 0}, "ThirdParty": {"NIT": "9001760205", "Name": "Cliente Agro Comercial SAS"}}], "metadata": {"ExchangeId": "AF-2026-05-9334", "GeneratedAt": "2026-05-23", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "9001766666"}, "StandardVersion": "1.0"}, "transactions": []}	2026-05-24	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-24 03:33:31.960104+00	2026-05-24 03:33:32.311454+00	2026-05-24 03:33:31.960104+00	\N
28d9e4d8-2257-4bb8-8de5-be28d2385d9f	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 1, "TotalTransactions": 0}, "invoices": [{"Lines": [{"Code": "SERV-AP23-01", "Name": "Servicio tecnico agricola", "Taxes": [{"Rate": 19, "Amount": 190000, "TaxType": "IVA"}], "Value": 1000000, "LineType": "SERVICE", "Quantity": 1, "UnitPrice": 1000000, "Description": "Factura compra HU-AP-23 E4"}], "Header": {"Type": {"Code": "02", "Name": "Compra"}, "Status": "ACTIVE", "DueDate": "2026-06-22", "IssueDate": "2026-05-23", "DocumentId": "FAC-PROV-2026-00444"}, "Totals": {"Subtotal": 1000000, "TotalVAT": 190000, "TotalPayment": 1190000, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 1190000}, "ThirdParty": {"NIT": "9012345678", "Name": "Proveedor Insumos Agro SAS"}}], "metadata": {"ExchangeId": "AF-2026-05-9423", "GeneratedAt": "2026-05-23", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "9001766666"}, "StandardVersion": "1.0"}, "transactions": []}	2026-05-24	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	rejected	1	1	2	\N	2026-05-24 04:03:35.836515+00	2026-05-24 04:03:36.127278+00	2026-05-24 04:03:35.836515+00	\N
3b9ff3ea-ddd2-42b4-b950-d93859da0bcc	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 2, "TotalTransactions": 1}, "invoices": [{"Lines": [{"Code": "FERT-0093", "Name": "Fertilizante Premium", "Taxes": [{"Rate": 19, "Amount": 123500, "TaxType": "IVA"}], "Value": 650000, "LineType": "PRODUCT", "Quantity": 13, "UnitPrice": 50000, "Description": "Compra nueva mayo"}], "Header": {"Type": {"Code": "02", "Name": "Compra"}, "Status": "PAID", "DueDate": "2026-06-07", "IssueDate": "2026-05-23", "DocumentId": "FC-2026-0093"}, "Totals": {"Subtotal": 650000, "TotalVAT": 123500, "TotalPayment": 773500, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 0}, "ThirdParty": {"NIT": "9012345678", "Name": "Proveedor Insumos Agro SAS"}}], "metadata": {"ExchangeId": "AF-2026-05-9323", "GeneratedAt": "2026-05-23", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "9001766666"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-23", "Type": {"Code": "PAY", "Name": "Pago Factura Compra"}, "Notes": "Pago total factura FC-2026-0093", "Amount": 773500, "Status": "COMPLETED", "Currency": "COP", "UpdatedAt": "2026-05-23", "DocumentId": "PAY-SUP-2026-0093", "ThirdParty": {"NIT": "9012345678", "Name": "Proveedor Insumos Agro SAS"}, "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia Bancaria"}, "RelatedInvoiceId": "FC-2026-0093"}]}	2026-05-24	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	partial	1	1	2	\N	2026-05-24 03:26:11.562585+00	2026-05-24 03:26:11.92094+00	2026-05-24 03:26:11.562585+00	\N
30f46f22-037f-4313-9960-864d0ebf8982	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 2, "TotalTransactions": 1}, "invoices": [{"Lines": [{"Code": "PROD-0094", "Name": "Kit Riego Premium", "Taxes": [{"Rate": 19, "Amount": 79800, "TaxType": "IVA"}], "Value": 420000, "LineType": "PRODUCT", "Quantity": 6, "UnitPrice": 70000, "Description": "Venta nueva mayo"}], "Header": {"Type": {"Code": "01", "Name": "Venta"}, "Status": "PAID", "DueDate": "2026-06-07", "IssueDate": "2026-05-23", "DocumentId": "FV-2026-0094"}, "Totals": {"Subtotal": 420000, "TotalVAT": 79800, "TotalPayment": 499800, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 0}, "ThirdParty": {"NIT": "9001760205", "Name": "Cliente Agro Comercial SAS"}}], "metadata": {"ExchangeId": "AF-2026-05-9394", "GeneratedAt": "2026-05-23", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "9001766666"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-23", "Type": {"Code": "PAY", "Name": "Pago Factura Venta"}, "Notes": "Pago total factura FV-2026-0094", "Amount": 499800, "Status": "COMPLETED", "Currency": "COP", "UpdatedAt": "2026-05-23", "DocumentId": "PAY-CLI-2026-0094", "ThirdParty": {"NIT": "9001760205", "Name": "Cliente Agro Comercial SAS"}, "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia Bancaria"}, "RelatedInvoiceId": "FV-2026-0094"}]}	2026-05-24	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-24 03:29:38.97127+00	2026-05-24 03:29:39.357146+00	2026-05-24 03:29:38.97127+00	\N
82faa91e-9bf9-4860-904a-905f7f00c0f9	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 0, "TotalDocuments": 1, "TotalTransactions": 1}, "invoices": [], "metadata": {"ExchangeId": "AF-2026-05-9395", "GeneratedAt": "2026-05-23", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "9001766666"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-23", "Type": {"Code": "ADV", "Name": "Anticipo a Proveedor"}, "Notes": "Anticipo a proveedor sin factura asociada (CxP)", "Amount": 350000, "Status": "COMPLETED", "Currency": "COP", "UpdatedAt": "2026-05-23", "DocumentId": "ADV-SUP-2026-0095", "ThirdParty": {"NIT": "9012345678", "Name": "Proveedor Insumos Agro SAS"}, "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia Bancaria"}}]}	2026-05-24	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-24 03:38:33.034322+00	2026-05-24 03:38:33.201355+00	2026-05-24 03:38:33.034322+00	\N
c9dd6a1f-817a-489a-b1db-c6c9486e93c5	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 1, "TotalTransactions": 0}, "invoices": [{"Lines": [{"Code": "SERV-AP23-01", "Name": "Servicio tecnico agricola", "Taxes": [{"Rate": 19, "Amount": 190000, "TaxType": "IVA"}], "Value": 1000000, "LineType": "SERVICE", "Quantity": 1, "UnitPrice": 1000000, "Description": "Factura compra HU-AP-23 E4"}], "Header": {"Type": {"Code": "02", "Name": "Compra"}, "Status": "PENDING", "DueDate": "2026-06-22", "IssueDate": "2026-05-23", "DocumentId": "FAC-PROV-2026-00444"}, "Totals": {"Subtotal": 1000000, "TotalVAT": 190000, "TotalPayment": 1190000, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 1190000}, "ThirdParty": {"NIT": "9012345678", "Name": "Proveedor Insumos Agro SAS"}}], "metadata": {"ExchangeId": "AF-2026-05-2423", "GeneratedAt": "2026-05-23", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "9001766666"}, "StandardVersion": "1.0"}, "transactions": []}	2026-05-24	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	rejected	1	1	2	\N	2026-05-24 04:04:52.881154+00	2026-05-24 04:04:53.010996+00	2026-05-24 04:04:52.881154+00	\N
db6dc095-ae83-48f8-aeaa-295df9974947	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 0, "TotalDocuments": 1, "TotalTransactions": 1}, "invoices": [], "metadata": {"ExchangeId": "AF-2026-05-9396", "GeneratedAt": "2026-05-23", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "9001766666"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-23", "Type": {"Code": "ADV", "Name": "Anticipo Proveedor"}, "Notes": "Anticipo a proveedor - Cuentas por Pagar", "Amount": 420000, "Status": "COMPLETED", "Currency": "COP", "UpdatedAt": "2026-05-23", "DocumentId": "ADV-AP-2026-0096", "ThirdParty": {"NIT": "9012345678", "Name": "Proveedor Insumos Agro SAS"}, "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia Bancaria"}}]}	2026-05-24	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-24 03:43:06.453254+00	2026-05-24 03:43:06.593637+00	2026-05-24 03:43:06.453254+00	\N
80edc693-b9dc-4cdb-af87-032414eb9ff5	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 0, "TotalDocuments": 1, "TotalTransactions": 1}, "invoices": [], "metadata": {"ExchangeId": "AF-2026-05-0396", "GeneratedAt": "2026-05-23", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "9001766666"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-23", "Type": {"Code": "ADV", "Name": "Anticipo Proveedor"}, "Notes": "Anticipo a proveedor - Cuentas por Pagar", "Amount": 600000, "Status": "COMPLETED", "Currency": "COP", "UpdatedAt": "2026-05-23", "DocumentId": "ADV-AP-2026-0096", "ThirdParty": {"NIT": "9012345678", "Name": "Proveedor Insumos Agro SAS"}, "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia Bancaria"}}]}	2026-05-24	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-24 03:54:58.819141+00	2026-05-24 03:54:59.004529+00	2026-05-24 03:54:58.819141+00	\N
f87cc107-13a9-49d5-bd4d-7bab57d77b95	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 0, "TotalDocuments": 1, "TotalTransactions": 1}, "invoices": [], "metadata": {"ExchangeId": "AF-2026-05-9405", "GeneratedAt": "2026-05-23", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "9001766666"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-23", "Type": {"Code": "ADV", "Name": "Anticipo a proveedor"}, "Notes": "HU-AP-05 E4 - Anticipo a proveedor por integracion", "Amount": 300000, "Status": "COMPLETED", "Currency": "COP", "UpdatedAt": "2026-05-23", "DocumentId": "ADV-AP-2026-0001", "ThirdParty": {"NIT": "9012345678", "Name": "Proveedor Insumos Agro SAS"}, "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}}]}	2026-05-24	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-24 04:01:32.576554+00	2026-05-24 04:01:32.931492+00	2026-05-24 04:01:32.576554+00	\N
b4c746f2-b665-4936-8689-915340dc0000	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 0, "TotalDocuments": 1, "TotalTransactions": 1}, "invoices": [], "metadata": {"ExchangeId": "AF-2026-05-7894", "GeneratedAt": "2026-05-25", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "9001766666"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-25", "Type": {"Code": "ADV", "Name": "Anticipo de cliente"}, "Amount": 180000, "Status": "COMPLETED", "Currency": "COP", "ThirdParty": {"NIT": "9001760205", "Name": "Cliente Prueba AR"}, "Description": "Anticipo recibido de cliente antes de facturar", "PaymentMethod": {"Code": "BANK_TRANSFER", "Name": "Transferencia Bancaria"}, "TransactionId": "ADV-AR-2026-0001"}]}	2026-05-25	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-25 22:31:48.098962+00	2026-05-25 22:31:48.436473+00	2026-05-25 22:31:48.098962+00	\N
68dd1518-3823-4a68-96c7-f69df6983181	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 0, "TotalDocuments": 1, "TotalTransactions": 1}, "invoices": [], "metadata": {"ExchangeId": "AF-2026-05-5751", "GeneratedAt": "2026-05-25", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "9001766666"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-25", "Type": {"Code": "ADV", "Name": "Anticipo tercero con ambos roles"}, "Amount": 210000, "Status": "COMPLETED", "Currency": "COP", "ThirdParty": {"NIT": "9001760205", "Name": "Tercero Mixto Prueba"}, "Description": "Prueba de prioridad ADV con tercero cliente/proveedor", "PaymentMethod": {"Code": "BANK_TRANSFER", "Name": "Transferencia Bancaria"}, "TransactionId": "ADV-BOTH-2026-0001"}]}	2026-05-25	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-25 22:36:42.555042+00	2026-05-25 22:36:42.892231+00	2026-05-25 22:36:42.555042+00	\N
6fdb206e-68f2-4870-8aee-5d6d053ed455	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 0, "TotalDocuments": 1, "TotalTransactions": 1}, "invoices": [], "metadata": {"ExchangeId": "AF-2026-05-1107", "GeneratedAt": "2026-05-26", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "9001766666"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-26", "Type": {"Code": "PAY", "Name": "Reversa de pago cliente"}, "Amount": 30000, "Status": "REVERSED", "Currency": "COP", "DocumentId": "PAY-FIX-REVERSED-CXC-1107", "ThirdParty": {"NIT": "9001760205", "Name": "Cliente Fix Paid CxC"}, "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}, "RelatedInvoiceId": "INV-FIX-PAID-CXC-1105"}]}	2026-05-27	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-27 02:38:54.845768+00	2026-05-27 02:38:55.051547+00	2026-05-27 02:38:54.845768+00	\N
bb4c4baf-19f9-4f09-a359-4263f345ac4d	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 0, "TotalDocuments": 1, "TotalTransactions": 1}, "invoices": [], "metadata": {"ExchangeId": "AF-2026-05-7878", "GeneratedAt": "2026-05-26", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "9001766666"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-26", "Type": {"Code": "PAY", "Name": "Reversa de pago cliente"}, "Amount": 30000, "Status": "REVERSED", "Currency": "COP", "DocumentId": "PAY-FIX-REVERSED-CXC-1107", "ThirdParty": {"NIT": "9001760205", "Name": "Cliente Fix Cancelled CxC"}, "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}, "RelatedInvoiceId": "INV-FIX-PAID-CXC-1105"}]}	2026-05-27	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-27 02:43:51.609918+00	2026-05-27 02:43:51.733142+00	2026-05-27 02:43:51.609918+00	\N
d3137fd5-337c-4bc6-8ba8-6e1b95727298	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 1, "TotalTransactions": 0}, "invoices": [{"Lines": [{"Code": "SERV-AP23-01", "Name": "Servicio tecnico agricola", "Taxes": [{"Rate": 19, "Amount": 190000, "TaxType": "IVA"}], "Value": 1000000, "LineType": "SERVICE", "Quantity": 1, "UnitPrice": 1000000, "Description": "Factura compra HU-AP-23 E4"}], "Header": {"Type": {"Code": "02", "Name": "Compra"}, "Status": "PENDING", "DueDate": "2026-06-22", "IssueDate": "2026-05-23", "DocumentId": "FAC-PROV-2026-00444"}, "Totals": {"Subtotal": 1000000, "TotalVAT": 190000, "TotalPayment": 1190000, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 1190000}, "ThirdParty": {"NIT": "9012345678", "Name": "Proveedor Insumos Agro SAS"}}], "metadata": {"ExchangeId": "AF-2026-05-7423", "GeneratedAt": "2026-05-23", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "9001766666"}, "StandardVersion": "1.0"}, "transactions": []}	2026-05-24	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-24 04:04:21.731029+00	2026-05-24 04:04:22.019608+00	2026-05-24 04:04:21.731029+00	\N
dabcbcc4-bbcb-40c7-bd30-1355da81fa00	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 1, "TotalTransactions": 0}, "invoices": [{"Lines": [{"Code": "NC-0093", "Name": "Reversa factura proveedor", "Taxes": [{"Rate": 19, "Amount": 123500, "TaxType": "IVA"}], "Value": 650000, "LineType": "SERVICE", "Quantity": 1, "UnitPrice": 650000, "Description": "HU-AP-09 E4 cancelacion/correccion desde AgroFusion"}], "Header": {"Type": {"Code": "03", "Name": "Nota Credito"}, "Status": "ACTIVE", "DueDate": "2026-05-23", "IssueDate": "2026-05-23", "DocumentId": "FC-2026-0093"}, "Totals": {"Subtotal": 650000, "TotalVAT": 123500, "TotalPayment": 773500, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 0}, "ThirdParty": {"NIT": "9012345678", "Name": "Proveedor Insumos Agro SAS"}}], "metadata": {"ExchangeId": "AF-2026-05-9494", "GeneratedAt": "2026-05-23", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "9001766666"}, "StandardVersion": "1.0"}, "transactions": []}	2026-05-24	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	rejected	1	1	2	\N	2026-05-24 04:13:24.192618+00	2026-05-24 04:13:24.307693+00	2026-05-24 04:13:24.192618+00	\N
30c0e6c6-32f0-4431-8aac-ad9da1db40a6	8084d91b-d49d-40f2-b10e-5460df450367	Nomina	Nomina	{"summary": {"Currency": "COP", "TotalNet": 618000, "TotalInvoices": 1, "TotalDocuments": 2, "TotalGrossAmount": 650000, "TotalTransactions": 1}, "invoices": [{"Lines": [{"Code": "SALARIO_BASE", "Name": "salario base", "Taxes": [], "Value": 400000, "LineType": "ingreso", "Quantity": 0.2, "UnitPrice": 2000000, "Description": "Salario base generado como base_salary * time_worked", "accounting_account": ["250505", "111005"]}, {"Code": "58", "Name": "Transporte", "Taxes": [], "Value": 250000, "LineType": "ingreso", "Quantity": 1, "UnitPrice": 250000, "Description": "Auxilio de transporte", "accounting_account": ["510527", ""]}, {"Code": "53", "Name": "Salud", "Taxes": [], "Value": 16000, "LineType": "deduccion", "Quantity": 1, "UnitPrice": 16000, "Description": "Descuento de salud", "accounting_account": ["510569", "237005"]}, {"Code": "54", "Name": "Pensión", "Taxes": [], "Value": 16000, "LineType": "deduccion", "Quantity": 1, "UnitPrice": 16000, "Description": "Descuento de pensión", "accounting_account": ["510570", "238030"]}], "Header": {"Type": {"Code": "03", "Name": "Honorarios"}, "Prefix": "NOM", "Serial": "24", "Status": "PAID", "DueDate": "2026-05-06", "IssueDate": "2026-05-01", "UpdatedAt": "2026-05-06", "DocumentId": "CON-2026-0001-00-24"}, "Totals": {"Subtotal": 650000, "TotalVAT": 0, "TotalPayment": 618000, "TotalDiscounts": 0, "TotalWithholdings": 32000, "OutstandingBalance": 0}, "ThirdParty": {"NIT": "", "City": null, "Name": "Maria Alejandra", "Email": "alejab2302@gmail.com", "Address": null, "Country": null}}], "metadata": {"ExchangeId": "AF-2026-05-2891462", "GeneratedAt": "2026-05-25", "GeneratedBy": "agrofusion-integration-service", "SourceSystem": {"SystemId": "sigma-prod-01", "SystemNIT": "9001766666", "SystemName": "Sigma", "Environment": "production"}, "RequestedPeriod": {"To": "2026-05-31", "From": "2026-05-01"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-01", "Type": {"Code": "PAY", "Name": "Pago de Nómina"}, "Notes": "Contrato: CON-2026-0001-00 | Período: 2026-05-01 / 2026-05-06", "Amount": 618000, "Status": "COMPLETED", "Currency": "COP", "UpdatedAt": "2026-05-01", "DocumentId": "PAY-CON-2026-0001-00-24-2026-05-01", "ThirdParty": {"NIT": "900123456", "City": null, "Name": "Empresa AgroFusion SA", "Email": null, "Address": null, "Country": null}, "PaymentMethod": {"Code": "20"}, "RelatedInvoiceId": "CON-2026-0001-00-24"}]}	2026-05-25	62410684-48a0-499e-8193-fa098a4c63f5	rejected	1	1	2	\N	2026-05-25 04:43:00.426578+00	2026-05-25 04:43:01.06261+00	2026-05-25 04:43:00.426578+00	\N
71dafd8b-cecd-4714-85de-d09bf96474a0	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"Currency": "COP", "TotalNet": 5538311.27, "TotalInvoices": 18, "TotalDocuments": 27, "TotalGrossAmount": 5096061.21, "TotalTransactions": 9}, "invoices": [{"Lines": [{"Code": "SVC-2025-0009", "Name": "Calibración de Equipos", "Taxes": [{"Rate": "3.00", "Amount": "4860.00", "TaxType": "01"}], "Value": 166860, "LineType": "Calibración de Equipos", "Quantity": 1, "UnitPrice": 180000, "Description": "Calibración de Equipos", "accounting_account": ["4310"]}], "Header": {"Type": {"Code": "01", "Name": "Factura de Venta"}, "Prefix": "SIGMA-FACT", "Serial": "SETP990017958", "Status": "PAID", "DueDate": "03-11-2025 12:29:35 AM", "IssueDate": "03-11-2025 12:29:34 AM", "UpdatedAt": "03-11-2025 12:29:35 AM", "DocumentId": "sigma-fact-5C7D65CF"}, "Totals": {"Subtotal": 162000, "TotalVAT": 4860, "TotalPayment": 166860, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 166860}, "ThirdParty": {"NIT": "", "City": null, "Name": "RAMIREZ SAS", "Email": "ramirezcollazos@gmail.com", "Address": "Cra 30 #29-31", "Country": null}}, {"Lines": [{"Code": "SVC-2025-0011", "Name": "Prueba 333", "Taxes": [{"Rate": "12.00", "Amount": "1.44", "TaxType": "01"}], "Value": 13.44, "LineType": "Prueba 333", "Quantity": 1, "UnitPrice": 12, "Description": "Prueba 333", "accounting_account": ["4310"]}], "Header": {"Type": {"Code": "01", "Name": "Factura de Venta"}, "Prefix": "SIGMA-FACT", "Serial": "SETP990017991", "Status": "PAID", "DueDate": "03-11-2025 05:19:15 PM", "IssueDate": "03-11-2025 05:19:14 PM", "UpdatedAt": "03-11-2025 05:19:15 PM", "DocumentId": "sigma-fact-6F0789A1"}, "Totals": {"Subtotal": 12, "TotalVAT": 1.44, "TotalPayment": 13.44, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 13.44}, "ThirdParty": {"NIT": "", "City": null, "Name": "RAMIREZ SAS", "Email": "ramirezcollazos@gmail.com", "Address": "Cra 30 #29-31", "Country": null}}, {"Lines": [{"Code": "SVC-2025-0008", "Name": "Reparación Sistema Hidráulico", "Taxes": [{"Rate": "19.00", "Amount": "47500.00", "TaxType": "01"}], "Value": 297500, "LineType": "Reparación Sistema Hidráulico", "Quantity": 1, "UnitPrice": 250000, "Description": "Reparación Sistema Hidráulico", "accounting_account": ["4310"]}, {"Code": "SVC-2025-0007", "Name": "Mantenimiento Preventivo Básico", "Taxes": [{"Rate": "19.00", "Amount": "28500.00", "TaxType": "01"}], "Value": 178500, "LineType": "Mantenimiento Preventivo Básico", "Quantity": 1, "UnitPrice": 150000, "Description": "Mantenimiento Preventivo Básico", "accounting_account": ["4310"]}], "Header": {"Type": {"Code": "01", "Name": "Factura de Venta"}, "Prefix": "SIGMA-FACT", "Serial": "SETP990017980", "Status": "PAID", "DueDate": "03-11-2025 04:19:20 PM", "IssueDate": "03-11-2025 04:19:19 PM", "UpdatedAt": "03-11-2025 04:19:20 PM", "DocumentId": "sigma-fact-A615BED4"}, "Totals": {"Subtotal": 400000, "TotalVAT": 76000, "TotalPayment": 476000, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 476000}, "ThirdParty": {"NIT": "", "City": null, "Name": "Fabian Ramos Semanate", "Email": "u20212199794@usco.edu.co", "Address": "Calle 21 # 83-35", "Country": null}}, {"Lines": [{"Code": "SVC-2025-0007", "Name": "Mantenimiento Preventivo Básico", "Taxes": [{"Rate": "19.00", "Amount": "28500.00", "TaxType": "01"}], "Value": 178500, "LineType": "Mantenimiento Preventivo Básico", "Quantity": 1, "UnitPrice": 150000, "Description": "Mantenimiento Preventivo Básico", "accounting_account": ["4310"]}, {"Code": "SVC-2025-0008", "Name": "Reparación Sistema Hidráulico", "Taxes": [{"Rate": "19.00", "Amount": "42750.00", "TaxType": "01"}], "Value": 267750, "LineType": "Reparación Sistema Hidráulico", "Quantity": 1, "UnitPrice": 250000, "Description": "Reparación Sistema Hidráulico", "accounting_account": ["4310"]}], "Header": {"Type": {"Code": "01", "Name": "Factura de Venta"}, "Prefix": "SIGMA-FACT", "Serial": "SETP990017966", "Status": "PAID", "DueDate": "03-11-2025 11:51:38 AM", "IssueDate": "03-11-2025 11:51:38 AM", "UpdatedAt": "03-11-2025 11:51:38 AM", "DocumentId": "sigma-fact-C8716450"}, "Totals": {"Subtotal": 375000, "TotalVAT": 71250, "TotalPayment": 446250, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 446250}, "ThirdParty": {"NIT": "", "City": null, "Name": "Agricolas del Huila", "Email": "raulperez@gmail.com", "Address": "Cra 1a # 20-24", "Country": null}}, {"Lines": [{"Code": "SVC-2025-0006", "Name": "Prueba manual 2", "Taxes": [{"Rate": "5.00", "Amount": "20.00", "TaxType": "01"}], "Value": 420, "LineType": "Prueba manual 2", "Quantity": 2, "UnitPrice": 200, "Description": "Prueba manual 2", "accounting_account": ["4310"]}], "Header": {"Type": {"Code": "01", "Name": "Factura de Venta"}, "Prefix": "SIGMA-FACT", "Serial": "SETP990017983", "Status": "PAID", "DueDate": "03-11-2025 04:39:06 PM", "IssueDate": "03-11-2025 04:39:05 PM", "UpdatedAt": "03-11-2025 04:39:06 PM", "DocumentId": "sigma-fact-2C37A1E9"}, "Totals": {"Subtotal": 400, "TotalVAT": 20, "TotalPayment": 420, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 420}, "ThirdParty": {"NIT": "", "City": null, "Name": "artic", "Email": null, "Address": null, "Country": null}}, {"Lines": [{"Code": "SVC-2025-0009", "Name": "Calibración de Equipos", "Taxes": [{"Rate": "3.00", "Amount": "5400.00", "TaxType": "01"}], "Value": 185400, "LineType": "Calibración de Equipos", "Quantity": 1, "UnitPrice": 180000, "Description": "Calibración de Equipos", "accounting_account": ["4310"]}], "Header": {"Type": {"Code": "01", "Name": "Factura de Venta"}, "Prefix": "SIGMA-FACT", "Serial": "SETP990017992", "Status": "PAID", "DueDate": "03-11-2025 05:20:42 PM", "IssueDate": "03-11-2025 05:20:41 PM", "UpdatedAt": "03-11-2025 05:20:42 PM", "DocumentId": "sigma-fact-EEA67BF8"}, "Totals": {"Subtotal": 180000, "TotalVAT": 5400, "TotalPayment": 185400, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 185400}, "ThirdParty": {"NIT": "", "City": null, "Name": "artic", "Email": null, "Address": null, "Country": null}}, {"Lines": [], "Header": {"Type": {"Code": "INVOICE", "Name": "Factura de Venta"}, "Prefix": "SIGMA-FACT", "Serial": "sigma-fact-9F5E1D3C", "Status": "PENDING", "DueDate": "2025-11-02", "IssueDate": "2025-11-02", "UpdatedAt": "2025-11-02", "DocumentId": "sigma-fact-9F5E1D3C"}, "Totals": {"Subtotal": 0, "TotalVAT": 0, "TotalPayment": 0, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 0}, "ThirdParty": {"NIT": "", "City": null, "Name": "Fabian Ramos Semanate", "Email": "u20212199794@usco.edu.co", "Address": "Calle 21 # 83-35", "Country": null}}, {"Lines": [{"Code": "SVC-2025-0011", "Name": "Prueba 333", "Taxes": [{"Rate": "12.00", "Amount": "1.37", "TaxType": "01"}], "Value": 12.77, "LineType": "Prueba 333", "Quantity": 1, "UnitPrice": 12, "Description": "Prueba 333", "accounting_account": ["4310"]}], "Header": {"Type": {"Code": "01", "Name": "Factura de Venta"}, "Prefix": "SIGMA-FACT", "Serial": "SETP990017982", "Status": "PAID", "DueDate": "03-11-2025 04:30:16 PM", "IssueDate": "03-11-2025 04:30:15 PM", "UpdatedAt": "03-11-2025 04:30:16 PM", "DocumentId": "sigma-fact-17DF2CD1"}, "Totals": {"Subtotal": 11.4, "TotalVAT": 1.37, "TotalPayment": 12.77, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 12.77}, "ThirdParty": {"NIT": "", "City": null, "Name": "Juan David Lozano", "Email": null, "Address": null, "Country": null}}, {"Lines": [{"Code": "SVC-2025-0012", "Name": "taller don Andress", "Taxes": [{"Rate": "12.00", "Amount": "1.44", "TaxType": "01"}], "Value": 13.44, "LineType": "taller don Andress", "Quantity": 1, "UnitPrice": 12, "Description": "taller don Andress", "accounting_account": ["4310"]}], "Header": {"Type": {"Code": "01", "Name": "Factura de Venta"}, "Prefix": "SIGMA-FACT", "Serial": "SETP990017987", "Status": "PAID", "DueDate": "03-11-2025 05:06:07 PM", "IssueDate": "03-11-2025 05:06:03 PM", "UpdatedAt": "03-11-2025 05:06:07 PM", "DocumentId": "sigma-fact-51B09140"}, "Totals": {"Subtotal": 12, "TotalVAT": 1.44, "TotalPayment": 13.44, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 13.44}, "ThirdParty": {"NIT": "", "City": null, "Name": "Fabian Ramos Semanate", "Email": "u20212199794@usco.edu.co", "Address": "Calle 21 # 83-35", "Country": null}}, {"Lines": [{"Code": "SVC-2025-0001", "Name": "Mantenimiento Preventivo Completo", "Taxes": [{"Rate": "19.00", "Amount": "47500.00", "TaxType": "01"}], "Value": 297500, "LineType": "Mantenimiento Preventivo Completo", "Quantity": 1, "UnitPrice": 250000, "Description": "Mantenimiento Preventivo Completo", "accounting_account": ["4310"]}], "Header": {"Type": {"Code": "01", "Name": "Factura de Venta"}, "Prefix": "SIGMA-FACT", "Serial": "SETP990017981", "Status": "PAID", "DueDate": "03-11-2025 04:27:29 PM", "IssueDate": "03-11-2025 04:27:28 PM", "UpdatedAt": "03-11-2025 04:27:29 PM", "DocumentId": "sigma-fact-B2F8BA1B"}, "Totals": {"Subtotal": 250000, "TotalVAT": 47500, "TotalPayment": 297500, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 297500}, "ThirdParty": {"NIT": "", "City": null, "Name": "Juan Camilito", "Email": null, "Address": null, "Country": null}}, {"Lines": [{"Code": "SVC-2025-0010", "Name": "taller don Luis", "Taxes": [{"Rate": "19.00", "Amount": "4.37", "TaxType": "01"}], "Value": 27.37, "LineType": "taller don Luis", "Quantity": 1, "UnitPrice": 23, "Description": "taller don Luis", "accounting_account": ["4310"]}], "Header": {"Type": {"Code": "01", "Name": "Factura de Venta"}, "Prefix": "SIGMA-FACT", "Serial": "SETP990017984", "Status": "PAID", "DueDate": "03-11-2025 04:50:30 PM", "IssueDate": "03-11-2025 04:50:29 PM", "UpdatedAt": "03-11-2025 04:50:30 PM", "DocumentId": "sigma-fact-AC4C95D3"}, "Totals": {"Subtotal": 23, "TotalVAT": 4.37, "TotalPayment": 27.37, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 27.37}, "ThirdParty": {"NIT": "", "City": null, "Name": "Agricolas del Huila", "Email": "raulperez@gmail.com", "Address": "Cra 1a # 20-24", "Country": null}}, {"Lines": [{"Code": "SVC-2025-0006", "Name": "Prueba manual 2", "Taxes": [{"Rate": "5.00", "Amount": "10.00", "TaxType": "01"}], "Value": 210, "LineType": "Prueba manual 2", "Quantity": 1, "UnitPrice": 200, "Description": "Prueba manual 2", "accounting_account": ["4310"]}], "Header": {"Type": {"Code": "01", "Name": "Factura de Venta"}, "Prefix": "SIGMA-FACT", "Serial": "SETP990017986", "Status": "PAID", "DueDate": "03-11-2025 05:03:16 PM", "IssueDate": "03-11-2025 05:03:15 PM", "UpdatedAt": "03-11-2025 05:03:16 PM", "DocumentId": "sigma-fact-4DC9C505"}, "Totals": {"Subtotal": 200, "TotalVAT": 10, "TotalPayment": 210, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 210}, "ThirdParty": {"NIT": "", "City": null, "Name": "Fabian Ramos Semanate", "Email": "u20212199794@usco.edu.co", "Address": "Calle 21 # 83-35", "Country": null}}, {"Lines": [{"Code": "SVC-2025-0008", "Name": "Reparación Sistema Hidráulico", "Taxes": [{"Rate": "19.00", "Amount": "95000.00", "TaxType": "01"}], "Value": 595000, "LineType": "Reparación Sistema Hidráulico", "Quantity": 2, "UnitPrice": 250000, "Description": "Reparación Sistema Hidráulico", "accounting_account": ["4310"]}], "Header": {"Type": {"Code": "01", "Name": "Factura de Venta"}, "Prefix": "SIGMA-FACT", "Serial": "SETP990017985", "Status": "PAID", "DueDate": "03-11-2025 05:00:30 PM", "IssueDate": "03-11-2025 05:00:28 PM", "UpdatedAt": "03-11-2025 05:00:30 PM", "DocumentId": "sigma-fact-11151C34"}, "Totals": {"Subtotal": 500000, "TotalVAT": 95000, "TotalPayment": 595000, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 595000}, "ThirdParty": {"NIT": "", "City": null, "Name": "Fabian Ramos Semanate", "Email": "u20212199794@usco.edu.co", "Address": "Calle 21 # 83-35", "Country": null}}, {"Lines": [{"Code": "SVC-2025-0008", "Name": "Reparación Sistema Hidráulico", "Taxes": [{"Rate": "19.00", "Amount": "47500.00", "TaxType": "01"}], "Value": 297500, "LineType": "Reparación Sistema Hidráulico", "Quantity": 1, "UnitPrice": 250000, "Description": "Reparación Sistema Hidráulico", "accounting_account": ["4310"]}], "Header": {"Type": {"Code": "01", "Name": "Factura de Venta"}, "Prefix": "SIGMA-FACT", "Serial": "SETP990017988", "Status": "PAID", "DueDate": "03-11-2025 05:10:12 PM", "IssueDate": "03-11-2025 05:10:12 PM", "UpdatedAt": "03-11-2025 05:10:12 PM", "DocumentId": "sigma-fact-9A09A57B"}, "Totals": {"Subtotal": 250000, "TotalVAT": 47500, "TotalPayment": 297500, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 297500}, "ThirdParty": {"NIT": "", "City": null, "Name": "artic", "Email": null, "Address": null, "Country": null}}, {"Lines": [{"Code": "SVC-2025-0009", "Name": "Calibración de Equipos", "Taxes": [{"Rate": "3.00", "Amount": "5400.00", "TaxType": "01"}], "Value": 185400, "LineType": "Calibración de Equipos", "Quantity": 1, "UnitPrice": 180000, "Description": "Calibración de Equipos", "accounting_account": ["4310"]}], "Header": {"Type": {"Code": "01", "Name": "Factura de Venta"}, "Prefix": "SIGMA-FACT", "Serial": "SETP990017989", "Status": "PAID", "DueDate": "03-11-2025 05:14:01 PM", "IssueDate": "03-11-2025 05:14:00 PM", "UpdatedAt": "03-11-2025 05:14:01 PM", "DocumentId": "sigma-fact-CDF5DE01"}, "Totals": {"Subtotal": 180000, "TotalVAT": 5400, "TotalPayment": 185400, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 185400}, "ThirdParty": {"NIT": "", "City": null, "Name": "Juan Camilito", "Email": null, "Address": null, "Country": null}}, {"Lines": [{"Code": "SVC-2025-0012", "Name": "taller don Andress", "Taxes": [{"Rate": "12.00", "Amount": "1.44", "TaxType": "01"}], "Value": 13.44, "LineType": "taller don Andress", "Quantity": 1, "UnitPrice": 12, "Description": "taller don Andress", "accounting_account": ["4310"]}], "Header": {"Type": {"Code": "01", "Name": "Factura de Venta"}, "Prefix": "SIGMA-FACT", "Serial": "SETP990017990", "Status": "PAID", "DueDate": "03-11-2025 05:15:51 PM", "IssueDate": "03-11-2025 05:15:50 PM", "UpdatedAt": "03-11-2025 05:15:51 PM", "DocumentId": "sigma-fact-DC6EC9E4"}, "Totals": {"Subtotal": 12, "TotalVAT": 1.44, "TotalPayment": 13.44, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 13.44}, "ThirdParty": {"NIT": "", "City": null, "Name": "Fabian Ramos Semanate", "Email": "u20212199794@usco.edu.co", "Address": "Calle 21 # 83-35", "Country": null}}, {"Lines": [{"Code": "SVC-2025-0001", "Name": "Mantenimiento Preventivo Completo", "Taxes": [{"Rate": "19.00", "Amount": "42750.00", "TaxType": "01"}], "Value": 267750, "LineType": "Mantenimiento Preventivo Completo", "Quantity": 1, "UnitPrice": 250000, "Description": "Mantenimiento Preventivo Completo", "accounting_account": ["4310"]}], "Header": {"Type": {"Code": "01", "Name": "Factura de Venta"}, "Prefix": "SIGMA-FACT", "Serial": "SETP990017994", "Status": "PAID", "DueDate": "04-11-2025 01:30:12 AM", "IssueDate": "04-11-2025 01:30:11 AM", "UpdatedAt": "04-11-2025 01:30:12 AM", "DocumentId": "sigma-fact-8ACE83CB"}, "Totals": {"Subtotal": 225000, "TotalVAT": 42750, "TotalPayment": 267750, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 267750}, "ThirdParty": {"NIT": "", "City": null, "Name": "Juan David Lozano", "Email": null, "Address": null, "Country": null}}, {"Lines": [{"Code": "SVC-2025-0001", "Name": "Mantenimiento Preventivo Completo", "Taxes": [{"Rate": "19.00", "Amount": "46550.00", "TaxType": "01"}], "Value": 291550, "LineType": "Mantenimiento Preventivo Completo", "Quantity": 1, "UnitPrice": 250000, "Description": "Mantenimiento Preventivo Completo", "accounting_account": ["4310"]}], "Header": {"Type": {"Code": "01", "Name": "Factura de Venta"}, "Prefix": "SIGMA-FACT", "Serial": "SETP990017995", "Status": "PAID", "DueDate": "04-11-2025 01:31:53 AM", "IssueDate": "04-11-2025 01:31:52 AM", "UpdatedAt": "04-11-2025 01:31:53 AM", "DocumentId": "sigma-fact-3BF9150D"}, "Totals": {"Subtotal": 245000, "TotalVAT": 46550, "TotalPayment": 291550, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 291550}, "ThirdParty": {"NIT": "", "City": null, "Name": "artic", "Email": null, "Address": null, "Country": null}}], "metadata": {"ExchangeId": "AF-2026-05-7175568", "GeneratedAt": "2026-05-25T04:51:02.936467Z", "GeneratedBy": "sigma-integration-service", "SourceSystem": {"SystemId": "sigma-prod-01", "SystemNIT": "9001766666", "SystemName": "Sigma", "Environment": "production"}, "RequestedPeriod": {"To": "2025-11-30", "From": "2025-11-01"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "03-11-2025 04:19:20 PM", "Type": {"Code": "PAY", "Name": "Pago de Factura"}, "Notes": "Pago asociado a factura sigma-fact-A615BED4", "Amount": 476000, "Status": "COMPLETED", "Currency": "COP", "UpdatedAt": "2025-10-30 02:08:09.872414+00:00", "DocumentId": "PAY-sigma-fact-A615BED4-03-11-2025", "ThirdParty": {"NIT": "", "City": null, "Name": "Fabian Ramos Semanate", "Email": null, "Address": null, "Country": null}, "PaymentMethod": {"Code": "CASH"}, "RelatedInvoiceId": "sigma-fact-A615BED4"}, {"Date": "03-11-2025 05:20:42 PM", "Type": {"Code": "PAY", "Name": "Pago de Factura"}, "Notes": "Pago asociado a factura sigma-fact-EEA67BF8", "Amount": 185400, "Status": "COMPLETED", "Currency": "COP", "UpdatedAt": "2025-10-25 04:14:21.386593+00:00", "DocumentId": "PAY-sigma-fact-EEA67BF8-03-11-2025", "ThirdParty": {"NIT": "", "City": null, "Name": "artic", "Email": null, "Address": null, "Country": null}, "PaymentMethod": {"Code": "CASH"}, "RelatedInvoiceId": "sigma-fact-EEA67BF8"}, {"Date": "03-11-2025 04:27:29 PM", "Type": {"Code": "PAY", "Name": "Pago de Factura"}, "Notes": "Pago asociado a factura sigma-fact-B2F8BA1B", "Amount": 297500, "Status": "COMPLETED", "Currency": "COP", "UpdatedAt": "2025-11-06 15:07:17.010993+00:00", "DocumentId": "PAY-sigma-fact-B2F8BA1B-03-11-2025", "ThirdParty": {"NIT": "", "City": null, "Name": "Juan Camilito", "Email": null, "Address": null, "Country": null}, "PaymentMethod": {"Code": "CASH"}, "RelatedInvoiceId": "sigma-fact-B2F8BA1B"}, {"Date": "03-11-2025 04:50:30 PM", "Type": {"Code": "PAY", "Name": "Pago de Factura"}, "Notes": "Pago asociado a factura sigma-fact-AC4C95D3", "Amount": 27.37, "Status": "COMPLETED", "Currency": "COP", "UpdatedAt": "2025-10-26 19:54:44.269614+00:00", "DocumentId": "PAY-sigma-fact-AC4C95D3-03-11-2025", "ThirdParty": {"NIT": "", "City": null, "Name": "Agricolas del Huila", "Email": null, "Address": null, "Country": null}, "PaymentMethod": {"Code": "CASH"}, "RelatedInvoiceId": "sigma-fact-AC4C95D3"}, {"Date": "03-11-2025 05:00:30 PM", "Type": {"Code": "PAY", "Name": "Pago de Factura"}, "Notes": "Pago asociado a factura sigma-fact-11151C34", "Amount": 595000, "Status": "COMPLETED", "Currency": "COP", "UpdatedAt": "2025-11-06 15:07:17.010993+00:00", "DocumentId": "PAY-sigma-fact-11151C34-03-11-2025", "ThirdParty": {"NIT": "", "City": null, "Name": "Fabian Ramos Semanate", "Email": null, "Address": null, "Country": null}, "PaymentMethod": {"Code": "CARD"}, "RelatedInvoiceId": "sigma-fact-11151C34"}, {"Date": "03-11-2025 05:10:12 PM", "Type": {"Code": "PAY", "Name": "Pago de Factura"}, "Notes": "Pago asociado a factura sigma-fact-9A09A57B", "Amount": 297500, "Status": "COMPLETED", "Currency": "COP", "UpdatedAt": "2025-11-06 15:07:17.010993+00:00", "DocumentId": "PAY-sigma-fact-9A09A57B-03-11-2025", "ThirdParty": {"NIT": "", "City": null, "Name": "artic", "Email": null, "Address": null, "Country": null}, "PaymentMethod": {"Code": "CASH"}, "RelatedInvoiceId": "sigma-fact-9A09A57B"}, {"Date": "03-11-2025 05:14:01 PM", "Type": {"Code": "PAY", "Name": "Pago de Factura"}, "Notes": "Pago asociado a factura sigma-fact-CDF5DE01", "Amount": 185400, "Status": "COMPLETED", "Currency": "COP", "UpdatedAt": "2025-11-06 15:07:17.010993+00:00", "DocumentId": "PAY-sigma-fact-CDF5DE01-03-11-2025", "ThirdParty": {"NIT": "", "City": null, "Name": "Juan Camilito", "Email": null, "Address": null, "Country": null}, "PaymentMethod": {"Code": "CASH"}, "RelatedInvoiceId": "sigma-fact-CDF5DE01"}, {"Date": "03-11-2025 05:15:51 PM", "Type": {"Code": "PAY", "Name": "Pago de Factura"}, "Notes": "Pago asociado a factura sigma-fact-DC6EC9E4", "Amount": 13.44, "Status": "COMPLETED", "Currency": "COP", "UpdatedAt": "2025-10-26 16:35:22.318462+00:00", "DocumentId": "PAY-sigma-fact-DC6EC9E4-03-11-2025", "ThirdParty": {"NIT": "", "City": null, "Name": "Fabian Ramos Semanate", "Email": null, "Address": null, "Country": null}, "PaymentMethod": {"Code": "CASH"}, "RelatedInvoiceId": "sigma-fact-DC6EC9E4"}, {"Date": "04-11-2025 01:31:53 AM", "Type": {"Code": "PAY", "Name": "Pago de Factura"}, "Notes": "Pago asociado a factura sigma-fact-3BF9150D", "Amount": 291550, "Status": "COMPLETED", "Currency": "COP", "UpdatedAt": "2025-10-28 17:13:01.901803+00:00", "DocumentId": "PAY-sigma-fact-3BF9150D-04-11-2025", "ThirdParty": {"NIT": "", "City": null, "Name": "artic", "Email": null, "Address": null, "Country": null}, "PaymentMethod": {"Code": "CARD"}, "RelatedInvoiceId": "sigma-fact-3BF9150D"}]}	2026-05-25	62410684-48a0-499e-8193-fa098a4c63f5	rejected	1	1	2	\N	2026-05-25 04:51:13.338389+00	2026-05-25 04:51:14.025003+00	2026-05-25 04:51:13.338389+00	\N
4d2ac162-7ffb-43f4-995a-d47911b876bc	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 1, "TotalTransactions": 0}, "invoices": [{"Lines": [{"Code": "NC-0093", "Name": "Reversa factura proveedor", "Taxes": [{"Rate": 19, "Amount": 123500, "TaxType": "IVA"}], "Value": 650000, "LineType": "SERVICE", "Quantity": 1, "UnitPrice": 650000, "Description": "HU-AP-09 E4 cancelacion/correccion desde AgroFusion"}], "Header": {"Type": {"Code": "03", "Name": "Nota Credito"}, "Status": "PAID", "DueDate": "2026-05-23", "IssueDate": "2026-05-23", "DocumentId": "FC-2026-0093"}, "Totals": {"Subtotal": 650000, "TotalVAT": 123500, "TotalPayment": 773500, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 0}, "ThirdParty": {"NIT": "9012345678", "Name": "Proveedor Insumos Agro SAS"}}], "metadata": {"ExchangeId": "AF-2026-05-9496", "GeneratedAt": "2026-05-23", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "9001766666"}, "StandardVersion": "1.0"}, "transactions": []}	2026-05-24	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	rejected	1	1	2	\N	2026-05-24 04:14:13.223702+00	2026-05-24 04:14:13.666182+00	2026-05-24 04:14:13.223702+00	\N
c9a8a005-469b-46f2-9c31-2c3347756694	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 1, "TotalTransactions": 0}, "invoices": [{"Lines": [{"Code": "NC-0093", "Name": "Reversa factura proveedor", "Taxes": [{"Rate": 19, "Amount": 123500, "TaxType": "IVA"}], "Value": 650000, "LineType": "SERVICE", "Quantity": 1, "UnitPrice": 650000, "Description": "HU-AP-09 E4 cancelacion/correccion desde AgroFusion"}], "Header": {"Type": {"Code": "03", "Name": "Nota Credito"}, "Status": "COMPLETED", "DueDate": "2026-05-23", "IssueDate": "2026-05-23", "DocumentId": "FC-2026-0093"}, "Totals": {"Subtotal": 650000, "TotalVAT": 123500, "TotalPayment": 773500, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 0}, "ThirdParty": {"NIT": "9012345678", "Name": "Proveedor Insumos Agro SAS"}}], "metadata": {"ExchangeId": "AF-2026-05-94963", "GeneratedAt": "2026-05-23", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "9001766666"}, "StandardVersion": "1.0"}, "transactions": []}	2026-05-24	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	rejected	1	1	2	\N	2026-05-24 04:15:45.541297+00	2026-05-24 04:15:45.741644+00	2026-05-24 04:15:45.541297+00	\N
119a7d29-d6b3-4857-9121-98f8bdb802cf	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 1, "TotalTransactions": 0}, "invoices": [{"Lines": [{"Code": "ITEM-001", "Name": "Material devuelto", "Taxes": [{"Rate": 19, "Amount": 95000, "TaxType": "IVA"}], "Value": 500000, "LineType": "PRODUCT", "Quantity": 1, "UnitPrice": 500000, "Description": "Cancelación por devolución total"}], "Header": {"Type": {"Code": "02", "Name": "Compra"}, "Status": "CANCELLED", "DueDate": "2026-06-10", "IssueDate": "2026-05-10", "DocumentId": "FC-EXISTENTE-AP-0001"}, "Totals": {"Subtotal": 500000, "TotalVAT": 95000, "TotalPayment": 595000, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 0}, "ThirdParty": {"NIT": "9012345678", "Name": "Proveedor Prueba AP"}}], "metadata": {"ExchangeId": "AF-2026-05-4509", "GeneratedAt": "2026-05-25", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "9001766666"}, "StandardVersion": "1.0"}, "transactions": []}	2026-05-25	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	partial	1	1	2	\N	2026-05-25 18:11:10.378189+00	2026-05-25 18:11:10.989095+00	2026-05-25 18:11:10.378189+00	\N
9dc5f6ae-44c6-4f22-aa00-e747217a8906	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 1, "TotalTransactions": 0}, "invoices": [{"Lines": [{"Code": "ITEM-001-CORR", "Name": "Ajuste de flete/costo", "Taxes": [{"Rate": 19, "Amount": 98800, "TaxType": "IVA"}], "Value": 520000, "LineType": "PRODUCT", "Quantity": 1, "UnitPrice": 520000, "Description": "Corrección de valor factura proveedor"}], "Header": {"Type": {"Code": "02", "Name": "Compra"}, "Status": "PAID", "DueDate": "2026-06-10", "IssueDate": "2026-05-10", "DocumentId": "FC-EXISTENTE-AP-0001"}, "Totals": {"Subtotal": 520000, "TotalVAT": 98800, "TotalPayment": 618800, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 0}, "ThirdParty": {"NIT": "9012345678", "Name": "Proveedor Prueba AP"}}], "metadata": {"ExchangeId": "AF-2026-05-4609", "GeneratedAt": "2026-05-25", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "9001766666"}, "StandardVersion": "1.0"}, "transactions": []}	2026-05-25	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-25 18:14:07.499773+00	2026-05-25 18:14:08.40053+00	2026-05-25 18:14:07.499773+00	\N
9e5a491a-9fca-4d13-a831-6b7a64df4561	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 1, "TotalTransactions": 0}, "invoices": [{"Lines": [{"Code": "ITEM-001", "Name": "Material devuelto", "Taxes": [{"Rate": 19, "Amount": 95000, "TaxType": "IVA"}], "Value": 500000, "LineType": "PRODUCT", "Quantity": 1, "UnitPrice": 500000, "Description": "Cancelación por devolución total"}], "Header": {"Type": {"Code": "02", "Name": "Compra"}, "Status": "CANCELLED", "DueDate": "2026-06-10", "IssueDate": "2026-05-10", "DocumentId": "FC-EXISTENTE-AP-0001"}, "Totals": {"Subtotal": 500000, "TotalVAT": 95000, "TotalPayment": 595000, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 0}, "ThirdParty": {"NIT": "9012345678", "Name": "Proveedor Prueba AP"}}], "metadata": {"ExchangeId": "AF-2026-05-5309", "GeneratedAt": "2026-05-25", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "9001766666"}, "StandardVersion": "1.0"}, "transactions": []}	2026-05-25	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	rejected	1	1	2	\N	2026-05-25 18:19:02.292925+00	2026-05-25 18:19:02.833843+00	2026-05-25 18:19:02.292925+00	\N
03cac59d-b1e8-4180-9ee1-0f3940b2013d	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 1, "TotalTransactions": 0}, "invoices": [{"Lines": [{"Code": "ITEM-AP09-E4-001", "Name": "Corrección por devolución parcial", "Taxes": [{"Rate": 19, "Amount": 85500, "TaxType": "IVA"}], "Value": 450000, "LineType": "PRODUCT", "Quantity": 1, "UnitPrice": 450000, "Description": "Ajuste enviado por AgroFusion sobre factura ya procesada"}], "Header": {"Type": {"Code": "02", "Name": "Compra"}, "Status": "PAID", "DueDate": "2026-06-10", "IssueDate": "2026-05-10", "DocumentId": "FC-EXISTENTE-AP-0001"}, "Totals": {"Subtotal": 450000, "TotalVAT": 85500, "TotalPayment": 535500, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 0}, "ThirdParty": {"NIT": "9012345678", "Name": "Proveedor Prueba AP"}}], "metadata": {"ExchangeId": "AF-2026-05-7777", "GeneratedAt": "2026-05-25", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "9001766666"}, "StandardVersion": "1.0"}, "transactions": []}	2026-05-25	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	rejected	1	1	2	\N	2026-05-25 18:20:54.233253+00	2026-05-25 18:20:54.38982+00	2026-05-25 18:20:54.233253+00	\N
ce9fff06-a156-48e4-a990-6fb9ff63d2a1	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 0, "TotalDocuments": 1, "TotalTransactions": 1}, "invoices": [], "metadata": {"ExchangeId": "AF-2026-05-4444", "GeneratedAt": "2026-05-25", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "9001766666"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-25", "Type": {"Code": "REF", "Name": "Reembolso / Nota Crédito Proveedor"}, "Amount": 50000, "Status": "COMPLETED", "Currency": "COP", "ThirdParty": {"NIT": "9012345678", "Name": "Proveedor Prueba AP"}, "Description": "Corrección/cancelación parcial enviada por AgroFusion sobre factura de compra ya contabilizada", "PaymentMethod": {"Code": "ADJUSTMENT", "Name": "Ajuste contable"}, "TransactionId": "AP09-E4-REF-0001", "ReferenceDocument": {"DocumentId": "FC-EXISTENTE-AP-0001"}}]}	2026-05-25	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	rejected	1	1	2	\N	2026-05-25 18:22:46.622573+00	2026-05-25 18:22:47.103384+00	2026-05-25 18:22:46.622573+00	\N
755b31b4-bc82-4c8d-b6d8-d69c7e964472	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 0, "TotalDocuments": 1, "TotalTransactions": 1}, "invoices": [], "metadata": {"ExchangeId": "AF-2026-05-5534", "GeneratedAt": "2026-05-25", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "9001766666"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-25", "Type": {"Code": "REF", "Name": "Reembolso"}, "Amount": 50000, "Status": "COMPLETED", "Currency": "COP", "ThirdParty": {"NIT": "9012345678", "Name": "Proveedor Prueba AP"}, "Description": "Corrección/cancelación parcial enviada por AgroFusion sobre factura de compra ya contabilizada", "PaymentMethod": {"Code": "ADJUSTMENT", "Name": "Ajuste contable"}, "TransactionId": "AP09-E4-REF-0002", "RelatedInvoiceId": "FC-EXISTENTE-AP-0001", "ReferenceDocument": {"DocumentId": "FC-EXISTENTE-AP-0001", "ExternalId": "FC-EXISTENTE-AP-0001"}}]}	2026-05-25	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-25 18:25:32.153226+00	2026-05-25 18:25:32.684676+00	2026-05-25 18:25:32.153226+00	\N
f72e45f6-abcc-4ecb-aebf-dff9305a1c68	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 0, "TotalDocuments": 1, "TotalTransactions": 1}, "invoices": [], "metadata": {"ExchangeId": "AF-2026-05-9171", "GeneratedAt": "2026-05-25", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "9001766666"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-25", "Type": {"Code": "ADV", "Name": "Anticipo a proveedor"}, "Amount": 250000, "Status": "COMPLETED", "Currency": "COP", "ThirdParty": {"NIT": "9012345678", "Name": "Proveedor Prueba AP"}, "Description": "Anticipo a proveedor antes de recibir factura", "PaymentMethod": {"Code": "BANK_TRANSFER", "Name": "Transferencia Bancaria"}, "TransactionId": "ADV-AP-2026-0001"}]}	2026-05-25	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-25 22:30:51.423702+00	2026-05-25 22:30:52.557344+00	2026-05-25 22:30:51.423702+00	\N
7f2983a9-c1e3-48b8-be1f-f970201897a9	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 1, "TotalTransactions": 0}, "invoices": [{"Lines": [{"Code": "INS-001", "Name": "Insumo agrícola", "Taxes": [{"Rate": 19, "Amount": 57000, "TaxType": "IVA"}], "Value": 300000, "LineType": "PRODUCT", "Quantity": 3, "UnitPrice": 100000, "Description": "Compra de insumo para operación"}], "Header": {"Type": {"Code": "02", "Name": "Compra"}, "Status": "PAID", "DueDate": "2026-06-24", "IssueDate": "2026-05-25", "DocumentId": "FC-AP-2026-0001"}, "Totals": {"Subtotal": 300000, "TotalVAT": 57000, "TotalPayment": 357000, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 0}, "ThirdParty": {"NIT": "9012345678", "Name": "Proveedor Prueba AP"}}], "metadata": {"ExchangeId": "AF-2026-05-4652", "GeneratedAt": "2026-05-25", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "9001766666"}, "StandardVersion": "1.0"}, "transactions": []}	2026-05-25	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-25 22:46:34.761491+00	2026-05-25 22:46:35.249699+00	2026-05-25 22:46:34.761491+00	\N
a2a110c1-4cf4-4493-824b-e844a282b4cf	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 1, "TotalTransactions": 0}, "invoices": [{"Lines": [{"Code": "P1", "Name": "Producto Base Reembolso", "Taxes": [{"Rate": 19, "Amount": 19000, "TaxType": "IVA"}], "Value": 100000, "LineType": "PRODUCT", "Quantity": 1, "UnitPrice": 100000, "Description": "Factura base para prueba de REF en CxC"}], "Header": {"Type": {"Code": "01", "Name": "Venta"}, "Status": "PENDING", "DueDate": "2026-06-25", "IssueDate": "2026-05-25", "DocumentId": "INV-RF06-AR-BASE-0601"}, "Totals": {"Subtotal": 100000, "TotalVAT": 19000, "TotalPayment": 119000, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 119000}, "ThirdParty": {"NIT": "9001760205", "Name": "Cliente Reembolso CxC"}}], "metadata": {"ExchangeId": "AF-2026-05-0601", "GeneratedAt": "2026-05-25", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "9001766666"}, "StandardVersion": "1.0"}, "transactions": []}	2026-05-26	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-26 04:35:14.463109+00	2026-05-26 04:35:14.787721+00	2026-05-26 04:35:14.463109+00	\N
565989ba-c4e7-4de2-bc42-b93ed4d15be2	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 0, "TotalDocuments": 1, "TotalTransactions": 1}, "invoices": [], "metadata": {"ExchangeId": "AF-2026-05-0602", "GeneratedAt": "2026-05-25", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "9001766666"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-26", "Type": {"Code": "REF", "Name": "Reembolso cliente"}, "Amount": 30000, "Status": "COMPLETED", "Currency": "COP", "DocumentId": "REF-RF06-AR-0602", "ThirdParty": {"NIT": "9001760205", "Name": "Cliente Reembolso CxC"}, "Description": "Reembolso parcial sobre factura de venta", "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}, "RelatedInvoiceId": "INV-RF06-AR-BASE-0601", "ReferenceDocument": {"DocumentId": "INV-RF06-AR-BASE-0601"}}]}	2026-05-26	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-26 04:35:45.731692+00	2026-05-26 04:35:46.354104+00	2026-05-26 04:35:45.731692+00	\N
11823a34-8943-4e1d-82bc-0974c0d411b6	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 1, "TotalTransactions": 0}, "invoices": [{"Lines": [{"Code": "CXC-CAN-1", "Name": "Producto", "Taxes": [{"Rate": 19, "Amount": 19000, "TaxType": "IVA"}], "Value": 100000, "LineType": "PRODUCT", "Quantity": 1, "UnitPrice": 100000, "Description": "Prueba CANCELLED CxC"}], "Header": {"Type": {"Code": "01", "Name": "Venta"}, "Status": "CANCELLED", "DueDate": "2026-06-26", "IssueDate": "2026-05-26", "DocumentId": "INV-FIX-CANCELLED-CXC-1101"}, "Totals": {"Subtotal": 100000, "TotalVAT": 19000, "TotalPayment": 119000, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 0}, "ThirdParty": {"NIT": "9001760205", "Name": "Cliente Fix Cancelled CxC"}}], "metadata": {"ExchangeId": "AF-2026-05-1101", "GeneratedAt": "2026-05-26", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "9001766666"}, "StandardVersion": "1.0"}, "transactions": []}	2026-05-27	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-27 02:24:35.053367+00	2026-05-27 02:24:36.376268+00	2026-05-27 02:24:35.053367+00	\N
6f097b77-5d41-4b24-b608-089caa6a79b5	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 1, "TotalTransactions": 0}, "invoices": [{"Lines": [{"Code": "CXP-CAN-1", "Name": "Insumo", "Taxes": [{"Rate": 19, "Amount": 38000, "TaxType": "IVA"}], "Value": 200000, "LineType": "PRODUCT", "Quantity": 1, "UnitPrice": 200000, "Description": "Prueba CANCELLED CxP"}], "Header": {"Type": {"Code": "02", "Name": "Compra"}, "Status": "CANCELLED", "DueDate": "2026-06-26", "IssueDate": "2026-05-26", "DocumentId": "INV-FIX-CANCELLED-CXP-1102"}, "Totals": {"Subtotal": 200000, "TotalVAT": 38000, "TotalPayment": 238000, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 0}, "ThirdParty": {"NIT": "9012345678", "Name": "Proveedor Fix Cancelled CxP"}}], "metadata": {"ExchangeId": "AF-2026-05-1102", "GeneratedAt": "2026-05-26", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "9001766666"}, "StandardVersion": "1.0"}, "transactions": []}	2026-05-27	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-27 02:25:16.645649+00	2026-05-27 02:25:17.209292+00	2026-05-27 02:25:16.645649+00	\N
b4e5049a-297e-4db9-876c-cf58bff2569d	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 2, "TotalTransactions": 1}, "invoices": [{"Lines": [{"Code": "CXC-PAR-1", "Name": "Producto", "Taxes": [{"Rate": 19, "Amount": 19000, "TaxType": "IVA"}], "Value": 100000, "LineType": "PRODUCT", "Quantity": 1, "UnitPrice": 100000, "Description": "Prueba PARTIAL CxC"}], "Header": {"Type": {"Code": "01", "Name": "Venta"}, "Status": "PARTIAL", "DueDate": "2026-06-26", "IssueDate": "2026-05-26", "DocumentId": "INV-FIX-PARTIAL-CXC-1103"}, "Totals": {"Subtotal": 100000, "TotalVAT": 19000, "TotalPayment": 119000, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 59000}, "ThirdParty": {"NIT": "9001760205", "Name": "Cliente Fix Partial CxC"}}], "metadata": {"ExchangeId": "AF-2026-05-1103", "GeneratedAt": "2026-05-26", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "9001766666"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-26", "Type": {"Code": "PAY", "Name": "Pago parcial cliente"}, "Amount": 60000, "Status": "COMPLETED", "Currency": "COP", "DocumentId": "PAY-FIX-PARTIAL-CXC-1103", "ThirdParty": {"NIT": "9001760205", "Name": "Cliente Fix Partial CxC"}, "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}, "RelatedInvoiceId": "INV-FIX-PARTIAL-CXC-1103"}]}	2026-05-27	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-27 02:26:38.037422+00	2026-05-27 02:26:38.755258+00	2026-05-27 02:26:38.037422+00	\N
6325a43d-579a-4db8-9432-4a2a5f38bee1	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 2, "TotalTransactions": 1}, "invoices": [{"Lines": [{"Code": "CXC-PAR-1", "Name": "Producto", "Taxes": [{"Rate": 19, "Amount": 19000, "TaxType": "IVA"}], "Value": 100000, "LineType": "PRODUCT", "Quantity": 1, "UnitPrice": 100000, "Description": "Prueba PARTIAL CxC"}], "Header": {"Type": {"Code": "01", "Name": "Venta"}, "Status": "PARTIAL", "DueDate": "2026-06-26", "IssueDate": "2026-05-26", "DocumentId": "INV-FIX-PARTIAL-CXC-1103"}, "Totals": {"Subtotal": 100000, "TotalVAT": 19000, "TotalPayment": 119000, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 59000}, "ThirdParty": {"NIT": "9001760000", "Name": "Cliente Fix Partial CxC"}}], "metadata": {"ExchangeId": "AF-2026-05-4503", "GeneratedAt": "2026-05-26", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "9001766666"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-26", "Type": {"Code": "PAY", "Name": "Pago parcial cliente"}, "Amount": 60000, "Status": "COMPLETED", "Currency": "COP", "DocumentId": "PAY-FIX-PARTIAL-CXC-1103", "ThirdParty": {"NIT": "9001760205", "Name": "Cliente Fix Partial CxC"}, "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}, "RelatedInvoiceId": "INV-FIX-PARTIAL-CXC-1103"}]}	2026-05-27	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	partial	1	1	2	\N	2026-05-27 02:31:34.389318+00	2026-05-27 02:31:35.122408+00	2026-05-27 02:31:34.389318+00	\N
a3ae65bd-442e-4697-9af3-4d97d3852b1d	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 0, "TotalDocuments": 1, "TotalTransactions": 1}, "invoices": [], "metadata": {"ExchangeId": "AF-2026-05-2237", "GeneratedAt": "2026-05-27", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "1077720925"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-27", "Type": {"Code": "PAY", "Name": "PAGO"}, "Amount": 97000, "Status": "REVERSED", "Currency": "COP", "DocumentId": "REF-CXP-REV-2117", "ThirdParty": {"NIT": "9100001037", "Name": "Proveedor Reverse Pacifico SAS"}, "Description": "Transaccion REF REVERSED para pruebas AAEF", "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}, "RelatedInvoiceId": "INV-CXP-REV-BASE-2116", "ReferenceDocument": {"DocumentId": "INV-CXP-REV-BASE-2116"}}]}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	rejected	1	1	2	\N	2026-05-28 15:42:01.903255+00	2026-05-28 15:42:02.169754+00	2026-05-28 15:42:01.903255+00	\N
a772f168-c991-4075-9a8d-4b57f26f0605	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 2, "TotalTransactions": 1}, "invoices": [{"Lines": [{"Code": "CXC-PAR-1", "Name": "Producto", "Taxes": [{"Rate": 19, "Amount": 19000, "TaxType": "IVA"}], "Value": 100000, "LineType": "PRODUCT", "Quantity": 1, "UnitPrice": 100000, "Description": "Prueba PARTIAL CxC"}], "Header": {"Type": {"Code": "01", "Name": "Venta"}, "Status": "PARTIAL", "DueDate": "2026-06-26", "IssueDate": "2026-05-26", "DocumentId": "INV-FIX-PARTIAL-CXC-1109"}, "Totals": {"Subtotal": 100000, "TotalVAT": 19000, "TotalPayment": 119000, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 59000}, "ThirdParty": {"NIT": "9001760000", "Name": "Cliente Fix Partial CxC"}}], "metadata": {"ExchangeId": "AF-2026-05-5888", "GeneratedAt": "2026-05-26", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "9001766666"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-26", "Type": {"Code": "PAY", "Name": "Pago parcial cliente"}, "Amount": 60000, "Status": "COMPLETED", "Currency": "COP", "DocumentId": "PAY-FIX-PARTIAL-CXC-1109", "ThirdParty": {"NIT": "9001760000", "Name": "Cliente Fix Partial v2 CxC"}, "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}, "RelatedInvoiceId": "INV-FIX-PARTIAL-CXC-1109"}]}	2026-05-27	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-27 02:33:07.77988+00	2026-05-27 02:33:08.519606+00	2026-05-27 02:33:07.77988+00	\N
132869db-9a98-4743-881b-3c29ddffc744	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 2, "TotalTransactions": 1}, "invoices": [{"Lines": [{"Code": "CXC-PAID-1", "Name": "Producto", "Taxes": [{"Rate": 19, "Amount": 19000, "TaxType": "IVA"}], "Value": 100000, "LineType": "PRODUCT", "Quantity": 1, "UnitPrice": 100000, "Description": "Prueba PAID CxC"}], "Header": {"Type": {"Code": "01", "Name": "Venta"}, "Status": "PAID", "DueDate": "2026-06-26", "IssueDate": "2026-05-26", "DocumentId": "INV-FIX-PAID-CXC-1105"}, "Totals": {"Subtotal": 100000, "TotalVAT": 19000, "TotalPayment": 119000, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 0}, "ThirdParty": {"NIT": "9001760205", "Name": "Cliente Fix Paid CxC"}}], "metadata": {"ExchangeId": "AF-2026-05-1105", "GeneratedAt": "2026-05-26", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "9001766666"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-26", "Type": {"Code": "PAY", "Name": "Pago total cliente"}, "Amount": 119000, "Status": "COMPLETED", "Currency": "COP", "DocumentId": "PAY-FIX-PAID-CXC-1105", "ThirdParty": {"NIT": "9001760205", "Name": "Cliente Fix Paid CxC"}, "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}, "RelatedInvoiceId": "INV-FIX-PAID-CXC-1105"}]}	2026-05-27	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-27 02:35:33.747646+00	2026-05-27 02:35:34.19407+00	2026-05-27 02:35:33.747646+00	\N
cf863d11-5fb6-4d1e-b6ae-01651713c013	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 2, "TotalTransactions": 1}, "invoices": [{"Lines": [{"Code": "CMP-901", "Name": "Compra base reversa REF", "Taxes": [{"Rate": 19, "Amount": 54150, "TaxType": "IVA"}], "Value": 285000, "LineType": "PRODUCT", "Quantity": 1, "UnitPrice": 285000, "Description": "Factura compra para prueba en dos lotes"}], "Header": {"Type": {"Code": "02", "Name": "Compra"}, "Status": "PAID", "DueDate": "2026-06-26", "IssueDate": "2026-05-26", "DocumentId": "INV-RV-REF-CXP-1401"}, "Totals": {"Subtotal": 285000, "TotalVAT": 54150, "TotalPayment": 339150, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 0}, "ThirdParty": {"NIT": "9016678453", "Name": "Servicios y Suministros Prisma S.A.S."}}], "metadata": {"ExchangeId": "AF-2026-05-1401", "GeneratedAt": "2026-05-26", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "9001766666"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-26", "Type": {"Code": "PAY", "Name": "Pago total proveedor"}, "Amount": 339150, "Status": "COMPLETED", "Currency": "COP", "DocumentId": "PAY-CXP-1401", "ThirdParty": {"NIT": "9016678453", "Name": "Servicios y Suministros Prisma S.A.S."}, "Description": "Pago completo factura compra", "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}, "RelatedInvoiceId": "INV-RV-REF-CXP-1401", "ReferenceDocument": {"DocumentId": "INV-RV-REF-CXP-1401"}}]}	2026-05-27	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-27 03:01:35.914475+00	2026-05-27 03:01:36.176715+00	2026-05-27 03:01:35.914475+00	\N
27125e57-385b-4045-8e37-ff01546cf016	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 0, "TotalDocuments": 1, "TotalTransactions": 1}, "invoices": [], "metadata": {"ExchangeId": "AF-2026-05-1402", "GeneratedAt": "2026-05-26", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "9001766666"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-26", "Type": {"Code": "REF", "Name": "Reversa de reembolso proveedor"}, "Amount": 120000, "Status": "REVERSED", "Currency": "COP", "DocumentId": "REF-RV-CXP-1402", "ThirdParty": {"NIT": "9016678453", "Name": "Servicios y Suministros Prisma S.A.S."}, "Description": "Reversa parcial usando REF con estado REVERSED", "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}, "RelatedInvoiceId": "INV-RV-REF-CXP-1401", "ReferenceDocument": {"DocumentId": "INV-RV-REF-CXP-1401"}}]}	2026-05-27	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-27 03:01:46.123584+00	2026-05-27 03:01:46.388748+00	2026-05-27 03:01:46.123584+00	\N
476c3b41-e784-4fea-9454-3dbf88cf0859	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 2, "TotalTransactions": 1}, "invoices": [{"Lines": [{"Code": "CXP-PAR-1", "Name": "Insumo", "Taxes": [{"Rate": 19, "Amount": 38000, "TaxType": "IVA"}], "Value": 200000, "LineType": "PRODUCT", "Quantity": 1, "UnitPrice": 200000, "Description": "Prueba PARTIAL CxP"}], "Header": {"Type": {"Code": "02", "Name": "Compra"}, "Status": "PARTIAL", "DueDate": "2026-06-26", "IssueDate": "2026-05-26", "DocumentId": "INV-FIX-PARTIAL-CXP-1104"}, "Totals": {"Subtotal": 200000, "TotalVAT": 38000, "TotalPayment": 238000, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 138000}, "ThirdParty": {"NIT": "9012345678", "Name": "Proveedor Fix Partial CxP"}}], "metadata": {"ExchangeId": "AF-2026-05-1104", "GeneratedAt": "2026-05-26", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "9001766666"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-26", "Type": {"Code": "PAY", "Name": "Pago parcial proveedor"}, "Amount": 100000, "Status": "COMPLETED", "Currency": "COP", "DocumentId": "PAY-FIX-PARTIAL-CXP-1104", "ThirdParty": {"NIT": "9012345678", "Name": "Proveedor Fix Partial CxP"}, "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}, "RelatedInvoiceId": "INV-FIX-PARTIAL-CXP-1104"}]}	2026-05-27	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-27 02:34:19.086309+00	2026-05-27 02:34:19.300254+00	2026-05-27 02:34:19.086309+00	\N
8fd8fadf-1954-4b26-83ce-c5611ef0ade1	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 2, "TotalTransactions": 1}, "invoices": [{"Lines": [{"Code": "CXP-PAID-1", "Name": "Insumo", "Taxes": [{"Rate": 19, "Amount": 38000, "TaxType": "IVA"}], "Value": 200000, "LineType": "PRODUCT", "Quantity": 1, "UnitPrice": 200000, "Description": "Prueba PAID CxP"}], "Header": {"Type": {"Code": "02", "Name": "Compra"}, "Status": "PAID", "DueDate": "2026-06-26", "IssueDate": "2026-05-26", "DocumentId": "INV-FIX-PAID-CXP-1106"}, "Totals": {"Subtotal": 200000, "TotalVAT": 38000, "TotalPayment": 238000, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 0}, "ThirdParty": {"NIT": "9012345678", "Name": "Proveedor Fix Paid CxP"}}], "metadata": {"ExchangeId": "AF-2026-05-1106", "GeneratedAt": "2026-05-26", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "9001766666"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-26", "Type": {"Code": "PAY", "Name": "Pago total proveedor"}, "Amount": 238000, "Status": "COMPLETED", "Currency": "COP", "DocumentId": "PAY-FIX-PAID-CXP-1106", "ThirdParty": {"NIT": "9012345678", "Name": "Proveedor Fix Paid CxP"}, "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}, "RelatedInvoiceId": "INV-FIX-PAID-CXP-1106"}]}	2026-05-27	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-27 02:37:41.794995+00	2026-05-27 02:37:42.342656+00	2026-05-27 02:37:41.794995+00	\N
d24d1f92-daec-4cf8-b899-7f00fedf80d0	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 2, "TotalDocuments": 2, "TotalTransactions": 0}, "invoices": [{"Lines": [{"Code": "ACT-CXC-1", "Name": "Servicio activo CxC", "Taxes": [{"Rate": 19, "Amount": 27550, "TaxType": "IVA"}], "Value": 145000, "LineType": "SERVICE", "Quantity": 1, "UnitPrice": 145000, "Description": "Prueba estado ACTIVE en factura de venta"}], "Header": {"Type": {"Code": "01", "Name": "Venta"}, "Status": "ACTIVE", "DueDate": "2026-06-26", "IssueDate": "2026-05-26", "DocumentId": "INV-ACTIVE-CXC-1501"}, "Totals": {"Subtotal": 145000, "TotalVAT": 27550, "TotalPayment": 172550, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 172550}, "ThirdParty": {"NIT": "9001760205", "Name": "Cliente Estado Active CxC"}}, {"Lines": [{"Code": "ACT-CXP-1", "Name": "Insumo activo CxP", "Taxes": [{"Rate": 19, "Amount": 61750, "TaxType": "IVA"}], "Value": 325000, "LineType": "PRODUCT", "Quantity": 1, "UnitPrice": 325000, "Description": "Prueba estado ACTIVE en factura de compra"}], "Header": {"Type": {"Code": "02", "Name": "Compra"}, "Status": "ACTIVE", "DueDate": "2026-06-26", "IssueDate": "2026-05-26", "DocumentId": "INV-ACTIVE-CXP-1501"}, "Totals": {"Subtotal": 325000, "TotalVAT": 61750, "TotalPayment": 386750, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 386750}, "ThirdParty": {"NIT": "9018897741", "Name": "Proveedor Estado Active CxP"}}], "metadata": {"ExchangeId": "AF-2026-05-1501", "GeneratedAt": "2026-05-26", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "9001766666"}, "StandardVersion": "1.0"}, "transactions": []}	2026-05-27	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-27 03:06:17.522535+00	2026-05-27 03:06:17.869346+00	2026-05-27 03:06:17.522535+00	\N
2b72d2d0-5f2a-4e79-a8bb-09f6a5500e39	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 2, "TotalTransactions": 1}, "invoices": [{"Lines": [{"Code": "SRV-901", "Name": "Servicio técnico especializado", "Taxes": [{"Rate": 19, "Amount": 66025, "TaxType": "IVA"}], "Value": 347500, "LineType": "SERVICE", "Quantity": 1, "UnitPrice": 347500, "Description": "Implementación y soporte mensual"}], "Header": {"Type": {"Code": "01", "Name": "Venta"}, "Status": "PAID", "DueDate": "2026-06-20", "IssueDate": "2026-05-26", "DocumentId": "INV-RV-CXC-1201"}, "Totals": {"Subtotal": 347500, "TotalVAT": 66025, "TotalPayment": 401025, "TotalDiscounts": 12500, "TotalWithholdings": 0, "OutstandingBalance": 0}, "ThirdParty": {"NIT": "9017784562", "Name": "Comercial La Sabana S.A.S."}}], "metadata": {"ExchangeId": "AF-2026-05-1201", "GeneratedAt": "2026-05-26", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "9001766666"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-26", "Type": {"Code": "PAY", "Name": "Reversa de pago cliente"}, "Amount": 150000, "Status": "REVERSED", "Currency": "COP", "DocumentId": "PAY-RV-CXC-1201", "ThirdParty": {"NIT": "9017784562", "Name": "Comercial La Sabana S.A.S."}, "Description": "Reversa parcial por ajuste comercial", "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}, "RelatedInvoiceId": "INV-RV-CXC-1201", "ReferenceDocument": {"DocumentId": "INV-RV-CXC-1201"}}]}	2026-05-27	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	partial	1	1	2	\N	2026-05-27 02:45:26.921953+00	2026-05-27 02:45:27.36205+00	2026-05-27 02:45:26.921953+00	\N
97377eb4-2a37-43d6-9660-4e00e691eb4e	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 3, "TotalTransactions": 2}, "invoices": [{"Lines": [{"Code": "SRV-922", "Name": "Servicio de implementación", "Taxes": [{"Rate": 19, "Amount": 54017, "TaxType": "IVA"}], "Value": 284300, "LineType": "SERVICE", "Quantity": 1, "UnitPrice": 284300, "Description": "Configuración y despliegue inicial"}], "Header": {"Type": {"Code": "01", "Name": "Venta"}, "Status": "PAID", "DueDate": "2026-06-20", "IssueDate": "2026-05-26", "DocumentId": "INV-RV-CXC-1202"}, "Totals": {"Subtotal": 284300, "TotalVAT": 54017, "TotalPayment": 330017, "TotalDiscounts": 8300, "TotalWithholdings": 0, "OutstandingBalance": 0}, "ThirdParty": {"NIT": "9016632451", "Name": "Distribuciones Horizonte S.A.S."}}], "metadata": {"ExchangeId": "AF-2026-05-1202", "GeneratedAt": "2026-05-26", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "9001766666"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-26", "Type": {"Code": "PAY", "Name": "Pago total factura"}, "Amount": 330017, "Status": "COMPLETED", "Currency": "COP", "DocumentId": "PAY-CXC-1202", "ThirdParty": {"NIT": "9016632451", "Name": "Distribuciones Horizonte S.A.S."}, "Description": "Pago completo de factura para cumplir regla PAID", "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}, "RelatedInvoiceId": "INV-RV-CXC-1202", "ReferenceDocument": {"DocumentId": "INV-RV-CXC-1202"}}, {"Date": "2026-05-26", "Type": {"Code": "PAY", "Name": "Reversa parcial de pago"}, "Amount": 120000, "Status": "REVERSED", "Currency": "COP", "DocumentId": "PAY-RV-CXC-1202", "ThirdParty": {"NIT": "9016632451", "Name": "Distribuciones Horizonte S.A.S."}, "Description": "Reversa parcial por ajuste comercial posterior", "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}, "RelatedInvoiceId": "INV-RV-CXC-1202", "ReferenceDocument": {"DocumentId": "INV-RV-CXC-1202"}}]}	2026-05-27	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-27 02:46:30.949259+00	2026-05-27 02:46:31.16946+00	2026-05-27 02:46:30.949259+00	\N
bedf349b-78fb-41b7-ad04-c28805575b1c	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 3, "TotalTransactions": 2}, "invoices": [{"Lines": [{"Code": "CMP-701", "Name": "Compra de insumos especializados", "Taxes": [{"Rate": 19, "Amount": 79002, "TaxType": "IVA"}], "Value": 415800, "LineType": "PRODUCT", "Quantity": 1, "UnitPrice": 415800, "Description": "Lote de materiales para operación"}], "Header": {"Type": {"Code": "02", "Name": "Compra"}, "Status": "PAID", "DueDate": "2026-06-22", "IssueDate": "2026-05-26", "DocumentId": "INV-RV-CXP-1203"}, "Totals": {"Subtotal": 415800, "TotalVAT": 79002, "TotalPayment": 485002, "TotalDiscounts": 9800, "TotalWithholdings": 0, "OutstandingBalance": 0}, "ThirdParty": {"NIT": "9018893472", "Name": "Abastecimientos del Norte S.A.S."}}], "metadata": {"ExchangeId": "AF-2026-05-1203", "GeneratedAt": "2026-05-26", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "9001766666"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-26", "Type": {"Code": "PAY", "Name": "Pago total factura proveedor"}, "Amount": 485002, "Status": "COMPLETED", "Currency": "COP", "DocumentId": "PAY-CXP-1203", "ThirdParty": {"NIT": "9018893472", "Name": "Abastecimientos del Norte S.A.S."}, "Description": "Pago completo para cumplir regla de factura PAID", "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}, "RelatedInvoiceId": "INV-RV-CXP-1203", "ReferenceDocument": {"DocumentId": "INV-RV-CXP-1203"}}, {"Date": "2026-05-26", "Type": {"Code": "PAY", "Name": "Reversa parcial pago proveedor"}, "Amount": 140000, "Status": "REVERSED", "Currency": "COP", "DocumentId": "PAY-RV-CXP-1203", "ThirdParty": {"NIT": "9018893472", "Name": "Abastecimientos del Norte S.A.S."}, "Description": "Reversa parcial por ajuste de compra", "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}, "RelatedInvoiceId": "INV-RV-CXP-1203", "ReferenceDocument": {"DocumentId": "INV-RV-CXP-1203"}}]}	2026-05-27	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	partial	1	1	2	\N	2026-05-27 02:53:20.938014+00	2026-05-27 02:53:21.295156+00	2026-05-27 02:53:20.938014+00	\N
fc2d6129-f804-4516-89f1-cb628e42fd32	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 3, "TotalTransactions": 2}, "invoices": [{"Lines": [{"Code": "CMP-702", "Name": "Compra insumos", "Taxes": [{"Rate": 19, "Amount": 76000, "TaxType": "IVA"}], "Value": 400000, "LineType": "PRODUCT", "Quantity": 1, "UnitPrice": 400000, "Description": "Prueba CxP con partida cuadrada"}], "Header": {"Type": {"Code": "02", "Name": "Compra"}, "Status": "PAID", "DueDate": "2026-06-22", "IssueDate": "2026-05-26", "DocumentId": "INV-RV-CXP-1204"}, "Totals": {"Subtotal": 400000, "TotalVAT": 76000, "TotalPayment": 476000, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 0}, "ThirdParty": {"NIT": "9018893472", "Name": "Abastecimientos del Norte S.A.S."}}], "metadata": {"ExchangeId": "AF-2026-05-1204", "GeneratedAt": "2026-05-26", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "9001766666"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-26", "Type": {"Code": "PAY", "Name": "Pago total factura proveedor"}, "Amount": 476000, "Status": "COMPLETED", "Currency": "COP", "DocumentId": "PAY-CXP-1204", "ThirdParty": {"NIT": "9018893472", "Name": "Abastecimientos del Norte S.A.S."}, "Description": "Pago completo factura CxP", "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}, "RelatedInvoiceId": "INV-RV-CXP-1204", "ReferenceDocument": {"DocumentId": "INV-RV-CXP-1204"}}, {"Date": "2026-05-26", "Type": {"Code": "PAY", "Name": "Reversa parcial pago proveedor"}, "Amount": 120000, "Status": "REVERSED", "Currency": "COP", "DocumentId": "PAY-RV-CXP-1204", "ThirdParty": {"NIT": "9018893472", "Name": "Abastecimientos del Norte S.A.S."}, "Description": "Reversa parcial por ajuste", "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}, "RelatedInvoiceId": "INV-RV-CXP-1204", "ReferenceDocument": {"DocumentId": "INV-RV-CXP-1204"}}]}	2026-05-27	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-27 02:54:38.142254+00	2026-05-27 02:54:38.512328+00	2026-05-27 02:54:38.142254+00	\N
3afa1a51-55a7-43a6-9196-f37cc034fda9	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 0, "TotalDocuments": 1, "TotalTransactions": 1}, "invoices": [], "metadata": {"ExchangeId": "AF-2026-85-9257", "GeneratedAt": "2026-05-27", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "1077720925"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-27", "Type": {"Code": "ADV", "Name": "Anticipo"}, "Amount": 143000, "Status": "COMPLETED", "Currency": "COP", "DocumentId": "ADV-CXP-2010", "ThirdParty": {"NIT": "9012345671", "Name": "Papelería Central"}, "Description": "Transaccion ADV COMPLETED para pruebas AAEF", "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}}]}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-28 17:29:10.541272+00	2026-05-28 17:29:11.003678+00	2026-05-28 17:29:10.541272+00	\N
52e6ac63-b5bd-49f7-a471-5bd6150f793f	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 1, "TotalTransactions": 0}, "invoices": [{"Lines": [{"Code": "LN-2001", "Name": "Item de prueba AAEF", "Taxes": [{"Rate": 19, "Amount": 27740, "TaxType": "IVA"}], "Value": 146000, "LineType": "PRODUCT", "Quantity": 1, "UnitPrice": 146000, "Description": "Linea para INV-CXC-ACTIVE-2001"}], "Header": {"Type": {"Code": "01", "Name": "Venta"}, "Status": "ACTIVE", "DueDate": "2026-06-27", "IssueDate": "2026-05-27", "DocumentId": "INV-CXC-ACTIVE-2001"}, "Totals": {"Subtotal": 146000, "TotalVAT": 27740, "TotalPayment": 173740, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 173740}, "ThirdParty": {"NIT": "9100000001", "Name": "Cliente Aurora Comercial SAS"}}], "metadata": {"ExchangeId": "AF-2026-05-2001", "GeneratedAt": "2026-05-27", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "1077720925"}, "StandardVersion": "1.0"}, "transactions": []}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-28 15:38:29.284894+00	2026-05-28 15:38:30.632405+00	2026-05-28 15:38:29.284894+00	\N
77b62e5b-b4e2-4db3-8bca-83b37394c3d8	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 2, "TotalTransactions": 1}, "invoices": [{"Lines": [{"Code": "LN-2116", "Name": "Item de prueba AAEF", "Taxes": [{"Rate": 19, "Amount": 81320, "TaxType": "IVA"}], "Value": 428000, "LineType": "PRODUCT", "Quantity": 1, "UnitPrice": 428000, "Description": "Linea para INV-CXP-REV-BASE-2116"}], "Header": {"Type": {"Code": "02", "Name": "Compra"}, "Status": "PAID", "DueDate": "2026-06-27", "IssueDate": "2026-05-27", "DocumentId": "INV-CXP-REV-BASE-2116"}, "Totals": {"Subtotal": 428000, "TotalVAT": 81320, "TotalPayment": 509320, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 0}, "ThirdParty": {"NIT": "9100001037", "Name": "Proveedor Reverse Pacifico SAS"}}], "metadata": {"ExchangeId": "AF-2026-05-2116", "GeneratedAt": "2026-05-27", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "1077720925"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-27", "Type": {"Code": "PAY", "Name": "Pago"}, "Amount": 509320, "Status": "COMPLETED", "Currency": "COP", "DocumentId": "PAY-CXP-REV-2116", "ThirdParty": {"NIT": "9100001037", "Name": "Proveedor Reverse Pacifico SAS"}, "Description": "Transaccion PAY COMPLETED para pruebas AAEF", "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}, "RelatedInvoiceId": "INV-CXP-REV-BASE-2116", "ReferenceDocument": {"DocumentId": "INV-CXP-REV-BASE-2116"}}]}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-28 15:40:11.793923+00	2026-05-28 15:40:12.716247+00	2026-05-28 15:40:11.793923+00	\N
fd074eca-b796-4eab-a086-348d3eab681e	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 0, "TotalDocuments": 1, "TotalTransactions": 1}, "invoices": [], "metadata": {"ExchangeId": "AF-2026-05-2117", "GeneratedAt": "2026-05-27", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "1077720925"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-27", "Type": {"Code": "REF", "Name": "Reembolso"}, "Amount": 97000, "Status": "REVERSED", "Currency": "COP", "DocumentId": "REF-CXP-REV-2117", "ThirdParty": {"NIT": "9100001037", "Name": "Proveedor Reverse Pacifico SAS"}, "Description": "Transaccion REF REVERSED para pruebas AAEF", "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}, "RelatedInvoiceId": "INV-CXP-REV-BASE-2116", "ReferenceDocument": {"DocumentId": "INV-CXP-REV-BASE-2116"}}]}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	rejected	1	1	2	\N	2026-05-28 15:40:36.560758+00	2026-05-28 15:40:36.784581+00	2026-05-28 15:40:36.560758+00	\N
27462edb-c133-4cd2-a9ed-d11e94f6697b	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 0, "TotalDocuments": 1, "TotalTransactions": 1}, "invoices": [], "metadata": {"ExchangeId": "AF-2026-05-9237", "GeneratedAt": "2026-05-27", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "1077720925"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-27", "Type": {"Code": "PAY", "Name": "PAGO"}, "Amount": 97000, "Status": "REVERSED", "Currency": "COP", "DocumentId": "REF-CXP-REV-2116", "ThirdParty": {"NIT": "9100001037", "Name": "Proveedor Reverse Pacifico SAS"}, "Description": "Transaccion REF REVERSED para pruebas AAEF", "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}, "RelatedInvoiceId": "INV-CXP-REV-BASE-2116", "ReferenceDocument": {"DocumentId": "INV-CXP-REV-BASE-2116"}}]}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	rejected	1	1	2	\N	2026-05-28 15:43:40.416447+00	2026-05-28 15:43:40.824968+00	2026-05-28 15:43:40.416447+00	\N
dc7e397f-34d3-4972-8fb9-81af7106247f	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 0, "TotalDocuments": 1, "TotalTransactions": 1}, "invoices": [], "metadata": {"ExchangeId": "AF-2026-05-2119", "GeneratedAt": "2026-05-27", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "9001766666"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-27", "Type": {"Code": "PAY", "Name": "Reversa de pago"}, "Amount": 509320, "Status": "REVERSED", "Currency": "COP", "DocumentId": "PAY-CXP-REV-2116", "ThirdParty": {"NIT": "9100001037", "Name": "Proveedor Reverse Pacifico SAS"}, "Description": "Reversa del pago original PAY-CXP-REV-2116", "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}, "RelatedInvoiceId": "INV-CXP-REV-BASE-2116", "ReferenceDocument": {"DocumentId": "INV-CXP-REV-BASE-2116"}}]}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	rejected	1	1	2	\N	2026-05-28 15:59:53.338275+00	2026-05-28 15:59:53.759061+00	2026-05-28 15:59:53.338275+00	\N
9f4c996c-f33d-4fe2-a285-d05359be5b97	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 0, "TotalDocuments": 1, "TotalTransactions": 1}, "invoices": [], "metadata": {"ExchangeId": "AF-2026-05-2012", "GeneratedAt": "2026-05-27", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "9001766666"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-27", "Type": {"Code": "REF", "Name": "Reembolso"}, "Amount": 85000, "Status": "COMPLETED", "Currency": "COP", "DocumentId": "REF-CXC-2012", "ThirdParty": {"NIT": "9100000371", "Name": "Cliente Reembolso Sigma SAS"}, "Description": "Transaccion REF COMPLETED para pruebas AAEF", "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}, "RelatedInvoiceId": "INV-CXC-REF-BASE-2011", "ReferenceDocument": {"DocumentId": "INV-CXC-REF-BASE-2011"}}]}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	rejected	1	1	2	\N	2026-05-28 16:51:36.789547+00	2026-05-28 16:51:36.902144+00	2026-05-28 16:51:36.789547+00	\N
187c531a-3559-45f1-a33a-778e16bf04cf	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 0, "TotalDocuments": 1, "TotalTransactions": 1}, "invoices": [], "metadata": {"ExchangeId": "AF-2026-05-7619", "GeneratedAt": "2026-05-27", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "1077720925"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-27", "Type": {"Code": "PAY", "Name": "Reversa de pago"}, "Amount": 509320, "Status": "REVERSED", "Currency": "COP", "DocumentId": "PAY-CXP-REV-2116", "ThirdParty": {"NIT": "9100001037", "Name": "Proveedor Reverse Pacifico SAS"}, "Description": "Reversa del pago original PAY-CXP-REV-2116", "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}, "RelatedInvoiceId": "INV-CXP-REV-BASE-2116", "ReferenceDocument": {"DocumentId": "INV-CXP-REV-BASE-2116"}}]}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-28 16:00:24.429013+00	2026-05-28 16:00:25.197854+00	2026-05-28 16:00:24.429013+00	\N
7982a117-2879-4593-99bf-0424d8cf689b	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 1, "TotalTransactions": 0}, "invoices": [{"Lines": [{"Code": "INS-REF-3401", "Name": "Insumo con saldo para reembolso", "Taxes": [{"Rate": 19, "Amount": 87400, "TaxType": "IVA"}], "Value": 460000, "LineType": "PRODUCT", "Quantity": 1, "UnitPrice": 460000, "Description": "Factura CxP con saldo pendiente para probar REF COMPLETED"}], "Header": {"Type": {"Code": "02", "Name": "Compra"}, "Status": "ACTIVE", "DueDate": "2026-06-28", "IssueDate": "2026-05-28", "UpdatedAt": "2026-05-28", "DocumentId": "FC-CXP-REF-BASE-3401"}, "Totals": {"Subtotal": 460000, "TotalVAT": 87400, "TotalPayment": 547400, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 547400}, "ThirdParty": {"NIT": "9100003401", "Name": "Proveedor Reembolso Saldo Boreal SAS"}}], "metadata": {"ExchangeId": "AF-2026-05-3401", "GeneratedAt": "2026-05-28", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "1077720925"}, "StandardVersion": "1.0"}, "transactions": []}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-28 16:34:36.196307+00	2026-05-28 16:34:36.360328+00	2026-05-28 16:34:36.196307+00	\N
c16f0c49-aaab-4feb-a56c-b66f3d4967ff	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 2, "TotalTransactions": 1}, "invoices": [{"Lines": [{"Code": "INS-REV-3201", "Name": "Insumo control reversa", "Taxes": [{"Rate": 19, "Amount": 71440, "TaxType": "IVA"}], "Value": 376000, "LineType": "PRODUCT", "Quantity": 1, "UnitPrice": 376000, "Description": "Factura CxP pagada para prueba de reversa PAY REVERSED"}], "Header": {"Type": {"Code": "02", "Name": "Compra"}, "Status": "PAID", "DueDate": "2026-06-28", "IssueDate": "2026-05-28", "UpdatedAt": "2026-05-28", "DocumentId": "FC-CXP-REV-BASE-3201"}, "Totals": {"Subtotal": 376000, "TotalVAT": 71440, "TotalPayment": 447440, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 0}, "ThirdParty": {"NIT": "9100003201", "Name": "Proveedor Reversa Nueva Andina SAS"}}], "metadata": {"ExchangeId": "AF-2026-05-3201", "GeneratedAt": "2026-05-28", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "1077720925"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-28", "Type": {"Code": "PAY", "Name": "Pago factura compra"}, "Amount": 447440, "Status": "COMPLETED", "Currency": "COP", "DocumentId": "PAY-CXP-REV-3201", "ThirdParty": {"NIT": "9100003201", "Name": "Proveedor Reversa Nueva Andina SAS"}, "Description": "Pago total factura FC-CXP-REV-BASE-3201", "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}, "RelatedInvoiceId": "FC-CXP-REV-BASE-3201", "ReferenceDocument": {"DocumentId": "FC-CXP-REV-BASE-3201"}}]}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-28 16:07:40.649021+00	2026-05-28 16:07:40.953917+00	2026-05-28 16:07:40.649021+00	\N
23260096-bf42-4c49-9ed8-01090c9b5c31	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 0, "TotalDocuments": 1, "TotalTransactions": 1}, "invoices": [], "metadata": {"ExchangeId": "AF-2026-05-2789", "GeneratedAt": "2026-05-28", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "1077720925"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-28", "Type": {"Code": "PAY", "Name": "Reversa pago factura compra"}, "Amount": 447440, "Status": "REVERSED", "Currency": "COP", "DocumentId": "PAY-CXP-REV-3201", "ThirdParty": {"NIT": "9100003201", "Name": "Proveedor Reversa Nueva Andina SAS"}, "Description": "Reversa del pago original PAY-CXP-REV-3201", "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}, "RelatedInvoiceId": "FC-CXP-REV-BASE-3201", "ReferenceDocument": {"DocumentId": "FC-CXP-REV-BASE-3201"}}]}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-28 16:09:10.188798+00	2026-05-28 16:09:10.463298+00	2026-05-28 16:09:10.188798+00	\N
54cb245f-5ac2-46a9-bcbb-79523d20b8a6	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 2, "TotalTransactions": 1}, "invoices": [{"Lines": [{"Code": "SERV-REV-3301", "Name": "Servicio control reversa", "Taxes": [{"Rate": 19, "Amount": 53770, "TaxType": "IVA"}], "Value": 283000, "LineType": "SERVICE", "Quantity": 1, "UnitPrice": 283000, "Description": "Factura CxC pagada para prueba de reversa PAY REVERSED"}], "Header": {"Type": {"Code": "01", "Name": "Venta"}, "Status": "PAID", "DueDate": "2026-06-28", "IssueDate": "2026-05-28", "UpdatedAt": "2026-05-28", "DocumentId": "FV-CXC-REV-BASE-3301"}, "Totals": {"Subtotal": 283000, "TotalVAT": 53770, "TotalPayment": 336770, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 0}, "ThirdParty": {"NIT": "9100003301", "Name": "Cliente Reversa Nueva Aurora SAS"}}], "metadata": {"ExchangeId": "AF-2026-05-4679", "GeneratedAt": "2026-05-28", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "1077720925"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-28", "Type": {"Code": "PAY", "Name": "Pago factura venta"}, "Amount": 336770, "Status": "COMPLETED", "Currency": "COP", "DocumentId": "PAY-CXC-REV-3301", "ThirdParty": {"NIT": "9100003301", "Name": "Cliente Reversa Nueva Aurora SAS"}, "Description": "Pago total factura FV-CXC-REV-BASE-3301", "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}, "RelatedInvoiceId": "FV-CXC-REV-BASE-3301", "ReferenceDocument": {"DocumentId": "FV-CXC-REV-BASE-3301"}}]}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-28 16:14:45.8795+00	2026-05-28 16:14:46.423085+00	2026-05-28 16:14:45.8795+00	\N
4644af70-5937-4662-8140-f6ac579ba0a1	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 0, "TotalDocuments": 1, "TotalTransactions": 1}, "invoices": [], "metadata": {"ExchangeId": "AF-2026-05-0999", "GeneratedAt": "2026-05-28", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "1077720925"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-28", "Type": {"Code": "PAY", "Name": "Reversa pago factura venta"}, "Amount": 336770, "Status": "REVERSED", "Currency": "COP", "DocumentId": "PAY-CXC-REV-3301", "ThirdParty": {"NIT": "9100003301", "Name": "Cliente Reversa Nueva Aurora SAS"}, "Description": "Reversa del pago original PAY-CXC-REV-3301", "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}, "RelatedInvoiceId": "FV-CXC-REV-BASE-3301", "ReferenceDocument": {"DocumentId": "FV-CXC-REV-BASE-3301"}}]}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-28 16:16:19.708089+00	2026-05-28 16:16:19.909956+00	2026-05-28 16:16:19.708089+00	\N
e5dad353-2307-4b1e-a17b-715518d36ac9	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 0, "TotalDocuments": 1, "TotalTransactions": 1}, "invoices": [], "metadata": {"ExchangeId": "AF-2026-05-2010", "GeneratedAt": "2026-05-27", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "1077720925"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-27", "Type": {"Code": "ADV", "Name": "Anticipo"}, "Amount": 143000, "Status": "COMPLETED", "Currency": "COP", "DocumentId": "ADV-CXP-2010", "ThirdParty": {"NIT": "9100000334", "Name": "Proveedor Anticipo Origen SAS"}, "Description": "Transaccion ADV COMPLETED para pruebas AAEF", "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}}]}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-28 17:16:41.36559+00	2026-05-28 17:16:41.549261+00	2026-05-28 17:16:41.36559+00	\N
2ffb5504-6b19-4063-930d-424cafe1e604	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 2, "TotalTransactions": 1}, "invoices": [{"Lines": [{"Code": "LN-2013", "Name": "Item de prueba AAEF", "Taxes": [{"Rate": 19, "Amount": 64790, "TaxType": "IVA"}], "Value": 341000, "LineType": "PRODUCT", "Quantity": 1, "UnitPrice": 341000, "Description": "Linea para INV-CXP-REF-BASE-2013"}], "Header": {"Type": {"Code": "02", "Name": "Compra"}, "Status": "PAID", "DueDate": "2026-06-27", "IssueDate": "2026-05-27", "DocumentId": "INV-CXP-REF-BASE-2013"}, "Totals": {"Subtotal": 341000, "TotalVAT": 64790, "TotalPayment": 405790, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 0}, "ThirdParty": {"NIT": "9100000408", "Name": "Proveedor Reembolso Meridian SAS"}}], "metadata": {"ExchangeId": "AF-2026-05-2013", "GeneratedAt": "2026-05-27", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "1077720925"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-27", "Type": {"Code": "PAY", "Name": "Pago"}, "Amount": 405790, "Status": "COMPLETED", "Currency": "COP", "DocumentId": "PAY-CXP-REF-2013", "ThirdParty": {"NIT": "9100000408", "Name": "Proveedor Reembolso Meridian SAS"}, "Description": "Transaccion PAY COMPLETED para pruebas AAEF", "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}, "RelatedInvoiceId": "INV-CXP-REF-BASE-2013", "ReferenceDocument": {"DocumentId": "INV-CXP-REF-BASE-2013"}}]}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-28 16:29:39.305608+00	2026-05-28 16:29:39.673993+00	2026-05-28 16:29:39.305608+00	\N
967178bf-a22d-4abd-b4f8-e83e6c45d76f	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 0, "TotalDocuments": 1, "TotalTransactions": 1}, "invoices": [], "metadata": {"ExchangeId": "AF-2026-05-2014", "GeneratedAt": "2026-05-27", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "9001766666"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-27", "Type": {"Code": "REF", "Name": "Reembolso"}, "Amount": 73000, "Status": "COMPLETED", "Currency": "COP", "DocumentId": "REF-CXP-2014", "ThirdParty": {"NIT": "9100000408", "Name": "Proveedor Reembolso Meridian SAS"}, "Description": "Transaccion REF COMPLETED para pruebas AAEF", "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}, "RelatedInvoiceId": "INV-CXP-REF-BASE-2013", "ReferenceDocument": {"DocumentId": "INV-CXP-REF-BASE-2013"}}]}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	rejected	1	1	2	\N	2026-05-28 16:30:54.548162+00	2026-05-28 16:30:54.965356+00	2026-05-28 16:30:54.548162+00	\N
d06d81e5-324b-45de-b433-5d8fe0c5bfc3	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 0, "TotalDocuments": 1, "TotalTransactions": 1}, "invoices": [], "metadata": {"ExchangeId": "AF-2026-07-2014", "GeneratedAt": "2026-05-27", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "1077720925"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-27", "Type": {"Code": "REF", "Name": "Reembolso"}, "Amount": 73000, "Status": "COMPLETED", "Currency": "COP", "DocumentId": "REF-CXP-2014", "ThirdParty": {"NIT": "9100000408", "Name": "Proveedor Reembolso Meridian SAS"}, "Description": "Transaccion REF COMPLETED para pruebas AAEF", "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}, "RelatedInvoiceId": "INV-CXP-REF-BASE-2013", "ReferenceDocument": {"DocumentId": "INV-CXP-REF-BASE-2013"}}]}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	rejected	1	1	2	\N	2026-05-28 16:31:25.674107+00	2026-05-28 16:31:25.944844+00	2026-05-28 16:31:25.674107+00	\N
c1a19dff-de09-48b7-aaa1-0617f72373a2	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 0, "TotalDocuments": 1, "TotalTransactions": 1}, "invoices": [], "metadata": {"ExchangeId": "AF-2026-05-3402", "GeneratedAt": "2026-05-28", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "1077720925"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-28", "Type": {"Code": "REF", "Name": "Reembolso proveedor"}, "Amount": 73000, "Status": "COMPLETED", "Currency": "COP", "DocumentId": "REF-CXP-3402", "ThirdParty": {"NIT": "9100003401", "Name": "Proveedor Reembolso Saldo Boreal SAS"}, "Description": "Reembolso aplicado sobre factura de compra con saldo pendiente", "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}, "RelatedInvoiceId": "FC-CXP-REF-BASE-3401", "ReferenceDocument": {"DocumentId": "FC-CXP-REF-BASE-3401"}}]}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-28 16:35:13.352637+00	2026-05-28 16:35:13.483961+00	2026-05-28 16:35:13.352637+00	\N
a3d5e239-73c4-4a66-9ebd-55e503f7c0ce	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 2, "TotalTransactions": 1}, "invoices": [{"Lines": [{"Code": "LN-2011", "Name": "Item de prueba AAEF", "Taxes": [{"Rate": 19, "Amount": 48260, "TaxType": "IVA"}], "Value": 254000, "LineType": "PRODUCT", "Quantity": 1, "UnitPrice": 254000, "Description": "Linea para INV-CXC-REF-BASE-2011"}], "Header": {"Type": {"Code": "01", "Name": "Venta"}, "Status": "PAID", "DueDate": "2026-06-27", "IssueDate": "2026-05-27", "DocumentId": "INV-CXC-REF-BASE-2011"}, "Totals": {"Subtotal": 254000, "TotalVAT": 48260, "TotalPayment": 302260, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 0}, "ThirdParty": {"NIT": "9100000371", "Name": "Cliente Reembolso Sigma SAS"}}], "metadata": {"ExchangeId": "AF-2026-05-2011", "GeneratedAt": "2026-05-27", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "1077720925"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-27", "Type": {"Code": "PAY", "Name": "Pago"}, "Amount": 302260, "Status": "COMPLETED", "Currency": "COP", "DocumentId": "PAY-CXC-REF-2011", "ThirdParty": {"NIT": "9100000371", "Name": "Cliente Reembolso Sigma SAS"}, "Description": "Transaccion PAY COMPLETED para pruebas AAEF", "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}, "RelatedInvoiceId": "INV-CXC-REF-BASE-2011", "ReferenceDocument": {"DocumentId": "INV-CXC-REF-BASE-2011"}}]}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-28 16:51:10.77577+00	2026-05-28 16:51:11.302013+00	2026-05-28 16:51:10.77577+00	\N
916613db-a669-4805-b9b2-b11e75b9c1ba	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 0, "TotalDocuments": 1, "TotalTransactions": 1}, "invoices": [], "metadata": {"ExchangeId": "AF-2026-05-3502", "GeneratedAt": "2026-05-28", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "1077720925"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-28", "Type": {"Code": "REF", "Name": "Reembolso cliente"}, "Amount": 83000, "Status": "COMPLETED", "Currency": "COP", "DocumentId": "REF-CXC-3502", "ThirdParty": {"NIT": "9100003501", "Name": "Cliente Reembolso Saldo Austral SAS"}, "Description": "Reembolso aplicado sobre factura de venta con saldo pendiente", "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}, "RelatedInvoiceId": "FV-CXC-REF-BASE-3501", "ReferenceDocument": {"DocumentId": "FV-CXC-REF-BASE-3501"}}]}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-28 16:53:32.435074+00	2026-05-28 16:53:32.574448+00	2026-05-28 16:53:32.435074+00	\N
99a31fd9-6330-4c70-aa01-11c390d8f038	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 2, "TotalTransactions": 1}, "invoices": [{"Lines": [{"Code": "LN-2003", "Name": "Item de prueba AAEF", "Taxes": [{"Rate": 19, "Amount": 39900, "TaxType": "IVA"}], "Value": 210000, "LineType": "PRODUCT", "Quantity": 1, "UnitPrice": 210000, "Description": "Linea para INV-CXC-PAID-2003"}], "Header": {"Type": {"Code": "01", "Name": "Venta"}, "Status": "PAID", "DueDate": "2026-06-27", "IssueDate": "2026-05-27", "DocumentId": "INV-CXC-PAID-2003"}, "Totals": {"Subtotal": 210000, "TotalVAT": 39900, "TotalPayment": 249900, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 0}, "ThirdParty": {"NIT": "9100000075", "Name": "Cliente Pagos Andinos SAS"}}], "metadata": {"ExchangeId": "AF-2026-05-2003", "GeneratedAt": "2026-05-27", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "9001766666"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-27", "Type": {"Code": "PAY", "Name": "Pago"}, "Amount": 249900, "Status": "COMPLETED", "Currency": "COP", "DocumentId": "PAY-CXC-2003", "ThirdParty": {"NIT": "9100000075", "Name": "Cliente Pagos Andinos SAS"}, "Description": "Transaccion PAY COMPLETED para pruebas AAEF", "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}, "RelatedInvoiceId": "INV-CXC-PAID-2003", "ReferenceDocument": {"DocumentId": "INV-CXC-PAID-2003"}}]}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-28 17:00:42.457738+00	2026-05-28 17:00:42.780145+00	2026-05-28 17:00:42.457738+00	\N
228da0bd-1b0d-46bc-a46c-550117b950c9	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 0, "TotalDocuments": 1, "TotalTransactions": 1}, "invoices": [], "metadata": {"ExchangeId": "AF-2026-05-4512", "GeneratedAt": "2026-05-27", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "1077720925"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-27", "Type": {"Code": "ADV", "Name": "Anticipo"}, "Amount": 143000, "Status": "COMPLETED", "Currency": "COP", "DocumentId": "ADV-CXP-2010", "ThirdParty": {"NIT": "9100000334", "Name": "Proveedor Anticipo Origen SAS"}, "Description": "Transaccion ADV COMPLETED para pruebas AAEF", "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}}]}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-28 17:18:51.442107+00	2026-05-28 17:18:51.572653+00	2026-05-28 17:18:51.442107+00	\N
49ddb31b-4b5c-4332-b5d6-9aaf9d62108d	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 0, "TotalDocuments": 1, "TotalTransactions": 1}, "invoices": [], "metadata": {"ExchangeId": "AF-2026-05-9257", "GeneratedAt": "2026-05-27", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "1077720925"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-27", "Type": {"Code": "ADV", "Name": "Anticipo"}, "Amount": 143000, "Status": "COMPLETED", "Currency": "COP", "DocumentId": "ADV-CXP-2010", "ThirdParty": {"NIT": "1077225314", "Name": "Juan Vidarte"}, "Description": "Transaccion ADV COMPLETED para pruebas AAEF", "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}}]}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-28 17:26:00.55191+00	2026-05-28 17:26:00.848283+00	2026-05-28 17:26:00.55191+00	\N
73f71437-8c6b-4a95-abd9-d2edf72db652	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 0, "TotalDocuments": 1, "TotalTransactions": 1}, "invoices": [], "metadata": {"ExchangeId": "AF-2026-05-2052", "GeneratedAt": "2026-05-27", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "1077720925"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-27", "Type": {"Code": "REF", "Name": "Reembolso"}, "Amount": 85000, "Status": "COMPLETED", "Currency": "COP", "DocumentId": "REF-CXC-2012", "ThirdParty": {"NIT": "9100000371", "Name": "Cliente Reembolso Sigma SAS"}, "Description": "Transaccion REF COMPLETED para pruebas AAEF", "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}, "RelatedInvoiceId": "INV-CXC-REF-BASE-2011", "ReferenceDocument": {"DocumentId": "INV-CXC-REF-BASE-2011"}}]}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	rejected	1	1	2	\N	2026-05-28 16:52:16.719706+00	2026-05-28 16:52:16.815023+00	2026-05-28 16:52:16.719706+00	\N
ae82a4a1-9c2e-43a1-a8f4-861f66d3a049	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 1, "TotalTransactions": 0}, "invoices": [{"Lines": [{"Code": "SERV-REF-3501", "Name": "Servicio con saldo para reembolso", "Taxes": [{"Rate": 19, "Amount": 74100, "TaxType": "IVA"}], "Value": 390000, "LineType": "SERVICE", "Quantity": 1, "UnitPrice": 390000, "Description": "Factura CxC con saldo pendiente para probar REF COMPLETED"}], "Header": {"Type": {"Code": "01", "Name": "Venta"}, "Status": "ACTIVE", "DueDate": "2026-06-28", "IssueDate": "2026-05-28", "UpdatedAt": "2026-05-28", "DocumentId": "FV-CXC-REF-BASE-3501"}, "Totals": {"Subtotal": 390000, "TotalVAT": 74100, "TotalPayment": 464100, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 464100}, "ThirdParty": {"NIT": "9100003501", "Name": "Cliente Reembolso Saldo Austral SAS"}}], "metadata": {"ExchangeId": "AF-2026-05-3501", "GeneratedAt": "2026-05-28", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "1077720925"}, "StandardVersion": "1.0"}, "transactions": []}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-28 16:52:49.322945+00	2026-05-28 16:52:49.563082+00	2026-05-28 16:52:49.322945+00	\N
c4766726-9efb-4f8e-8388-643408fb3a2a	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 1, "TotalTransactions": 0}, "invoices": [{"Lines": [{"Code": "LN-2002", "Name": "Item de prueba AAEF", "Taxes": [{"Rate": 19, "Amount": 60420, "TaxType": "IVA"}], "Value": 318000, "LineType": "PRODUCT", "Quantity": 1, "UnitPrice": 318000, "Description": "Linea para INV-CXP-ACTIVE-2002"}], "Header": {"Type": {"Code": "02", "Name": "Compra"}, "Status": "ACTIVE", "DueDate": "2026-06-27", "IssueDate": "2026-05-27", "DocumentId": "INV-CXP-ACTIVE-2002"}, "Totals": {"Subtotal": 318000, "TotalVAT": 60420, "TotalPayment": 378420, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 378420}, "ThirdParty": {"NIT": "9100000038", "Name": "Proveedor Norte Industrial SAS"}}], "metadata": {"ExchangeId": "AF-2026-05-2002", "GeneratedAt": "2026-05-27", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "1077720925"}, "StandardVersion": "1.0"}, "transactions": []}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-28 17:00:20.421241+00	2026-05-28 17:00:20.788162+00	2026-05-28 17:00:20.421241+00	\N
93bcadc8-dee5-4b4a-aeef-a033751f2079	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 2, "TotalTransactions": 1}, "invoices": [{"Lines": [{"Code": "LN-2003", "Name": "Item de prueba AAEF", "Taxes": [{"Rate": 19, "Amount": 39900, "TaxType": "IVA"}], "Value": 210000, "LineType": "PRODUCT", "Quantity": 1, "UnitPrice": 210000, "Description": "Linea para INV-CXC-PAID-2003"}], "Header": {"Type": {"Code": "01", "Name": "Venta"}, "Status": "PAID", "DueDate": "2026-06-27", "IssueDate": "2026-05-27", "DocumentId": "INV-CXC-PAID-2003"}, "Totals": {"Subtotal": 210000, "TotalVAT": 39900, "TotalPayment": 249900, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 0}, "ThirdParty": {"NIT": "9100000075", "Name": "Cliente Pagos Andinos SAS"}}], "metadata": {"ExchangeId": "AF-2026-05-2093", "GeneratedAt": "2026-05-27", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "1077720925"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-27", "Type": {"Code": "PAY", "Name": "Pago"}, "Amount": 249900, "Status": "COMPLETED", "Currency": "COP", "DocumentId": "PAY-CXC-2003", "ThirdParty": {"NIT": "9100000075", "Name": "Cliente Pagos Andinos SAS"}, "Description": "Transaccion PAY COMPLETED para pruebas AAEF", "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}, "RelatedInvoiceId": "INV-CXC-PAID-2003", "ReferenceDocument": {"DocumentId": "INV-CXC-PAID-2003"}}]}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	partial	1	1	2	\N	2026-05-28 17:01:09.973259+00	2026-05-28 17:01:10.276298+00	2026-05-28 17:01:09.973259+00	\N
94a32920-0d08-4ef7-8585-5250a3705b97	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 2, "TotalTransactions": 1}, "invoices": [{"Lines": [{"Code": "SERV-SAMEPAY-3701", "Name": "Servicio pago mismo lote", "Taxes": [{"Rate": 19, "Amount": 59850, "TaxType": "IVA"}], "Value": 315000, "LineType": "SERVICE", "Quantity": 1, "UnitPrice": 315000, "Description": "Factura CxC PAID con PAY en el mismo payload"}], "Header": {"Type": {"Code": "01", "Name": "Venta"}, "Status": "PAID", "DueDate": "2026-06-28", "IssueDate": "2026-05-28", "UpdatedAt": "2026-05-28", "DocumentId": "FV-CXC-SAMEPAY-3701"}, "Totals": {"Subtotal": 315000, "TotalVAT": 59850, "TotalPayment": 374850, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 0}, "ThirdParty": {"NIT": "9100003701", "Name": "Cliente Pago Mismo Lote Cedro SAS"}}], "metadata": {"ExchangeId": "AF-2026-05-9638", "GeneratedAt": "2026-05-28", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "1077720925"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-28", "Type": {"Code": "PAY", "Name": "Pago factura venta"}, "Amount": 374850, "Status": "COMPLETED", "Currency": "COP", "DocumentId": "PAY-CXC-SAMEPAY-3701", "ThirdParty": {"NIT": "9100003701", "Name": "Cliente Pago Mismo Lote Cedro SAS"}, "Description": "Pago total de la factura FV-CXC-SAMEPAY-3701 en el mismo lote", "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}, "RelatedInvoiceId": "FV-CXC-SAMEPAY-3701", "ReferenceDocument": {"DocumentId": "FV-CXC-SAMEPAY-3701"}}]}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-28 17:05:00.069416+00	2026-05-28 17:05:00.272031+00	2026-05-28 17:05:00.069416+00	\N
6c0d1b6a-4667-4687-98bd-fde7a7c36339	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 2, "TotalTransactions": 1}, "invoices": [{"Lines": [{"Code": "LN-2004", "Name": "Item de prueba AAEF", "Taxes": [{"Rate": 19, "Amount": 70680, "TaxType": "IVA"}], "Value": 372000, "LineType": "PRODUCT", "Quantity": 1, "UnitPrice": 372000, "Description": "Linea para INV-CXP-PAID-2004"}], "Header": {"Type": {"Code": "02", "Name": "Compra"}, "Status": "PAID", "DueDate": "2026-06-27", "IssueDate": "2026-05-27", "DocumentId": "INV-CXP-PAID-2004"}, "Totals": {"Subtotal": 372000, "TotalVAT": 70680, "TotalPayment": 442680, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 0}, "ThirdParty": {"NIT": "9100000112", "Name": "Proveedor Soluciones Prisma SAS"}}], "metadata": {"ExchangeId": "AF-2026-05-2004", "GeneratedAt": "2026-05-27", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "1077720925"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-27", "Type": {"Code": "PAY", "Name": "Pago"}, "Amount": 442680, "Status": "COMPLETED", "Currency": "COP", "DocumentId": "PAY-CXP-2004", "ThirdParty": {"NIT": "9100000112", "Name": "Proveedor Soluciones Prisma SAS"}, "Description": "Transaccion PAY COMPLETED para pruebas AAEF", "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}, "RelatedInvoiceId": "INV-CXP-PAID-2004", "ReferenceDocument": {"DocumentId": "INV-CXP-PAID-2004"}}]}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-28 17:08:02.927906+00	2026-05-28 17:08:03.50544+00	2026-05-28 17:08:02.927906+00	\N
1e3fae93-7075-453b-b901-ff5718edfee4	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 1, "TotalTransactions": 0}, "invoices": [{"Lines": [{"Code": "LN-2007", "Name": "Item de prueba AAEF", "Taxes": [{"Rate": 19, "Amount": 31160, "TaxType": "IVA"}], "Value": 164000, "LineType": "PRODUCT", "Quantity": 1, "UnitPrice": 164000, "Description": "Linea para INV-CXC-CANCELLED-2007"}], "Header": {"Type": {"Code": "01", "Name": "Venta"}, "Status": "CANCELLED", "DueDate": "2026-06-27", "IssueDate": "2026-05-27", "DocumentId": "INV-CXC-CANCELLED-2007"}, "Totals": {"Subtotal": 164000, "TotalVAT": 31160, "TotalPayment": 195160, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 0}, "ThirdParty": {"NIT": "9100000223", "Name": "Cliente Cancelado Litoral SAS"}}], "metadata": {"ExchangeId": "AF-2026-05-2007", "GeneratedAt": "2026-05-27", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "1077720925"}, "StandardVersion": "1.0"}, "transactions": []}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-28 17:09:09.081729+00	2026-05-28 17:09:09.587889+00	2026-05-28 17:09:09.081729+00	\N
b6c8e084-4281-407d-97c9-be9be5d1d7da	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 1, "TotalTransactions": 0}, "invoices": [{"Lines": [{"Code": "LN-2008", "Name": "Item de prueba AAEF", "Taxes": [{"Rate": 19, "Amount": 82270, "TaxType": "IVA"}], "Value": 433000, "LineType": "PRODUCT", "Quantity": 1, "UnitPrice": 433000, "Description": "Linea para INV-CXP-CANCELLED-2008"}], "Header": {"Type": {"Code": "02", "Name": "Compra"}, "Status": "CANCELLED", "DueDate": "2026-06-27", "IssueDate": "2026-05-27", "DocumentId": "INV-CXP-CANCELLED-2008"}, "Totals": {"Subtotal": 433000, "TotalVAT": 82270, "TotalPayment": 515270, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 0}, "ThirdParty": {"NIT": "9100000260", "Name": "Proveedor Cancelado Delta SAS"}}], "metadata": {"ExchangeId": "AF-2026-05-2008", "GeneratedAt": "2026-05-27", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "1077720925"}, "StandardVersion": "1.0"}, "transactions": []}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-28 17:10:22.322272+00	2026-05-28 17:10:22.530071+00	2026-05-28 17:10:22.322272+00	\N
72403a0c-55d9-44a0-9a95-adf2a9ab5ff7	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 0, "TotalDocuments": 1, "TotalTransactions": 1}, "invoices": [], "metadata": {"ExchangeId": "AF-2026-05-2009", "GeneratedAt": "2026-05-27", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "1077720925"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-27", "Type": {"Code": "ADV", "Name": "Anticipo"}, "Amount": 95000, "Status": "COMPLETED", "Currency": "COP", "DocumentId": "ADV-CXC-2009", "ThirdParty": {"NIT": "9100000297", "Name": "Cliente Anticipo Brisa SAS"}, "Description": "Transaccion ADV COMPLETED para pruebas AAEF", "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}}]}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-28 17:14:48.820193+00	2026-05-28 17:14:49.064184+00	2026-05-28 17:14:48.820193+00	\N
0f3b71e0-4ec2-4afb-a69c-5d0c0b3030c2	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 0, "TotalDocuments": 1, "TotalTransactions": 1}, "invoices": [], "metadata": {"ExchangeId": "AF-2026-05-3801", "GeneratedAt": "2026-05-28", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "1077720925"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-28", "Type": {"Code": "ADV", "Name": "Anticipo a proveedor"}, "Amount": 186000, "Status": "COMPLETED", "Currency": "COP", "DocumentId": "ADV-CXP-3801", "ThirdParty": {"NIT": "9100003801", "Name": "Proveedor Anticipo CxP Roble SAS"}, "Description": "Anticipo pagado a proveedor por integración AAEF. Debe registrarse en Cuentas por Pagar como anticipo a proveedor.", "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}}]}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-28 17:40:24.042608+00	2026-05-28 17:40:24.655417+00	2026-05-28 17:40:24.042608+00	\N
a8f82cac-6ac5-402b-bce8-5824f057f275	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 0, "TotalDocuments": 1, "TotalTransactions": 1}, "invoices": [], "metadata": {"ExchangeId": "AF-2026-45-3801", "GeneratedAt": "2026-05-28", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "1077720925"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-28", "Type": {"Code": "ADV", "Name": "Anticipo a proveedor"}, "Amount": 78624, "Status": "COMPLETED", "Currency": "COP", "DocumentId": "ADV-CXP-3801", "ThirdParty": {"NIT": "9100003801", "Name": "Proveedor Anticipo CxP Roble SAS"}, "Description": "Anticipo pagado a proveedor por integración AAEF. Debe registrarse en Cuentas por Pagar como anticipo a proveedor.", "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}}]}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-28 17:58:48.731611+00	2026-05-28 17:58:48.984643+00	2026-05-28 17:58:48.731611+00	\N
f3d00eaf-5f25-44e9-aebc-d5d14a234b72	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 1, "TotalTransactions": 0}, "invoices": [{"Lines": [{"Code": "LN-5001", "Name": "Item de prueba AAEF", "Taxes": [{"Rate": 19, "Amount": 19000, "TaxType": "IVA"}], "Value": 100000, "LineType": "SERVICE", "Quantity": 1, "UnitPrice": 100000, "Description": "Línea de prueba para FV-CXC-ACTIVE-5001"}], "Header": {"Type": {"Code": "01", "Name": "Venta"}, "Status": "ACTIVE", "DueDate": "2026-06-28", "IssueDate": "2026-05-28", "UpdatedAt": "2026-05-28", "DocumentId": "FV-CXC-ACTIVE-5001"}, "Totals": {"Subtotal": 100000, "TotalVAT": 19000, "TotalPayment": 119000, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 119000}, "ThirdParty": {"NIT": "9100005001", "Name": "Cliente Active Cedro SAS"}}], "metadata": {"ExchangeId": "AF-2026-05-5001", "GeneratedAt": "2026-05-28", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "9001766666"}, "StandardVersion": "1.0"}, "transactions": []}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-28 18:17:46.022538+00	2026-05-28 18:17:46.684264+00	2026-05-28 18:17:46.022538+00	\N
029117aa-d002-42aa-bc52-f4871270a896	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 0, "TotalDocuments": 1, "TotalTransactions": 1}, "invoices": [], "metadata": {"ExchangeId": "AF-2026-05-5010", "GeneratedAt": "2026-05-28", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "1077720925"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-28", "Type": {"Code": "ADV", "Name": "Anticipo a proveedor"}, "Amount": 186000, "Status": "COMPLETED", "Currency": "COP", "DocumentId": "ADV-CXP-5010", "ThirdParty": {"NIT": "9100005010", "Name": "Proveedor Anticipo Cedro SAS"}, "Description": "Anticipo pagado a proveedor para CxP/AP", "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}}]}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-28 18:32:24.274121+00	2026-05-28 18:32:24.416174+00	2026-05-28 18:32:24.274121+00	\N
8cb240f4-0097-4d42-ad9e-945b9dfdbf79	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 1, "TotalTransactions": 0}, "invoices": [{"Lines": [{"Code": "LN-5011", "Name": "Item de prueba AAEF", "Taxes": [{"Rate": 19, "Amount": 74100, "TaxType": "IVA"}], "Value": 390000, "LineType": "SERVICE", "Quantity": 1, "UnitPrice": 390000, "Description": "Línea de prueba para FV-CXC-REF-BASE-5011"}], "Header": {"Type": {"Code": "01", "Name": "Venta"}, "Status": "ACTIVE", "DueDate": "2026-06-28", "IssueDate": "2026-05-28", "UpdatedAt": "2026-05-28", "DocumentId": "FV-CXC-REF-BASE-5011"}, "Totals": {"Subtotal": 390000, "TotalVAT": 74100, "TotalPayment": 464100, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 464100}, "ThirdParty": {"NIT": "9100005011", "Name": "Cliente Reembolso Saldo CxC SAS"}}], "metadata": {"ExchangeId": "AF-2026-05-5011", "GeneratedAt": "2026-05-28", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "1077720925"}, "StandardVersion": "1.0"}, "transactions": []}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-28 18:32:57.598927+00	2026-05-28 18:32:57.760259+00	2026-05-28 18:32:57.598927+00	\N
186826b3-2200-4cb2-b00f-f95b6f33e29f	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 0, "TotalDocuments": 1, "TotalTransactions": 1}, "invoices": [], "metadata": {"ExchangeId": "AF-2026-05-5012", "GeneratedAt": "2026-05-28", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "1077720925"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-28", "Type": {"Code": "REF", "Name": "Reembolso"}, "Amount": 83000, "Status": "COMPLETED", "Currency": "COP", "DocumentId": "REF-CXC-5012", "ThirdParty": {"NIT": "9100005011", "Name": "Cliente Reembolso Saldo CxC SAS"}, "Description": "Transacción REF COMPLETED para pruebas AAEF", "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}, "RelatedInvoiceId": "FV-CXC-REF-BASE-5011", "ReferenceDocument": {"DocumentId": "FV-CXC-REF-BASE-5011"}}]}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-28 18:33:45.178877+00	2026-05-28 18:33:45.312363+00	2026-05-28 18:33:45.178877+00	\N
e31ce433-3b1f-4246-b240-8e9f453137ca	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 1, "TotalTransactions": 0}, "invoices": [{"Lines": [{"Code": "LN-5002", "Name": "Item de prueba AAEF", "Taxes": [{"Rate": 19, "Amount": 32300, "TaxType": "IVA"}], "Value": 170000, "LineType": "PRODUCT", "Quantity": 1, "UnitPrice": 170000, "Description": "Línea de prueba para FC-CXP-ACTIVE-5002"}], "Header": {"Type": {"Code": "02", "Name": "Compra"}, "Status": "ACTIVE", "DueDate": "2026-06-28", "IssueDate": "2026-05-28", "UpdatedAt": "2026-05-28", "DocumentId": "FC-CXP-ACTIVE-5002"}, "Totals": {"Subtotal": 170000, "TotalVAT": 32300, "TotalPayment": 202300, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 202300}, "ThirdParty": {"NIT": "9100005002", "Name": "Proveedor Active Nogal SAS"}}], "metadata": {"ExchangeId": "AF-2026-05-5002", "GeneratedAt": "2026-05-28", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "9001766666"}, "StandardVersion": "1.0"}, "transactions": []}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-28 18:18:08.330952+00	2026-05-28 18:18:08.579486+00	2026-05-28 18:18:08.330952+00	\N
23cec3f2-abb7-4cfb-8b8d-e008e7ff8f34	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 2, "TotalTransactions": 1}, "invoices": [{"Lines": [{"Code": "LN-5004", "Name": "Item de prueba AAEF", "Taxes": [{"Rate": 19, "Amount": 57000, "TaxType": "IVA"}], "Value": 300000, "LineType": "PRODUCT", "Quantity": 1, "UnitPrice": 300000, "Description": "Línea de prueba para FC-CXP-PAID-5004"}], "Header": {"Type": {"Code": "02", "Name": "Compra"}, "Status": "PAID", "DueDate": "2026-06-28", "IssueDate": "2026-05-28", "UpdatedAt": "2026-05-28", "DocumentId": "FC-CXP-PAID-5004"}, "Totals": {"Subtotal": 300000, "TotalVAT": 57000, "TotalPayment": 357000, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 0}, "ThirdParty": {"NIT": "9100005004", "Name": "Proveedor Paid Guayacan SAS"}}], "metadata": {"ExchangeId": "AF-2026-05-5004", "GeneratedAt": "2026-05-28", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "1077720925"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-28", "Type": {"Code": "PAY", "Name": "Pago"}, "Amount": 357000, "Status": "COMPLETED", "Currency": "COP", "DocumentId": "PAY-CXP-5004", "ThirdParty": {"NIT": "9100005004", "Name": "Proveedor Paid Guayacan SAS"}, "Description": "Transacción PAY COMPLETED para pruebas AAEF", "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}, "RelatedInvoiceId": "FC-CXP-PAID-5004", "ReferenceDocument": {"DocumentId": "FC-CXP-PAID-5004"}}]}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-28 18:24:32.655735+00	2026-05-28 18:24:32.976291+00	2026-05-28 18:24:32.655735+00	\N
a560b18b-57d8-4060-aea8-e9619b4c2250	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 1, "TotalTransactions": 0}, "invoices": [{"Lines": [{"Code": "ITEM-CANCEL-6102", "Name": "Insumo cancelado", "Taxes": [{"Rate": 19, "Amount": 52250, "TaxType": "IVA"}], "Value": 275000, "LineType": "PRODUCT", "Quantity": 1, "UnitPrice": 275000, "Description": "Factura de compra enviada como CANCELLED en lote único"}], "Header": {"Type": {"Code": "02", "Name": "Compra"}, "Status": "CANCELLED", "DueDate": "2026-06-28", "IssueDate": "2026-05-28", "UpdatedAt": "2026-05-28", "DocumentId": "FC-CXP-CANCEL-6102"}, "Totals": {"Subtotal": 275000, "TotalVAT": 52250, "TotalPayment": 327250, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 0}, "ThirdParty": {"NIT": "9100006102", "Name": "Proveedor Cancelado Directo CxP SAS"}}], "metadata": {"ExchangeId": "AF-2026-05-6102", "GeneratedAt": "2026-05-28", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "1077720925"}, "StandardVersion": "1.0"}, "transactions": []}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-28 18:30:14.290258+00	2026-05-28 18:30:14.451458+00	2026-05-28 18:30:14.290258+00	\N
84addc6b-9c4e-4546-810d-fa8833bb05a5	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 1, "TotalTransactions": 0}, "invoices": [{"Lines": [{"Code": "LN-5002", "Name": "Item de prueba AAEF", "Taxes": [{"Rate": 19, "Amount": 32300, "TaxType": "IVA"}], "Value": 170000, "LineType": "PRODUCT", "Quantity": 1, "UnitPrice": 170000, "Description": "Línea de prueba para FC-CXP-ACTIVE-5002"}], "Header": {"Type": {"Code": "02", "Name": "Compra"}, "Status": "ACTIVE", "DueDate": "2026-06-28", "IssueDate": "2026-05-28", "UpdatedAt": "2026-05-28", "DocumentId": "FC-CXP-ACTIVE-5002"}, "Totals": {"Subtotal": 170000, "TotalVAT": 32300, "TotalPayment": 202300, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 202300}, "ThirdParty": {"NIT": "9100005002", "Name": "Proveedor Active Nogal SAS"}}], "metadata": {"ExchangeId": "AF-2026-05-5902", "GeneratedAt": "2026-05-28", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "1077720925"}, "StandardVersion": "1.0"}, "transactions": []}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-28 18:18:36.975596+00	2026-05-28 18:18:37.203226+00	2026-05-28 18:18:36.975596+00	\N
fc8a52d5-0d01-4adb-95d2-9546c836b53c	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 1, "TotalTransactions": 0}, "invoices": [{"Lines": [{"Code": "LN-5002", "Name": "Item de prueba AAEF", "Taxes": [{"Rate": 19, "Amount": 32300, "TaxType": "IVA"}], "Value": 170000, "LineType": "PRODUCT", "Quantity": 1, "UnitPrice": 170000, "Description": "Línea de prueba para FC-CXP-ACTIVE-5002"}], "Header": {"Type": {"Code": "02", "Name": "Compra"}, "Status": "ACTIVE", "DueDate": "2026-06-28", "IssueDate": "2026-05-28", "UpdatedAt": "2026-05-28", "DocumentId": "FC-CXP-ACTIVE-5002"}, "Totals": {"Subtotal": 170000, "TotalVAT": 32300, "TotalPayment": 202300, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 202300}, "ThirdParty": {"NIT": "9100005002", "Name": "Proveedor Active Nogal SAS"}}], "metadata": {"ExchangeId": "AF-2026-05-5502", "GeneratedAt": "2026-05-28", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "1077720925"}, "StandardVersion": "1.0"}, "transactions": []}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	rejected	1	1	2	\N	2026-05-28 18:21:24.65629+00	2026-05-28 18:21:24.762811+00	2026-05-28 18:21:24.65629+00	\N
d2df052e-55f9-460d-845b-0158da785562	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 1, "TotalTransactions": 0}, "invoices": [{"Lines": [{"Code": "LN-5001", "Name": "Item de prueba AAEF", "Taxes": [{"Rate": 19, "Amount": 19000, "TaxType": "IVA"}], "Value": 100000, "LineType": "SERVICE", "Quantity": 1, "UnitPrice": 100000, "Description": "Línea de prueba para FV-CXC-ACTIVE-5001"}], "Header": {"Type": {"Code": "01", "Name": "Venta"}, "Status": "ACTIVE", "DueDate": "2026-06-28", "IssueDate": "2026-05-28", "UpdatedAt": "2026-05-28", "DocumentId": "FV-CXC-ACTIVE-5001"}, "Totals": {"Subtotal": 100000, "TotalVAT": 19000, "TotalPayment": 119000, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 119000}, "ThirdParty": {"NIT": "9100005001", "Name": "Cliente Active Cedro SAS"}}], "metadata": {"ExchangeId": "AF-2026-05-9001", "GeneratedAt": "2026-05-28", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "1077720925"}, "StandardVersion": "1.0"}, "transactions": []}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-28 18:22:46.170836+00	2026-05-28 18:22:46.409892+00	2026-05-28 18:22:46.170836+00	\N
a951e756-fe5e-4419-8eeb-30cc67db51b9	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 2, "TotalTransactions": 1}, "invoices": [{"Lines": [{"Code": "LN-5003", "Name": "Item de prueba AAEF", "Taxes": [{"Rate": 19, "Amount": 39900, "TaxType": "IVA"}], "Value": 210000, "LineType": "SERVICE", "Quantity": 1, "UnitPrice": 210000, "Description": "Línea de prueba para FV-CXC-PAID-5003"}], "Header": {"Type": {"Code": "01", "Name": "Venta"}, "Status": "PAID", "DueDate": "2026-06-28", "IssueDate": "2026-05-28", "UpdatedAt": "2026-05-28", "DocumentId": "FV-CXC-PAID-5003"}, "Totals": {"Subtotal": 210000, "TotalVAT": 39900, "TotalPayment": 249900, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 0}, "ThirdParty": {"NIT": "9100005003", "Name": "Cliente Paid Arrayan SAS"}}], "metadata": {"ExchangeId": "AF-2026-05-5003", "GeneratedAt": "2026-05-28", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "1077720925"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-28", "Type": {"Code": "PAY", "Name": "Pago"}, "Amount": 249900, "Status": "COMPLETED", "Currency": "COP", "DocumentId": "PAY-CXC-5003", "ThirdParty": {"NIT": "9100005003", "Name": "Cliente Paid Arrayan SAS"}, "Description": "Transacción PAY COMPLETED para pruebas AAEF", "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}, "RelatedInvoiceId": "FV-CXC-PAID-5003", "ReferenceDocument": {"DocumentId": "FV-CXC-PAID-5003"}}]}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-28 18:23:47.437169+00	2026-05-28 18:23:47.937191+00	2026-05-28 18:23:47.437169+00	\N
b22b917f-717e-42b2-b43b-b6c57a5be5e2	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 1, "TotalTransactions": 0}, "invoices": [{"Lines": [{"Code": "LN-5007", "Name": "Item de prueba AAEF", "Taxes": [{"Rate": 19, "Amount": 23750, "TaxType": "IVA"}], "Value": 125000, "LineType": "SERVICE", "Quantity": 1, "UnitPrice": 125000, "Description": "Línea de prueba para FV-CXC-CANCEL-5007"}], "Header": {"Type": {"Code": "01", "Name": "Venta"}, "Status": "ACTIVE", "DueDate": "2026-06-28", "IssueDate": "2026-05-28", "UpdatedAt": "2026-05-28", "DocumentId": "FV-CXC-CANCEL-5007"}, "Totals": {"Subtotal": 125000, "TotalVAT": 23750, "TotalPayment": 148750, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 148750}, "ThirdParty": {"NIT": "9100005007", "Name": "Cliente Cancelar CxC SAS"}}], "metadata": {"ExchangeId": "AF-2026-05-5007", "GeneratedAt": "2026-05-28", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "1077720925"}, "StandardVersion": "1.0"}, "transactions": []}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-28 18:25:19.158875+00	2026-05-28 18:25:19.768397+00	2026-05-28 18:25:19.158875+00	\N
a317040e-b1b5-4a0f-b7ab-bbbb113e9c7f	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 0, "TotalDocuments": 1, "TotalTransactions": 1}, "invoices": [], "metadata": {"ExchangeId": "AF-2026-05-5009", "GeneratedAt": "2026-05-28", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "1077720925"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-28", "Type": {"Code": "ADV", "Name": "Anticipo de cliente"}, "Amount": 143000, "Status": "COMPLETED", "Currency": "COP", "DocumentId": "ADV-CXC-5009", "ThirdParty": {"NIT": "9100005009", "Name": "Cliente Anticipo Roble SAS"}, "Description": "Anticipo recibido de cliente para CxC/AR", "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}}]}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-28 18:31:39.294085+00	2026-05-28 18:31:39.594589+00	2026-05-28 18:31:39.294085+00	\N
dd57a85f-46c0-427a-8a68-ec6cbf52f409	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 1, "TotalTransactions": 0}, "invoices": [{"Lines": [{"Code": "LN-5007", "Name": "Item de prueba AAEF", "Taxes": [{"Rate": 19, "Amount": 23750, "TaxType": "IVA"}], "Value": 125000, "LineType": "SERVICE", "Quantity": 1, "UnitPrice": 125000, "Description": "Línea de prueba para FV-CXC-CANCEL-5007"}], "Header": {"Type": {"Code": "01", "Name": "Venta"}, "Status": "ACTIVE", "DueDate": "2026-06-28", "IssueDate": "2026-05-28", "UpdatedAt": "2026-05-28", "DocumentId": "FV-CXC-CANCEL-5007"}, "Totals": {"Subtotal": 125000, "TotalVAT": 23750, "TotalPayment": 148750, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 148750}, "ThirdParty": {"NIT": "9100005007", "Name": "Cliente Cancelar CxC SAS"}}], "metadata": {"ExchangeId": "AF-2026-05-5707", "GeneratedAt": "2026-05-28", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "1077720925"}, "StandardVersion": "1.0"}, "transactions": []}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-28 18:27:10.477948+00	2026-05-28 18:27:11.006009+00	2026-05-28 18:27:10.477948+00	\N
476f509b-74cc-4acb-ab3b-3109f89587ae	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 1, "TotalTransactions": 0}, "invoices": [{"Lines": [{"Code": "SERV-CANCEL-6101", "Name": "Servicio cancelado", "Taxes": [{"Rate": 19, "Amount": 35150, "TaxType": "IVA"}], "Value": 185000, "LineType": "SERVICE", "Quantity": 1, "UnitPrice": 185000, "Description": "Factura de venta enviada como CANCELLED en lote único"}], "Header": {"Type": {"Code": "01", "Name": "Venta"}, "Status": "CANCELLED", "DueDate": "2026-06-28", "IssueDate": "2026-05-28", "UpdatedAt": "2026-05-28", "DocumentId": "FV-CXC-CANCEL-6101"}, "Totals": {"Subtotal": 185000, "TotalVAT": 35150, "TotalPayment": 220150, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 0}, "ThirdParty": {"NIT": "9100006101", "Name": "Cliente Cancelado Directo CxC SAS"}}], "metadata": {"ExchangeId": "AF-2026-05-6101", "GeneratedAt": "2026-05-28", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "1077720925"}, "StandardVersion": "1.0"}, "transactions": []}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-28 18:29:06.373976+00	2026-05-28 18:29:06.539714+00	2026-05-28 18:29:06.373976+00	\N
38c066e9-ccfa-457e-b364-6feb1830d294	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 0, "TotalDocuments": 1, "TotalTransactions": 1}, "invoices": [], "metadata": {"ExchangeId": "AF-2026-05-5033", "GeneratedAt": "2026-05-28", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "80924568"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-28", "Type": {"Code": "PAY", "Name": "Pago"}, "Amount": 336770, "Status": "REVERSED", "Currency": "COP", "DocumentId": "PAY-CXC-REV-5032", "ThirdParty": {"NIT": "9100005032", "Name": "Cliente Reversa CxC SAS"}, "Description": "Transacción PAY REVERSED para pruebas AAEF", "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}, "RelatedInvoiceId": "FV-CXC-REV-BASE-5032", "ReferenceDocument": {"DocumentId": "FV-CXC-REV-BASE-5032"}}]}	2026-06-04	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	sent	1	1	3	\N	2026-06-04 04:13:48.958524+00	\N	2026-06-04 04:13:48.958524+00	\N
771e0f65-9e6f-47b7-8cf1-2a6956e0371b	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 2, "TotalTransactions": 1}, "invoices": [{"Lines": [{"Code": "LN-5034", "Name": "Item de prueba AAEF", "Taxes": [{"Rate": 19, "Amount": 71440, "TaxType": "IVA"}], "Value": 376000, "LineType": "PRODUCT", "Quantity": 1, "UnitPrice": 376000, "Description": "Línea de prueba para FC-CXP-REV-BASE-5034"}], "Header": {"Type": {"Code": "02", "Name": "Compra"}, "Status": "PAID", "DueDate": "2026-06-28", "IssueDate": "2026-05-28", "UpdatedAt": "2026-05-28", "DocumentId": "FC-CXP-REV-BASE-5034"}, "Totals": {"Subtotal": 376000, "TotalVAT": 71440, "TotalPayment": 447440, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 0}, "ThirdParty": {"NIT": "9100005034", "Name": "Proveedor Reversa CxP SAS"}}], "metadata": {"ExchangeId": "AF-2026-05-5034", "GeneratedAt": "2026-05-28", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "80924568"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-28", "Type": {"Code": "PAY", "Name": "Pago"}, "Amount": 447440, "Status": "COMPLETED", "Currency": "COP", "DocumentId": "PAY-CXP-REV-5034", "ThirdParty": {"NIT": "9100005034", "Name": "Proveedor Reversa CxP SAS"}, "Description": "Transacción PAY COMPLETED para pruebas AAEF", "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}, "RelatedInvoiceId": "FC-CXP-REV-BASE-5034", "ReferenceDocument": {"DocumentId": "FC-CXP-REV-BASE-5034"}}]}	2026-06-04	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	sent	1	1	3	\N	2026-06-04 04:15:48.959321+00	\N	2026-06-04 04:15:48.959321+00	\N
fcb0daf8-b141-487a-9924-e367667ab027	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 1, "TotalTransactions": 0}, "invoices": [{"Lines": [{"Code": "LN-5013", "Name": "Item de prueba AAEF", "Taxes": [{"Rate": 19, "Amount": 87400, "TaxType": "IVA"}], "Value": 460000, "LineType": "PRODUCT", "Quantity": 1, "UnitPrice": 460000, "Description": "Línea de prueba para FC-CXP-REF-BASE-5013"}], "Header": {"Type": {"Code": "02", "Name": "Compra"}, "Status": "ACTIVE", "DueDate": "2026-06-28", "IssueDate": "2026-05-28", "UpdatedAt": "2026-05-28", "DocumentId": "FC-CXP-REF-BASE-5013"}, "Totals": {"Subtotal": 460000, "TotalVAT": 87400, "TotalPayment": 547400, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 547400}, "ThirdParty": {"NIT": "9100005013", "Name": "Proveedor Reembolso Saldo CxP SAS"}}], "metadata": {"ExchangeId": "AF-2026-05-5013", "GeneratedAt": "2026-05-28", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "1077720925"}, "StandardVersion": "1.0"}, "transactions": []}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-28 18:34:16.074389+00	2026-05-28 18:34:16.245454+00	2026-05-28 18:34:16.074389+00	\N
ed523687-7c09-41f4-9a0c-6980bfce13f0	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 0, "TotalDocuments": 1, "TotalTransactions": 1}, "invoices": [], "metadata": {"ExchangeId": "AF-2026-05-5014", "GeneratedAt": "2026-05-28", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "1077720925"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-28", "Type": {"Code": "REF", "Name": "Reembolso"}, "Amount": 73000, "Status": "COMPLETED", "Currency": "COP", "DocumentId": "REF-CXP-5014", "ThirdParty": {"NIT": "9100005013", "Name": "Proveedor Reembolso Saldo CxP SAS"}, "Description": "Transacción REF COMPLETED para pruebas AAEF", "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}, "RelatedInvoiceId": "FC-CXP-REF-BASE-5013", "ReferenceDocument": {"DocumentId": "FC-CXP-REF-BASE-5013"}}]}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-28 18:35:07.748162+00	2026-05-28 18:35:07.883534+00	2026-05-28 18:35:07.748162+00	\N
6d60a6f7-3924-4b65-92bb-36b012bfd364	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 0, "TotalDocuments": 1, "TotalTransactions": 1}, "invoices": [], "metadata": {"ExchangeId": "AF-2026-05-5018", "GeneratedAt": "2026-05-28", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "1077720925"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-28", "Type": {"Code": "ADJ", "Name": "Ajuste"}, "Amount": 30000, "Status": "COMPLETED", "Currency": "COP", "DocumentId": "ADJ-CXP-5018", "ThirdParty": {"NIT": "9100005017", "Name": "Proveedor Ajuste CxP SAS"}, "Description": "Transacción ADJ COMPLETED para pruebas AAEF", "AdjustmentReason": "Corrección autorizada por diferencia de valor", "RelatedInvoiceId": "FC-CXP-ADJ-BASE-5017", "ReferenceDocument": {"DocumentId": "FC-CXP-ADJ-BASE-5017"}}]}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-28 18:37:32.815454+00	2026-05-28 18:37:33.097695+00	2026-05-28 18:37:32.815454+00	\N
0c855663-5efb-422d-9fec-2c0003a11572	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 0, "TotalDocuments": 1, "TotalTransactions": 1}, "invoices": [], "metadata": {"ExchangeId": "AF-2026-05-5033", "GeneratedAt": "2026-05-28", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "80924568"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-28", "Type": {"Code": "PAY", "Name": "Pago"}, "Amount": 336770, "Status": "REVERSED", "Currency": "COP", "DocumentId": "PAY-CXC-REV-5032", "ThirdParty": {"NIT": "9100005032", "Name": "Cliente Reversa CxC SAS"}, "Description": "Transacción PAY REVERSED para pruebas AAEF", "PaymentMethod": {"Code": "TRANSFER", "Name": "Transferencia bancaria"}, "RelatedInvoiceId": "FV-CXC-REV-BASE-5032", "ReferenceDocument": {"DocumentId": "FV-CXC-REV-BASE-5032"}}]}	2026-06-04	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	failed	1	1	3	Sin ACK después de 3 reintentos (90 min totales).	2026-06-04 04:44:43.706457+00	2026-06-04 05:14:48.959413+00	2026-06-04 04:44:43.706457+00	\N
edba6a62-2138-4ac8-9ce2-5b1302680b47	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 1, "TotalTransactions": 0}, "invoices": [{"Lines": [{"Code": "LN-5015", "Name": "Item de prueba AAEF", "Taxes": [{"Rate": 19, "Amount": 41800, "TaxType": "IVA"}], "Value": 220000, "LineType": "SERVICE", "Quantity": 1, "UnitPrice": 220000, "Description": "Línea de prueba para FV-CXC-ADJ-BASE-5015"}], "Header": {"Type": {"Code": "01", "Name": "Venta"}, "Status": "ACTIVE", "DueDate": "2026-06-28", "IssueDate": "2026-05-28", "UpdatedAt": "2026-05-28", "DocumentId": "FV-CXC-ADJ-BASE-5015"}, "Totals": {"Subtotal": 220000, "TotalVAT": 41800, "TotalPayment": 261800, "TotalDiscounts": 0, "TotalWithholdings": 0, "OutstandingBalance": 261800}, "ThirdParty": {"NIT": "9100005015", "Name": "Cliente Ajuste CxC SAS"}}], "metadata": {"ExchangeId": "AF-2026-05-5015", "GeneratedAt": "2026-05-28", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "1077720925"}, "StandardVersion": "1.0"}, "transactions": []}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-28 18:35:42.253645+00	2026-05-28 18:35:42.495602+00	2026-05-28 18:35:42.253645+00	\N
02f37bdf-b75c-40c3-a21a-0179e3112341	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 0, "TotalDocuments": 1, "TotalTransactions": 1}, "invoices": [], "metadata": {"ExchangeId": "AF-2026-05-5016", "GeneratedAt": "2026-05-28", "SourceSystem": {"Version": "1.0", "SystemId": "AgroFusion", "SystemNIT": "1077720925"}, "StandardVersion": "1.0"}, "transactions": [{"Date": "2026-05-28", "Type": {"Code": "ADJ", "Name": "Ajuste"}, "Amount": 25000, "Status": "COMPLETED", "Currency": "COP", "DocumentId": "ADJ-CXC-5016", "ThirdParty": {"NIT": "9100005015", "Name": "Cliente Ajuste CxC SAS"}, "Description": "Transacción ADJ COMPLETED para pruebas AAEF", "AdjustmentReason": "Corrección autorizada por diferencia de valor", "RelatedInvoiceId": "FV-CXC-ADJ-BASE-5015", "ReferenceDocument": {"DocumentId": "FV-CXC-ADJ-BASE-5015"}}]}	2026-05-28	2124f0cd-8d50-4703-a0cb-11fe4f523a2c	accepted	1	1	2	\N	2026-05-28 18:36:11.099223+00	2026-05-28 18:36:11.221009+00	2026-05-28 18:36:11.099223+00	\N
bbf4c9e7-6ffb-4687-84ec-04a34d6ce807	8084d91b-d49d-40f2-b10e-5460df450367	Facturación	Facturación	{"summary": {"TotalInvoices": 1, "TotalDocuments": 1, "TotalTransactions": 0}, "invoices": [{"Lines": [{"Code": "LN-5017", "Name": "Item de prueba AAEF", "Taxes": [{"Rate": 19, "Amount": 53200, "TaxType": "IVA"}], "Value": 280000, "L