-- Disposable research fixture, not a Kapsel capability or migration.
BEGIN;
CREATE ROLE reservation_owner NOLOGIN;
CREATE ROLE alice LOGIN PASSWORD 'disposable-alice';
CREATE ROLE mallory LOGIN PASSWORD 'disposable-mallory';
CREATE SCHEMA reservation AUTHORIZATION reservation_owner;
REVOKE ALL ON SCHEMA reservation FROM PUBLIC;
GRANT USAGE ON SCHEMA reservation TO alice, mallory;
SET ROLE reservation_owner;
CREATE TABLE reservation.budget (
    principal name PRIMARY KEY,
    remaining integer NOT NULL CHECK (remaining >= 0)
);
CREATE TABLE reservation.approval (
    operation_id text PRIMARY KEY,
    principal name NOT NULL,
    units integer NOT NULL CHECK (units > 0),
    consumed boolean NOT NULL DEFAULT false
);
CREATE TABLE reservation.result (
    operation_id text PRIMARY KEY REFERENCES reservation.approval,
    payload jsonb NOT NULL
);
INSERT INTO reservation.budget VALUES ('alice', 10);
INSERT INTO reservation.approval (operation_id, principal, units) VALUES
    ('parallel', 'alice', 3), ('rollback', 'alice', 2),
    ('precrash', 'alice', 2), ('postcrash', 'alice', 2),
    ('lost', 'alice', 1), ('outside', 'alice', 1),
    ('too-large', 'alice', 11);

-- The caller's login identity is database-authenticated; the function owner is NOLOGIN.
-- All names are qualified and search_path excludes caller-writable schemas.
CREATE FUNCTION reservation.consume(p_id text, p_units integer) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    approved reservation.approval%ROWTYPE;
    outcome jsonb;
    balance integer;
BEGIN
    -- Lock the identity BEFORE any budget mutation, including duplicate attempts.
    SELECT * INTO approved FROM reservation.approval AS a
        WHERE a.operation_id = p_id FOR UPDATE;
    IF NOT FOUND OR approved.principal <> session_user OR approved.units <> p_units THEN
        RAISE EXCEPTION 'not approved for this identity and payload';
    END IF;
    IF approved.consumed THEN
        SELECT r.payload INTO STRICT outcome FROM reservation.result AS r
            WHERE r.operation_id = p_id;
        RETURN outcome;
    END IF;
    UPDATE reservation.budget AS b SET remaining = b.remaining - p_units
        WHERE b.principal = approved.principal AND b.remaining >= p_units
        RETURNING b.remaining INTO balance;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'insufficient budget';
    END IF;
    UPDATE reservation.approval AS a SET consumed = true WHERE a.operation_id = p_id;
    outcome := jsonb_build_object('operation_id', p_id, 'units', p_units,
                                  'remaining', balance);
    INSERT INTO reservation.result VALUES (p_id, outcome);
    RETURN outcome;
END;
$$;
RESET ROLE;
-- PostgreSQL grants EXECUTE to PUBLIC on new functions by default. Revoke before COMMIT.
REVOKE ALL ON FUNCTION reservation.consume(text, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION reservation.consume(text, integer) TO alice, mallory;
COMMIT;
