-- Step 7C release-readiness fix: on a genuinely fresh clone, only the
-- POSTGRES_DB database (asm) exists -- nothing ever created the
-- asm_test database that TEST_DATABASE_URL points at, so `pytest`
-- failed outright (204/204 errors: "database asm_test does not exist").
-- This ran silently unnoticed because the long-lived dev Postgres volume
-- already had it from early in the project.
--
-- Postgres's official image runs every *.sql/*.sh file in
-- /docker-entrypoint-initdb.d/ automatically, but ONLY the first time a
-- container starts against a completely empty data directory -- it will
-- not run again against this project's existing dev volume (which
-- already has asm_test) or error if it did. For a pre-existing volume
-- from before this fix, run manually instead:
--   docker compose exec db psql -U asm -d asm -c "CREATE DATABASE asm_test;"
CREATE DATABASE asm_test;

-- The explicit "disposable test database" marker the pytest suite
-- requires before it will truncate/drop anything (tests/isolation.py,
-- verify_test_database_marker). Set here, at provisioning time -- never by
-- the suite itself. For a pre-existing volume, mark it once manually:
--   docker compose exec db psql -U asm -d asm_test -c "COMMENT ON DATABASE asm_test IS 'asm-disposable-test-database';"
COMMENT ON DATABASE asm_test IS 'asm-disposable-test-database';
