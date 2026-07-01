-- platform-db migration 027
-- Azure integration support: multi-provider integrations + relaxed cloud account id

-- platform.integrations: allow azure provider and provider-specific credentials
ALTER TABLE platform.integrations
  DROP CONSTRAINT IF EXISTS integrations_provider_check,
  DROP CONSTRAINT IF EXISTS integrations_account_id_check;

ALTER TABLE platform.integrations
  ALTER COLUMN role_arn DROP NOT NULL,
  ALTER COLUMN external_id DROP NOT NULL;

ALTER TABLE platform.integrations
  ADD COLUMN IF NOT EXISTS azure_tenant_id TEXT,
  ADD COLUMN IF NOT EXISTS azure_client_id TEXT,
  ADD COLUMN IF NOT EXISTS azure_client_secret TEXT;

ALTER TABLE platform.integrations
  ADD CONSTRAINT integrations_provider_check
    CHECK (provider IN ('aws', 'azure'));

ALTER TABLE platform.integrations
  ADD CONSTRAINT integrations_account_id_check CHECK (
    (provider = 'aws' AND account_id ~ '^[0-9]{12}$')
    OR (
      provider = 'azure'
      AND account_id ~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    )
  );

ALTER TABLE platform.integrations
  ADD CONSTRAINT integrations_aws_credentials_check CHECK (
    provider <> 'aws'
    OR (role_arn IS NOT NULL AND btrim(role_arn) <> '' AND external_id IS NOT NULL AND btrim(external_id) <> '')
  );

ALTER TABLE platform.integrations
  ADD CONSTRAINT integrations_azure_credentials_check CHECK (
    provider <> 'azure'
    OR (
      azure_tenant_id IS NOT NULL AND btrim(azure_tenant_id) <> ''
      AND azure_client_id IS NOT NULL AND btrim(azure_client_id) <> ''
      AND azure_client_secret IS NOT NULL AND btrim(azure_client_secret) <> ''
      AND role_arn IS NULL
      AND external_id IS NULL
    )
  );

COMMENT ON COLUMN platform.integrations.account_id IS
  'Cloud account identifier: AWS 12-digit account id or Azure subscription GUID.';
COMMENT ON COLUMN platform.integrations.azure_tenant_id IS
  'Entra ID tenant GUID for Azure integrations (encrypted client secret stored separately).';
COMMENT ON COLUMN platform.integrations.azure_client_id IS
  'Service principal application (client) id for Azure integrations.';
COMMENT ON COLUMN platform.integrations.azure_client_secret IS
  'Encrypted service principal client secret ciphertext (app-layer Fernet).';

-- platform.collection_runs: allow Azure subscription id
ALTER TABLE platform.collection_runs
  DROP CONSTRAINT IF EXISTS collection_runs_account_id_check;

ALTER TABLE platform.collection_runs
  ADD CONSTRAINT collection_runs_account_id_check CHECK (
    account_id ~ '^[0-9]{12}$'
    OR account_id ~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
  );

-- assets.resources: allow Azure subscription id on normalized rows
ALTER TABLE assets.resources
  DROP CONSTRAINT IF EXISTS resources_account_id_check;

ALTER TABLE assets.resources
  ADD CONSTRAINT resources_account_id_check CHECK (
    account_id ~ '^[0-9]{12}$'
    OR account_id ~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
  );

INSERT INTO platform.schema_migrations (version)
VALUES ('027_azure_integrations')
ON CONFLICT (version) DO NOTHING;
