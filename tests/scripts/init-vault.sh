#!/usr/bin/env bash

# Start vault in background.  `|| true` eats the non-zero exit code, when the
# background process is killed, so that it does not fail the Github Action.
{ vault server -dev -dev-root-token-id="${VAULT_TOKEN}" & } || true

until vault status
do
    sleep 0.1
done

vault secrets enable transit

vault write -force transit/keys/test-key-ed25519 type=ed25519
