# Cathedral Computer customer receipts

`cathedral_customer_receipt_v1` is a public, offline-verifiable contract for
receipts issued by the Cathedral Computer customer API. It is separate from
the subnet assurance receipt contract in `cathedral/receipt.py`.

The verifier proves two bounded facts:

1. a locally trusted Cathedral Ed25519 key signed the exact receipt fields; and
2. the signed document contains a complete, internally consistent execution,
   billing, and teardown assertion for the named customer profile.

It does not replay Intel TDX quotes, validate NVIDIA evidence, inspect the
billing ledger, contact a cloud provider, or independently confirm teardown.
For both CPU and GPU receipts, hardware and execution verification fields are
Cathedral's signed assertions.

## Command

```bash
cathedral customer-receipt verify \
  --receipt customer-receipt.json \
  --trusted-keys customer-receipt-trusted-keys.json
```

Add `--max-age-seconds N` when the consumer requires freshness relative to its
own UTC clock. Success and failure are JSON. Failure categories are `schema`,
`policy`, `key`, `signature`, `status`, `binding`, `billing`, and `stale`.
Successful output includes:

```json
{
  "valid": true,
  "verification_scope": "cathedral_signed_assertions",
  "evidence_independently_verified": false
}
```

## Canonical bytes and signature input

The full receipt file must be exactly the ASCII bytes produced by:

```python
json.dumps(
    document,
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=True,
    allow_nan=False,
).encode("ascii")
```

There is no trailing newline. The signature input uses the same encoding after
removing only the top-level `signature` field. Every other field is signed.
The signature object is:

```json
{"algorithm":"ed25519","value_base64":"BASE64_OF_EXACTLY_64_BYTES"}
```

Parsing rejects duplicate keys, floating-point values, non-finite numbers,
noncanonical bytes, integers outside the signed 64-bit range, documents over
256 KiB, and excessive depth or node count.

`issued_at`, `valid_from`, and `valid_until` use exactly six fractional digits:
`YYYY-MM-DDTHH:MM:SS.ffffffZ`.

## Policy identifier

The v1 policy constant is the exact ASCII byte string below, with no newline
or NUL terminator:

```text
cathedral.customer-receipt.policy.v1
```

Its required digest is:

```text
sha256:c7ff160107c32648e99773feacaaff4f5a4dae059ef237ac8992b2a6fae743eb
```

The exports are `CUSTOMER_RECEIPT_POLICY_V1` and
`CUSTOMER_RECEIPT_POLICY_DIGEST` in `cathedral/customer_receipt.py`.

## Flat receipt fields

No top-level extensions are accepted in v1.

Common identity and status fields:

- `schema`: `cathedral_customer_receipt_v1`
- `receipt_id`: canonical lowercase UUID text
- `issued_at`
- `policy_digest`
- `signing_key_id`
- `receipt_status`: `ready`

Common execution fields:

- `execution_class`: `tdx_cpu` or `cc_gpu`
- `profile_id`
- `cpu_tee`
- `gpu_type`
- `gpu_count`
- `execution_outcome`: `succeeded`, `customer_error`, or `customer_timeout`
- `nonce_sha256`, `workload_sha256`, `result_sha256`: exactly 64 lowercase
  hexadecimal characters, without a `sha256:` prefix
- `execution_binding_verified`
- `report_data_match`
- `intel_verified`
- `gpu_attestation_verified`
- `guest_binding_verified`
- `runtime_execution_verified`
- `teardown_required`
- `teardown_confirmed`

Billing fields:

- `billed`
- `billing_status`: `billed`, `trusted_service`, or `complimentary`
- `billing_outcome`: `charged` or `not_charged`

A billed receipt must use `billed` plus `charged`. An unbilled receipt must use
`trusted_service` or `complimentary` plus `not_charged`.

For `tdx_cpu`, `profile_id` is `attest.v1`, `cpu_tee` is `intel_tdx`,
`gpu_type` is null, `gpu_count` is zero, `report_data_match` and
`intel_verified` are true, and the three GPU verification fields are null.

For `cc_gpu`, `profile_id` is `gcp-g4-rtx-pro-6000-sev-v1`, `cpu_tee` is
`amd_sev`, GPU type and count are populated, `report_data_match` and
`intel_verified` are null, and all three GPU verification fields are true.
This does not assert an AMD SEV-SNP host attestation.

Both execution classes require a true execution binding and confirmed
teardown before a `ready` receipt verifies.

## Locally trusted keys

The verifier takes a local trust file. The file is not fetched from the receipt
and is not authenticated by the receipt. Pin and distribute it through an
independent trusted channel.

Schema example, containing no production key:

```json
{
  "schema": "cathedral_customer_receipt_trusted_keys_v1",
  "keys": {
    "replace-with-key-id": {
      "algorithm": "ed25519",
      "public_key_base64": "REPLACE_WITH_BASE64_OF_32_RAW_BYTES",
      "status": "active",
      "valid_from": "2026-01-01T00:00:00.000000Z",
      "valid_until": "2027-01-01T00:00:00.000000Z"
    }
  }
}
```

`signing_key_id` selects one entry. `active` and `retired` keys verify receipts
issued inside `[valid_from, valid_until)`. `revoked` keys fail every receipt.
Key rotation and trust-file publication remain operator responsibilities.
