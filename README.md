# Odoo Integration Labs

Implemented by **Muhammad Shahyan Khalid**.

Independent Outlook, Zoho CRM, QuickBooks and Stripe test-payment connector implementations.

This repository provides an independently reconstructed implementation using
fictional business data and public Odoo Community APIs. The documented workflows
and configuration demonstrate the implementation without distributing client data.

## Implemented features

- Outlook contacts, Zoho CRM sandbox and QuickBooks sandbox customer imports.
- Connection-scoped mappings, conflict policies and retry inbox.
- OAuth code flow, refresh handling and encrypted token storage.
- Stripe test PaymentIntent, signed receipt, native payment and full-credit review.

Odoo 18.0 Community. Addon `independent_connectors`. Database `integration_demo`. Port `8180`.
See `docs/FEATURES.md` for scope, assumptions and limitations.

## Setup (commands for your later use; not executed)

```powershell
python scripts/bootstrap.py
.\scripts\lab.ps1 -Action init
.\scripts\lab.ps1 -Action up
.\scripts\lab.ps1 -Action upgrade
.\scripts\lab.ps1 -Action stop
```

Open http://127.0.0.1:8180. Admin password: `.local/credentials.json`.
Local email capture: http://127.0.0.1:8030. SMTP goes to Mailpit.
`reset` deletes only this Compose project's named demonstration database.
`seed` reloads custom XML external IDs. Other projects are not dependencies.

Each project has its own Compose name, PostgreSQL volume, filestore, database,
loopback web port, credentials and addons mount. Images are pinned by digest.
Default networking is internal and blocks live providers. To use an explicitly
authorized sandbox, change the project's network setting and supply its secrets
through the private environment. No production integration is enabled by default.

User-supplied historical behavior is the evidence source. Exact thresholds,
identifiers, providers and rules absent from it are proposed configuration. Native
Odoo invoices, payments, inventory, CRM and HR are used where applicable. Configure
a suitable chart, journals, taxes and payment methods before accounting actions.

See [PUBLICATION_SAFETY_REPORT.md](PUBLICATION_SAFETY_REPORT.md) for repository
contents and exclusions. Validation history is recorded separately in
[docs/VERIFICATION.md](docs/VERIFICATION.md).
