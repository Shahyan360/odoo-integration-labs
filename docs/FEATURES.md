# Source implementation and review boundaries

These are NEW independent technical demonstrations. No historical employer or
client association is asserted for any provider. All implementations are source
only and untested, including API compatibility and security behavior.

Implemented:
- Connection/company scoped mappings, one-page contact imports, immutable inbox,
  deduplication by delivery ID and content hash, per-connection database lock,
  bounded exponential retry and disabled background job.
- Outlook delegated Contacts.Read imports using Microsoft Graph v1.0, immutable
  IDs, bounded pagination and an allowed Graph path. No mailbox read permission.
- Zoho CRM v8 US SANDBOX Contacts or Leads -> partners and optional new leads.
  First ten pages and then page tokens; no production Zoho token accepted.
- QuickBooks US sandbox Customer -> partner imports with query pagination.
- Stateful OAuth authorization code exchange, Microsoft PKCE, refresh rotation,
  fixed provider URLs, session/user-bound nonce with ten-minute TTL. Encrypted
  database token vault; the Fernet key and client secrets stay in environment.
- Explicit contact conflict policy: review, preserve local edits, or replace the
  three mapped fields. No automatic matching by email. Same external IDs remain
  independent across connections. Existing local leads are not overwritten.
- Stripe test PaymentIntent creation for a bound posted invoice, provider
  idempotency key, raw-body timestamp/HMAC webhook verification, test-mode-only
  inbox, re-fetch before sandbox accounting, exact amount/currency/database/
  binding checks, native payment registration and reconciliation. Independent
  payment-intent uniqueness prevents two different delivery IDs paying twice.
- Simulator generates fictional normalized contacts or a signed Stripe test
  event and invokes the same mapping path. It makes no network request.
- Draft full credit note for human accounting review. This DOES NOT send a refund
  to Stripe or refund money. Stripe fees, payouts and partial credits are native
  accounting/manual work outside the implemented adapter.

Additional scope outside these connectors: Outlook email/calendar, contact exports or deletions, Zoho Mail/
Books, QBO invoice/tax export and bidirectional accounting, Terminal hardware,
Stripe checkout/browser card collection, automatic confirmation, dispute/refund
webhooks, Sage/Zuper/Dynamics or a general connector framework. Contact scans
are bounded page-based full scans, not delta or webhook synchronization. OAuth
revoke at the provider must be performed in that provider's app console; the local
disconnect action only erases locally held tokens. Zoho is intentionally US only.

Sandbox use requires explicit configuration, registered developer application,
registered callback, provider account permissions, private credentials and a
network change. Outlook has no separate API sandbox; use a dedicated fictional
developer mailbox. QBO requires a sandbox realm. Never use a real account here.
Configure a dedicated active company-limited connector manager service user.
Stripe application processing also requires native invoicing permissions and
an inbound method in the selected bank journal. Managers must also be granted
native accounting rights explicitly; the connector role does not grant them.

The generic contact job data and provider object metadata contain personal data
if pointed at a real account. Use fictional developer data only. Tokens are not
rendered in forms. Database backups and encryption keys remain private. Do not
enable verbose HTTP logging. A hardened reverse proxy and request-body limit are
needed before exposing any endpoint. Loopback is the default binding.

Source references (consulted 2026-10-28):
- https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow
- https://learn.microsoft.com/en-us/graph/api/user-list-contacts?view=graph-rest-1.0
- https://www.zoho.com/crm/developer/docs/api/v8/get-records.html
- https://www.zoho.com/crm/developer/docs/api/v8/auth-request.html
- https://developer.intuit.com/.well-known/openid_configuration/
- https://developer.intuit.com/app/developer/qbo/docs/develop/authentication-and-authorization
- https://docs.stripe.com/api/payment_intents/create
- https://docs.stripe.com/webhooks/signature

Later personal review: install/upgrade; run each fictional contact simulator;
edit its mapped partner and import changed input to review conflict behavior;
configure a local chart/journal/method, post a fictional invoice, select Stripe
simulator, prepare/create/simulate receipt, review inbox and native payment. Repeat
signed delivery to examine deduplication; inspect a draft credit without posting.
These are future review steps, not results of an executed test.
