# HEARD

**Your rights. Your voice. Your next step.**

HEARD is a public-interest project being built to help people understand their rights, make sense of government actions that affect their lives, and find paths to answers and accountability. It brings clear information, practical support, and firsthand stories together in one place.

Questions about your rights deserve careful answers. Experiences deserve to be taken seriously. And when public institutions make mistakes or misuse their power, people need ways to document what happened and seek review or redress.

## What HEARD will offer

- **Know your rights.** Plain-language guides explaining legal protections, government powers, and the procedures that matter, with sources and jurisdiction-specific context.
- **Ask a question.** A simple place to explore concerns about something that happened or a government decision you want to understand.
- **Find support.** Resources and carefully managed connections to people who may be able to help, including legal professionals, researchers, and advocates.
- **Share an experience.** A way to preserve an account, organize evidence, and choose whether to share a story more widely.
- **Help someone else.** Opportunities to contribute relevant information, time, or professional expertise.
- **Explore stories.** Firsthand accounts presented with available documents, updates, and clear distinctions between reported experiences and independently verified findings.

**The platform's central promise is clarity and choice:** useful information, respectful treatment, and control over what is shared and with whom. Those promises must be supported by tested product behavior, not merely words.

## Content and editorial direction

Public copy is maintained in [content/site-copy.json](content/site-copy.json), with its editorial standards in [docs/CONTENT_STRATEGY.md](docs/CONTENT_STRATEGY.md). The site should feel welcoming and serious, not like a law office, court filing, political solicitation, or sensationalized exposé.

Rights guides must identify their sources, relevant jurisdiction, and review date. Published accounts must distinguish a contributor's experience from documentary evidence, corrections, and independently confirmed findings. Communications about privacy must describe actual protections and meaningful limitations.

## Development documentation

- [Complete development plan](docs/DEVELOPMENT_PLAN.md) — architecture, security, data model, user workflows, phased work packages, acceptance and release gates.
- [Product decisions](docs/DECISIONS.md) — settled product boundaries and unresolved material decisions.
- [Independent-account handoff](docs/CROSS_ACCOUNT_HANDOFF.md) — implementation status, dependency tracking, and next steps.
- [Content strategy](docs/CONTENT_STRATEGY.md) — brand voice, interface wording, sensitive copy rules, and review process.
- [Canonical interface copy](content/site-copy.json) — strings and screen-level copy for the eventual application.

## Related projects

- [Justice For All](https://github.com/neophilism/Justic-For-All) — the broader initiative; any technical integration must be checked before implementation.
- [Secure Intake & Case Workflow Engine](https://github.com/neophilism/Secure-Intake-Case-Workflow-Engine) — reusable private intake and case workflow capabilities, subject to compatibility tests.
- [End-To-End-Everywhere Security Architecture Standard](https://github.com/neophilism/End-To-End-Everywhere-Security-Architecture-Standard) — applicable security requirements, evaluated per component and data flow.
- [FOIA Aggregator](https://github.com/neophilism/FOIA_Aggregator) — potential source of verifiable public-record references.

## Current project status

HEARD is in early development. **There is no live HEARD service accepting private questions, testimony, or evidence.** Do not submit sensitive information through GitHub issues, pull requests, demonstration forms, or repository discussions.

Work units HEARD-01 through HEARD-13 are merged: the public site shell, deployable Node web service with health/readiness, PostgreSQL schema with default-deny row-level security, anonymous identity and recovery, resource authorization, versioned consent, an accessible intake wizard with encrypted drafts and receipts, resumable private uploads and malware quarantine. Private intake is **disabled by default** and has not been deployed or independently reviewed. See [the handoff](docs/CROSS_ACCOUNT_HANDOFF.md) for exact PRs, tests, blockers and next steps, and [registry/prs.json](registry/prs.json) for the machine-readable plan.

Development progress and live readiness are tracked separately. A completed roadmap entry is not evidence that the corresponding service is deployed or safe for sensitive use.

## End-to-End Everywhere progress

The canonical [security/e2eesa-status.json](security/e2eesa-status.json) records standard implementation, complete testing and independent expert review separately. Engine Room reads it automatically from GitHub. All initial stages are pending; existing profile locks and approved decisions remain authoritative. Read [adoption and independent-account instructions](docs/E2EESA_ADOPTION.md), and run `python3 scripts/validate_e2eesa_status.py`. Record validation does not establish product security or certification.


## Engineering app and deployment

The Next.js web service lives in `apps/web`; framework-agnostic API modules live in `packages/*` (`config`, `operations`, `database`, `server`, …). See [workspace setup and verification limits](docs/WORKSPACE_PLAN.md) for local commands and [Render deployment](docs/DEPLOYMENT_RENDER.md) for build/start commands, health/readiness endpoints and every environment variable. The service runs without external credentials (public shell only); private intake is disabled by default and requires a database and keys. This engineering preview does not accept personal information or provide live case services.

```sh
npm ci --ignore-scripts
npm run check            # foundation, registry, unit tests
npm run test:database    # native PostgreSQL 17 migrations and RLS
npm run test:server      # API modules against native PostgreSQL
npm run build && npm run test:web && npm start
```

## Requirements handoff

[Product charter](PRODUCT_REQUIREMENTS.md), [versioned requirements ledger](requirements/ledger.json), [user-role matrix](docs/USER_ROLES.md) and [decision process](docs/ADR/README.md) preserve the approved scope without relying on conversation memory. `npm run check:requirements` verifies all 48 build/acceptance statements and their owners and initial test destinations. It checks planning traceability, not completion of those features.

## Privacy architecture handoff

[Threat model and data map](docs/THREAT_MODEL.md) and [versioned privacy design](security/privacy-design.json) enumerate intended boundaries, recipients, potential plaintext exposure and negative-test destinations. `npm run check:privacy-design` validates this design register only; it does not certify runtime security or complete the E2EESA inventory.

## Database baseline

[Schema and migration notes](docs/SCHEMA_MIGRATION_NOTES.md) document the checksum-bound runner, default-deny roles, fictional fixtures and separate native/WASM database test commands. Native and provider acceptance remain explicit; passing foundation checks do not establish database security or deployment readiness.
