# Research and dataset design rationale

Research checked on 2026-09-21. The architectural source is the supplied
`Access_Review_Prototype_Architecture_1.docx`; the implementation contract is
[contract.md](contract.md). External standards inform the design but do not
replace the project's module boundaries or establish compliance.

## Why a purpose-built synthetic dataset

The prototype needs authoritative identity context and policy intent that can
be compared with access discovered independently. A public HR analytics dataset
would not establish this organization's policy, reliable account correlation,
or entitlement definitions. We therefore created a fictional demonstration
dataset for this contract instead of acquiring real employee records. It is
test material, not a representative sample of an employer or evidence of a
working access-review deployment.

The records retain only context used by the prototype: stable identifier,
username, display name, department, role, employment status/type, manager, and
employment dates. Personal email, phone, address, birth date, salary, national
identifiers, and demographic attributes are omitted. The `synthetic` flag
declares the dataset's purpose; it does not prove provenance. A future real HR
feed will require a trusted ingestion process and controlled access to its
contents.

The frozen snapshot makes results repeatable. Lifecycle cases and role cohorts
are deliberately constructed for tests. Their counts must not be interpreted
as employment statistics, calibrated probabilities, or a training benchmark
for access-risk scoring.

## Identity and correlation

SCIM separates a persistent resource identifier from a username and includes
enterprise department and manager attributes. It also discusses limiting
disclosure of identity attributes to those needed for a purpose. These support
our stable `id`, separate login hint, manager reference, and small HR field set.
This is a custom JSON contract: it does not implement SCIM resources, endpoints,
or protocol behavior, and is not advertised as SCIM compliant.
[RFC 7643 §§3.1, 4.1.1, 4.3, 9.3](https://www.rfc-editor.org/rfc/rfc7643.html)

Project decisions:

- `id` is opaque and permanent. A rename, department transfer, or rehire retains
  the same person's ID; an unrelated new person receives a new ID.
- `username` is unique inside a snapshot, but is not a durable global key.
  Its restricted lowercase syntax is a prototype convention, not a universal
  description of account names in target systems.
- Module 4 must correlate each discovered source account in its source
  namespace. Reused names, multiple accounts, and ambiguous matches need
  explicit evidence; comparing names alone is insufficient.
- A snapshot cannot prove that an ID was never reused. Retained snapshot
  history and the trusted HR publisher must establish continuity.
- Display names may repeat and may contain Unicode. Neither spelling nor
  transliteration is identity evidence.

The current contract represents one employment interval per person in each
snapshot. Historical intervals and rehire history are not an event log inside
the identity record. Consumers must retain prior snapshots if they need to
explain such changes.

## Policy intent is separate from discovered access

NIST describes attribute-based access control in terms of subject, object,
operation, and environment attributes evaluated against policies and
relationships. That separation informs our use of HR attributes and a
catalog of business capabilities as review inputs. Module 1 does not implement
a general ABAC policy engine or runtime authorization service.
[NIST SP 800-162](https://csrc.nist.gov/pubs/sp/800/162/upd2/final)

Department/role pairs select explicit policy profiles. Entitlement IDs denote
generic business capabilities; Module 3 will map discovered native access to
them. This keeps policy stable when a target system renames a group or when
multiple native assignments confer the same capability. Module 1 does not
contain account assignments or native group mappings.

The three policy lists have distinct meanings:

| List | Contract decision |
| --- | --- |
| `expected` | Normally needed baseline access; absence is a later review signal. |
| `restricted` | Explicitly forbidden access; cannot overlap an allowed list. |
| `privileged` | Elevated access permitted for this profile when present; not required merely by being listed. |

Privilege is also a global catalog flag so that elevated access remains
recognizable outside a permitted profile. Sensitivity expresses the potential
impact of access to the capability; it is separate from administrative power.
An expected capability may be privileged, but must then also appear in the
profile's privileged list. Unlisted or unknown access remains reviewable.
These are project policy semantics, not vocabulary imposed by the cited
standards.

## Lifecycle decisions

The prototype allows role-policy access only for `active` people. It specifies
no access for `on_leave`, `pre_hire`, and `terminated` people. Suspending all
leave access and disallowing pre-start provisioning are deliberate conservative
defaults for this prototype, not claims about every employer's practice.

Employment dates use the snapshot's UTC calendar date. Start dates are
inclusive; end dates are exclusive. Contractors require an end date. A person
cannot remain `active` or `on_leave` at or after that end date in a valid
snapshot. An expired contractor should therefore be represented with a
consistent nonactive status, rather than relying on a later reviewer to repair
contradictory HR records. Status restrictions take precedence over role lists.

An employee and contractor with the same department/role receive the same
role policy in version 1.0.0. Employment type supports lifecycle validation and
peer-cohort separation; it is not an extra authorization selector. A future
need for different permissions must be expressed by an explicit policy/schema
change, not inferred from the person's name or contract type.

## Validation and its limits

JSON Schema Draft 2020-12 defines structural constraints and distinguishes
format annotations from optional format assertions. A `format: date` or
`format: date-time` declaration alone must not be assumed to reject invalid
calendar values. The project combines schema validation with explicit semantic
checks for dates, references, uniqueness, graph consistency, and policy
relationships.
[JSON Schema Validation, draft 2020-12 §§6–7](https://json-schema.org/draft/2020-12/json-schema-validation)

The Python library documentation confirms that format enforcement is not
enabled by default and that some format checkers require optional dependencies.
Tests must exercise impossible dates and malformed timestamps, rather than
assuming a validator configuration provides this behavior.
[python-jsonschema: validating formats](https://python-jsonschema.readthedocs.io/en/stable/validate/#validating-formats)

Successful loading means that a pair of documents satisfies this version's
structural and semantic contract. It does not prove publisher authenticity,
freshness, HR accuracy, full source coverage, secure target configuration, or
the correctness of a later access decision. These need separate evidence at
ingestion and review time.

## Peer comparisons and future evaluation

The intended initial comparison group is active people with the same
department and role; employment type can further split it. Singleton and
small cohorts are intentionally possible. Module 4 must expose cohort size
and avoid presenting weak comparisons as strong statistical evidence. No
statistical threshold or risk-score calibration is established by this
dataset. Peer agreement never overrides an explicit restriction: shared
overprovisioning can be common and still be inappropriate.

Expected review results belong in Module 4 tests, not in authoritative HR rows
or policy payloads.
