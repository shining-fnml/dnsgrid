Publication review
==================

This is preparation for an owner-reviewed visibility decision, not permission
to publish. Keep the repository private and the preparation PR unmerged until
review. The GNU AGPL-3.0 license in ``LICENSE`` is unchanged.

Pre-publication checklist
------------------------

* Review the current tracked tree, staged changes, configuration samples,
  migrations, tests, and documentation. Check environment files (including
  ignored ones), Gandi tokens, Django ``SECRET_KEY``, passwords, API/session
  credentials, private keys, and deployment configuration. Examples must
  contain fictitious data, not copies of working credentials.
* Review every branch and tag that will remain accessible, with its entire
  reachable history, including deleted/renamed files, commit messages, and
  annotated tag messages. A shallow or single-branch clone is insufficient
  for that decision. Use a complete authorized checkout and enumerate refs
  before repeating local scans; include remote branches absent here.
* Check SQLite/database files and journals/WALs, dumps, inventory archives,
  backups, downloaded DNS/DHCP/VPN/Gandi/DSM exports, and NAS backup responses.
  Database users, password hashes, sessions, and pending settings confirmations
  may be sensitive. A saved Gandi token and pending confirmations are not
  encrypted at rest. Application archives exclude credentials but still
  contain host notes, inventory, and Gandi ownership history.
* Review real host/site names, domains, IPs, MACs, notes, and topology for
  information the owner does not want public. Private IP ranges and the
  ``192.168.g.x`` / ``172.28.g.x`` conventions are not credentials: preserve
  legitimate examples and network conventions rather than deleting every
  address. Decide whether concrete inventory is intended for disclosure.
* Review GitHub issues, PR titles/descriptions/reviews/comments and quoted
  conversations, discussions, attachments, releases, and any wiki. Review
  Actions logs, artifacts, caches, and uploaded reports, including old runs.
  Repository-file scans do not cover these surfaces; do not assume a
  visibility change hides old disclosures. Also inspect deployment copies
  and local ignored/untracked files before sharing bundles.
* Check ``git status --short --ignored`` and ``git ls-files``. The ignore
  rules cover local environment variants, SQLite files, root ``backups/`` /
  ``exports/`` directories, and named root downloads. They deliberately
  keep source/tests/docs and ``.env.example`` / ``.env.sample`` visible.
  Samples still require review. Ignoring a path does not untrack an existing
  file, sanitize history, or protect data stored elsewhere.
* If actual secrets or sensitive inventory/history are found, mark
  **PUBLICATION BLOCKED** until owner review and remediation. Revoke/rotate
  exposed credentials through an authorized process; removal alone does
  not invalidate them. Identify locations/categories with redaction, never
  copy values into logs, PR text, or external scanners.
* Removing a file in a new commit does **not** remove it from history.
  Obtain separate authorization for any history rewrite, branch/tag
  deletion, credential rotation, or account/repository setting changes.
  Agree a remediation plan covering retained refs, clones, and GitHub
  surfaces; a PR deleting current files alone is not sufficient.
* After resolving findings and the remaining audit gaps, review this PR,
  rerun checks on the reviewed revision, and decide separately whether to
  merge and change visibility. Only the owner performs publication.
  Anonymous HTTPS clone/pull works after publication; pushing still
  requires write authorization. Publishing source does not publish the
  running web application or its database.

Audit record
------------

The best-effort audit for this preparation is limited to the agent clone
and the GitHub surfaces explicitly listed below. It is not a complete
audit or a safety guarantee.

**PUBLICATION BLOCKED pending owner review.** The initial PR #10 description
copied an infrastructure example from the task conversation (host identifier
and VPN assignment). Values are intentionally not reproduced here. The
current description was replaced with a redacted progress checklist, but
that is not evidence that all retained copies or related conversations have
been removed. The owner must decide whether this was fictitious or sensitive
inventory and review/remediate any retained disclosure before publication.

Local coverage on 2026-10-08:

* The working tree scan covered all 49 tracked files, including the README
  and ignore-rule edits. The new publication document was checked separately
  by the pre-commit changed-file secret scan.
* ``git rev-parse --is-shallow-repository`` returned ``true``.
  ``git for-each-ref`` found only the local preparation branch and its
  remote-tracking counterpart; no local tags or other branches were available.
  ``git rev-list --all`` reached two commits:
  ``39858e5ab51eb2b4f7112a4ddf686d458281dd01`` and
  ``b8298b3f2831ea80950adb833a8877caedc2b6c8``. Their source trees were identical.
* Local Git object inspection covered all 46 distinct reachable blobs,
  49 blob/path versions, 10 trees, and both commit messages. Git enumeration
  used ``git rev-list --objects --all``, ``git ls-tree -r -z``, and
  ``git cat-file``. Contents were captured locally for redacted analysis,
  not printed or submitted to a third-party scanner.
* Available Git/Python tools were used for credential-signature and entropy
  checks, private-key markers, credential-bearing URLs, password hashes,
  address/MAC classification, binary/generated-file checks, and inspection
  of secret defaults and serialization. Dedicated local secret scanners
  were unavailable; heuristic checks cannot prove the absence of secrets.

No confirmed embedded credentials, private keys, operational inventory,
binary files, or tracked generated database/export/archive artifacts were
found in that local scope. Model and migration domains are illustrative;
the seed migration creates four generic numbered sites and no hosts.
Address conventions and MAC validation/test literals were not treated as
secrets. These findings also apply to the identical trees of both inspected
commits, not to unavailable ancestors.

Secret handling was inspected in ``dnsgrid/settings.py:25``,
``inventory/models.py:112``, ``inventory/gandi.py:34,65-75``,
``inventory/views.py:50-54,203-247``, and
``inventory/archives.py:18-27,68-75``. There is no committed Django signing
secret; the environment overrides a random startup fallback. Gandi supports
an environment token and a saved database token, with browser preview
redaction. Database/session copies can still contain that token. Portable
archives omit tokens but include inventory and ownership data.

GitHub inspection was limited to recent workflow metadata, the failed-job
query for VPN-report run ``37686115964`` (no failed jobs), and PR #10's
initial description/state. This was not an audit of successful job logs,
artifact contents, caches, other PRs/issues/comments, discussions, releases,
or attachments. No failed CI run was identified in the consulted recent
metadata. These surfaces must still be reviewed by the owner.

Unavailable ancestors/remote refs, dangling objects, reflogs, deployment
files, and ignored/untracked operational data were not audited. No history
was fetched or rewritten, refs deleted, credentials rotated, or account /
repository settings changed. The local findings do not clear the PR-body
review blocker or the remaining coverage gaps.

Validation
----------

Using the existing ``requirements.txt`` in an isolated virtualenv outside
the repository, the following commands passed from the repository root::

    python manage.py test inventory.test_exports inventory.test_vpn_report inventory.test_dsm_apply
    python manage.py test inventory
    python manage.py check
    python manage.py makemigrations --check --dry-run
    git diff --check

The focused run passed 41 tests; the complete existing suite passed 187.
System checks reported no issues and no migrations were needed. The first
attempt with the system interpreter stopped because Django was absent;
the successful runs used the isolated environment with the pinned project
requirements. No dependency or application behavior was changed.
``git check-ignore --no-index`` verified representative operational paths
are ignored and source/test/documentation/sample paths remain visible.
README/publication text and links were reviewed manually against code;
no RST renderer was available, so no rendering check is claimed.
