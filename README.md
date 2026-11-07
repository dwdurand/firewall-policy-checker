# Firewall Policy Sanity Checker

A read-only Python and Streamlit tool for reviewing Palo Alto Networks security-policy spreadsheet exports. It surfaces defined review candidates, displays summary counts and rule details, and generates an Excel report for engineering review.

Developed by Dave Durand / A1 Cyber Services LLC.

**This version uses deterministic checks. It does not use an LLM or perform AI analysis.**

## Status

The corrected implementation has been exercised with synthetic data through offline tests, the Streamlit dashboard, and browser-downloaded Excel reports. It has not been validated against production exports in this development cycle.

This package contains the corrected implementation as `app.py`, its synthetic sample workbook, repeatable offline tests, and recorded validation results. No AI/API integration is included.

## What it checks

| Check | Rules considered | Finding condition |
| --- | --- | --- |
| Broad address selection | Enabled allow rules | Source Address or Destination Address is explicitly `any` |
| Explicit application names | Enabled allow rules | Application contains an exact `telnet`, `http`, or `ftp` token |
| Missing security-profile attachment | Enabled allow rules | Profile is blank, whitespace, or `none` |
| Session logging disabled | Enabled rules, including deny rules | Both session-start and session-end logging flags are explicitly off |
| Missing forwarding profile | Enabled rules, including deny rules | Log Setting is blank, whitespace, or `none` |
| Unknown session-logging state | Enabled rules | Either session-logging flag is blank or unrecognized |

The application check accepts semicolon, comma, or whitespace separators, including line breaks. Matching ignores capitalization and surrounding whitespace. For example, `ssl;telnet` matches; `sftp` and `telnet-custom` do not.

Address matches are review candidates, not proof of network exposure. A named profile indicates attachment only; the tool does not verify its contents or effectiveness.

## Local setup

The corrected version was tested on Windows with Python 3.13. Run these commands from the project folder after saving the corrected implementation as `app.py`:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install streamlit pandas openpyxl
.\.venv\Scripts\python.exe -m streamlit run app.py --server.address 127.0.0.1 --server.headless true --browser.gatherUsageStats false
```

Open the local URL printed by Streamlit. Keeping the server bound to `127.0.0.1` limits access to this computer. Stop the server with `Ctrl+C` in its terminal.

Direct dependencies are Streamlit, pandas, and openpyxl. `requirements.txt` pins the tested environment, including transitive dependencies, for Windows/Python 3.13. Other operating systems and Python versions have not been verified.

## Spreadsheet format

- File type: `.xlsx`.
- Worksheet name: `firewall`, exactly.
- Row 1: title or other metadata; the importer skips it.
- Row 2: column headers, exactly as listed below.
- Row 3 onward: one security-policy rule per row.

| Required column | Expected content |
| --- | --- |
| UUID | Rule identifier; preserve uniqueness across the exported scope |
| Rule Name | Rule name |
| Source Address | Explicit address value, object, or group name |
| Destination Address | Explicit address value, object, or group name |
| Application | Application name or delimited list |
| Service | Exported service selection |
| Action | Exported action; `allow` is required for the first three checks |
| Profile | Attached security profile/group name, or blank/`none` |
| Log Setting | **Log-forwarding profile name**, or blank/`none` |
| Source Zone | Exported source zone selection |
| Destination Zone | Exported destination zone selection |
| Disabled | `yes`/`no`, `true`/`false`, or `1`/`0` |
| Log at Session Start | `yes`/`no`, `true`/`false`, or `1`/`0` |
| Log at Session End | `yes`/`no`, `true`/`false`, or `1`/`0` |

For Disabled, a true value means the rule is disabled and is excluded from the checks. For session-logging flags, a true value means that logging option is enabled. Capitalization and surrounding whitespace are normalized.

**Confirm the export's column meanings before use.** In particular, `Log Setting` must represent the forwarding profile, not a combined description of logging options. The tool does not automatically map different export formats.

Missing required inputs can stop processing with an on-screen error. A missing or unknown Disabled state stops analysis. Blank or unrecognized session flags produce an unknown-state finding. Blank application/address values are not resolved and must not be interpreted as proof of safety.

## Review and export

1. Upload the spreadsheet in the local dashboard.
2. Review the Executive Dashboard and Detailed Audit Findings tabs.
3. Compare findings with the original policy context before proposing changes.
4. Select **Download Remediation Excel Report** to download `firewall_remediation_report.xlsx`.

The output worksheet is `Remediation Action Items`. It contains the original columns for matching rows, deduplicated by **UUID + Rule Name**. It does not add a finding-reason column; use the dashboard's category tables to understand each match.

The summary's **Findings Requiring Review** adds category counts. One rule can match multiple categories, so this number can exceed the number of unique rows exported. Unknown logging states and missing forwarding attachments are included as review findings, not confirmed vulnerabilities.

## Validation performed

Offline cases covered missing profiles, application-list matching, session logging versus forwarding, broad address selection, and invalid inputs. Each correction also received dashboard and downloaded-report verification using the same 13-rule synthetic workbook.

For the final corrected version, the synthetic workbook produced:

| Result | Expected and observed |
| --- | ---: |
| Rules loaded | 13 |
| Enabled allow rules with an explicit `any` address | 0 |
| Missing-profile findings | 6 |
| Explicit application-name findings | 1 |
| Rules with both session-logging flags disabled | 0 |
| Missing forwarding-profile findings | 1 |
| Unknown session-logging states | 0 |
| Unique rules in downloaded Excel | 8 |

The `application-list` rule containing `ssl;telnet` was included. The `deny-any-address` and `disabled-missing` rules were excluded from the final report. Separate offline address cases exercised positive `any` matches; the dashboard workbook's address result is zero.

These are focused synthetic checks, not a claim of comprehensive test coverage. The package includes `sample-data/firewall-synthetic-validation.xlsx`, a portable test suite, and pinned dependencies. Run the tests from the repository root:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Tests record Streamlit UI calls while executing the actual app, read the real sample workbook, and reopen its in-memory Excel export. They do not automate a browser. Recorded browser verification is included under `validation/`.

## Scope and limitations

- Reads an uploaded workbook and generates review output. It does not connect to Panorama or firewalls, request API credentials, or create, modify, delete, commit, or push configuration.
- Does not parse Panorama XML, resolve shared/device-group inheritance, combine pre/post rulebases, or calculate effective policy.
- Does not assess address/application groups, dependencies, negation, rule order, shadowing, NAT, routing, or effective reachability.
- The explicit application list is limited to `telnet`, `http`, and `ftp`. It does not establish whether all cleartext traffic is blocked; `any`, other App-IDs, and service ports require separate review.
- Does not inspect security-profile contents, log-forwarding destinations, actual log generation, or delivery to Panorama/syslog.
- A named forwarding profile is not evidence of successful forwarding. Both session flags being off concerns session traffic logging; it does not establish that every other log type is disabled.
- Export deduplication uses UUID + Rule Name only. Scope collisions or incomplete identifiers can collapse distinct rows; prepare exports accordingly.
- Findings require engineering review. Zero findings means no matches for these implemented checks, not a secure or compliant policy.

## Data handling

Use synthetic or appropriately sanitized workbooks for demonstrations and repository samples. Run the app locally and keep production exports, credentials, and generated reports out of GitHub. This implementation contains no external AI/API calls. Uploaded data is processed by the running local app; downloaded reports retain the selected input fields and should be handled accordingly.

## Planned next steps

- Validate an agreed real export format using sanitized data.
- Develop Panorama parsing incrementally as a separate read-only capability.
- Explore evidence-grounded AI explanations only after structured findings are validated.
