# Threat Hunting (TH) Template

## Hunt Metadata

| Field | Value |
|---|---|
| **Hunt ID** | TH-YYYY-NNN |
| **Hunt Title** | |
| **Analyst** | |
| **Date Started** | |
| **Date Completed** | |
| **Status** | Open / In Progress / Closed |
| **Hypothesis** | |
| **MITRE ATT&CK Technique(s)** | |
| **Data Sources** | Splunk (`index=nix`, `sourcetype=linux:audit`, `linux:audit:enriched`) |
| **Scope (Hosts / Users / Timeframe)** | |

---

## 1. Hypothesis & Objective

**Hypothesis:**
> _Describe what adversary behavior you expect to find and why._

**Objective:**
> _What question is this hunt trying to answer?_

---

## 2. Triage: Review Pending Notables

Use this query to view all pending notables for the Threat Hunting process.

```spl
`notable`
| search NOT suppression a1_process="Threat Hunting"
| chart sum(count) over rule_name by status_label
| sort_chart
```

**Findings / Notables of interest:**

| Rule Name | Status | Count | Selected for Investigation (Y/N) | Notes |
|---|---|---|---|---|
| | | | | |

---

## 3. Investigation: Process Lookup by Host & Message ID (Message Audit)

Replace `lx380ot001` with the target host and `(1724410631.883:6149827)` with the audit message ID.

```spl
index=nix host=lx380ot001
[| search index=* host=lx380ot001 "(1724410631.883:6149827)" | fields msg]
| append [search index=* type=EXECVE host=lx380ot001 "(1724410631.883:6149827)"]
| eval cmd= a0." ".coalesce(a1,"")." ".coalesce(a2,"")." ".coalesce(a3,"")." ".coalesce(a4,"")." ".coalesce(a5,"")." ".coalesce(a6,"")." ".coalesce(a7,"")." ".coalesce(a8,"")." ".coalesce(a9,"")." ".coalesce(a10,"")." ".coalesce(a11,"")." ".coalesce(a12,"")." ".coalesce(a13,"")." ".coalesce(a14,"")." ".coalesce(a15,"")
```

**Inputs used:**

| Parameter | Value |
|---|---|
| Host | |
| Message ID | |

**Observations:**
> _Commands executed, parent/child processes, suspicious arguments, etc._

---

## 4. Investigation: Process Lookup by Host & Session (SES)

Fill in the `host=` and `ses=` placeholders (both occurrences of `host=`).

```spl
index=nix sourcetype="linux:audit" OR sourcetype="linux:audit:enriched" host=[] type IN ("EXECVE", "USER_", "CRED")
[ search index=nix sourcetype="linux:audit" OR sourcetype="linux:audit:enriched" type="SYSCALL" host=[] ses=
| fields msg
| dedup msg]
| eval cmd= a0." ".coalesce(a1,"")." ".coalesce(a2,"")." ".coalesce(a3,"")." ".coalesce(a4,"")." ".coalesce(a5,"")." ".coalesce(a6,"")." ".coalesce(a7,"")." ".coalesce(a8,"")." ".coalesce(a9,"")." ".coalesce(a10,"")." ".coalesce(a11,"")." ".coalesce(a12,"")." ".coalesce(a13,"")." ".coalesce(a14,"")." ".coalesce(a15,"")
| eval value=lower(cmd)
| eval cmdDecoded=urldecode(ltrim(replace(value,"([a-f0-9]{2})","%\1"),"0x"))
| table _time, host, user, type, argc, a0, system_call, ppid, pid, cmd, cmdDecoded, msg, audit_description, name, objtype, distribution_release, audit_value, event_id,
| sort _time
```

**Inputs used:**

| Parameter | Value |
|---|---|
| Host | |
| Session ID (`ses`) | |

**Observations:**
> _Session timeline, user activity, credential events, decoded commands._

---

## 5. Timeline of Events

| Time (UTC) | Host | User | Event / Command | Source Query | Notes |
|---|---|---|---|---|---|
| | | | | | |

---

## 6. Analysis & Findings

**Indicators of Compromise (IOCs):**

| Type | Value | Context |
|---|---|---|
| | | |

**Assessment:**
- [ ] Benign / Expected activity
- [ ] Suspicious – requires further investigation
- [ ] Confirmed malicious – escalate to incident response

**Summary of findings:**
> _Narrative description of what was found and the reasoning behind the conclusion._

---

## 7. Actions & Recommendations

| Action | Owner | Due Date | Status |
|---|---|---|---|
| Escalate to IR (if applicable) | | | |
| Create/tune detection rule | | | |
| Suppress notable (with justification) | | | |
| Remediation steps | | | |

---

## 8. Lessons Learned / Detection Improvements

- **Gaps in visibility:**
- **New detection opportunities:**
- **Query improvements:**

---

## 9. Sign-off

| Role | Name | Date |
|---|---|---|
| Analyst | | |
| Reviewer | | |
