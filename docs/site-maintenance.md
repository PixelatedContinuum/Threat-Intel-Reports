# Site Maintenance — Adding New Content

Reference guide for updating The Hunter's Ledger after publishing a new report.

---

## Every New Report

A typical report produces three files:
- `reports/[report-name]/index.md` — the report itself
- `hunting-detections/[report-name]-detections.md` — detection rules (if applicable)
- `ioc-feeds/[report-name]-iocs.json` — IOC feed (if applicable)

After committing those files, update the index pages below.

---

## Step 1 — Update `reports/index.md`

**Add a new featured card at the top of the grid.**

Open `reports/index.md`. Find the `hl-grid` block near the top. Add a new `report-card` include as the **first line** inside the `<div class="hl-grid">` tag:

```liquid
{% include report-card.html title="Your Report Title" date="Mar 2026" severity="high" tags="Tag1,Tag2" url="/reports/your-report-slug/" %}
```

**Severity values:** `high`, `med`, or leave the parameter out entirely for informational.

**Tag values and their colors:**

| Tag | Color |
|---|---|
| `MaaS`, `C2`, `RAT`, `IP`, `Hash` | Blue |
| `Webshell`, `RCE`, `Threat`, `Toolkit`, `Ransomware` | Red |
| `Open Dir`, `Domain`, `Sigma`, `Cryptominer`, `Scanner` | Green |
| `Loader`, `Suricata`, `YARA`, `Stealer` | Purple |
| `Note`, `Warning` | Yellow |

**If the grid already has 6 cards:** Move the oldest card (the last `report-card` include in the `hl-grid` block) down to the `hl-row-list` section. Change it from a `report-card` include to a `report-row` include — the parameters are identical:

```liquid
{% include report-row.html title="Older Report Title" date="Jan 2026" severity="high" tags="Tag1,Tag2" url="/reports/older-report-slug/" %}
```

Add it as the first line of the `hl-row-list` block (newest first).

---

## Step 2 — Update `index.md` (Homepage)

The homepage shows the 2 most recent reports. Update them to always show your latest 2.

Open `index.md`. Find the `hl-grid` block (the one under `Latest Reports`). Replace the two `report-card` includes with your 2 newest reports. The format is the same as in `reports/index.md`:

```liquid
<div class="hl-grid">
{% include report-card.html title="Your Newest Report" date="Mar 2026" severity="high" tags="Tag1,Tag2" url="/reports/your-newest-slug/" %}
{% include report-card.html title="Your Second Newest Report" date="Mar 2026" severity="med" tags="Tag1" url="/reports/second-newest-slug/" %}
</div>
```

---

## Step 3 — Update `hunting-detections/index.md` (if the report has detection rules)

Only do this step if the report produced a detections file.

Open `hunting-detections/index.md`. Find the `hl-row-list` block. Add a new `report-row` include as the **first line** inside the block:

```liquid
{% include report-row.html title="Detection Rules — Your Report Title" date="Mar 2026" severity="high" tags="Sigma,YARA" url="/hunting-detections/your-report-slug-detections" %}
```

**Tags for detections** show which rule types are included — use only the ones that actually exist in the detections file:
- `Sigma` — Sigma rules present
- `YARA` — YARA rules present
- `Suricata` — Suricata rules present

---

## Step 4 — Update `ioc-feeds/index.md` (if the report has an IOC feed)

Only do this step if the report produced an IOC feed file.

Open `ioc-feeds/index.md`. Find the `hl-row-list` block. Add a new `report-row` include as the **first line** inside the block:

```liquid
{% include report-row.html title="Your Report Title — IOC Feed" date="Mar 2026" severity="high" tags="IP,Hash,Domain" url="/ioc-feeds/your-report-slug-iocs.json" %}
```

**Tags for IOC feeds** show which indicator types are in the feed — use only the ones actually present:
- `IP` — IP addresses
- `Hash` — file hashes
- `Domain` — domain names

---

## Summary Checklist

For every new report:

- [ ] Commit the report files (`reports/`, `hunting-detections/`, `ioc-feeds/`)
- [ ] Add `report-card` to the top of the featured grid in `reports/index.md`
- [ ] If the grid now has more than 6 cards, move the oldest card to the row list as a `report-row`
- [ ] Update the 2-card preview in `index.md` to show your latest 2 reports
- [ ] If detections exist: add `report-row` to the top of `hunting-detections/index.md`
- [ ] If IOC feed exists: add `report-row` to the top of `ioc-feeds/index.md`
- [ ] Commit and push

---

## Adding a New Tag Type

If you create a report that uses a tag not in the current list (e.g., a new malware category), add it to `_includes/tag-badge.html`. Find the relevant color group and add your new tag to the condition:

```liquid
{% elsif tl == "c2" or tl == "rat" or tl == "your-new-tag" %}
  <span class="hl-tag hl-tag--blue">{{ t }}</span>
```

Tag matching is case-insensitive, so `MaaS` and `maas` both work.
