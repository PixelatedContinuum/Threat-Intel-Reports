---
title: "MISP Feed Changelog"
layout: page
permalink: /feeds/misp/changelog/
description: "Every event withdrawn from The Hunters Ledger MISP feed, with the reason, so a subscriber who matched on it can find out what it was."
---

Changes to the MISP feed at [`/feeds/misp/`](/feeds/misp/).

Events are added as campaigns publish and updated in place when a report, a detection page or
a STIX bundle changes; those additions and updates are not itemised here, because each event's
`timestamp` already tells a subscriber it moved. **What is itemised is every event withdrawn
after publication, with the reason.** An event leaving the feed silently is indistinguishable,
from a subscriber's side, from an event that was never there. If you ever matched on an
attribute from a UUID listed below, this page is how you find out what it was.

A withdrawn UUID is **never reissued**: event and attribute UUIDs are derived from the campaign
and the attribute's own type and value, so a different campaign can never land on a UUID an old
match in your archive still points at.

The feed's generator refuses to publish a withdrawal that is not itemised here. If an event is
missing from the feed and absent from this page, that is a defect, and the place to say so is
the site's repository.

---

*No event has been withdrawn since the feed went live on 2026-10-09.*
