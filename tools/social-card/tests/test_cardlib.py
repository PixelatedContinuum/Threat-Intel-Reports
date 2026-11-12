import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import cardlib as c

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))  # was a Windows path (T-0563)

# ---- pure helpers ----
def test_format_card_date():
    assert c.format_card_date("2026-05-06") == "May 6, 2026"
    import datetime
    assert c.format_card_date(datetime.date(2025, 12, 1)) == "Dec 1, 2025"

def test_severity_label():
    assert c.severity_label("critical") == "CRITICAL"
    assert c.severity_label("med") == "MEDIUM"
    assert c.severity_label("high") == "HIGH"
    assert c.severity_label("low") == "LOW"
    assert c.severity_label("bogus") == "HIGH"

def test_derive_kicker():
    assert c.derive_kicker("MaaS Operation", ["x"]) == "MAAS OPERATION"
    assert c.derive_kicker(None, ["PhaaS", "Phishing"]) == "PHAAS"
    assert c.derive_kicker(None, []) == "THREAT INTELLIGENCE"

# ---- parsing + card_fields (against real reports) ----
def test_load_front_matter():
    fm = c.load_front_matter(os.path.join(REPO, "reports/PULSAR-RAT/index.md"))
    assert fm["title"].startswith("PULSAR RAT")
    assert fm["permalink"] == "/reports/PULSAR-RAT/"

def test_severity_for_slug():
    assert c.severity_for_slug(REPO, "PULSAR-RAT") == "CRITICAL"
    assert c.severity_for_slug(REPO, "opendirectory-62-60-237-100-20260506") == "HIGH"

# ---- severity for a slug the catalog has no live entry for (preview) ----
def _fake_repo(root, slug, extra_fm="", catalog=""):
    """A repo with one report and a catalog entry for some other slug."""
    os.makedirs(os.path.join(root, "_data"))
    os.makedirs(os.path.join(root, "reports", slug))
    with open(os.path.join(root, "_data", "catalog.yml"), "w", encoding="utf-8") as fh:
        fh.write('entries:\n  - title: "Other"\n    severity: high\n'
                 '    report_url: /reports/other/\n' + catalog)
    with open(os.path.join(root, "reports", slug, "index.md"), "w", encoding="utf-8") as fh:
        fh.write('---\ntitle: "Test"\ndate: 2026-05-06\n'
                 f'permalink: /reports/{slug}/\ndescription: "d"\n{extra_fm}---\nBody\n')

def test_severity_uncatalogued_parked_entry():
    """Branch 1: a preview parks its catalog entry as a commented block; the card reads it."""
    import tempfile, shutil
    root = tempfile.mkdtemp()
    try:
        slug = "preview-parked"
        _fake_repo(root, slug, catalog=(
            "  # ===== PENDING GO-LIVE - test (uncomment at launch) =====\n"
            '  #  - title: "Test"\n'
            "  #    date: 2026-05-06\n"
            "  #    severity: low\n"
            "  #    report_url: /reports/preview-parked/\n"
            "  # ========================================================\n"))
        assert c.severity_for_slug(root, slug) == "LOW"
        assert c.card_fields(root, slug)["severity_source"] == "catalog-parked"
    finally:
        shutil.rmtree(root)

def test_severity_uncatalogued_parked_entry_without_dash():
    """A hand-written parked block with no list dash is still the entry, not a fallback."""
    import tempfile, shutil
    root = tempfile.mkdtemp()
    try:
        slug = "preview-flat"
        _fake_repo(root, slug, catalog=(
            "  # ===== PENDING GO-LIVE - flat entry =====\n"
            '  #  title: "Test"\n'
            "  #  severity: critical\n"
            "  #  report_url: /reports/preview-flat/\n"
            "  # =======================================\n"))
        assert c.severity_for_slug(root, slug) == "CRITICAL"
    finally:
        shutil.rmtree(root)

def test_severity_uncatalogued_front_matter():
    """Branch 2: no live or parked entry, but the report declares a severity itself."""
    import tempfile, shutil
    root = tempfile.mkdtemp()
    try:
        slug = "preview-declared"
        _fake_repo(root, slug, extra_fm="severity: med\n")
        assert c.severity_for_slug(root, slug) == "MEDIUM"
        assert c.card_fields(root, slug)["severity_source"] == "front-matter"
    finally:
        shutil.rmtree(root)

def test_severity_uncatalogued_fallback_warns():
    """Branch 3: nothing declares a severity, so the fallback is drawn and the CLI says so."""
    import tempfile, shutil, io, contextlib
    import generate_card
    root = tempfile.mkdtemp()
    try:
        slug = "preview-bare"
        _fake_repo(root, slug)
        f = c.card_fields(root, slug)
        assert f["severity"] == "HIGH"
        assert f["severity_source"] == "fallback"
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            warned = generate_card.warn_if_fallback(slug, f)
        assert warned is True
        assert slug in err.getvalue() and "fallback" in err.getvalue()
        # control: a catalogued report's own severity draws no warning
        err2 = io.StringIO()
        with contextlib.redirect_stderr(err2):
            generate_card.warn_if_fallback("PULSAR-RAT", c.card_fields(REPO, "PULSAR-RAT"))
        assert err2.getvalue() == ""
    finally:
        shutil.rmtree(root)


def test_card_fields():
    f = c.card_fields(REPO, "PULSAR-RAT")
    assert f["severity"] == "CRITICAL"
    assert f["date"] == "Dec 1, 2025"
    assert "ioc" not in f
    assert "PULSAR RAT" in f["title"]
    assert f["kicker"] == "REMOTE ACCESS TROJAN"
    assert f["slug"] == "PULSAR-RAT"

# ---- rendering ----
def test_render_card():
    f = c.card_fields(REPO, "PULSAR-RAT")
    p = os.path.join(REPO, "tools/social-card/tests/_out.png")
    c.render_card(f, p)
    from PIL import Image
    with Image.open(p) as im:            # context-manage so Windows releases the handle
        assert im.size == (1200, 630)
        assert im.format == "PNG"
    os.remove(p)

def test_render_hub_card():
    p = os.path.join(REPO, "tools/social-card/tests/_hub_out.png")
    c.render_hub_card({"pill": "STIX 2.1", "kicker": "THREAT INTELLIGENCE",
                       "title": "STIX Bundles",
                       "subtitle": "Per-campaign STIX 2.1 bundles for import.",
                       "footer_left": "CC BY 4.0"}, p)
    from PIL import Image
    with Image.open(p) as im:            # context-manage so Windows releases the handle
        assert im.size == (1200, 630)
        assert im.format == "PNG"
    os.remove(p)

# ---- thumbnail front matter ----
def test_ensure_thumbnail_line():
    sample = "---\ntitle: \"X\"\npermalink: /reports/foo/\nhide: true\n---\nBody\n"
    out, changed = c.ensure_thumbnail_line(sample, "foo")
    assert changed is True
    assert "thumbnail: /assets/images/cards/foo.png\n" in out
    assert out.index("thumbnail:") > out.index("permalink:")
    out2, changed2 = c.ensure_thumbnail_line(out, "foo")  # idempotent
    assert changed2 is False and out2 == out

if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    fails = 0
    for fn in fns:
        try:
            fn(); print("PASS", fn.__name__)
        except AssertionError as e:
            fails += 1; print("FAIL", fn.__name__, repr(e))
        except Exception as e:
            fails += 1; print("ERROR", fn.__name__, repr(e))
    print("ALL PASS" if not fails else f"{fails} FAILED")
    sys.exit(1 if fails else 0)
