import datetime as dt, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "feedbuilder"))
import enrich

DOC = {"vulnerabilities": [
    {"cveID": "CVE-1", "vendorProject": "Adobe", "product": "Commerce (Magento)", "dateAdded": "2026-10-27"},
    {"cveID": "CVE-2", "vendorProject": "Microsoft", "product": "Windows", "dateAdded": "2026-10-27"},
    {"cveID": "CVE-3", "vendorProject": "WordPress", "product": "WordPress", "dateAdded": "2026-10-01"},
    {"cveID": "CVE-4", "vendorProject": "PHP", "product": "PHP", "dateAdded": "2019-01-01"},
]}
T = dt.date(2026, 11, 13)

def test_flags_php_related_missing():
    assert [g[0] for g in enrich.kev_gaps(DOC, {"CVE-3"}, days=365, today=T)] == ["CVE-1"]

def test_window_and_all():
    assert [g[0] for g in enrich.kev_gaps(DOC, set(), today=T)] == ["CVE-1", "CVE-3", "CVE-4"]

def test_base_has_the_three_magento_kev():
    b = json.loads((Path(__file__).resolve().parent.parent / "feedbuilder/base/php-cve-feed.base.json").read_text())
    ids = {a["cve"] for a in b["composer_advisories"] if a["package"] == "magento/community-edition"}
    assert {"CVE-2026-48356", "CVE-2026-71362", "CVE-2026-75650"} <= ids


def test_kev_status_scope_and_sla():
    now = dt.datetime(2026, 11, 13, 12, 0, tzinfo=dt.timezone.utc)
    doc = {"catalogVersion": "2026.11.13", "vulnerabilities": DOC["vulnerabilities"] + [
        {"cveID": "CVE-5", "vendorProject": "Laravel", "product": "Framework", "dateAdded": "2026-11-13"},
        {"cveID": "CVE-6", "vendorProject": "Joomla!", "product": "Joomla!", "dateAdded": "2026-11-01"}]}
    st = enrich.kev_status(doc, {"CVE-3", "CVE-4", "CVE-1"}, {"CVE-6": "Joomla core"}, now=now)
    assert [g["cve"] for g in st["gaps"]] == ["CVE-5"] and st["gaps"][0]["hours_since_listing"] == 12
    assert st["sla_met"] is True                       # 12h old: still inside the 24h window
    assert st["out_of_scope"] == [{"cve": "CVE-6", "reason": "Joomla core"}]
    assert st["kev_php_related"] == 5 and st["kev_php_related_in_feed"] == 3 and st["sla_hours"] == 24
    late = enrich.kev_status(doc, {"CVE-3", "CVE-4"}, {"CVE-6": "x"}, now=now)   # CVE-1 listed 17 days ago
    assert late["sla_met"] is False and {g["cve"] for g in late["gaps"]} == {"CVE-1", "CVE-5"}
    clean = enrich.kev_status(doc, {"CVE-1", "CVE-3", "CVE-4", "CVE-5"}, {"CVE-6": "x"}, now=now)
    assert clean["gaps"] == [] and clean["sla_met"] is True


def test_out_of_scope_file_is_valid():
    f = Path(__file__).resolve().parent.parent / "feedbuilder/kev-out-of-scope.json"
    oos = json.loads(f.read_text())["out_of_scope"]
    assert all(k.startswith("CVE-") and len(v) > 10 for k, v in oos.items()) and "CVE-2026-41940" in oos


if __name__ == "__main__":
    for _n, _f in list(globals().items()):
        if _n.startswith("test_"):
            _f(); print("PASS", _n)
    print("\nRESULT: ALL PASS")
