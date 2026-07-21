import ipaddress
import json
import re
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import urlopen


SOURCE = "https://lolrmm.io/api/rmm_tools.json"
OUTPUT = Path(__file__).resolve().parent.parent / "Remote Access"
VERSION_RE = re.compile(r"^! Version: (\d+)$", re.MULTILINE)
HOST_RE = re.compile(r"^[a-z0-9*_](?:[a-z0-9.*_-]*[a-z0-9*_])?$")
REGEX_WILDCARD_RE = re.compile(r"\[[^]]+\](?:\{\d+(?:,\d*)?\}|[+?*])?")


def normalize(value):
    value = value.strip().lower().rstrip(".")
    if not value or value == "user_managed" or value.startswith("<"):
        return None

    try:
        if "://" in value:
            value = urlsplit(value).hostname or ""
        else:
            value = re.sub(r":\d+$", "", value)
    except ValueError:
        return None

    value = REGEX_WILDCARD_RE.sub("*", value)
    if value.startswith("*."):
        value = value[2:]
    if value.startswith("www."):
        value = value[4:]

    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass

    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None

    labels = value.split(".")
    if len(value) > 253 or len(labels) < 2 or any(
        len(label) > 63 or not HOST_RE.fullmatch(label) for label in labels
    ):
        return None
    return value


def covered(domain, exact):
    labels = domain.split(".")
    return any(".".join(labels[i:]) in exact for i in range(len(labels) - 1))


def minimize(domains):
    exact = set()
    patterns = set()
    for domain in domains:
        (patterns if "*" in domain else exact).add(domain)

    kept = set()
    for domain in sorted(exact, key=lambda item: (item.count("."), item)):
        if not covered(domain, kept):
            kept.add(domain)

    kept.update(pattern for pattern in patterns if not covered(pattern, kept))
    return sorted(kept)


def extract(data):
    values = []
    for tool in data:
        values.append(tool.get("Details", {}).get("Website", ""))
        for artifact in tool.get("Artifacts", {}).get("Network", []):
            values.extend(artifact.get("Domains", []))
    normalized = [domain for value in values if (domain := normalize(value))]
    return minimize(normalized), len(values) - len(normalized)


def version():
    if not OUTPUT.exists():
        return 1
    match = VERSION_RE.search(OUTPUT.read_text(encoding="utf-8"))
    if not match:
        raise ValueError(f"missing numeric version in {OUTPUT}")
    return int(match.group(1)) + 1


def render(domains, current_version):
    header = f"""[Adblock Plus]
! Title: NyeUsr's Remote Access Blacklist
! Description: Blocks websites and network domains associated with remote access tools tracked by LOLRMM.
! Homepage: https://github.com/NyeUsr/Blacklist/
! Expires: 8 hours
! Version: {current_version}
! Source: {SOURCE}

"""
    return header + "".join(f"||{domain}^\n" for domain in domains)


def self_check():
    values = [normalize(value) for value in ["sub.example.com", "example.com", "*.other.test"]]
    assert minimize(values) == [
        "example.com",
        "other.test",
    ]
    assert normalize("https://WWW.Example.com/path") == "example.com"
    assert normalize("relay-[a-f0-9]{8}.net.example.com:443") == "relay-*.net.example.com"
    assert normalize(f"{'a' * 64}.example.com") is None
    assert VERSION_RE.sub("", render(["example.com"], 1)) == VERSION_RE.sub(
        "", render(["example.com"], 2)
    )
    assert VERSION_RE.sub("", render(["example.com"], 1)) != VERSION_RE.sub(
        "", render(["changed.example"], 2)
    )


def main():
    self_check()
    with urlopen(SOURCE, timeout=30) as response:
        data = json.load(response)
    if not isinstance(data, list):
        raise ValueError("LOLRMM response is not a list")

    domains, skipped = extract(data)
    if not domains:
        raise ValueError("LOLRMM response contained no usable domains")

    next_version = version()
    content = render(domains, next_version)
    if OUTPUT.exists() and VERSION_RE.sub(
        "", OUTPUT.read_text(encoding="utf-8")
    ) == VERSION_RE.sub("", content):
        print(f"no changes ({len(domains)} rules, version unchanged)")
        return

    temporary = OUTPUT.with_suffix(".tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.replace(OUTPUT)
    print(f"wrote {len(domains)} rules to {OUTPUT.name} (version {next_version}, {skipped} invalid values skipped)")


if __name__ == "__main__":
    main()
