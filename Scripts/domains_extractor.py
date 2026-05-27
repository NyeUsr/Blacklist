import re
from pathlib import Path

repo_root = Path(__file__).resolve().parent.parent
input_path = repo_root / "Main"
output_path = repo_root / "Domains"

# Extract plain blocking domains from rules like: ||example.com^
domain_pattern = re.compile(r"^\|\|([^\$@\^/]+)\^")


with input_path.open("r", encoding="utf-8") as input_file, output_path.open(
    "w", encoding="utf-8"
) as output_file:
    for line in input_file:
        domain_match = domain_pattern.search(line.strip())
        if domain_match:
            output_file.write(domain_match.group(1) + "\n")
