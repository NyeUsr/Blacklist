import re

# Define regex pattern to extract domains from line
domain_pattern = re.compile(r"\|\|([^\$@\^/]+)\^")

# Patterns to discard lines
unwanted_patterns = {'@@', '\$', '^/', '/$', '[\$\@]', '\*'}

with open("input.txt", "r") as input_file, open("Domains", "w") as output_file:
    # Extract domains from input file using regex pattern
    for line in input_file:
        # Check if line contains any unwanted patterns
        if any(re.search(pattern, line) for pattern in unwanted_patterns):
            continue

        # Extract domain from line using regex pattern
        domain_match = domain_pattern.search(line)
        if domain_match:
            domain = domain_match.group(1)
            output_file.write(domain + "\n")
