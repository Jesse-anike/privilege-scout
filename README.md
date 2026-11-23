# PRIVILEGE SCOUT — SUID/SGID Inventory

A defensive, read-only Linux filesystem auditor that inventories regular files with the SUID or SGID permission bits set. It produces JSON findings so an administrator can review privileged executables.

## What it checks
- SUID (set-user-ID) files.
- SGID (set-group-ID) files.
- File mode and relative path within the scan root.
- Filesystem entries that could not be inspected, reported separately.

## Requirements
- Python 3.10+
- Python standard library only.

## Run
```bash
python main.py /usr/bin
```

Save a machine-readable report:
```bash
python main.py /usr/bin --output privilege-report.json
```

Use a controlled test directory:
```bash
mkdir -p lab
touch lab/example
chmod 4755 lab/example
python main.py lab
```

## Tests
```bash
python -m unittest discover -s tests -v
python main.py --help
```

## Security notes
This tool only reads file metadata. It does not execute discovered files, alter permissions, or attempt privilege escalation. Scan only systems and directories you own or are authorized to assess. A SUID/SGID bit is not automatically a vulnerability; review the executable, ownership, package provenance, and operational purpose before making changes.

## Portfolio context
Built for Anike-Moses Melie Jesse's defensive cybersecurity portfolio, demonstrating Linux permission auditing, filesystem traversal, Python automation, structured reporting, and safe security review.
