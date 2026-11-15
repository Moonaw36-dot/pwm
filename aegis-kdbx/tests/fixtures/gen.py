#!/usr/bin/env python3
"""Generate tests/fixtures/pykeepass.kdbx with an external KeePass implementation.

    pip install pykeepass   # tested with pykeepass 4.2.0
    python3 -I gen.py [output-path]

The database is KDBX4 (pykeepass' blank template) with the password
"fixture-password". The KDF is set to a single cheap Argon2 pass so the
import test stays fast. The test in tests/external_fixture.rs checks the
values written here, so keep the two in sync.
"""

import sys
from datetime import datetime, timezone

from pykeepass import create_database

OUT = sys.argv[1] if len(sys.argv) > 1 else "pykeepass.kdbx"

kp = create_database(OUT, password="fixture-password")

# Cheap KDF: 1 iteration, 1 MiB, 1 lane (keeps `cargo test` fast).
kdf = kp.kdbx.header.value.dynamic_header.kdf_parameters.data.dict
kdf["I"].value = 1
kdf["M"].value = 1024 * 1024
kdf["P"].value = 1

work = kp.add_group(kp.root_group, "Work")
servers = kp.add_group(work, "Servers")

e = kp.add_entry(
    servers,
    title="Build server",
    username="deploy",
    password="s3cr3t-Pa55",
    url="https://ci.example.com",
    notes="Line one\nLine two",
    tags=["infra", "ci"],
)
e.otp = (
    "otpauth://totp/Example:deploy?secret=JBSWY3DPEHPK3PXP"
    "&period=30&digits=6&issuer=Example"
)
e.set_custom_property("PIN", "4321", protect=True)
e.set_custom_property("Region", "eu-west-3")
e.ctime = datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
binary_id = kp.add_binary(b"attachment payload")
e.add_attachment(binary_id, "readme.txt")

kp.add_entry(kp.root_group, title="Root entry", username="root", password="toor")

old = kp.add_entry(kp.root_group, title="Old account", username="old", password="gone")
kp.trash_entry(old)

kp.save()
print(f"wrote {OUT}")
