#!/usr/bin/env python3
"""Print the production endpoints and pins from web/src as key=value lines.

pir2_url, pir2_binary, pir2_transition, and for the Direct ORAM host
oram_url, oram_measurement, oram_binary, oram_ark. A missing value prints
as "-" (all oram_* are "-" while ORAM_PROVIDER is null).
"""
import re
from pathlib import Path

web = Path(__file__).resolve().parent.parent / "web" / "src"
providers = (web / "production-providers.ts").read_text(encoding="utf-8")
pins = (web / "attest-pin.ts").read_text(encoding="utf-8")


def const(text, name):
    m = re.search(rf"export const {name}\b[^=]*=\s*(null;|\{{.*?\n\}};)", text, re.S)
    return m.group(1) if m and m.group(1) != "null;" else ""


def field(block, name):
    m = re.search(rf"\b{name}:\s*'([^']+)'", block)
    return m.group(1).lower() if m else "-"


def ident(block, name):
    m = re.search(rf"\b{name}:\s*([A-Z0-9_]+)", block)
    return m.group(1) if m else ""


pir2 = const(providers, "PIR2_PROVIDER")
pir2_pin = const(pins, "PIR2_MACBOOK_PIN")
values = {
    "pir2_url": field(pir2, "endpoint"),
    "pir2_binary": field(pir2_pin, "binarySha256Hex"),
    "pir2_transition": field(pir2_pin, "transitionBinarySha256Hex"),
}

oram = const(providers, "ORAM_PROVIDER")
oram_pin = const(pins, ident(oram, "serverPin")) if oram else ""
ark = re.search(
    rf"export const {ident(oram, 'expectedArkFingerprint')}_HEX\s*=\s*'([0-9a-fA-F]{{64}})'", pins
) if oram else None
values.update({
    "oram_url": field(oram, "endpoint"),
    "oram_measurement": field(oram_pin, "measurementHex"),
    "oram_binary": field(oram_pin, "binarySha256Hex"),
    "oram_ark": ark.group(1).lower() if ark else "-",
})

for key, value in values.items():
    print(f"{key}={value}")
