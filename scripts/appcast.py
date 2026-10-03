#!/usr/bin/env python3
"""Adds a release to SMP's Sparkle appcast.

The appcast lives as `appcast.xml` on the GitHub releases; the app reads
https://github.com/kirikakaese/SMP/releases/latest/download/appcast.xml. Each release carries the
previous entries plus its own, so the newest stable release always has the full history.

Usage:
  appcast.py --previous old.xml --output appcast.xml --version 0.9.0 --build 123 \
      --url https://.../SMP-0.9.0.zip --signature-line 'sparkle:edSignature="…" length="…"' \
      --notes-url https://github.com/kirikakaese/SMP/releases/tag/v0.9.0 [--beta]
"""
import argparse
import email.utils
import pathlib
import re
import sys
import xml.etree.ElementTree as ET

SPARKLE = "http://www.andymatuschak.org/xml-namespaces/sparkle"
ET.register_namespace("sparkle", SPARKLE)
MAX_ITEMS = 20


def tag(name):
    return f"{{{SPARKLE}}}{name}"


def load(previous):
    path = pathlib.Path(previous) if previous else None
    if path and path.exists() and path.stat().st_size > 0:
        try:
            return ET.parse(path)
        except ET.ParseError:
            print("warning: previous appcast is not valid XML; starting a new one", file=sys.stderr)
    rss = ET.Element("rss", {"version": "2.0"})
    channel = ET.SubElement(rss, "channel")
    ET.SubElement(channel, "title").text = "SSH Management Platform"
    ET.SubElement(channel, "link").text = "https://github.com/kirikakaese/SMP"
    ET.SubElement(channel, "language").text = "en"
    return ET.ElementTree(rss)


def parse_signature(line):
    signature = re.search(r'sparkle:edSignature="([^"]+)"', line)
    length = re.search(r'length="(\d+)"', line)
    if not signature or not length:
        sys.exit("error: sign_update output did not contain an EdDSA signature and length")
    return signature.group(1), length.group(1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--previous")
    parser.add_argument("--output", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--build", required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--signature-line", required=True)
    parser.add_argument("--notes-url", required=True)
    parser.add_argument("--minimum-system", default="14.0")
    parser.add_argument("--beta", action="store_true")
    args = parser.parse_args()

    if not re.fullmatch(r"\d+", args.build):
        sys.exit("error: the build number must be an integer")
    signature, length = parse_signature(args.signature_line)

    tree = load(args.previous)
    channel = tree.getroot().find("channel")
    # Replace an entry for the same build (re-running a release), keep everything else.
    for item in channel.findall("item"):
        if item.findtext(tag("version")) == args.build:
            channel.remove(item)

    item = ET.Element("item")
    ET.SubElement(item, "title").text = f"Version {args.version}"
    ET.SubElement(item, "pubDate").text = email.utils.formatdate(usegmt=True)
    ET.SubElement(item, tag("version")).text = args.build
    ET.SubElement(item, tag("shortVersionString")).text = args.version
    ET.SubElement(item, tag("minimumSystemVersion")).text = args.minimum_system
    ET.SubElement(item, tag("releaseNotesLink")).text = args.notes_url
    if args.beta:
        ET.SubElement(item, tag("channel")).text = "beta"
    ET.SubElement(item, "enclosure", {
        "url": args.url,
        "type": "application/octet-stream",
        tag("edSignature"): signature,
        "length": length,
    })

    items = channel.findall("item")
    for old in items:
        channel.remove(old)
    ordered = [item] + items
    ordered.sort(key=lambda entry: int(entry.findtext(tag("version")) or 0), reverse=True)
    for entry in ordered[:MAX_ITEMS]:
        channel.append(entry)

    ET.indent(tree, space="  ")
    tree.write(args.output, encoding="utf-8", xml_declaration=True)
    print(f"appcast: {len(ordered[:MAX_ITEMS])} entries, newest {args.version} ({args.build})")


if __name__ == "__main__":
    main()
