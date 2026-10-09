"""SMP's app icon as SVG: the same geometry as Packages/SMPKit/Sources/SMPUI/AppIconArtwork.swift,
which draws the icons in the app. Change both together. Canvas 1024x1024.

Keys are built from primitives in a horizontal layout around the center (bow left), then
translated, scaled and rotated 45 degrees about (512, 512). Holes are cut out of the union.

Usage: python3 icons.py OUT_DIR   (writes OUT_DIR/<shape>-<style>.svg for every combination)

The bundle's icon (App/Resources/Assets.xcassets/AppIcon.appiconset) is modern-graphite.svg,
rendered at 1024 x 1024 with a transparent background (for example in a browser) and scaled to
16, 32, 64, 128, 256 and 512 pixels.
"""
import sys

TILE = (100, 100, 824, 824, 185)

# Shapes: list of ("rrect", x, y, w, h, r) | ("circle", cx, cy, r) | ("poly", [(x, y), ...]);
# holes use the same primitives; "marks" are drawn on top with a dark tint (button, contacts).
SHAPES = {
    "modern": dict(offset=(-5, 0), scale=0.9, solid=[
        ("rrect", 200, 322, 270, 380, 70),
        ("poly", [(460, 452), (790, 452), (834, 512), (790, 572), (760, 572), (734, 542), (708, 572),
                  (682, 542), (656, 572), (630, 542), (604, 572), (460, 572)]),
    ], holes=[("circle", 300, 512, 38)], marks=[]),
    "classic": dict(offset=(14, -10), solid=[
        ("circle", 300, 512, 140),
        ("rrect", 420, 470, 402, 84, 22),
        ("rrect", 734, 520, 56, 134, 14),
        ("rrect", 660, 520, 56, 116, 14),
        ("rrect", 700, 520, 50, 80, 0),
    ], holes=[("circle", 300, 512, 50)], marks=[]),
    "symbol": dict(offset=(19, -14), solid=[
        ("circle", 330, 512, 160),
        ("rrect", 450, 466, 366, 92, 46),
        ("rrect", 714, 520, 46, 152, 22),
        ("rrect", 596, 520, 46, 120, 22),
    ], holes=[("circle", 330, 512, 56)], marks=[]),
    "securityKey": dict(offset=(-18, 0), solid=[
        ("rrect", 230, 420, 470, 184, 64),
        ("rrect", 680, 452, 150, 120, 12),
    ], holes=[("circle", 292, 512, 30), ("rrect", 744, 478, 34, 24, 4), ("rrect", 744, 522, 34, 24, 4)],
       marks=[("circle", 530, 512, 58)]),
}

FLAGS = {
    "rainbow": [("#E40303", 1), ("#FF8C00", 1), ("#FFED00", 1), ("#008026", 1), ("#004DFF", 1), ("#750787", 1)],
    "progress": [("#E40303", 1), ("#FF8C00", 1), ("#FFED00", 1), ("#008026", 1), ("#004DFF", 1), ("#750787", 1)],
    "transgender": [("#5BCEFA", 1), ("#F5A9B8", 1), ("#FFFFFF", 1), ("#F5A9B8", 1), ("#5BCEFA", 1)],
    "nonbinary": [("#FCF434", 1), ("#FFFFFF", 1), ("#9C59D1", 1), ("#2C2C2C", 1)],
    "bisexual": [("#D60270", 2), ("#9B4F96", 1), ("#0038A8", 2)],
    "pansexual": [("#FF218C", 1), ("#FFD800", 1), ("#21B1FF", 1)],
    "lesbian": [("#D52D00", 1), ("#EF7627", 1), ("#FF9A56", 1), ("#FFFFFF", 1), ("#D162A4", 1), ("#B55690", 1), ("#A30262", 1)],
    "asexual": [("#000000", 1), ("#A3A3A3", 1), ("#FFFFFF", 1), ("#800080", 1)],
    "aromantic": [("#3DA542", 1), ("#A7D379", 1), ("#FFFFFF", 1), ("#A9A9A9", 1), ("#000000", 1)],
}
PROGRESS_CHEVRON = ["#000000", "#784F17", "#5BCEFA", "#F5A9B8", "#FFFFFF"]  # outermost first
GRADIENTS = {"graphite": ("#5b616b", "#24282e"), "blue": ("#4f9bff", "#0b4fd0"), "silver": ("#fbfbfd", "#c7ccd4")}
GOLD = ("#ffe9a8", "#e6b43a", "#b8840f")
WHITE = ("#ffffff", "#eef2f8", "#c8d1de")


def prim(p):
    if p[0] == "rrect":
        _, x, y, w, h, r = p
        return f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{r}"/>'
    if p[0] == "circle":
        _, cx, cy, r = p
        return f'<circle cx="{cx}" cy="{cy}" r="{r}"/>'
    return '<polygon points="' + " ".join(f"{x},{y}" for x, y in p[1]) + '"/>'


def svg(shape, style):
    s = SHAPES[shape]
    dx, dy = s["offset"]
    scale = s.get("scale", 1)
    transform = f"rotate(45 512 512) translate({dx} {dy}) translate(512 512) scale({scale}) translate(-512 -512)"
    x, y, w, h, r = TILE
    if style in GRADIENTS:
        a, b = GRADIENTS[style]
        bg = f'<rect x="{x}" y="{y}" width="{w}" height="{h}" fill="url(#bg)"/>'
        bgdef = f'<linearGradient id="bg" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="{a}"/><stop offset="1" stop-color="{b}"/></linearGradient>'
    else:
        stripes = FLAGS[style]
        total = sum(weight for _, weight in stripes)
        top, parts = y, []
        for color, weight in stripes:
            height = h * weight / total
            parts.append(f'<rect x="{x}" y="{top:.2f}" width="{w}" height="{height + 0.5:.2f}" fill="{color}"/>')
            top += height
        if style == "progress":
            for i, color in enumerate(PROGRESS_CHEVRON):
                tip = x + w * (0.46 - 0.075 * i)
                left = x + w * (0.0 - 0.075 * i) - 1
                parts.append(f'<polygon points="{left},{y} {tip},{y + h / 2} {left},{y + h}" fill="{color}"/>')
        bg, bgdef = "".join(parts), ""
    on_flag = style not in GRADIENTS
    k0, k1, k2 = WHITE if (style == "blue" or on_flag) else GOLD
    solid = "".join(prim(p) for p in s["solid"])
    holes = "".join(prim(p) for p in s["holes"])
    marks = "".join(prim(p) for p in s["marks"])
    outline = (f'<g transform="{transform}" mask="url(#holes)" fill="none" stroke="#000" stroke-opacity="0.35" '
               f'stroke-width="20">{solid}</g>') if on_flag else ""
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="1024" height="1024" viewBox="0 0 1024 1024">
<defs>{bgdef}
<linearGradient id="gloss" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#fff" stop-opacity="0.20"/><stop offset="0.5" stop-color="#fff" stop-opacity="0"/></linearGradient>
<linearGradient id="key" gradientUnits="userSpaceOnUse" x1="230" y1="230" x2="800" y2="800"><stop offset="0" stop-color="{k0}"/><stop offset="0.5" stop-color="{k1}"/><stop offset="1" stop-color="{k2}"/></linearGradient>
<clipPath id="tile"><rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{r}"/></clipPath>
<mask id="holes" maskUnits="userSpaceOnUse" x="0" y="0" width="1024" height="1024"><rect width="1024" height="1024" fill="#fff"/><g transform="{transform}" fill="#000">{holes}</g></mask>
<filter id="tileShadow" x="-20%" y="-20%" width="140%" height="140%"><feDropShadow dx="0" dy="10" stdDeviation="12" flood-color="#000" flood-opacity="0.30"/></filter>
<filter id="keyShadow" x="-20%" y="-20%" width="140%" height="140%"><feDropShadow dx="0" dy="16" stdDeviation="16" flood-color="#000" flood-opacity="{0.55 if on_flag else 0.40}"/></filter>
</defs>
<g filter="url(#tileShadow)"><g clip-path="url(#tile)">{bg}<rect x="{x}" y="{y}" width="{w}" height="{h}" fill="url(#gloss)"/></g>
<rect x="{x + 1}" y="{y + 1}" width="{w - 2}" height="{h - 2}" rx="{r - 1}" fill="none" stroke="#fff" stroke-opacity="0.16" stroke-width="2"/></g>
<g filter="url(#keyShadow)">{outline}<g mask="url(#holes)"><g transform="{transform}" fill="url(#key)">{solid}</g>
<g transform="{transform}" fill="#000" fill-opacity="0.22">{marks}</g></g></g>
</svg>"""


if __name__ == "__main__":
    out = sys.argv[1]
    for shape in SHAPES:
        for style in list(GRADIENTS) + list(FLAGS):
            open(f"{out}/{shape}-{style}.svg", "w").write(svg(shape, style))
