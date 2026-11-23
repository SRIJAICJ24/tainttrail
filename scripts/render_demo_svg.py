"""Render `tainttrail demo` as a terminal-window SVG for the README.

    python scripts/render_demo_svg.py [docs/demo.svg]

The demo is deterministic, so the picture is reproducible: rerun this after
changing the demo's wording. Stdlib only; runs the demo in a temporary home.
"""

from __future__ import annotations

import html
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

BG, FG, DIM = "#0d1117", "#c9d1d9", "#8b949e"
COLORS = [  # (substring, colour) - first match wins for the whole line
    ("STOPPED", "#ff7b72"), ("QUARANTINED", "#d2a8ff"), ("taint re-attached", "#d2a8ff"),
    ("SESSION", "#79c0ff"), ("hides an instruction", "#e3b341"), ("<!--", "#e3b341"),
    ("hash chain intact", "#3fb950"), ("because:", "#ff7b72"),
]
CHAR_W, LINE_H, PAD_X, TOP = 8.4, 20, 20, 52


def render(lines: list[str]) -> str:
    width = int(max(len(l) for l in lines) * CHAR_W + PAD_X * 2)
    height = TOP + LINE_H * (len(lines) - 1) + 22
    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" aria-label="tainttrail demo output">',
        f'<rect width="{width}" height="{height}" rx="10" fill="{BG}"/>',
        '<circle cx="22" cy="20" r="6" fill="#ff5f56"/><circle cx="42" cy="20" r="6" '
        'fill="#ffbd2e"/><circle cx="62" cy="20" r="6" fill="#27c93f"/>',
        f'<text x="{width / 2:.0f}" y="25" fill="{DIM}" font-family="ui-monospace,SFMono-Regular,'
        f'Menlo,Consolas,monospace" font-size="13" text-anchor="middle">$ tainttrail demo</text>',
        f'<g font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,monospace" font-size="14" '
        f'xml:space="preserve" style="white-space:pre">',
    ]
    for i, line in enumerate(lines):
        colour = next((c for key, c in COLORS if key in line), FG if line.strip() else DIM)
        weight = ' font-weight="bold"' if colour in ("#ff7b72", "#79c0ff") else ""
        indent = len(line) - len(line.lstrip(" "))       # renderers collapse leading spaces
        out.append(f'<text x="{PAD_X + indent * CHAR_W:.1f}" y="{TOP + i * LINE_H}" '
                   f'fill="{colour}"{weight}>{html.escape(line.lstrip(" "))}</text>')
    out.append("</g></svg>")
    return "\n".join(out) + "\n"


def main() -> int:
    from tainttrail import demo

    target = Path(sys.argv[1]) if len(sys.argv) > 1 else \
        Path(__file__).resolve().parent.parent / "docs" / "demo.svg"
    result = demo.run(say=lambda _l: None)
    if not result.ok:
        print("the demo did not stop the attack - not rendering", file=sys.stderr)
        return 1
    target.write_text(render(result.lines), encoding="utf-8")
    print(f"wrote {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
