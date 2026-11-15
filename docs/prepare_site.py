"""Use the generated API overview as the published documentation home page."""

from pathlib import Path

site = Path(__file__).parent / ".lake/build/doc"
overview = (site / "LeanNetDocs.html").read_text()
(site / "index.html").write_text(
    overview.replace("<title>LeanNetDocs</title>", "<title>lean-net API</title>")
)

# This imports-only build module has no child modules. Show its overview as
# a link instead of the empty expander emitted by the pinned doc-gen4 version.
navbar = site / "navbar.html"
html = navbar.read_text()
empty_section = (
    '<details class="nav_sect" data-path="./LeanNetDocs.html">'
    '<summary>LeanNetDocs (<a href="./LeanNetDocs.html">file</a>)</summary></details>'
)
overview_link = '<div class="nav_link"><a href="./">API overview</a></div>'
if html.count(empty_section) == 1:
    navbar.write_text(html.replace(empty_section, overview_link))
elif html.count(overview_link) != 1 or 'data-path="./LeanNetDocs.html"' in html:
    raise SystemExit("unexpected doc-gen4 overview navigation markup")
