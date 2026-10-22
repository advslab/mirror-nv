# NVD feed mirror

A daily GitHub Actions job that downloads NIST's NVD JSON feeds with their `.meta` files,
verifies each (gzSize and NIST's content sha256) and replaces the changed ones in a single
rolling release tagged `feeds`. Nothing piles up: every feed is exactly one asset, replaced
in place, data file before its `.meta`.

Feeds: `nvdcpe-2.0.tar.gz`, `nvdcpematch-2.0.tar.gz`, `nvdcve-2.0-<year>.json.gz` for every
year since 2002, `nvdcve-2.0-modified.json.gz`, `nvdcve-2.0-recent.json.gz`, each with its
`.meta`. The vendor statements XML is not mirrored (NIST publishes no checksum for it).

Stable download links, always the latest verified copy:

    https://github.com/<owner>/<repo>/releases/download/feeds/<file>

for example

    https://github.com/<owner>/<repo>/releases/download/feeds/nvdcpematch-2.0.tar.gz
    https://github.com/<owner>/<repo>/releases/download/feeds/nvdcpematch-2.0.meta
    https://github.com/<owner>/<repo>/releases/download/feeds/nvdcve-2.0-2026.json.gz

Runs daily at 06:20 UTC, after NIST's nightly rebuild; also by hand from the Actions tab, or
on demand: `gh api repos/<owner>/<repo>/dispatches -f event_type=mirror`. A run fetches only
the feeds whose `.meta` changed, stops starting new downloads after about four hours and
leaves the rest for the next day; the release notes record each run's counts.

Four feeds download at once (`PARALLEL` in the workflow), and a big one is fetched as up to
six byte ranges in parallel (`SEGMENTS`, one per `SEGMENT_MIB`), since NIST throttles each
connection. Each log line names its feed, a progress line (size, percent, speed) is printed
every minute per running download, an overall `== n/N done` line follows each finished feed,
and the run's summary page shows a table of every feed's result, size and time.

Data: public domain, from https://nvd.nist.gov/. This project uses and redistributes data
from the NVD API but is not endorsed or certified by the NVD.
