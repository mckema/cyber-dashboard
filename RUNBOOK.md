# Cyber Threat Exploit Watch: runbook (stack self-host, FR-A1)

Runbook vận hành bản fork `ediphy-tthau/cyber-dashboard-poc`. Bản fork phát triển tiếp prototype của Mark McKee (xem [README.md](README.md)) để đáp ứng FR-A1 của MS-30:
- ingest đủ các nguồn CERT-EU, ENISA, CISA KEV, NCSC, NVD/CVE và MISP/CIRCL OSINT;
- item mới xuất hiện trong 1 giờ;
- mỗi item ghi nguồn và timestamp.

Wiki.js chạy self-host bằng Docker Compose trên máy local. Phần deploy lên GCP để ở phase sau.

> [!IMPORTANT]
> **Runbook được viết cuốn chiếu.** Mỗi section chỉ chứa những gì đã thực sự chạy: lệnh nguyên văn, trích output thật và ngày chạy. Section còn marker **Chưa triển khai** thì chưa có nội dung đã kiểm chứng; đừng làm theo phần chữ mô tả mục đích của nó.

Bối cảnh và lý do chọn nguồn feed nằm trong tài liệu kiến trúc `fairct_ms30-exploit-watch_kien-truc.md` (C4 level 1). Xem [§12](#12-related-files).

Mọi lệnh trong runbook chạy từ thư mục gốc của repo, trong Git Bash trên Windows. Mọi thời gian là UTC, trừ khi ghi rõ khác.

---

## 1. Hiện có gì

Trạng thái ngày 2026-11-03.

| Thing | State |
|---|---|
| Wiki.js | `ghcr.io/requarks/wiki:2` = **2.5.317** (Node 24.22.1), SQLite trong named volume `wiki-data`, chỉ publish ở `127.0.0.1:3000`. Không dùng tag `latest`: `latest` là 3.x, API khác. |
| Page | `en/CTP/run-books/Cyber-Exploit-Watch`, **id 1** trên wiki local. Instance gốc của Mark là id 51. Content lấy từ `page/skeleton.html`, CSS (`scriptCss`) lấy từ `page/style.css`. |
| Job | Service `job`: `python rebuild.py --every 1800`, image `python:3.12-slim` + `requests` 2.34.2, chạy bằng uid 1000. Repo được bind-mount vào `/app`, nên sửa code không cần build lại image. |
| Credential của job | API key `exploit-watch`, gắn group `exploit-watch` với quyền tối thiểu (xem §7), hết hạn sau 1 năm. Lưu trong `.env`; file này đã có trong `.gitignore`. |
| Nguồn feed | 8 module trong `feeds/`. Lượt chạy thật 2026-11-03 03:54 UTC: cả 8 nguồn OK. Số item trong 7 ngày: KEV 8 · EUVD 7 · CVE.org 3.119 · NVD 3.121 · GitHub 136 · CERT-EU 0 · NCSC-NL 10 · CIRCL 1. |
| Page sau lượt ghi đầu | 326.927 byte. Bảng CVE hiện 300/1.304 dòng critical/high (`CVE_ROW_CAP=300`). |
| Test | 72 unit test, không gọi network, đều pass (`python -m unittest discover -s tests`). |
| Chưa có | GitHub Actions workflow (quyết định 2026-11-03: chưa tạo); deploy GCP; FR-A2..A4. |

---

## 2. Cần chuẩn bị gì

| Thứ cần có | Ghi chú |
|---|---|
| Docker Desktop đang chạy, có Compose v2+ | Đã chạy với Docker 29.9.2, Compose v5.6.1. Máy **không cần Python**: mọi lệnh Python chạy trong container. |
| Biến `HTTP_PROXY`, `HTTPS_PROXY` trên host | Mạng công ty bắt đi qua proxy `http://192.168.112.253:3128`. Compose truyền hai biến này vào lúc build image và vào container `job`. Xem §3. |
| File `.env` | `bootstrap_wiki.py` tự tạo từ `.env.example` và tự điền `WIKI_ADMIN_PASSWORD`, `WIKI_PAGE_ID`, `WIKIJS_API_KEY`. |
| `GITHUB_TOKEN` (khuyến nghị) | Token không cần scope nào. Không có token thì GitHub chỉ cho 60 request/giờ, và quota này **dùng chung cho cả IP proxy công ty** (xem §7). |
| `NVD_API_KEY` (tuỳ chọn) | Key miễn phí. Không có key thì job phải chờ 6 giây giữa các trang NVD. |

Không dùng email cá nhân trong `.env`, kể cả trong `USER_AGENT`. Admin của wiki local là `admin@example.com`.

---

## 3. Chỗ dễ vướng

1. **Container không ra được Internet nếu không truyền proxy.** Triệu chứng: `Name or service not known` khi `pip install` hoặc khi fetch feed. Compose đã truyền proxy vào service `job`. Nếu chạy tay bằng `docker run`, phải thêm `-e HTTP_PROXY=$HTTP_PROXY -e HTTPS_PROXY=$HTTPS_PROXY`.
2. **Git Bash tự đổi đường dẫn Windows trong tham số của `docker`.** Thêm `MSYS_NO_PATHCONV=1` trước lệnh và dùng đường dẫn dạng `C:\...` cho `-v`.
3. **Thư mục `state/` phải thuộc uid 1000.** Job chạy bằng uid 1000. Nếu `state/` được tạo bởi container chạy root (ví dụ `docker run` với image `python:3.12-slim`), job gặp `PermissionError: [Errno 13] Permission denied: '/app/state/items/kev.json.tmp'` (gặp ngày 2026-11-03). Cách sửa:
   ```bash
   MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd -W):/app" python:3.12-slim chown -R 1000:1000 /app/state
   ```
   Để tránh lỗi này, luôn chạy job bằng `docker compose run --rm job …`.
4. **`cisa.gov` trả 403 cho request đi qua proxy**, kể cả khi dùng User-Agent của trình duyệt. Job tự chuyển sang mirror GitHub `cisagov/kev-data`; bảng health ghi "Read from github mirror. cisa.gov refused the request."
5. **Đăng nhập admin của Wiki.js bị giới hạn 5 lần mỗi 60 giây**, tính cả lần sai: `Too many requests, please try again in N seconds.` Mỗi lần chạy `bootstrap_wiki.py` dùng 1 lần đăng nhập.
6. **Sau `docker compose down -v`, password và key trong `.env` không còn khớp.** Volume `wiki-data` chứa admin và key đã bị xoá. Chạy lại `bootstrap_wiki.py`: script tạo lại admin bằng password cũ trong `.env` và thay key mới.

---

## 4. Repo layout

```
.
├── rebuild.py            job: gọi 8 feed, gộp, render, ghi page; --dry-run / --out / --every
├── render.py             dựng HTML cho 6 bảng và các counter; --demo để preview
├── bootstrap_wiki.py     setup Wiki.js, API key quyền tối thiểu, tạo page; --reseed / --update-css / --purge-history
├── feeds/
│   ├── __init__.py       ALL (thứ tự fetch), CORE = {kev, cvelist}
│   ├── common.py         contract: Item, SourceError, Fatal, get() có ETag cache
│   ├── state.py          đọc/ghi state/ (atomic), seen.json, runs.jsonl
│   ├── kev.py euvd.py cvelist.py nvd.py github.py      nhóm CVE
│   └── certeu.py ncscnl.py circl.py                    nhóm advisory
├── page/
│   ├── skeleton.html     content của page (các anchor id)
│   └── style.css         scriptCss của page
├── tests/                72 unit test + fixtures/ (payload thật, đã cắt gọn)
├── docker-compose.yml    service wiki + job
├── Dockerfile            image của job (python:3.12-slim, uid 1000)
├── requirements.txt      requests
├── .env.example          mẫu biến môi trường (.env bị gitignore)
├── README.md             thiết kế gốc của Mark
└── RUNBOOK.md            tài liệu này
```

`state/` (gitignored) chỉ được tạo khi chạy:

| Đường dẫn | Nội dung |
|---|---|
| `state/http/` | Cache của conditional GET: ETag cùng body của lần trả 200 gần nhất |
| `state/items/<module>.json` | Item của lần fetch thành công gần nhất. Dùng khi nguồn chưa tới lượt fetch hoặc fetch bị lỗi |
| `state/cursors/` | Con trỏ của từng module: `fetchTime` của deltaLog cvelistV5, store CVE và NVD, cache CERT-EU và NCSC-NL, trang kế tiếp của GitHub |
| `state/seen.json` | `item key → first_seen`, giữ 30 ngày. Là cơ sở để đo SLA |
| `state/wiki.json` | Fingerprint dữ liệu và thời điểm ghi page gần nhất |
| `state/runs.jsonl` | Mỗi lượt chạy một dòng (xem §9) |

Ngày 2026-11-03, `state/` nặng khoảng 16 MB.

---

## 5. Lần chạy đầu

Đã chạy ngày 2026-11-03.

```bash
docker compose build job
docker compose up -d --wait wiki
docker compose run --rm job python bootstrap_wiki.py
```

Output của bootstrap trên wiki mới (trích, khoảng 8 giây):

```
.env       created from .env.example
.env       WIKI_ADMIN_PASSWORD generated ****nHf1 (32 chars)
setup      finalizing (admin admin@example.com, siteUrl http://localhost:3000)
setup      done, wiki restarted
api        enabled
group      created 'exploit-watch' id 3
group      read:pages+write:pages START 'CTP/run-books/'; manage:pages EXACT 'CTP/run-books/Cyber-Exploit-Watch'; locale en
page       created en/CTP/run-books/Cyber-Exploit-Watch id 1 (15447 B content, 12659 B css)
apikey     created 'exploit-watch' for group 3, expires in 1y (****WJ0g (502 chars))
smoke      bot key reads page 1 (CTP/run-books/Cyber-Exploit-Watch, 15447 B)
bootstrap  ok (.env updated: WIKI_ADMIN_PASSWORD, WIKI_PAGE_ID, WIKIJS_API_KEY)
```

Chạy bootstrap lần 2 không tạo thêm gì mới: `apikey .env key works, keeping it` / `bootstrap ok (.env unchanged)`.

Tiếp theo, chạy dry-run (fetch và render, không ghi page), rồi chạy thật:

```bash
docker compose run --rm job python rebuild.py --dry-run
docker compose run --rm job python rebuild.py
```

Output của lượt ghi thật đầu tiên (2026-11-03 03:54 UTC):

```
window 2026-10-27T03:54:39Z -> 2026-11-03T03:54:39Z
  CISA KEV           ok           8  Read from github mirror. cisa.gov refused the request.
  ENISA EUVD         ok           7
  CVE.org cvelistV5  ok        3119  delta: 1 changed records, 2 requests.
  NVD                cached    3121  Polled every 2 h; next fetch after 3 Nov 05:47 UTC.
  GitHub Advisory    ok         136  3 requests.
  CERT-EU            ok           0
  NCSC-NL            ok          10
  CIRCL OSINT        ok           1
content 15,447 -> 326,927 bytes (data changed)
written: Page has been updated.
```

Chạy lại ngay sau đó: `no data change since 2026-11-03T03:54:39Z — skipping write`.

Cuối cùng, cho job chạy liên tục mỗi 30 phút:

```bash
docker compose up -d --wait
docker compose logs -f job
```

Page xem tại `http://localhost:3000/en/CTP/run-books/Cyber-Exploit-Watch`.

> [!NOTE]
> Lần fetch đầu tiên của cvelistV5 phải backfill 7 ngày: 105 request, 46,7 MB, khoảng 18,5 giây. NVD lần đầu: 2 trang, 8,4 MB, khoảng 68 giây khi không có `NVD_API_KEY`. Các lượt sau nhẹ hơn nhiều (xem §6).

---

## 6. Job làm gì trong một lượt chạy

1. Tính cửa sổ `now − 7 ngày .. now` (UTC).
2. Gọi lần lượt 8 module theo thứ tự `feeds.ALL`. Nguồn chưa tới lượt (`CADENCE`) thì dùng lại item của lần thành công gần nhất (`state/items/`).
3. Gộp dữ liệu:
   - KEV và EUVD gộp theo CVE vào bảng exploited; dòng của CISA được ưu tiên vì có cột due date.
   - Điểm NVD được bổ sung vào bản ghi CVE.org. CVE nào CNA và CISA ADP đều chưa chấm thì lấy điểm NVD (`score_source = NVD`).
   - CERT-EU và NCSC-NL vào chung một bảng advisory.
4. `render.build_regions()` dựng 6 bảng, các counter và dòng stamp. `render.apply_regions()` chèn chúng vào page hiện tại; chỉ vùng nằm trong anchor bị thay.
5. Tính fingerprint của dữ liệu, bỏ qua các vùng thay đổi theo giờ: bảng health, `n-health`, `winlabel`. Chỉ ghi page khi fingerprint khác lần trước, hoặc đã quá `HEARTBEAT_HOURS` (mặc định 6 giờ) kể từ lần ghi gần nhất.
6. Ghi page bằng một lệnh `pages.update`. Không gửi `scriptCss`.
7. Ghi `first_seen` cho từng item vào `seen.json` và thêm một dòng vào `runs.jsonl`.

| Nguồn | Cadence | Cách fetch | Timestamp hiển thị | Chi phí một lượt bình thường (2026-11-03) |
|---|---|---|---|---|
| CISA KEV | mỗi lượt | `cisa.gov` (403), rồi mirror GitHub với `If-None-Match` | `dateAdded` (chỉ có ngày) | 1 lần 403 + 1 lần **304**, 0 byte |
| ENISA EUVD | mỗi lượt | `/api/search?fromKEVDate&toKEVDate`, không có ETag | `exploitedSince` (ngày) | 1 request, khoảng 53 KB |
| CVE.org cvelistV5 | mỗi lượt | Range 128 KB đầu `deltaLog.json` (`Accept-Encoding: identity`), sau đó tải JSON từng CVE thay đổi | `datePublished` (giây, UTC) | Lúc vắng: 1 request, 0,3 giây. 28 thay đổi: 29 request, 331 KB, 2,2 giây |
| NVD | 2 giờ | `lastModStartDate` từ cursor − 15 phút | `published` | 1 request, 0,7 giây |
| GitHub Advisory | mỗi lượt | `published=<ngày>..<ngày>`, theo `Link: rel="next"` | `published_at` (giây) | 3 request, đều **304** |
| CERT-EU | mỗi lượt | RSS (luôn 200); chỉ tải JSON khi serial mới hoặc vừa đổi | `publish_date` của JSON (UTC) | 1 request, 10 KB |
| NCSC-NL | mỗi lượt | `changes.csv` với ETag; chỉ tải tài liệu CSAF mới hoặc vừa đổi | `initial_release_date` / `current_release_date` | 1 request, **304** |
| CIRCL OSINT | mỗi lượt | `manifest.json` với ETag | `date` (ngày), `timestamp` | 1 request, **304**, 0,9 giây |

---

## 7. Quirk của Wiki.js và feed, learned the hard way

Những điểm dưới đây được tìm ra bằng chạy thử ngày 2026-11-03 trên Wiki.js 2.5.317 và các feed thật.

**Wiki.js**

| Quirk | Hệ quả / cách code xử lý |
|---|---|
| `pages.single` kiểm tra quyền `manage:pages` (hoặc `delete:pages`), không kiểm tra `read:pages` | Key chỉ có `read:pages` + `write:pages` thì nhận `You are not authorized to view this page.` Group `exploit-watch` vì vậy có thêm `manage:pages`, giới hạn bằng rule **EXACT** chỉ cho đúng page này. Không cấp `delete:pages`. |
| Key sai **không** trả 401 | Key không tồn tại bị coi là guest: HTTP 200 kèm `not authorized`. Key đã revoke: HTTP 500 `API Key is invalid or was revoked.` API đang tắt: HTTP 500 `API is disabled…`. `gql()` in kèm gợi ý khi gặp các thông báo này. |
| Admin gọi `pages.update` mà không gửi `scriptCss`/`scriptJs` thì Wiki.js **xoá** CSS và JS của page | Bootstrap luôn gửi lại cả hai. Key của job không có `write:styles`, nên khi job update page thì CSS được giữ nguyên (đã kiểm tra: 11.643 B trước và sau). |
| Mỗi lệnh update tạo một page version mới, kể cả khi nội dung không đổi | Job chỉ ghi khi fingerprint dữ liệu thay đổi (§6). History được dọn bằng `--purge-history` (§9). |
| `scriptJs` được chèn vào `<body>` dưới dạng HTML thô (`common.js`: `injectCode.body += page.extra.js`) | README §7 của Mark ghi là "not executed". Thực tế đoạn code đặt trong `<script>` có thể chạy (suy ra từ source, chưa thử). Giữ `scriptJs` rỗng. |
| HTML sanitiser bỏ `<style>`, `<script>`, `<link>` và làm hỏng inline `style=` dài | Skeleton và `render.py` không dùng inline style nào; mọi style nằm trong `page/style.css`, đặt dưới wrapper `.xw`. |
| `pages.create` báo sai thông điệp khi bị từ chối: errorCode 6010 `…not authorized to delete this page.` | Đừng tin vào nội dung thông điệp, chỉ xem errorCode. |
| `scriptCss` bị minify khi lưu (12.659 B → 11.643 B) | Không ảnh hưởng gì. |

**Feed**

| Quirk | Bằng chứng (2026-11-03) |
|---|---|
| `cisa.gov` trả 403 qua proxy | Kể cả với UA của Chrome. Mirror `raw.githubusercontent.com/cisagov/kev-data` trả 200 và hỗ trợ 304. |
| Range request trên response gzip tính theo byte đã nén | `deltaLog.json` phải gửi kèm `Accept-Encoding: identity`. |
| Backfill bằng zip end-of-day sót lượt cập nhật ngay sau 00:00 UTC | Lượt đó không nằm trong zip của ngày nào. Lần đầu sót 12 CVE; đã sửa bằng cách đọc lại deltaLog quanh mốc nửa đêm. |
| EUVD: path đúng là `/api/search` (`/api/vulnerabilities` trả 404) | `aliases` hay đặt GHSA trước CVE; `epss` là phần trăm (82,64), không phải số 0–1. |
| CERT-EU chặn request không có User-Agent (Azure Application Gateway trả 403) | `.env` có dòng `USER_AGENT=` để trống, nên code dùng `os.environ.get("USER_AGENT") or <mặc định>`. |
| `publish_date` trong JSON CERT-EU là thời điểm của **bản sửa mới nhất** | Thời điểm publish lần đầu lấy từ dòng v1.0 trong History. `original_date` là ngày vendor công bố, không phải của CERT-EU. |
| Nhãn "CEST" trong RSS của CERT-EU | Chưa kiểm chứng được nhãn có đổi sang "CET" sau 2026-10-25 hay không, vì chưa có advisory mới nào. Code dùng JSON (UTC) làm nguồn chính; bảng zone `{CEST: +02:00, CET: +01:00}` chỉ dùng làm fallback. |
| Link `advisory?id=` của NCSC-NL trả 200 kể cả với ID không tồn tại | Dùng `https://advisories.ncsc.nl/<năm>/<id>.html`; ID sai trả 404. |
| Một số tài liệu NCSC-NL chỉ có vector CVSS 4.0 trong note, không có `scores[]` | Item đó có score 0 và severity rỗng. Không tự tính CVSS 4.0. |
| Quota 60 request/giờ của GitHub khi không xác thực dùng chung cho cả IP proxy | Lúc bắt đầu test chỉ còn 16/60. Với request không xác thực, 304 vẫn bị tính quota. |
| GitHub `published=` dùng timestamp đầy đủ thì URL đổi mỗi lượt và không bao giờ nhận được 304 | Query theo ngày, rồi lọc lại đúng cửa sổ trong code. |

---

## 8. Failure behaviour

| Condition | Behaviour | Đã kiểm chứng |
|---|---|---|
| CISA KEV lỗi ở **cả** `cisa.gov` lẫn mirror | `FATAL: CISA KEV: CISA KEV (cisa.gov): HTTP 403 …; CISA KEV (github mirror): HTTP 404`. Không ghi page; chạy đơn lẻ thì exit 1 | 2026-11-03, cố tình trỏ URL sai |
| cvelistV5 lỗi | `Fatal`, không ghi page (cùng nhóm `CORE` với KEV) | Theo code; unit test có kiểm các message |
| Nguồn không thuộc CORE lỗi, đã từng thành công | Dùng item của lần thành công gần nhất; bảng health ghi **Stale**, ví dụ `Stale since 3 Nov 03:58 UTC: CERT-EU RSS: HTTP 404`. Page vẫn được dựng, exit 0 | 2026-11-03, cố tình trỏ RSS CERT-EU sai |
| Nguồn không thuộc CORE lỗi, chưa từng thành công | Bảng health ghi **Error**, bảng của nguồn đó rỗng | Theo code |
| Lỗi lập trình trong một module (exception không phải `SourceError`) | Xử lý như lỗi của nguồn đó: `internal error: <Type>: …` | Theo code |
| Mọi nguồn đều rỗng | `every feed came back empty — refusing to publish an empty brief` | Theo code (giữ nguyên từ Mark) |
| Page thiếu anchor | `page anchor <tbody id="…"> not found — re-seed the page skeleton` | Unit test |
| Dữ liệu không đổi, chưa tới heartbeat | `no data change since … — skipping write`, không tạo version mới | 2026-11-03 |
| Đang ở chế độ `--every` mà gặp `Fatal` | In `FATAL: …`, ghi `{"result": "fatal"}` vào `runs.jsonl`, chạy tiếp ở lượt sau | Theo code |
| Lỗi quyền ghi `state/` | `PermissionError … state/items/kev.json.tmp`: xem §3 mục 3 | 2026-11-03 |

---

## 9. Vận hành thường ngày

```bash
# trạng thái và log
docker compose ps
docker compose logs -f job

# chạy một lượt ngay, không chờ vòng 30 phút
docker compose run --rm job python rebuild.py

# 5 lượt chạy gần nhất (kết quả, số item mới, độ trễ SLA)
tail -5 state/runs.jsonl

# dừng / chạy lại job (wiki vẫn chạy)
docker compose stop job
docker compose up -d job

# dọn page history cũ hơn 7 ngày (admin, áp dụng cho mọi page)
docker compose run --rm job python bootstrap_wiki.py --purge-history P7D

# đẩy lại skeleton hoặc CSS sau khi sửa page/skeleton.html hoặc page/style.css
docker compose run --rm job python bootstrap_wiki.py --reseed --update-css

# preview page bằng dữ liệu thật mà không ghi wiki
docker compose run --rm job python rebuild.py --out state/out.html
```

Mỗi dòng trong `runs.jsonl` (trích lượt ghi đầu tiên ngày 2026-11-03):

```json
{"run_at": "2026-11-03T03:54:39Z", "mode": "write", "result": "written", "bytes": 326927,
 "feeds": {"CISA KEV": {"status": "ok", "items": 8, "new": 8, ...}, ...}, "seconds": ...}
```

- `result` nhận một trong các giá trị `written`, `unchanged`, `would-write` (dry-run), `out`, `fatal`, `crash`.
- `feeds.<nguồn>` gồm `status`, `items`, `new`, `baseline`, `lag_max_min`, `over_sla`.

Reset state: chỉ xoá đúng phần cần. Xoá `state/http/` buộc job tải lại toàn bộ (mất 304). Xoá `state/cursors/cvelist*` buộc job backfill lại 7 ngày (khoảng 47 MB). Xoá `state/seen.json` làm lượt kế tiếp thành baseline, nên không đo được SLA cho lượt đó.

Chạy unit test:

```bash
docker compose run --rm job python -m unittest discover -s tests
```

> [!NOTE]
> Rotate API key: **chưa triển khai.** Theo code, `bootstrap_wiki.py` tạo key mới khi key trong `.env` không còn dùng được.

---

## 10. Operational notes

- **Rate limit:**
  - NVD: 5 request/30 giây khi không có key; code chờ 6 giây giữa các trang.
  - GitHub API: 60 request/giờ khi không xác thực (tính theo IP, dùng chung cả proxy); 5.000/giờ với token cá nhân, 1.000/giờ với `GITHUB_TOKEN` của Actions.
  - Tải từ `raw.githubusercontent.com` và GitHub Releases không tính vào quota API.
- **Đo SLA 1 giờ:**
  - `lag = first_seen − (updated hoặc published)` của item mới, tính bằng phút. `over_sla` là số item mới có lag lớn hơn 60 phút.
  - Item chỉ có ngày (KEV `dateAdded`) không đo được.
  - Lượt đầu tiên của mỗi nguồn là baseline nên không đo.
  - `first_seen` chỉ được ghi khi page đã được ghi hoặc không đổi; dry-run và `--out` không ghi.
- **Dung lượng:**
  - Page khoảng 327 KB với 300 dòng CVE.
  - Ước tính: mỗi lần dữ liệu đổi tạo một version khoảng 327 KB. Nếu gần như lượt nào cũng đổi (cvelistV5 có CVE mới liên tục) thì khoảng 48 version/ngày, tương đương khoảng 15 MB/ngày. Con số thật sẽ đo sau khi job chạy vài giờ.
  - DB SQLite của wiki: 1,29 MB lúc 04:01 UTC ngày 2026-11-03, sau khi đã purge history.
  - `state/`: khoảng 16 MB.
- **Volume CVE** (7 ngày tính đến 2026-11-03): 3.119 CVE. Có 278 CRITICAL và 1.018 HIGH (theo điểm CNA hoặc CISA ADP), 1 CVE có SSVC "active". 597 CVE (khoảng 19%) chưa có điểm từ CNA lẫn ADP.

---

## 11. Known limitations

- **Giao diện Wiki.js hiện nhãn thô** (`header.search`, `sidebar.browse`) và toast "An unexpected error occurred". Container wiki không tải được gói ngôn ngữ, vì Wiki.js dùng `fetch` của Node, mà `fetch` bỏ qua `HTTP(S)_PROXY` (đã thử ngày 2026-11-03). Page không bị ảnh hưởng.
- **KEV qua mirror có thể trễ khoảng 3,4 giờ** so với `dateReleased` (một mẫu ngày 2026-10-30), vì `cisa.gov` chặn request. Với KEV, mốc 1 giờ chỉ đạt khi lấy được dữ liệu từ `cisa.gov`.
- **CIRCL OSINT không có event mới từ 2026-08-13.** Feed vẫn được fetch mỗi lượt (một lần 304), nhưng gần như luôn rỗng.
- **Bảng CVE chỉ hiện 300 dòng** đầu tiên theo điểm. Phần bị ẩn được ghi ở `n-cvecap`.
- **Tiêu đề NCSC-NL bằng tiếng Hà Lan**, lấy nguyên từ tài liệu CSAF.
- **Dọn history phải chạy bằng tay, bằng quyền admin.** Key của job không có quyền purge.
- **Nhãn CEST/CET của CERT-EU sau khi đổi giờ chưa được kiểm chứng** (xem §7).
- **Chưa có:** GitHub Actions workflow, deploy GCP, cảnh báo khi job lỗi, xoay vòng kích thước `runs.jsonl`.

---

## 12. Related files

| File | Nội dung |
|---|---|
| [README.md](README.md) | Thiết kế gốc của Mark McKee (2026-10-17): Wiki.js sau IAP, WIF, `rebuild.py` |
| `working/fairct_ms30-exploit-watch_kien-truc.md` (workspace Claude Code của team, ngoài repo) | C4 level 1, flow của một lượt chạy, quyết định nguồn feed và bằng chứng kiểm tra ngày 2026-11-03 |
| `feeds/common.py` | Contract cho mọi feed module: thuộc tính module, `Item.extra` theo bảng, schema dòng health |

---

## 13. Nhật ký triển khai

| Ngày (UTC) | Việc | Kết quả |
|---|---|---|
| 2026-11-03 | Checkout branch `feature/fr-a1-ingest-threat-feeds` (trùng `main` tại `eac04f7`), dựng sườn runbook | Sườn có 13 section |
| 2026-11-03 | Phát hiện container cần proxy; build image dev có `requests` | Container ra Internet qua `192.168.112.253:3128` |
| 2026-11-03 | WS0: `feeds/common.py`, `feeds/state.py` | Smoke test: KEV trả 200 rồi 304 (body lấy từ cache); Range trả 206; `cisa.gov` 403 thành `SourceError` |
| 2026-11-03 | WS-A: compose, Dockerfile, bootstrap | Wiki.js 2.5.317 healthy; page id 1; key quyền tối thiểu bị từ chối mọi thao tác ngoài phạm vi; bootstrap lần 2 không tạo trùng |
| 2026-11-03 | WS-B: skeleton, CSS, `render.py` | 27 test pass; preview sáng/tối |
| 2026-11-03 | WS-C: KEV, EUVD, cvelistV5, NVD, GitHub | 22 test pass; backfill cvelistV5 3.119 CVE; sửa lỗi sót lượt cập nhật quanh nửa đêm (12 CVE); `fetch_gh` lấy đủ trang 2 (136 advisory) |
| 2026-11-03 | WS-D: CERT-EU, NCSC-NL, CIRCL | 23 test pass; NCSC-NL 10 advisory; lượt 2 đều 304 |
| 2026-11-03 03:54 | WS-E: viết lại `rebuild.py`, ghi page lần đầu | 8/8 nguồn OK; page 15.447 → 326.927 byte; lượt kế tiếp `skipping write` |
| 2026-11-03 03:58 | Kiểm tra failure | CERT-EU lỗi: Stale, page vẫn dựng. KEV lỗi cả hai nguồn: FATAL, không ghi |
| 2026-11-03 | Sửa bug `div.refresh` của Mark (mỗi lần ghi thừa một `</div>`) | Dùng anchor `id="rstat"` trong `render.apply_regions()` |
| 2026-11-03 | Thêm `--purge-history`; chạy `P7D` | `history purged versions older than P7D (all pages)` |
| 2026-11-03 04:01 | `docker compose up -d`: job chạy vòng 30 phút | Lượt đầu: `no data change … skipping write` |
| 2026-11-03 | Sửa `USER_AGENT=` rỗng trong `.env` làm mất UA mặc định | `common.USER_AGENT` rơi về giá trị mặc định khi biến rỗng |
