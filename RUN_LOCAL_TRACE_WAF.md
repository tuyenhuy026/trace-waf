# TRACE-WAF — chạy checkpoint trực tiếp trên macOS, không cần Codex

> **Chỉ chạy trên repository `tuyenhuy026/trace-waf` của bạn và các container localhost do bạn quản lý.** Bộ này không nhắm đến hệ thống ngoài lab. Đây là **bộ chạy thí nghiệm**, chưa phải kết quả mới: chỉ được công bố kết quả sau khi script chạy và kiểm tra evidence.

**Nguồn checkpoint đã khóa:** `results/checkpoint/rule-study/20261016T170642475819Z`. Giữ nguyên tất cả bản ghi cũ. Các công cụ dùng `gpt-6-luna` nếu bạn chọn thử nghiệm GPT bổ sung, không sử dụng model khác.

## 1. Cài bộ công cụ vào repository hiện có

Tải `TRACE_WAF_LOCAL_RUNNER.zip`, mở Terminal tại **thư mục gốc của repo có `lab/` và `results/`** (không tạo repo mới), rồi giải nén:

```bash
cd /duong-dan-den-repository/trace-waf
unzip -o ~/Downloads/TRACE_WAF_LOCAL_RUNNER.zip -d .
```

Nếu ZIP nằm ở thư mục khác, thay `~/Downloads/...` bằng đường dẫn của bạn. ZIP chỉ thêm `checkpoint_tools/` và `RUN_LOCAL_TRACE_WAF.md`; **không ghi đè** các thư mục dữ liệu cũ. Có thể xem mã Python trước khi chạy; script không yêu cầu quyền root.

Chuẩn bị Docker Desktop, Python 3.12 và Playwright. Nếu môi trường `.venv` từ lượt Codex cũ vẫn hoạt động, giữ nguyên. Nếu **chưa có** `.venv`, tạo bằng `python3.12 -m venv .venv` (cần Python 3.12 đã cài). Sau đó:

```bash
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m playwright install chromium
python -m unittest discover -s checkpoint_tools/tests -v
```

Các bài unittest trong gói không kết nối Docker, không gửi request và không gọi GPT. Chỉ dùng những dependency đã có trong dự án (`requests`, `playwright`). Mở Docker Desktop rồi khởi động lab cơ sở:

```bash
docker compose -f lab/compose.yaml up -d
```

## Cách ngắn nhất: một lệnh thực hiện ba bước và đóng gói kết quả

Sau khi chuẩn bị `.venv`, Playwright và Docker Desktop như Mục 1, bạn có thể chạy toàn bộ quy trình (không gọi GPT):

```bash
bash checkpoint_tools/run_all.sh --i-own-local-lab
```

Lệnh này chạy unit test → Docker lab → final test (tiếp tục nếu có dữ liệu trước đó) → CVE → drift canary nếu final thành công → evidence ZIP. Dù một bước không thành công, script vẫn cố gắng đóng gói những bằng chứng có sẵn và báo trạng thái **chưa hoàn thành**. Trường hợp muốn opt-in đúng một lời gọi GPT bổ sung:

```bash
bash checkpoint_tools/run_all.sh --i-own-local-lab --with-llm
```

**Không** dùng `--with-llm` nếu chưa sẵn sàng gateway và chưa đồng ý chi phí inference. Có thể chạy từng hạng mục thủ công theo các bước dưới đây để kiểm soát chặt hơn.

## 2. Hoàn thành final test 7 phương án: ưu tiên chạy đầu tiên

Trước hết chỉ kiểm tra trạng thái và hash, **không đo test case**:

```bash
python checkpoint_tools/final_test.py --status
python checkpoint_tools/final_test.py --preflight
```

Khi `PRE-FLIGHT PASS`, chạy **một lần**:

```bash
python checkpoint_tools/final_test.py --run
```

- Tự xác minh SHA-256 của corpus, source runner, frozen plan, từng `B0.conf`, `B1.conf`, `L1..L5.conf` và quyết định validation `NO_GO`.
- **B0:** đọc chính xác `results/checkpoint/final-test/B0-test/observations.jsonl`, giữ nguyên 93 dòng cũ, chỉ đo 11 case từ vị trí còn thiếu. Trường hợp repo của bạn có số dòng khác hoặc cấu hình lệch sẽ từ chối chạy, **không tự làm mới**.
- **B1 và L1–L5:** đo mỗi case một lần theo input frozen, không chọn ứng viên theo test.
- Mỗi case có **write-ahead in-flight marker**: nếu script crash giữa lúc gửi yêu cầu và ghi nhận kết quả, lần tiếp tục sẽ đánh dấu `uncertain_interrupted`; không lặp request để lấy số đẹp.
- Luôn khôi phục `active-rules.conf` theo bản `original-rules.conf`, restart WAF và xác thực health/header rollback.
- Toàn bộ bằng chứng mới nằm trong `results/checkpoint/final-test-continuation/20261016T170642475819Z/`. Folder test cũ **không bị sửa**.

Nếu script/Terminal bị ngắt, **không chạy `--run` lần nữa**. Sau khi kiểm tra WAF/Docker, chỉ dùng:

```bash
python checkpoint_tools/final_test.py --resume
python checkpoint_tools/final_test.py --status
```

**Chú ý khoa học:** B0 gồm hai phiên chạy do sự cố trước đó; không mô tả như một lượt chạy liên tục. Một case có `uncertain_interrupted` khiến nghiệm thu chưa đủ điều kiện, dù đã đủ số dòng. So sánh oracle trực tiếp qua các phương án; nếu có sai khác sẽ đánh dấu `REVIEW`, không ngầm loại trừ.

## 3. CVE-2024-23334: thử trên aiohttp dễ bị ảnh hưởng và bản đã vá

Độc lập với final test, tạo **bốn container tách biệt**: aiohttp `3.9.1`, aiohttp `3.9.2`, WAF CRS trước mỗi backend. Docker image có thể cần Internet để kéo image và cài đúng phiên bản từ PyPI. Host chỉ bind vào `127.0.0.1` cổng `18190–18193`; mạng container riêng, không nhắm trang ngoài. **Chỉ một tệp `TRACE_CVE_2024_23334_SYNTHETIC_MARKER`** được đặt cạnh thư mục static để xác nhận vấn đề đọc sai phạm vi.

```bash
python checkpoint_tools/cve_2024_23334.py --run
```

Thí nghiệm thử request path nguyên trạng (không để HTTP client tự chuẩn hóa), ghi body/status/hash/echo, kiểm chứng:

1. Bản `aiohttp 3.9.1` với `follow_symlinks=True` có đọc được **marker tổng hợp** từ ngoài static root hay không.
2. Bản `aiohttp 3.9.2` cùng cấu hình từ chối yêu cầu đó hay không.
3. Yêu cầu qua WAF có bị CRS chặn, bị proxy biến đổi, hay marker vẫn bị lộ. 403 **không đủ** để khẳng định CRS chặn: bắt buộc đối chiếu log `949110` cùng request ID.
4. Ghi `PROXY_ERROR_OVERRIDE`, ghi log hai backend và hai WAF, Docker image/version; dừng toàn bộ container CVE khi hoàn thành.

Kết quả tại `results/checkpoint/cve-2024-23334/<UTC>/cve-summary.json`. Nếu trực tiếp bản lỗi **không** đọc được marker thì chưa xác nhận CVE, dù proxy trả 403. Đây là một nghiên cứu tình huống CWE-22, **không** đại diện mọi CVE hoặc ba nhóm CWE.

Advisory chuẩn: https://github.com/aio-libs/aiohttp/security/advisories/GHSA-5h86-8mv2-jq9f. Version `3.9.2` là bản vá.

## 4. Drift: replay thực và canary có kiểm soát

Sau khi hoàn thành final test (để không vô tình đánh giá lại tập holdout), chạy:

```bash
python checkpoint_tools/drift_replay.py --run --approve-canary
```

Script thực sự phát lại yêu cầu **validation**, không đọc test, qua hai phiên bản đã khóa. Kịch bản:

- **A:** mẫu tấn công biểu diễn gốc + 16 benign.
- **B:** mẫu tấn công đã biến đổi + cùng 16 benign.
- **Quan sát:** thực hiện B0 và tính biến đổi cơ cấu input, coverage/robustness/FPR trên mỗi window.
- **Đề xuất:** sử dụng B1 đã khóa từ trước; không sinh luật mới và không sử dụng kết quả test để chọn luật.
- **Phê duyệt + canary trong lab:** bật bởi `--approve-canary`; phát lại hai window với B1.
- **Rollback:** phục hồi bản gốc và xác minh WAF health/header; nếu FPR hoặc hồi quy chức năng vi phạm cổng thì `LAB_NO_GO_ROLLBACK`.

Nếu không muốn chạy canary, bỏ `--approve-canary` nhưng lúc đó chỉ đo replay, **không** đủ quy trình lab. Kết quả trong `results/checkpoint/drift-replay/<UTC>/drift-summary.json`.

**Định nghĩa đúng:** đây là replay với **chuyển dịch cơ cấu dữ liệu do người nghiên cứu thiết kế**, có thao tác đổi chính sách qua phê duyệt; **không** phải drift sản xuất theo thời gian và **không** chứng minh hệ thống tự học/tự thích nghi không cần con người.

## 5. (Tùy chọn) Một lượt GPT `gpt-6-luna` mới, dev-only

Chỉ dùng nếu máy có gateway đã cấp phép chạy tại `http://127.0.0.1:20128/v1/chat/completions`, và bạn chấp nhận thời gian/chi phí API. **Mặc định không có cuộc gọi nào.** Chạy sau khi kết thúc final test:

```bash
python checkpoint_tools/optional_llm_dev.py --run --reps 1
```

Lệnh này tạo đúng **1 lời gọi** alias `gpt-6-luna` với ngân sách yêu cầu 12 case (4 SQLi, 4 XSS, 4 traversal), không retry, không đổi prompt để cải thiện số liệu. Có thể chọn `--reps 2` **trước lần chạy đầu tiên** (tối đa 24 case), không nâng ngân sách sau khi nhìn thấy đầu ra. Response không đạt JSON/budget cũng giữ nguyên thành thất bại. Khi generation hợp lệ, script so sánh với cùng ngân sách case heuristic trên **dev**, cùng WAF B0, không dùng test hay tuning. Kết quả exploratory **không** thuộc 7 phương án final test và không chứng minh GPT tốt hơn khi chưa có đối chứng độc lập.

Thư mục: `results/checkpoint/llm-exploratory-dev-20261017/`. Chạy một lần: thư mục tồn tại sẽ chặn việc tạo thêm lượt chỉ để chọn kết quả đẹp. Kết nối gateway có thể không hoạt động; khi đó script giữ lỗi thay vì tự chuyển model.

## 6. Gửi bằng chứng về để cập nhật MD, DOCX, LaTeX

Sau khi chạy các bước trên (kể cả khi có bước lỗi), đóng gói evidence:

```bash
python checkpoint_tools/bundle_evidence.py
```

Dòng `zip` in ra đường dẫn file dạng:

```text
results/checkpoint/TRACE_WAF_EVIDENCE_YYYYMMDDTHHMMSSZ.zip
```

**Hãy upload ZIP đó vào cuộc trò chuyện.** Tôi sẽ đối chiếu SHA, log, từng CWE/CVE, diễn giải đúng drift và cập nhật ba báo cáo. ZIP mặc định **không** gửi raw GPT prompt/response; nếu bạn muốn có bằng chứng nguyên vẹn cho phần optional GPT, đọc và rà soát dữ liệu trước, rồi xuất với `--include-llm-raw`.

Vui lòng **không** gửi API token, `.env`, `.venv`, private key hay toàn bộ log chứa dữ liệu nhạy cảm khác. Gói chỉ lấy các thư mục evidence riêng và vài chứng cứ đã khóa, có manifest SHA-256.

## 7. Trạng thái nghiệm thu cần duy trì

| Hạng mục | Chỉ coi là hoàn thành khi |
|---|---|
| Final test | 7/7 chính sách đủ 104 case, không có `uncertain`, oracle giữa chính sách ổn định, rollback được xác thực. |
| CVE-2024-23334 | Đúng version, 3.9.1 chứng minh leak marker, 3.9.2 không leak, WAF phân loại dựa cả log, không coi proxy 404 là chặn. |
| Drift replay | Có request thực dưới A/B, cả B0/B1 trong lab, canary được phê duyệt, rollback thành công; nhãn vẫn là synthetic shift. |
| LLM bổ sung | Dev-only, cố định số lời gọi/case, lưu thất bại; không đổi kết luận đã khóa của checkpoint. |

**Kết luận nghiên cứu trước khi có bằng chứng mới luôn NO-GO.** Không xóa hoặc viết lại `results/checkpoint/final-test` hay `results/checkpoint/rule-study`.

## 8. Hotfix Playwright (17/10/2026)

Bản cập nhật sửa lỗi `AttributeError: 'PlaywrightContextManager' object has no attribute 'stop'` tại giai đoạn preflight. Hàm `browser_context()` trả về đúng đối tượng `Playwright` từ `sync_playwright().start()` để các nơi dùng `stop()` có hiệu lực. Bổ sung hai regression tests (tổng 9 bài test).

Cài bản ZIP mới vào **repo gốc** và chạy lại `bash checkpoint_tools/run_all.sh --i-own-local-lab`. Giữ nguyên toàn bộ dữ liệu `results/checkpoint/` và **không xóa** thư mục continuation. Nếu lần chạy trước dừng đúng tại preflight của lỗi trên, runner chưa khởi tạo continuation.
