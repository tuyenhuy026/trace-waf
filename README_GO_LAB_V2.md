# TRACE-WAF: một vòng kiểm chứng mới hướng tới **LAB-GO**, không sửa lịch sử

## Mục tiêu và những điều KHÔNG được làm

Bộ này là **một nghiên cứu mới, tiến cứu ở cấp phòng thí nghiệm**. Không đổi số liệu checkpoint 17/10/2026: 7×104 final test, L3 có coverage/robustness 100% nhưng FPR 11,36% và còn benign regression, nên **NO-GO** của checkpoint cũ vẫn đúng.

Bộ này giúp thu thập bằng chứng để *có thể* đạt LAB-GO trong một lần đánh giá mới. **Không hứa chắc GO**, không thay ngưỡng, không chỉ lựa kết quả đẹp, không thử lại holdout đã nhìn thấy, không sửa rule theo final test.

- **Thử nghiệm 1 — CVE-2024-23334**: sửa mạng Docker, giữ localhost và chỉ dùng *synthetic canary*. Đo aiohttp 3.9.1 trực tiếp, aiohttp 3.9.2 trực tiếp, cả hai đi qua CRS WAF. `CVE_CONFIRMED` cần bản dễ lỗi thực sự đọc được canary từ ngoài static root và bản đã vá không đọc được. `WAF_PROTECTED` phải có 403 **và audit rule CRS cùng request ID**, không chỉ status 403. **Thử nghiệm này dùng CRS trong lab, không sử dụng luật LLM G2.**
- **Thử nghiệm 2 — luật LLM mới**: dùng gateway localhost đúng **`gpt-5.6-sol`** (hoặc `gpt-6-luna` nếu khả dụng) sinh *một* JSON policy; lưu cả requested model và response.model. Compiler có whitelist lấy từ chính repository. Đóng băng 92 case trong corpus mới (30 intended attack, 62 benign) **trước khi gọi model**. Đo B1 không LLM và G2 do LLM đề xuất trên **cùng corpus**, cùng ModSecurity/CRS, cùng cấu hình reverse proxy. Bao gồm negative cases trên `/sql` và `/xss` vốn còn thiếu trong checkpoint cũ. Không lấy dữ liệu từ test cũ vào prompt.
- **Cổng kết luận**: tính LAB_GO khi (i) chính sách LLM vượt tất cả ngưỡng cố định và không kém B1 ở trục nào, có ít nhất một cải thiện; (ii) mỗi CWE có ít nhất hai family tấn công hiệu lực; (iii) không uncertain/hồi quy, rollback đúng; (iv) CVE trực tiếp/vá/WAF có bằng chứng. Điều này là **hai kết quả lab cùng đạt**, không chứng minh *chính luật LLM G2* bảo vệ CVE và **không cho phép triển khai production**.

## Cài đặt

Giải nén ZIP vào thư mục gốc repo `trace-waf`, **không ghi đè** thư mục cũ `results/checkpoint/...`:

```bash
cd /duong-dan-den/trace-waf
unzip -o ~/Downloads/TRACE_WAF_GO_V2.zip -d .
source .venv/bin/activate
python -m unittest discover -s tests/go_lab_v2 -v
```

Yêu cầu: Python 3.12, Docker Desktop, thư viện `requests`, `playwright` trong `.venv` của repo, và Playwright Chromium (`python -m playwright install chromium`). Gói patch không thay code gốc của `lab/` hoặc `checkpoint_tools/` cũ.

## A. Chạy CVE riêng (ưu tiên đầu tiên)

```bash
python checkpoint_tools/go_lab_v2/run_cve.py --run
```

Phần `cve_compose.yaml` thay mạng `internal: true` duy nhất bằng *hai mạng*: `isolated` + `host_access`, chỉ publish `127.0.0.1:18190`–`18193`. Docker vẫn không đưa các cổng ra địa chỉ công cộng. Trường hợp mạng vẫn không thông, script xuất `docker_ps.json`, lệnh build, logs và kết quả 4 cổng trước khi kết luận `INCOMPLETE`. Nếu preflight OK mới gửi bốn probe **chỉ tới synthetic marker** nằm bên ngoài static root của 2 container của bạn.

**Cảnh báo:** Đây là bản có lỗi có chủ đích; chỉ chạy trên máy lab do bạn kiểm soát. Không biến địa chỉ/cổng cố định trong script thành một công cụ dò quét hoặc hướng đến site khác. Tắt stack sau thử nghiệm (script tự `down`, cả khi thất bại).

Kết quả: `results/checkpoint/go-lab-v2/<UTC>/cve/cve_v2_summary.json`, kèm logs WAF/backend. Nếu `CVE_CONFIRMED_WAF_NOT_CONFIRMED` hoặc `INCOMPLETE`, **không gọi CVE đã được WAF bảo vệ**.

## B. Sinh một ứng viên luật LLM và đóng băng

Gateway model phải đang chạy ở `http://127.0.0.1:20128/v1/chat/completions`, và model cần khớp **chính xác** `response.model`. Vì bạn đã xác nhận chuyển model sang `gpt-5.6-sol`, mặc định:

```bash
python checkpoint_tools/go_lab_v2/trial.py --prepare --model gpt-5.6-sol
```

Lệnh này tạo một thư mục `results/checkpoint/go-lab-v2/<UTC>/rule-trial/`, file `preregistration.json` với SHA-256 corpus, ngân sách **đúng một** lời gọi LLM, raw response, `candidate_policy.json`, `G2.conf`, `B1.conf`. Nếu model hoặc policy invalid, trạng thái sẽ là `INCOMPLETE_MODEL_CALL`, **không** gọi lại tự động. Lượt `--prepare` mới sau khi đã có lượt cũ yêu cầu `--new-round-rationale "lý do kỹ thuật/khoa học cụ thể"`, mọi lượt trước đều được lưu.

**Không sửa file `frozen_cohort.json`, `G2.conf`, `B1.conf` sau khi prepare.** Đó là phép thử độc lập tiếp theo; các thay đổi sau khi xem test sẽ làm hỏng tư cách confirmatory. Nếu bắt buộc sửa, mở **một nghiên cứu mới có mã trial khác**, công bố thất bại trước đó.

## C. Đánh giá một lần trên 92 case mới

Thay `<...>` bằng đúng đường dẫn `rule-trial` mà bước prepare in ra:

```bash
python checkpoint_tools/go_lab_v2/trial.py --evaluate results/checkpoint/go-lab-v2/<UTC>/rule-trial
```

Chương trình tự chạy B1 rồi G2, cùng `lab_override.yaml` (`PROXY_ERROR_OVERRIDE=off`) để thử bảo toàn response 404 **trong cả hai nhánh**. Thay đổi proxy là một can thiệp riêng và phải được công bố trong paper, không được nhập số này chung với checkpoint cũ. Script ghi request+oracle cho từng trường hợp, `inflight.json` trước mỗi request, SHA và bản rollback trở về Compose gốc. Một khi `evaluation-started.json` tồn tại thì **không thể chạy lại trial đó**; nếu lỗi giữa chừng, chỉ công bố `INCOMPLETE` và phân tích sự cố.

Lưu ý thận trọng: tập 92 case này được xây dựng từ fixture backend cũ sau khi đã biết kết quả cũ; mặc dù được đóng băng trước model call và chỉ đánh giá một lần, đây **chưa phải benchmark độc lập trên một ứng dụng khác**. Các payload `%` URL-encoded thường không hiệu lực do cách mã hóa `urlencode` của runner: kết quả phải ghi `invalid_attack` và mẫu số dựa trên direct oracle.

## D. Phán quyết đúng (không thể tự đổi thành GO)

Khi hai phần trên đã có `summary.json`, chạy:

```bash
python checkpoint_tools/go_lab_v2/go_gate.py \
  --trial results/checkpoint/go-lab-v2/<UTC_rule>/rule-trial/confirmatory-summary.json \
  --cve results/checkpoint/go-lab-v2/<UTC_cve>/cve/cve_v2_summary.json
```

Phán quyết `LAB_GO` cần đồng thời:

| Điều kiện | Ngưỡng đã công bố từ trước |
|---|---:|
| Coverage trên attack có hiệu lực | ≥ 90% |
| Robustness trên transformed có hiệu lực | ≥ 85% |
| FPR trên benign có thể đánh giá | ≤ 5% |
| Quy mô dữ liệu | ≥ 40 benign; ≥ 10 valid attacks; ≥ 5 transformed valid |
| Theo CWE | ≥ 2 family có hiệu lực trên mỗi CWE |
| Kết quả không chắc chắn hoặc lỗi chức năng | 0 |
| B1 so với G2 | G2 không kém trục nào, và cải thiện ít nhất một trục |
| Tính toàn vẹn | model metadata khớp; freeze/sha; một lượt; oracle ổn định; rollback |
| CVE-2024-23334 | Direct bản lỗi có canary; bản vá không có; WAF CRS có audit chặn cùng request ID |

`LAB_GO` là minh chứng triển khai an toàn **trong lab cụ thể và trường hợp CVE cụ thể**, chưa phải chuẩn phê duyệt rule cho hệ thống ngoài thực tế. Nếu vẫn NO_GO, **không thay test/đổi ngưỡng để đổi màu kết luận**; paper có thể báo cáo nghiên cứu giới hạn có giá trị khoa học.

## E. Upload evidence để cập nhật báo cáo

```bash
python checkpoint_tools/go_lab_v2/bundle.py
```

Upload ZIP `results/checkpoint/TRACE_WAF_GO_LAB_V2_EVIDENCE_*.zip` vào cuộc trò chuyện. Tôi sẽ xác minh SHA, xem nhật ký oracle, rule ID, lỗi proxy, cách diễn giải GO hoặc NO-GO rồi cập nhật đồng bộ MD/DOCX/LaTeX/slide. Script không tự gán kết quả GO khi chưa có dữ liệu.

## Không được trộn ba kết luận

1. *CVE bị ảnh hưởng trực tiếp đã tái lập* ≠ *CVE được WAF chặn*.
2. *LLM đề xuất rule tốt hơn B1 trên một cohort* ≠ *LLM bảo vệ CVE cụ thể*. Muốn kết luận sau phải thử ứng viên LLM riêng trên **cùng lab CVE**, thiết kế compiler luật tương ứng `/static`, đối chứng CRS và tiền đăng ký mới.
3. *LAB_GO* ≠ *production GO*. Phần production còn cần chủ sở hữu phê duyệt, đánh giá bảo mật độc lập, quan sát canary thực và khả năng rollback an toàn.
