# TRACE-WAF — Bộ hồ sơ nộp học phần

**Học phần:** Chính sách và quản trị An ninh mạng  
**Ngày chốt tài liệu:** 16/10/2026  
**Đề tài:** TRACE-WAF — Khung đánh giá ba trục và quản trị sinh luật tường lửa ứng dụng web có truy vết CWE/CVE trước kỹ thuật biến đổi né tránh.

## 1. Nội dung bàn giao

| Tệp/thư mục | Mục đích |
|---|---|
| `BAO_CAO_TRACE_WAF.docx` | Báo cáo tiếng Việt định dạng Word, 13 trang theo cấu hình xuất hiện tại. |
| `BAO_CAO_TRACE_WAF.tex` | Toàn bộ mã nguồn LaTeX của **cùng nội dung nghiên cứu**. |
| `BAO_CAO_TRACE_WAF.md` | Bản nguồn thống nhất được dùng để sinh cả DOCX và LaTeX. |
| `slides/BAO_VE_TRACE_WAF.pptx` | Slide bảo vệ, 15 trang 16:9, có thuyết minh (speaker notes). |
| `slides/build_slides.js` | Mã PptxGenJS tạo lại slide. |
| `src/wafbench.py` | Sinh mẫu và kiểm tra ba chính sách mô phỏng ngoại tuyến. |
| `src/audit_rules.py` | Kiểm tra sổ luật có trường truy vết. |
| `src/plot_results.py` | Tái tạo hình/biểu đồ (cần `matplotlib`). |
| `tests/test_wafbench.py` | Sáu bài kiểm thử tự động. |
| `results/` | Dữ liệu kết quả, dự đoán từng mẫu, thống kê ba trục. |
| `rules/rule_register.json` | Ba rule nguyên mẫu kèm chứng cứ CWE và quản trị thay đổi. |
| `assets/` | Sơ đồ và biểu đồ nhúng trong báo cáo/slide. |
| `tools/build_documents.py` | Tạo lại DOCX/LaTeX từ Markdown với Pandoc. |
| `GOI_Y_BAO_VE.md` | Dàn ý bảo vệ và 6 câu hỏi phản biện có câu trả lời. |

**Quan trọng:** Tệp `.tex` tham chiếu hình trong `assets/`, nên khi chuyển sang Overleaf, hãy upload `BAO_CAO_TRACE_WAF.tex` **cùng toàn bộ thư mục `assets/`**, giữ nguyên đường dẫn tương đối. Nếu bạn dùng bản ZIP của hồ sơ thì đã có đầy đủ.

## 2. Chạy lại thực nghiệm

Cần Python >= 3.10 (thí nghiệm lõi chỉ dùng thư viện chuẩn). Mở terminal trong **thư mục gốc của bộ hồ sơ**, chạy:

```bash
python src/wafbench.py --output results
python -m unittest discover -s tests -v
python src/audit_rules.py rules/rule_register.json
```

Ba chiến lược đo cùng 570 test case tổng hợp (450 attack-pattern, 120 benign):

| Chính sách | Coverage | FPR | Robustness |
|---|---:|---:|---:|
| Raw signature | 50,67% | 50,00% | 38,33% |
| Canonical signature | 93,33% | 50,00% | 91,67% |
| TRACE-Policy | 100,00% | 16,67% | 100,00% |

SHA-256 kỳ vọng của `results/detailed_predictions.csv`:

```
4f50ab19c6679411fb9702eb7d2c28f8423aa45fe8e5366cb41283723ec3be86
```

Kết quả đã được chạy và kiểm tra bằng 6 bài unittest. Thư mục results còn giữ bản ghi mỗi test case để giáo viên có thể kiểm tra.

Để tạo lại hình vẽ:

```bash
python -m pip install 'matplotlib>=3.5'
python src/plot_results.py
```

## 3. Biên dịch báo cáo LaTeX

Có thể dùng **Overleaf** (đặt trình biên dịch `XeLaTeX`) hoặc TeX Live/MacTeX có cài `Noto Serif`, `Noto Sans`, `Noto Sans Mono`.

```bash
xelatex BAO_CAO_TRACE_WAF.tex
xelatex BAO_CAO_TRACE_WAF.tex
```

LaTeX và DOCX có cùng nội dung văn bản do cùng xuất phát từ `BAO_CAO_TRACE_WAF.md`; số trang/chi tiết dàn trang sẽ khác vì bộ máy biên dịch khác nhau. Lần kiểm tra xuất bản: DOCX 13 trang, bản XeLaTeX biên dịch 11 trang. Nên giữ nguyên hình và các file hỗ trợ trong ZIP.

Để tái tạo DOCX/LaTeX từ Markdown cần Pandoc và `python-docx`:

```bash
python -m pip install python-docx
python tools/build_documents.py
```

Để tái tạo slide cần Node.js với `pptxgenjs` và bộ helper của môi trường tạo ban đầu; **không bắt buộc** chạy lệnh này khi chỉ mở hoặc trình chiếu `.pptx`.

## 4. Nhấn mạnh khi nộp/bảo vệ

- Đây là **thực nghiệm mô phỏng hoàn toàn ngoại tuyến** trên dấu hiệu SQLi, XSS và Path Traversal, **không phải** benchmark hệ thống WAF thương mại, ứng dụng thật hay LLM.
- Mục tiêu **LLM sinh payload và đề xuất rule** được trình bày trong kiến trúc và lộ trình tiếp theo. **Chưa chạy inference hoặc training LLM**; tuyệt đối không nói đã thử nghiệm LLM.
- Rule hiện truy vết về **CWE**, chưa chứng minh được khả năng ngăn bất kỳ **CVE cụ thể** nào bằng thực nghiệm ứng dụng.
- Quyết định quản trị là **NO-GO**: `TRACE-Policy` có FPR = 16,67% trên tập benign được cố ý thiết kế chứa hard-negative, vượt ngưỡng 5% **minh họa**, mặc dù hai chỉ số còn lại tốt.
- Số liệu Miggo về 52% bypass phản ánh **bộ CVE và cấu hình riêng của nghiên cứu nhà cung cấp**, không phải tỷ lệ thất bại phổ quát của WAF.
- Vì nhiều biến thể có chung template gốc, không diễn giải 570 case như các quan sát thống kê độc lập từ lưu lượng Internet thực tế.

## 5. Trước khi nộp

1. **Thay trường `[Bổ sung họ tên và mã học viên]`** ở trang đầu bản DOCX và nguồn Markdown/LaTeX bằng thông tin thật của bạn.
2. Kiểm tra yêu cầu định dạng của giảng viên (cỡ chữ, lề, trích dẫn, số trang) và chỉnh nếu cần.
3. Nếu upload lên Google Docs, hãy dùng trực tiếp file `.docx`. Nếu dùng Overleaf, upload `.tex` và thư mục `assets/`.
4. Chạy trình chiếu thử ít nhất một lần để bảo đảm phông tiếng Việt và speaker notes hiển thị ổn.

