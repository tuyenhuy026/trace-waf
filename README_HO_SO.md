# TRACE-WAF checkpoint paper — 17/10/2026

## Bản nộp

- `BAO_CAO_TRACE_WAF.md`: bản nguồn báo cáo học thuật (Markdown, UTF-8).
- `BAO_CAO_TRACE_WAF.docx`: bản Word một cột khổ A4.
- `BAO_CAO_TRACE_WAF.tex`: bản LaTeX tương ứng, biên dịch XeLaTeX.
- `BAO_CAO_TRACE_WAF.pdf`: bản xem trước xuất từ XeLaTeX.
- `assets/`: hình ảnh từ báo cáo trước, được giữ nguyên và tham chiếu bởi LaTeX.

Tại thư mục này chạy: `xelatex BAO_CAO_TRACE_WAF.tex` hai lần. Font LaTeX: Tinos, Noto Sans, Noto Sans Mono; yêu cầu cài bộ font này và gói XeLaTeX/phụ thuộc thông dụng.

## Bằng chứng/giới hạn

Báo cáo phân tách rõ S0 offline (570 chuỗi gắn nhãn theo mẫu), S1–S2 checkpoint ModSecurity/CRS hoàn tất validation bảy chính sách, final test B0 bị ngắt sau 93/104 quan sát, và các hạng mục chưa kiểm chứng. FPR validation: B0 31,25%, B1/L1–L5 6,25%, cả bảy NO-GO và có 1 benign response regression. Không chạy thêm API GPT hoặc tuning. Không thực nghiệm CVE, replay drift, hay vòng tự thích nghi mới khi làm tài liệu. Việc chỉ tổng hợp bằng chứng sẵn có không phải một lần chạy test cuối.

Kiểm tra host Docker gốc và tính toàn vẹn của bản final-test bị ngắt, cũng như quyền GitHub Contents:write, là công việc bắt buộc trước khi có thể nghiệm thu test và cập nhật repository.

## Chú ý

Thay các trường `[Họ và tên tác giả]`, `[Đơn vị đào tạo / trường]`, `[Địa chỉ email]` trong các phiên bản trước khi nộp. Bản ZIP không chứa slide.
