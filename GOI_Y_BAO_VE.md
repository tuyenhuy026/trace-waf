# Gợi ý bảo vệ TRACE-WAF — 9 đến 12 phút

Dành để luyện nói, không phải nội dung báo cáo học thuật mới. Slide `.pptx` đã có speaker notes cho từng trang.

| Trang | Thời lượng | Luận điểm chính |
|---|---:|---|
| 1–2 | 1 phút | Giới thiệu vấn đề: phát hiện tốt chưa đủ; rủi ro của chặn nhầm và bypass. Con số Miggo chỉ là ngữ cảnh từ nghiên cứu của đơn vị đó. |
| 3–4 | 1 phút | Tổng quan DEG-WAF, GenSQLi, OWASP CRS và ba câu hỏi RQ1–RQ3. |
| 5–6 | 1,5 phút | Kiến trúc có nhánh LLM ở cấp đề xuất, nhưng hiện chỉ kiểm tra offline; định nghĩa coverage/FPR/robustness và ngưỡng đồng thời. |
| 7–8 | 1 phút | Tập test 570 case và ba baseline công bằng; lưu ý tập benign hard-negative thiên lệch có chủ đích. |
| 9–11 | 2 phút | Kết quả ba trục, lỗi false positive ở SQLi, phép thử synthetic drift; tránh suy rộng sang mạng thật. |
| 12–13 | 1,5 phút | Quyết định NO-GO theo ngưỡng minh họa và vòng đời kiểm toán rule. Đây là trọng tâm chính sách/quản trị. |
| 14–15 | 1 phút | Hạn chế, lộ trình kiểm tra CRS/WAF thực, kết luận và mời phản biện. |

## Câu chốt bài đề xuất

> “Đề tài không kết luận TRACE-Policy bảo vệ hệ thống thực tốt nhất. Điểm chứng minh được là ta có thể đo đồng thời khả năng phát hiện, chặn nhầm và sức bền trước biến đổi, rồi ra quyết định quản trị có chứng cứ. Trên tập mô phỏng, phương án phát hiện 100% attack-pattern vẫn phải bị từ chối triển khai vì tỷ lệ chặn nhầm 16,67%.”

## Sáu câu hỏi phản biện cần nắm vững

**1. Đã dùng LLM sinh payload và rule thật chưa?**  
Chưa. Thành phần LLM là kiến trúc dự định triển khai ở giai đoạn tiếp theo. Bài hiện kiểm chứng phương pháp đánh giá bằng bộ sinh xác định và luật thủ công, không gán số đo cho LLM.

**2. Vì sao kết quả 100% coverage chưa đủ?**  
Vì chỉ áp dụng cho họ mẫu tổng hợp hẹp, có nguy cơ trùng dạng với luật; nhãn chưa dựa trên thực thi exploit ở backend; FPR vẫn 16,67% so với ngưỡng chấp nhận minh họa 5%.

**3. Coverage có phải là số CVE được ngăn chặn?**  
Không. Coverage ở đây là attack-pattern recall trên 450 mẫu có nhãn. Chưa có kiểm chứng bảo vệ CVE thật. CWE chỉ phân loại điểm yếu và giúp truy vết nguồn.

**4. Chính sách `/api/tutorial` có làm WAF bị bypass không?**  
Có thể, nếu giả định backend escape HTML là sai. Vì thế chính sách này chỉ mô phỏng lợi ích của ngữ cảnh tin cậy; cần xác minh backend semantics, review threat model và regression test trước khi sử dụng ngoại lệ.

**5. Vì sao bộ test dùng 120 benign mà lại cho FPR cao?**  
Tập benign được bố trí 60 hard-negative/120 mẫu, nhằm ép bộ luật bộc lộ lỗi chặn nhầm. Tỷ lệ 16,67% không phải ước lượng chặn nhầm của người dùng ngoài sản xuất. Bộ thử thực phải có mẫu benign theo endpoint và tỷ lệ base-rate thực.

**6. Đóng góp và tính mới nằm ở đâu?**  
Đóng góp quy mô học phần là benchmark ba trục nhất quán, dữ liệu/mã tái lập, sổ rule có truy vết CWE, approval gate và quyết định rollback. Không tuyên bố đây là chuẩn quốc tế đầu tiên hoặc đã vượt những công trình liên quan.

## Demo ngắn (30–60 giây nếu giảng viên yêu cầu)

Chạy từ thư mục gốc:

```bash
python -m unittest discover -s tests -v
python src/wafbench.py --output results
python src/audit_rules.py rules/rule_register.json
```

Chỉ ngay dòng cuối của kết quả: coverage 100,0%; FPR 16,7%; robustness 100,0%. Hỏi ngược lại: *“Có nên tự động triển khai rule này không?”* — trả lời **Không**, vì vượt ngưỡng chặn nhầm và chưa thử trên WAF/ứng dụng thật.

