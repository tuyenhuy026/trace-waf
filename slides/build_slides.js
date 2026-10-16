/**
 * TRACE-WAF defense presentation (15 slides) from the paper's recorded results.
 * Build: node slides/build_slides.js
 * Needs PptxGenJS; images are created by python src/plot_results.py.
 */
const pptxgen = require('pptxgenjs');
const fs = require('fs');
const path = require('path');
const { imageSizingContain, warnIfSlideHasOverlaps, warnIfSlideElementsOutOfBounds } =
  require('/home/oai/skills/slides/pptxgenjs_helpers');
const ROOT=path.resolve(__dirname,'..');
const OUT=path.join(__dirname,'BAO_VE_TRACE_WAF.pptx');
const data=JSON.parse(fs.readFileSync(path.join(ROOT,'results','metrics.json'),'utf8'));
const rows=data.metrics.filter(x=>x.cwe==='ALL');
const byName=Object.fromEntries(rows.map(r=>[r.strategy,r]));
const cleanTest=data.test_cases;
const pptx=new pptxgen();
pptx.layout='LAYOUT_WIDE';
pptx.author='TRACE-WAF research course';
pptx.subject='Defense presentation: three-axis WAF policy benchmark and governance';
pptx.title='TRACE-WAF | Bảo vệ đề tài chính sách và quản trị an ninh mạng';
pptx.company='Academic coursework';
pptx.lang='vi-VN';
pptx.theme={headFontFace:'Noto Sans',bodyFontFace:'Noto Sans',lang:'vi-VN'};

const C={navy:'17334D',deep:'0D263D',teal:'159A95',ltTeal:'EAF8F6',orange:'E9954C',paleOrange:'FFF4E9',slate:'41566D',muted:'667B8D',white:'FFFFFF',light:'F5F8FA',blue:'EAF1F6',rule:'D8E2EA',red:'B85155',paleRed:'FFF0F1'};
const S=pptx.ShapeType;
const W=13.3333333,H=7.5;
const M=.72;
const f='Noto Sans';

function rect(slide,x,y,w,h,fill=C.white,line=fill,radius=.12){
  slide.addShape(radius?S.roundRect:S.rect,{x,y,w,h,rectRadius:radius,fill:{color:fill},line:{color:line,width:.7},radius});
}
function line(slide,x1,y1,x2,y2,color=C.rule,width=1.0){
  slide.addShape(S.line,{x:x1,y:y1,w:x2-x1,h:y2-y1,line:{color,width}});
}
function txt(slide,text,x,y,w,h,size=18,color=C.navy,opts={}){
  slide.addText(text,{x,y,w,h,fontFace:f,fontSize:size,color,bold:opts.bold||false,
    breakLine:false,margin:0,vertAlign:opts.valign||'mid',valign:opts.valign||'mid',
    lineSpacingMultiple:1.05,breakLine:false,paraSpaceAfterPt:0,
    align:opts.align||'left',isTextBox:true,
    ...opts});
}
function bg(slide,fill=C.white){slide.background={color:fill};}
function header(slide,section,title,kicker='TRACE-WAF • NGHIÊN CỨU'){
  bg(slide);
  txt(slide,kicker,M,.24,8,.26,10,C.teal,{bold:true,charSpacing:1.4});
  txt(slide,section,10.6,.26,2.0,.24,9,C.muted,{align:'right'});
  txt(slide,title,M,.70,11.95,.74,27,C.navy,{bold:true,valign:'top'});
  line(slide,M,1.54,W-M,1.54,C.rule,1.1);
}
function footer(slide,n,source=''){
  line(slide,M,7.10,W-M,7.10,C.rule,.8);
  txt(slide,'TRACE-WAF  /  Báo cáo bảo vệ học phần',M,7.17,6.9,.18,8.5,C.muted);
  if(source)txt(slide,source,7.9,7.17,3.9,.18,8.0,C.muted,{align:'right'});
  txt(slide,String(n).padStart(2,'0'),12.26,7.14,.28,.24,9,C.teal,{bold:true,align:'right'});
}
function note(slide,talk,sources=[]){
  slide.addNotes('GỢI Ý THUYẾT TRÌNH:\n'+talk+'\n\n[Sources]\n'+sources.map(x=>'- '+x).join('\n')+'\n[/Sources]');
}
function label(slide,text,x,y,w,h,fill=C.blue,color=C.navy){
  rect(slide,x,y,w,h,fill,fill,.12);txt(slide,text,x+.14,y+.03,w-.28,h-.06,11,color,{bold:true});
}
function point(slide,n,x,y,title,detail,fill=C.blue){
  rect(slide,x,y,3.72,3.6,fill,fill,.14);
  txt(slide,String(n).padStart(2,'0'),x+.28,y+.22,1,.50,30,C.teal,{bold:true});
  txt(slide,title,x+.28,y+.92,3.1,.84,20,C.navy,{bold:true,valign:'top'});
  txt(slide,detail,x+.28,y+2.0,3.04,1.25,14,C.slate,{valign:'top',breakLine:true});
}
function roundedBigNumber(slide,x,y,w,n,desc,col=C.navy){
  rect(slide,x,y,w,1.42,C.light,C.rule,.15);
  txt(slide,n,x+.20,y+.20,w-.40,.55,31,col,{bold:true});
  txt(slide,desc,x+.20,y+.83,w-.40,.39,12,C.slate);
}
function addPicture(slide,name,x,y,w,h){
  const p=path.join(ROOT,'assets',name);
  slide.addImage({path:p,...imageSizingContain(p,x,y,w,h)});
}
function hRow(slide,x,y,w,labelText,value,valueColor=C.navy){
  line(slide,x,y+w*.0,x+w,y,C.rule,.8);
  txt(slide,labelText,x+.08,y+.12,w*.58,.40,16,C.slate);
  txt(slide,value,x+w*.60,y+.12,w*.33,.40,17,valueColor,{bold:true,align:'right'});
}
function sourceLabel(slide,t){txt(slide,t,M,6.69,11.6,.24,9,C.muted);}

// Slide 1 --------------------------------------------------------
{
 const s=pptx.addSlide();bg(s,C.deep);
 rect(s,0,0,.19,H,C.teal,C.teal,0);
 txt(s,'PAPER NGHIÊN CỨU · 2026',.88,.69,9,.31,12,'6ED3CC',{bold:true,charSpacing:1.8});
 txt(s,'TRACE-WAF',.88,1.58,10.5,.9,46,C.white,{bold:true});
 txt(s,'Đánh giá ba trục và quản trị sinh luật WAF\ncó truy vết CWE/CVE',.92,2.65,11.45,1.50,30,C.white,{bold:true,valign:'top'});
 line(s,.92,4.60,12.4,4.60,'4D647B',1.1);
 txt(s,'Coverage × False positive × Evasion robustness',.92,4.84,11.1,.48,20,'9FE0DD');
 txt(s,'Học phần: Chính sách và quản trị An ninh mạng',.92,6.18,9,.30,15,'E0E9F1');
 txt(s,'16.10.2026  ·  Nguyên mẫu kiểm thử ngoại tuyến',.92,6.59,10,.27,11,'9DB4C6');
 label(s,'CWE-89',10.0,6.12,.78,.36,'23475B','D7F5EF');
 label(s,'CWE-79',10.84,6.12,.78,.36,'23475B','D7F5EF');
 label(s,'CWE-22',11.68,6.12,.78,.36,'23475B','D7F5EF');
 note(s,'Giới thiệu: đề tài đánh giá WAF theo ba trục và có góc nhìn chính sách, quản trị. Nhấn mạnh đây là paper có nguyên mẫu ngoại tuyến; LLM/WAF thương mại nằm trong lộ trình tương lai.');
}
// Slide 2 --------------------------------------------------------
{
 const s=pptx.addSlide();header(s,'Bối cảnh','Một tỷ lệ chặn cao chưa đủ chứng minh WAF an toàn');
 rect(s,.80,1.90,7.00,3.95,C.light,C.rule,.15);
 txt(s,'52%',1.15,2.24,3.5,1.17,52,C.navy,{bold:true});
 txt(s,'bypass trong mẫu đánh giá hơn 360 CVE\ndo Miggo công bố (12/2025)',1.19,3.51,5.95,1.01,20,C.slate,{bold:true,valign:'top'});
 txt(s,'Không phải tỷ lệ phổ quát của mọi WAF.',1.2,5.27,5.95,.3,13,C.muted);
 rect(s,8.12,1.9,4.42,1.08,C.ltTeal,C.ltTeal);txt(s,'Phát hiện thiếu',8.38,2.14,3.8,.35,18,C.navy,{bold:true});
 rect(s,8.12,3.21,4.42,1.08,C.paleOrange,C.paleOrange);txt(s,'Chặn nhầm giao dịch hợp lệ',8.38,3.42,3.8,.51,18,C.navy,{bold:true});
 rect(s,8.12,4.52,4.42,1.08,C.blue,C.blue);txt(s,'Luật thiếu nguồn gốc / rollback',8.38,4.71,3.8,.53,17,C.navy,{bold:true});
 sourceLabel(s,'Nguồn: Miggo Security (2025); OWASP CRS.');footer(s,2,'Miggo 2025 · OWASP CRS');
 note(s,'Tác giả Miggo nêu 52% bypass trong tập CVE và cấu hình của họ. Tuy nhiên một quyết định vận hành phải đồng thời xét false negative, false positive và governance. Không suy diễn từ số Miggo sang nghiên cứu thực nghiệm của chúng ta.',[
  'https://www.miggo.io/reports-webinar/benchmark-study-of-waf-weakness-and-ai-mitigation',
  'https://owasp.org/projects/crs/']);
}
// Slide 3 --------------------------------------------------------
{
 const s=pptx.addSlide();header(s,'Tổng quan','Các công trình gợi mở — bài toán quản trị vẫn cần được đo');
 const cards=[
  ['OWASP CRS','Tập luật + anomaly scoring, đặt trọng tâm giảm false positive.','Tuning rule'],
  ['DEG-WAF (2025)','LLM + RL sinh biến thể kiểm tra độ bền của WAF.','Evasion testing'],
  ['GenSQLi (2025)','LLM sinh SQLi, xác minh và xây dựng luật giảm bypass.','Attack ↔ defense'],
 ];
 cards.forEach((c,i)=>{
  const x=.76+i*4.20;
  rect(s,x,1.94,3.94,3.47,i%2?C.light:C.blue,C.rule);
  txt(s,c[0],x+.26,2.22,3.35,.48,22,C.navy,{bold:true});
  txt(s,c[1],x+.26,3.03,3.30,1.12,16,C.slate,{valign:'top'});
  label(s,c[2],x+.26,4.73,2.65,.41,C.ltTeal,C.teal);
 });
 rect(s,.84,5.83,11.73,.67,C.deep,C.deep,.08);
 txt(s,'TRACE-WAF: đánh giá 3 trục  +  chứng cứ nguồn  +  cổng thay đổi có người duyệt',1.10,5.98,11.10,.36,17,C.white,{bold:true});
 footer(s,3,'OWASP · DEG-WAF · GenSQLi');
 note(s,'Các ý tưởng thành phần đã tồn tại. Đóng góp của bài này là giao thức kết hợp ba trục và change control ở quy mô bài tập, không tuyên bố tiêu chuẩn đầu tiên. Công bố DEG-WAF/GenSQLi khác bộ test và mô hình của chúng ta.',[
  'https://owasp.org/projects/crs/',
  'https://doi.org/10.54654/isj.v2i25.1128',
  'https://doi.org/10.3390/fi17010008']);
}
// Slide 4 --------------------------------------------------------
{
 const s=pptx.addSlide();header(s,'Mục tiêu','Ba câu hỏi nghiên cứu, một quy trình có thể kiểm toán');
 point(s,1,.83,2.00,'RQ1 · Đo như thế nào?','Chuẩn hóa coverage, FPR và robustness vào một benchmark tái lập.',C.blue);
 point(s,2,4.81,2.00,'RQ2 · Điều gì thay đổi?','So sánh chữ ký thô, giải mã và policy theo tuyến xử lý tin cậy.',C.ltTeal);
 point(s,3,8.80,2.00,'RQ3 · Khi nào áp dụng?','Gắn CWE, người chịu trách nhiệm, phê duyệt và rollback cho mỗi rule.',C.paleOrange);
 txt(s,'Đầu ra mong đợi: mô hình đánh giá + code + hồ sơ bằng chứng + quyết định go/no-go',1.02,6.15,11.20,.44,17,C.navy,{bold:true});
 footer(s,4);
 note(s,'RQ1 là đo đúng, RQ2 là làm rõ trade-off giữa các cách xử lý, RQ3 là kiểm soát rủi ro khi đưa rule vào vận hành. Kết quả nghiên cứu được trình bày minh bạch theo các câu hỏi này.');
}
// Slide 5 --------------------------------------------------------
{
 const s=pptx.addSlide();header(s,'Kiến trúc','TRACE-WAF tách lớp kỹ thuật khỏi quyết định triển khai');
 addPicture(s,'architecture.png',.88,1.79,11.55,4.37);
 label(s,'Đã có: generator xác định + 3 bộ phát hiện mô phỏng',.95,6.26,5.61,.40,C.ltTeal,C.teal);
 label(s,'Chưa có: LLM inference / WAF thực / CVE oracle',6.76,6.26,5.61,.40,C.paleOrange,'976021');
 footer(s,5);
 note(s,'Mô tả bốn tầng: nguồn CWE/CVE và benign, sinh ứng viên, kiểm tra rule, đánh giá ba trục, cổng review. Phân biệt kiến trúc tham vọng LLM với phần đã thực thi: dataset deterministic, regex, parser giả lập. Không có khai thác ngoài lab hay lưu lượng gửi đi.',[
  'https://cwe.mitre.org/data/definitions/89.html',
  'https://cwe.mitre.org/data/definitions/79.html',
  'https://cwe.mitre.org/data/definitions/22.html']);
}
// Slide 6 --------------------------------------------------------
{
 const s=pptx.addSlide();header(s,'Phương pháp','Benchmark đồng thời 3 trục, không đánh đổi bằng phép cộng điểm');
 const cards=[
   {x:.83,c:C.blue,t:'COVERAGE',eq:'TP / (TP + FN)',d:'Tỷ lệ mẫu tấn công có dấu hiệu bị chặn',dir:'↑'},
   {x:4.78,c:C.paleOrange,t:'FALSE-POSITIVE RATE',eq:'FP / (FP + TN)',d:'Tỷ lệ mẫu hợp lệ bị chặn nhầm',dir:'↓'},
   {x:8.73,c:C.ltTeal,t:'EVASION ROBUSTNESS',eq:'TP biến đổi / N biến đổi',d:'Recall trên tập biến thể đã định nghĩa',dir:'↑'},
 ];
 cards.forEach(q=>{
  rect(s,q.x,1.92,3.75,3.20,q.c,q.c);
  txt(s,q.t,q.x+.23,2.19,3.27,.41,17,C.navy,{bold:true});
  txt(s,q.eq,q.x+.23,2.82,3.27,.45,19,C.teal,{bold:true});
  txt(s,q.d,q.x+.23,3.63,3.20,.78,15,C.slate,{valign:'top'});
  txt(s,q.dir,q.x+3.12,4.51,.30,.35,19,C.teal,{bold:true});
 });
 rect(s,1.16,5.43,11.0,.82,C.deep,C.deep);
 txt(s,'Cổng minh họa:   Coverage ≥ 90%     AND     FPR ≤ 5%     AND     Robustness ≥ 85%',1.42,5.63,10.47,.42,18,C.white,{bold:true});
 txt(s,'Ngưỡng là lựa chọn nghiên cứu, không phải chuẩn công nghiệp.',1.27,6.47,10.8,.24,10,C.muted);
 footer(s,6);
 note(s,'Định nghĩa coverage là recall trên chuỗi có dấu hiệu tấn công, không phải bao phủ CVE. Robustness là recall trên biến thể trong benchmark; FPR theo benign hard-negative, không đại diện cơ cấu sản xuất. Cổng AND khiến một trục yếu không bị che bằng chỉ số trung bình.');
}
// Slide 7 --------------------------------------------------------
{
 const s=pptx.addSlide();header(s,'Thực nghiệm','Dữ liệu tổng hợp có tập giữ lại và tái lập được');
 roundedBigNumber(s,.85,1.92,3.67,String(cleanTest),'tổng case trên tập test',C.navy);
 roundedBigNumber(s,4.82,1.92,3.66,'450','case dấu hiệu tấn công',C.teal);
 roundedBigNumber(s,8.81,1.92,3.66,'120','case benign: 60 thường + 60 khó',C.orange);
 txt(s,'Thiết kế attack-case',.90,3.75,4.9,.36,21,C.navy,{bold:true});
 txt(s,'3 CWE × 5 template × 6 ID giữ lại × 5 biến thể = 450',.90,4.24,11.5,.43,19,C.slate);
 const st=[['CWE-89','SQLi'],['CWE-79','XSS'],['CWE-22','Traversal']];
 st.forEach((r,i)=>{label(s,r[0]+'  ·  '+r[1],.92+i*4.0,4.94,3.56,.49,C.blue,C.navy);});
 txt(s,'Không mạng · Không khai thác thật · Không gọi LLM · Python standard library',.93,6.00,11.4,.38,17,C.teal,{bold:true});
 footer(s,7);
 note(s,'Mỗi CWE có 5 dạng gốc, mỗi dạng 10 biến thể theo ID, phát triển 4 ID và test 6 ID. Tập test có 450 attack-pattern và 120 benign; hard-negative cố ý chiếm 50% của benign. Đây không phải mẫu đại diện traffic thật, và giữ lại ID không chứng minh tổng quát hóa sang family chưa thấy.');
}
// Slide 8 --------------------------------------------------------
{
 const s=pptx.addSlide();header(s,'Thiết kế đối chứng','Ba chiến lược, một tập test, cùng nhãn');
 const rows=[
  ['01','Raw signature','Regex kiểm tra chuỗi gốc',C.blue],
  ['02','Canonical signature','URL/HTML decode có giới hạn + regex',C.ltTeal],
  ['03','TRACE-Policy','Giải mã + tuyến tin cậy + rule có ngữ cảnh',C.paleOrange],
 ];
 rows.forEach((it,i)=>{
  const y=1.92+i*1.41;rect(s,.86,y,11.61,1.15,it[3],it[3]);
  txt(s,it[0],1.15,y+.26,.85,.60,26,C.teal,{bold:true});
  txt(s,it[1],2.19,y+.19,4.05,.39,20,C.navy,{bold:true});
  txt(s,it[2],6.32,y+.19,5.60,.68,17,C.slate);
 });
 txt(s,'Lưu ý: đây là bộ phân loại mô phỏng, không phải cấu hình OWASP CRS.',.94,6.40,11.4,.33,14,C.muted);
 footer(s,8);
 note(s,'Raw nhìn chuỗi chưa giải mã, canonical có thể lột hai cấp URL encode, trace thêm xử lý comment SQL và traversal escaping document root. Chúng không phải là OWASP CRS hay sản phẩm WAF thực; do đó không so sánh hiệu quả với các hãng.');
}
// Slide 9 --------------------------------------------------------
{
 const s=pptx.addSlide();header(s,'Kết quả','Chuẩn hóa cải thiện coverage — nhưng trade-off FPR còn lớn');
 addPicture(s,'metrics.png',.71,1.80,9.35,4.44);
 rect(s,10.14,1.95,2.34,3.85,C.blue,C.blue);
 txt(s,'TRACE-Policy',10.39,2.25,1.86,.45,17,C.navy,{bold:true});
 txt(s,'100%',10.36,3.02,1.88,.71,35,C.teal,{bold:true});
 txt(s,'coverage\ntrên test',10.39,3.78,1.8,.74,14,C.slate,{valign:'top'});
 txt(s,'16,67%',10.38,4.78,1.80,.55,24,C.orange,{bold:true});
 txt(s,'FPR chưa đạt',10.39,5.39,1.77,.32,12,C.slate);
 txt(s,'570 case test · 3 chiến lược so sánh đồng thời',1.08,6.31,11.6,.34,15,C.navy,{bold:true});
 footer(s,9);
 note(s,'Nêu tỷ lệ thực đo và các con số đếm: Raw TP 228 FP60; canonical TP420 FP60; Trace TP450 FP20. Robustness trên 360 biến thể là 38.33, 91.67, 100%. Vẫn chưa đạt gate do FPR. Không gọi đây là hiệu quả trên sản xuất.');
}
// Slide 10 --------------------------------------------------------
{
 const s=pptx.addSlide();header(s,'Phân tích lỗi','SQLi là nút thắt false positive trong nguyên mẫu');
 const x=[.88,3.43,5.75,8.10,10.22];
 const widths=[2.50,2.30,2.28,2.07,2.13];
 ['CWE','Raw coverage','Canonical','TRACE','FPR TRACE'].forEach((a,i)=>{
  rect(s,x[i],1.97,widths[i],.58,C.navy,C.navy,0);txt(s,a,x[i]+.10,2.08,widths[i]-.2,.35,12,C.white,{bold:true});
 });
 const d=[
  ['CWE-89 / SQLi','40,0%','80,0%','100,0%','50,0%'],
  ['CWE-79 / XSS','52,0%','100,0%','100,0%','0,0%'],
  ['CWE-22 / Path','60,0%','100,0%','100,0%','0,0%'],
 ];
 d.forEach((row,j)=>row.forEach((v,i)=>{
  const y=2.58+j*.87;rect(s,x[i],y,widths[i],.80,j===0&&i===4?C.paleOrange:(j%2?C.light:C.white),C.rule,0);
  txt(s,v,x[i]+.12,y+.19,widths[i]-.24,.36,16,(j===0&&i===4)?'AE6A1C':C.navy,{bold:j===0&&i===4});
 }));
 rect(s,.92,5.57,11.57,.87,C.ltTeal,C.ltTeal);
 txt(s,'20 benign chứa văn bản SQL bị chặn nhầm  →  không thể phê duyệt rule chỉ theo recall.',1.23,5.77,10.96,.50,18,C.navy,{bold:true});
 footer(s,10);
 note(s,'Trong test mỗi CWE có 150 attack và 40 benign. Hard-negative SQL chứa chuỗi UNION SELECT ở ngữ cảnh tài liệu, bị cả ba chính sách phát hiện như tấn công. Đó là lý do TRACE vẫn FPR 50% với SQLi, 16.67% toàn tập. Nếu tự thêm ngoại lệ theo nội dung user gửi sẽ rất nguy hiểm.');
}
// Slide 11 --------------------------------------------------------
{
 const s=pptx.addSlide();header(s,'Robustness','Synthetic drift: thay đổi tỷ trọng biểu diễn làm raw recall sụt mạnh');
 addPicture(s,'drift.png',.70,1.82,10.00,4.48);
 rect(s,10.85,2.03,1.80,3.63,C.paleOrange,C.paleOrange);
 txt(s,'−82,22',11.06,2.48,1.39,.73,29,'9A5818',{bold:true});
 txt(s,'điểm %',11.06,3.24,1.39,.38,15,'9A5818',{bold:true});
 txt(s,'Raw: A → B',11.06,4.15,1.39,.73,14,C.slate);
 txt(s,'Đây là dịch chuyển cơ cấu test, không phải chuỗi thời gian thật.',1.09,6.35,11.4,.38,14,C.muted);
 footer(s,11);
 note(s,'Giai đoạn A có 180 mẫu raw/case, B có 270 mã hóa/transform. Raw phát hiện 100% A nhưng 17.78% B, tương ứng giảm 82.22 điểm %. Đây không phải drift lưu lượng quan sát ngoài đời mà là thí nghiệm cơ cấu có kiểm soát.');
}
// Slide 12 --------------------------------------------------------
{
 const s=pptx.addSlide();bg(s,C.deep);
 txt(s,'CỔNG QUẢN TRỊ',.86,.56,8,.37,12,'79D8CF',{bold:true,charSpacing:1.6});
 txt(s,'NO-GO',.86,1.19,10.2,.88,48,C.white,{bold:true});
 txt(s,'Không phương án nào đạt đồng thời ba điều kiện triển khai.',.90,2.12,10.9,.57,23,'D5E6EF',{bold:true});
 const k=[
  ['Coverage ≥ 90%', 'TRACE: 100%',true],
  ['Robustness ≥ 85%', 'TRACE: 100%',true],
  ['FPR ≤ 5%', 'TRACE: 16,67%',false],
 ];
 k.forEach((c,i)=>{
  const y=3.12+i*.97;
  rect(s,.91,y,11.3,.79,'1B3B52','31516A',.1);
  txt(s,c[0],1.22,y+.21,5.00,.34,18,C.white,{bold:true});
  txt(s,c[1],7.11,y+.21,3.13,.34,18,c[2]?'8CE1D2':'F4BB9B',{bold:true});
  txt(s,c[2]?'PASS':'FAIL',10.48,y+.21,1.33,.34,16,c[2]?'8CE1D2':'FFAFB4',{bold:true,align:'right'});
 });
 txt(s,'Ngưỡng minh họa; chưa có triển khai sản xuất hoặc đo CRS thực.',1.00,6.69,11.20,.28,12,'C9DAE4');
 note(s,'Đây là điểm mấu chốt của học phần quản trị: đạt coverage và robustness không có nghĩa được auto-deploy. FPR không qua gate. Gate là minh họa, phải định nghĩa theo appetite của doanh nghiệp và dữ liệu production. Khuyến nghị chỉ triển khai shadow và xét lại sau khi có tập benign thật.');
}
// Slide 13 --------------------------------------------------------
{
 const s=pptx.addSlide();header(s,'Quản trị','Rule phải có bằng chứng, chủ sở hữu và lối quay lui');
 const phase=[['01','Đề xuất','CWE/CVE & chứng cứ'],['02','Kiểm tra','Cú pháp / semantics'],['03','Đánh giá','Benchmark ba trục'],['04','Phê duyệt','AppSec + ứng dụng'],['05','Canary','Giám sát / rollback']];
 phase.forEach((p,i)=>{
  const x=.82+i*2.49;
  rect(s,x,2.00,2.25,2.22,i===4?C.ltTeal:C.blue,C.rule,.12);
  txt(s,p[0],x+.18,2.18,.56,.41,20,C.teal,{bold:true});
  txt(s,p[1],x+.18,2.78,1.95,.42,18,C.navy,{bold:true});
  txt(s,p[2],x+.18,3.40,1.91,.54,12,C.slate,{valign:'top'});
  if(i<4)txt(s,'→',x+2.29,2.82,.15,.33,19,C.teal,{bold:true});
 });
 rect(s,1.02,4.93,11.24,1.18,C.light,C.rule,.12);
 txt(s,'Sổ rule: ID • CWE • Evidence • Scope • Owner • Review state • TTL • Rollback',1.39,5.19,10.50,.36,17,C.navy,{bold:true});
 txt(s,'Prototype hiện có 3 bản ghi: TW-001 / TW-002 / TW-003',1.42,5.68,10.3,.26,13,C.muted);
 footer(s,13,'NIST AI RMF 1.0');
 note(s,'Sổ luật có mã TW-001/002/003, liên kết CWE nguồn, phạm vi route, owner giả định, trạng thái prototype_only, rollback và TTL review 30 ngày. NIST AI RMF cung cấp cấu trúc Govern, Map, Measure, Manage cho phần LLM nếu nghiên cứu mở rộng. Không có ánh xạ CVE xác thực tại thời điểm này.',[
   'https://doi.org/10.6028/NIST.AI.100-1',
   'https://cwe.mitre.org/']);
}
// Slide 14 --------------------------------------------------------
{
 const s=pptx.addSlide();header(s,'Hạn chế','Tuyên bố chính xác giới hạn → thiết kế thí nghiệm tiếp theo');
 rect(s,.83,1.92,5.62,3.80,C.paleOrange,C.paleOrange);
 txt(s,'CHƯA KIỂM CHỨNG',1.13,2.21,4.9,.39,17,'9A5818',{bold:true});
 const left=['LLM inference hay sinh rule thật','WAF thương mại và OWASP CRS chạy thật','Hiệu lực khai thác CVE trên backend','Lưu lượng benign sản xuất / latency'];
 left.forEach((v,i)=>txt(s,'• '+v,1.15,2.89+i*.57,4.86,.46,15,C.navy));
 rect(s,6.80,1.92,5.62,3.80,C.ltTeal,C.ltTeal);
 txt(s,'BƯỚC TIẾP THEO',7.11,2.21,4.9,.39,17,C.teal,{bold:true});
 const right=['Lab ModSecurity + CRS có ghim phiên bản','Xác minh nhãn bằng app vulnerable có phép','Corpus benign độc lập theo ứng dụng','LLM có baseline, ngân sách và audit'];
 right.forEach((v,i)=>txt(s,'• '+v,7.12,2.89+i*.57,4.92,.46,15,C.navy));
 txt(s,'Kết quả hiện tại là proof of method, không phải chứng minh WAF/LLM tốt hơn sản phẩm thực.',1.03,6.10,11.5,.43,15,C.slate,{bold:true});
 footer(s,14);
 note(s,'Nói thẳng hạn chế. Đặc biệt seed-template overlap, semantics biến đổi không được thực thi; mô hình route /tutorial giả định HTML escape; hard negatives cố ý dày. Muốn bảo vệ publish khoa học cần đối chứng LLM, CWE/CVE độc lập và kết quả trên WAF thực có phép.');
}
// Slide 15 --------------------------------------------------------
{
 const s=pptx.addSlide();bg(s,C.deep);
 txt(s,'KẾT LUẬN',.91,.73,9,.33,13,'7DE3D7',{bold:true,charSpacing:1.6});
 txt(s,'Đo đúng trước khi\nđưa rule vào vận hành.',.92,1.51,11.68,1.80,36,C.white,{bold:true,valign:'top'});
 rect(s,.95,4.17,11.41,1.29,'1D4357','1D4357');
 txt(s,'3 trục đánh giá  +  nguồn CWE/CVE  +  human approval  +  canary/rollback',1.31,4.47,10.73,.69,19,C.white,{bold:true});
 txt(s,'Câu hỏi & phản biện',.94,6.31,9.5,.52,21,'A6DBD8');
 txt(s,'Kết quả có thể tái lập  ·  Không tuyên bố hiệu quả LLM hay WAF thương mại',.96,6.92,10.8,.27,11,'BACCDD');
 note(s,'Kết luận một câu: nghiên cứu bổ sung một cổng quyết định có truy vết, mã chạy lại và chính sách không auto-deploy khi FPR vẫn cao. Nếu được hỏi tính mới, nhấn mạnh tích hợp các trục và change-control ở quy mô bài tập, không khẳng định chuẩn đầu tiên. Nếu được hỏi 100% coverage: chỉ trong test hẹp, không chứng minh không có bypass.');
}

// Every externally sourced claim has a matching [Sources] note block.
// Diagnostics are run for all slides. Decorative cards intentionally contain text.
for (const slide of pptx._slides){
  warnIfSlideHasOverlaps(slide,pptx);
  warnIfSlideElementsOutOfBounds(slide,pptx);
}
pptx.writeFile({fileName:OUT});
console.log('Generated',OUT,'slides',pptx._slides.length);
