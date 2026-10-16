#!/usr/bin/env python3
"""Build DOCX and standalone XeLaTeX source from one Markdown manuscript.
Needs pandoc, python-docx and an installed XeLaTeX for optional PDF compile.
"""
from pathlib import Path
import subprocess
import re
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_CELL_VERTICAL_ALIGNMENT
from docx.oxml import OxmlElement
from docx.oxml.ns import qn

ROOT=Path(__file__).resolve().parents[1]
NAME="BAO_CAO_TRACE_WAF"
MD=ROOT/f"{NAME}.md"
REF=ROOT/"tools/reference.docx"
NAVY=RGBColor(30,54,80)
TEAL=RGBColor(25,130,127)
GRAY=RGBColor(76,89,101)

def set_font(style,face,size,color=None,bold=None):
    style.font.name=face
    style.font.size=Pt(size)
    if color:style.font.color.rgb=color
    if bold is not None:style.font.bold=bold
    rpr=style.element.get_or_add_rPr()
    rf=rpr.rFonts
    if rf is None:
        rf=OxmlElement('w:rFonts');rpr.insert(0,rf)
    for tag in ('ascii','hAnsi','eastAsia','cs'): rf.set(qn('w:'+tag),face)

def make_reference():
    doc=Document()
    sec=doc.sections[0]
    sec.page_width=Inches(8.5)
    sec.page_height=Inches(11)
    sec.top_margin=Inches(.86)
    sec.bottom_margin=Inches(.86)
    sec.left_margin=Inches(.91)
    sec.right_margin=Inches(.91)
    sec.header_distance=Inches(.36)
    sec.footer_distance=Inches(.42)
    styles=doc.styles
    normal=styles['Normal'];set_font(normal,'Noto Serif',10.5,RGBColor(38,48,60))
    normal.paragraph_format.space_after=Pt(7)
    normal.paragraph_format.line_spacing=1.27
    for i,size in ((1,13.8),(2,11.7),(3,10.8)):
        st=styles[f'Heading {i}'];set_font(st,'Noto Sans',size,NAVY,True)
        st.paragraph_format.space_before=Pt(15 if i==1 else 10)
        st.paragraph_format.space_after=Pt(5)
        st.paragraph_format.keep_with_next=True
    for sn,face,size,col in [('Title','Noto Sans',17.8,NAVY),('Subtitle','Noto Sans',10,GRAY),('Caption','Noto Serif',9,GRAY),('Source Code','Noto Sans Mono',8.4,GRAY)]:
        if sn in styles:
            st=styles[sn];set_font(st,face,size,col,sn=='Title')
            st.paragraph_format.space_after=Pt(6)
    for sn in ('Table Caption','Image Caption'):
        if sn in styles:
            set_font(styles[sn],'Noto Serif',9,GRAY)
    foot=sec.footer.paragraphs[0]
    foot.alignment=WD_ALIGN_PARAGRAPH.RIGHT
    rr=foot.add_run('TRACE-WAF · Báo cáo nghiên cứu  |  Trang ')
    rr.font.name='Noto Sans';rr.font.size=Pt(8);rr.font.color.rgb=GRAY
    fld=OxmlElement('w:fldSimple');fld.set(qn('w:instr'),'PAGE');foot._p.append(fld)
    doc.save(REF)

def style_docx():
    doc=Document(ROOT/f"{NAME}.docx")
    # First paragraph is the manuscript title; rest is unchanged.
    first=next((p for p in doc.paragraphs if p.text.strip()),None)
    if first:
        first.style=doc.styles['Title']
        first.paragraph_format.space_after=Pt(18)
    for p in doc.paragraphs:
        p.paragraph_format.widow_control=True
        if p.style.name in ('Heading 1','Heading 2','Heading 3'):
            p.paragraph_format.keep_with_next=True
    for ti,old in enumerate(list(doc.tables)):
        data=[[c.text for c in r.cells] for r in old.rows]
        t=doc.add_table(rows=len(data),cols=len(data[0]))
        old._tbl.addprevious(t._tbl)
        old._tbl.getparent().remove(old._tbl)
        for ri,values in enumerate(data):
            for ci,value in enumerate(values): t.rows[ri].cells[ci].text=value
        t.alignment=WD_TABLE_ALIGNMENT.CENTER
        widths = [
            [1.25,1.62,1.60,2.08],
            [2.15,1.00,1.18,2.22],
            [1.75,0.67,0.67,1.05,0.65,1.76],
            [1.54,1.20,1.58,1.19,1.04],
            [2.40,0.67,1.16,1.27,1.05],
            [1.42,3.18,1.95]
        ][ti]
        t.autofit=False
        tblw=t._tbl.tblPr.find(qn('w:tblW'))
        if tblw is not None:
            tblw.set(qn('w:w'),str(round(sum(widths)*1440)))
            tblw.set(qn('w:type'),'dxa')
        for i,w in enumerate(widths):t.columns[i].width=Inches(w)
        for ri,row in enumerate(t.rows):
            trpr=row._tr.get_or_add_trPr()
            cant=OxmlElement('w:cantSplit');trpr.append(cant)
            for i,w in enumerate(widths):row.cells[i].width=Inches(w)
            for ci,cell in enumerate(row.cells):
                cell.vertical_alignment=WD_CELL_VERTICAL_ALIGNMENT.CENTER
                tcPr=cell._tc.get_or_add_tcPr()
                mar=tcPr.first_child_found_in('w:tcMar')
                if mar is None:
                    mar=OxmlElement('w:tcMar');tcPr.append(mar)
                for side in ('top','start','bottom','end'):
                    x=mar.find(qn('w:'+side))
                    if x is None: x=OxmlElement('w:'+side);mar.append(x)
                    x.set(qn('w:w'), '75' if side in ('top','bottom') else '95')
                    x.set(qn('w:type'),'dxa')
                if ri == 0:
                    shade=tcPr.find(qn('w:shd'))
                    if shade is None: shade=OxmlElement('w:shd');tcPr.append(shade)
                    shade.set(qn('w:fill'),'EAF1F6')
                for p in cell.paragraphs:
                    p.paragraph_format.space_after=Pt(0)
                    p.paragraph_format.line_spacing=1.15
                    for r in p.runs:
                        r.font.name='Noto Serif';r.font.size=Pt(8.6 if len(t.columns)>=5 else 9)
                        if ri==0:r.font.bold=True;r.font.color.rgb=NAVY
            if ri==0:
                trPr=row._tr.get_or_add_trPr()
                tblhdr=OxmlElement('w:tblHeader');tblhdr.set(qn('w:val'),'true');trPr.append(tblhdr)
    for image in doc.inline_shapes:
        maxwidth=Inches(6.52)
        if image.width>maxwidth:
            ratio=maxwidth/image.width
            image.width=maxwidth
            image.height=int(image.height*ratio)
    doc.save(ROOT/f"{NAME}.docx")


def main():
    make_reference()
    subprocess.run(['pandoc',str(MD),'-f','markdown+pipe_tables+tex_math_dollars+fenced_code_blocks',
        '--resource-path',str(ROOT),'-t','docx','--reference-doc',str(REF),
        '-o',str(ROOT/f'{NAME}.docx')],check=True,cwd=ROOT)
    style_docx()
    subprocess.run(['pandoc',str(MD),'-f','markdown+pipe_tables+tex_math_dollars+fenced_code_blocks',
        '--resource-path',str(ROOT),'-t','latex','--standalone','-V','documentclass=article',
        '-V','mainfont=Noto Serif','-V','sansfont=Noto Sans','-V','monofont=Noto Sans Mono',
        '-V','fontsize=10.5pt','-V','geometry=margin=0.91in','-V','papersize=letter',
        '-V','linestretch=1.17','-V','colorlinks=false','-V','urlcolor=NavyBlue',
        '-o',str(ROOT/f'{NAME}.tex')],check=True,cwd=ROOT)
    # Improve LaTeX line breaks for long literal reference links and place the
    # third figure at a page boundary rather than overflowing after longtable.
    tex_path=ROOT/f'{NAME}.tex'
    latex=tex_path.read_text(encoding='utf-8')
    begin=latex.index(r'\subsection{Tài liệu tham khảo}')
    finish=latex.index(r'\subsection{Phụ lục A.')
    ref=latex[begin:finish]
    ref=re.sub(r'https://[^\s\\{}<>]+',lambda m:r'\url{'+m.group(0).rstrip('.')+'}'+('.' if m.group(0).endswith('.') else ''),ref)
    latex=latex[:begin]+ref+latex[finish:]
    latex=re.sub(r'\\caption\\{Hình [0-9]+\\. ',r'\\caption{',latex)
    latex=latex.replace(r'\begin{document}',r'\renewcommand{\figurename}{Hình}'+'\n'+r'\begin{document}')
    latex=latex.replace('\\begin{figure}\n\\centering\n\\includegraphics[width=0.92\\textwidth,height=\\textheight]{assets/drift.png}',
        '\\clearpage\n\\begin{figure}[!htbp]\n\\centering\n\\includegraphics[width=0.86\\textwidth,height=0.40\\textheight,keepaspectratio]{assets/drift.png}')
    tex_path.write_text(latex,encoding='utf-8')
    print('Built DOCX and TEX from the same Markdown source')

if __name__=='__main__':main()
