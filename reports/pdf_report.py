"""
Obsidian Lens — Professional PDF Forensic Report Generator
Generates per-capture reports with:
  - Cover page with capture metadata
  - Behavioral analysis summary
  - Most influential parameters (feature importance)
  - XAI conclusions
  - Analysis suggestions
  - Flow classifications
  - Protocol distribution & DNS analysis
  - 78-dimension behavioral fingerprint reference
"""

import os
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch, mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether
)
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.graphics import renderPDF
from config import REPORTS_FOLDER


# ─── Color Palette ────────────────────────────────────────────────────────────

DARK_BG       = colors.HexColor('#0a0e17')
CARD_BG       = colors.HexColor('#1a1f2e')
ACCENT_BLUE   = colors.HexColor('#60a5fa')
ACCENT_PURPLE = colors.HexColor('#a78bfa')
ACCENT_GREEN  = colors.HexColor('#34d399')
ACCENT_ORANGE = colors.HexColor('#fb923c')
ACCENT_RED    = colors.HexColor('#f87171')
ACCENT_AMBER  = colors.HexColor('#fbbf24')
TEXT_PRIMARY  = colors.HexColor('#111827')
TEXT_MUTED    = colors.HexColor('#6b7280')
TEXT_WHITE    = colors.HexColor('#f9fafb')
BORDER_COLOR  = colors.HexColor('#e5e7eb')
ROW_ALT       = colors.HexColor('#f8fafc')
HEADER_BG     = colors.HexColor('#1e293b')


# ─── Page callback for header/footer ─────────────────────────────────────────

class _HeaderFooterCanvas:
    """Adds a thin top accent line + footer on every page."""

    def __init__(self, filename, analysis_id, report_title, **kwargs):
        from reportlab.pdfgen import canvas as _canvas
        self._canvas = _canvas.Canvas(filename, **kwargs)
        self.analysis_id = analysis_id
        self.report_title = report_title
        self._saved_page_states = []

    def __getattr__(self, name):
        return getattr(self._canvas, name)

    def showPage(self):
        self._saved_page_states.append(dict(self._canvas.__dict__))
        self._start_new_page()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self._canvas.__dict__.update(state)
            self._draw_header_footer(num_pages)
            self._canvas.showPage()
        self._canvas.save()

    def _start_new_page(self):
        self._canvas._startPage()

    def _draw_header_footer(self, page_count):
        c = self._canvas
        w, h = A4
        page_num = self._canvas._pageNumber

        # Top accent bar
        c.setFillColor(ACCENT_BLUE)
        c.rect(0, h - 6, w, 6, fill=1, stroke=0)

        # Footer line
        c.setStrokeColor(BORDER_COLOR)
        c.setLineWidth(0.5)
        c.line(20 * mm, 14 * mm, w - 20 * mm, 14 * mm)

        # Footer text
        c.setFillColor(TEXT_MUTED)
        c.setFont("Helvetica", 7)
        c.drawString(20 * mm, 10 * mm, f"Obsidian Lens — Forensic Report  ·  ID: {self.analysis_id}")
        c.drawRightString(w - 20 * mm, 10 * mm, f"Page {page_num} of {page_count}  ·  {datetime.now().strftime('%Y-%m-%d')}")
        c.drawCentredString(w / 2, 10 * mm, self.report_title)


# ─── Feature Importance Bar Chart (pure ReportLab Drawing) ───────────────────

def _feature_bar_chart(top_features, width=440, bar_height=14, padding=6):
    """Returns a ReportLab Drawing with horizontal feature importance bars."""
    if not top_features:
        return None

    max_val = max(v for _, v in top_features) if top_features else 1
    bar_colors = [ACCENT_BLUE, ACCENT_PURPLE, ACCENT_PURPLE, ACCENT_BLUE,
                  ACCENT_BLUE, TEXT_MUTED, TEXT_MUTED, TEXT_MUTED, TEXT_MUTED, TEXT_MUTED]

    label_width = 150
    bar_area = width - label_width - 60  # 60 for value label
    row_h = bar_height + padding
    total_h = len(top_features) * row_h + 10

    d = Drawing(width, total_h)

    for i, (name, val) in enumerate(top_features):
        y = total_h - (i + 1) * row_h + padding // 2
        bar_w = (val / max_val) * bar_area if max_val > 0 else 0
        color = bar_colors[i] if i < len(bar_colors) else TEXT_MUTED

        # Feature name
        d.add(String(0, y + 2, name[:28], fontName='Courier', fontSize=7, fillColor=TEXT_PRIMARY))

        # Background track
        track = Rect(label_width, y, bar_area, bar_height - 2,
                     fillColor=colors.HexColor('#f1f5f9'), strokeColor=None)
        d.add(track)

        # Filled bar
        if bar_w > 0:
            bar = Rect(label_width, y, bar_w, bar_height - 2,
                       fillColor=color, strokeColor=None)
            d.add(bar)

        # Value label
        pct_str = f"{val * 100:.1f}%"
        d.add(String(label_width + bar_area + 4, y + 2, pct_str,
                     fontName='Helvetica', fontSize=7, fillColor=TEXT_MUTED))

    return d


# ─── Main Entry Point ─────────────────────────────────────────────────────────

def generate_pdf_report(analysis_id, analysis_data, predictions=None,
                        explanations=None, topology=None, metadata=None):
    """
    Generate a professional per-record PDF forensic report.

    Args:
        analysis_id:    Short analysis ID string
        analysis_data:  flow_analysis dict from the analysis record
        predictions:    list of prediction dicts (category, confidence, is_malicious, …)
        explanations:   list with top_features + insights from XAI engine
        topology:       optional network topology summary dict
        metadata:       capture metadata dict (total_packets, total_flows, …)

    Returns:
        str: absolute path to the generated PDF file
    """
    os.makedirs(REPORTS_FOLDER, exist_ok=True)
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"ObsidianLens_Report_{analysis_id}_{ts}.pdf"
    filepath = os.path.join(REPORTS_FOLDER, filename)

    predictions  = predictions  or []
    explanations = explanations or []
    metadata     = metadata     or {}

    doc = SimpleDocTemplate(
        filepath, pagesize=A4,
        leftMargin=20 * mm, rightMargin=20 * mm,
        topMargin=28 * mm, bottomMargin=22 * mm,
        title=f"Obsidian Lens Forensic Report — {analysis_id}",
        author="Obsidian Lens Automated Analysis Engine",
        subject="Network Forensic Report",
    )

    styles = _create_styles()
    elements = []

    # ─── COVER PAGE ──────────────────────────────────────────────────────────
    elements.append(Spacer(1, 40))

    # Logo / Brand
    elements.append(Paragraph("OBSIDIAN LENS", styles['Brand']))
    elements.append(Spacer(1, 4))
    elements.append(Paragraph(
        "Behavioral Fingerprinting for Network Forensics in Encrypted Traffic",
        styles['BrandSub']
    ))
    elements.append(Spacer(1, 32))
    elements.append(HRFlowable(width="100%", thickness=2, color=ACCENT_BLUE, spaceAfter=0))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=ACCENT_PURPLE, spaceBefore=3, spaceAfter=20))

    elements.append(Paragraph("Forensic Analysis Report", styles['CoverTitle']))
    elements.append(Spacer(1, 6))

    # Threat level badge
    malicious_count = sum(1 for p in predictions if p.get('is_malicious'))
    threat_pct = (malicious_count / len(predictions) * 100) if predictions else 0
    threat_label = "CRITICAL" if threat_pct > 50 else "ELEVATED" if threat_pct > 10 else "CLEAR"
    threat_color = ACCENT_RED if threat_label == "CRITICAL" else ACCENT_AMBER if threat_label == "ELEVATED" else ACCENT_GREEN

    threat_table = Table(
        [[Paragraph(f"THREAT LEVEL: {threat_label}", styles['ThreatBadge'])]],
        colWidths=[200]
    )
    threat_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), threat_color),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('ROUNDEDCORNERS', [4]),
    ]))
    # Center it
    cover_layout = Table([[None, threat_table, None]], colWidths=[100, 200, 100])
    cover_layout.setStyle(TableStyle([('ALIGN', (0, 0), (-1, -1), 'CENTER'), ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')]))
    elements.append(cover_layout)

    elements.append(Spacer(1, 28))

    # Metadata grid
    gen_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
    meta_rows = [
        ['Analysis ID',      analysis_id,
         'Generated',        gen_time],
        ['System',           'Obsidian Lens v2 — 78 Behavioral Features',
         'Source',           metadata.get('source', 'PCAP Upload').replace('_', ' ').title()],
        ['Total Packets',    f"{metadata.get('total_packets', 'N/A'):,}" if isinstance(metadata.get('total_packets'), int) else str(metadata.get('total_packets', 'N/A')),
         'Total Flows',      str(len(predictions))],
        ['Capture Duration', f"{float(metadata.get('capture_duration', 0)):.2f}s",
         'Identities Found', str(metadata.get('identities_created', '—'))],
    ]
    meta_table = Table(meta_rows, colWidths=[95, 130, 75, 130])
    meta_table.setStyle(TableStyle([
        ('FONTNAME',      (0, 0), (-1, -1), 'Helvetica'),
        ('FONTNAME',      (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTNAME',      (2, 0), (2, -1), 'Helvetica-Bold'),
        ('FONTSIZE',      (0, 0), (-1, -1), 9),
        ('TEXTCOLOR',     (0, 0), (0, -1), ACCENT_BLUE),
        ('TEXTCOLOR',     (2, 0), (2, -1), ACCENT_BLUE),
        ('TOPPADDING',    (0, 0), (-1, -1), 7),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 7),
        ('LINEBELOW',     (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ('BACKGROUND',    (0, 0), (-1, 0), colors.HexColor('#f8fafc')),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 20))

    # Key finding callout
    elements.append(_callout(
        "⚡ Behavioral Persistence Engine",
        "BENFET identifies devices by analyzing <b>78 behavioral dimensions</b> — not IP addresses. "
        "Even when attackers change IPs via VPN or proxy, their behavioral fingerprint remains consistent. "
        "This enables high-confidence identification of cyber criminals across sessions.",
        styles
    ))
    elements.append(Spacer(1, 8))

    # ─── PAGE 2: XAI SECTION ─────────────────────────────────────────────────
    elements.append(PageBreak())
    elements.append(_section_header("Most Influential Parameters", styles))

    top_features = explanations[0].get('top_features', []) if explanations else []
    insights     = explanations[0].get('insights', [])     if explanations else []

    if top_features:
        elements.append(Paragraph(
            "The following features had the highest attribution weight in the model's classification decision. "
            "Scores represent normalised SHAP / Gini importance across the Random Forest ensemble.",
            styles['Body']
        ))
        elements.append(Spacer(1, 10))

        chart = _feature_bar_chart(top_features[:10])
        if chart:
            elements.append(chart)
            elements.append(Spacer(1, 16))

        # Table version for precise values
        feat_rows = [['Rank', 'Feature', 'Importance Weight', 'Contribution']]
        for i, (name, val) in enumerate(top_features[:10], 1):
            bar_cells = '█' * int(val / max(v for _, v in top_features) * 20) if top_features else ''
            feat_rows.append([
                str(i), name,
                f"{val * 100:.2f}%",
                bar_cells or '▌',
            ])
        feat_table = Table(feat_rows, colWidths=[30, 160, 90, 140])
        feat_table.setStyle(_table_style(header_color=HEADER_BG))
        elements.append(feat_table)
        elements.append(Spacer(1, 20))
    else:
        elements.append(Paragraph(
            "Feature importance data unavailable — run analysis with a trained model to generate XAI insights.",
            styles['Muted']
        ))
        elements.append(Spacer(1, 16))

    # ─── XAI CONCLUSIONS ─────────────────────────────────────────────────────
    elements.append(_section_header("XAI Conclusions", styles))

    if insights:
        elements.append(Paragraph(
            "The following conclusions were automatically generated by correlating the model's feature attribution "
            "with the Obsidian Lens forensic knowledge base. Each finding identifies the exact behavioral signal "
            "that drove the classification.",
            styles['Body']
        ))
        elements.append(Spacer(1, 10))

        for i, insight in enumerate(insights, 1):
            # Parse the structured insight string: [feature] (weight%): text
            import re
            feature_match = re.match(r'^\[([^\]]+)\]', insight)
            weight_match  = re.search(r'\(([^)]+Weight[^)]*)\)', insight)
            feature_name  = feature_match.group(1) if feature_match else f"Finding {i}"
            weight_label  = weight_match.group(1)  if weight_match  else ""

            # Strip the [feature] (weight): prefix to get pure text
            body = re.sub(r'^\[[^\]]+\]\s*\([^)]+\):\s*', '', insight).strip()

            insight_data = [
                [Paragraph(f"<b>{i}. [{feature_name}]</b>  <font color='#6b7280' size='8'>{weight_label}</font>", styles['InsightTitle'])],
                [Paragraph(body, styles['InsightBody'])],
            ]
            insight_table = Table(insight_data, colWidths=[430])
            insight_table.setStyle(TableStyle([
                ('BACKGROUND',    (0, 0), (-1, 0), colors.HexColor('#eff6ff')),
                ('BACKGROUND',    (0, 1), (-1, 1), colors.white),
                ('LEFTPADDING',   (0, 0), (-1, -1), 12),
                ('RIGHTPADDING',  (0, 0), (-1, -1), 12),
                ('TOPPADDING',    (0, 0), (-1, 0), 8),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
                ('TOPPADDING',    (0, 1), (-1, 1), 6),
                ('BOTTOMPADDING', (0, 1), (-1, 1), 10),
                ('BOX',           (0, 0), (-1, -1), 0.5, BORDER_COLOR),
                ('LINEBELOW',     (0, 0), (-1, 0), 0.5, BORDER_COLOR),
                ('ROUNDEDCORNERS', [4]),
            ]))
            elements.append(KeepTogether([insight_table, Spacer(1, 8)]))
    else:
        elements.append(Paragraph("No XAI insights available for this capture.", styles['Muted']))
    elements.append(Spacer(1, 10))

    # ─── ANALYSIS SUGGESTIONS ────────────────────────────────────────────────
    elements.append(_section_header("Analysis Suggestions", styles))
    suggestions = _build_suggestions(predictions)
    sug_rows = [[Paragraph(f"<b>{s['icon']} {s['title']}</b>", styles['SugTitle']),
                 Paragraph(s['text'], styles['Body'])]
                for s in suggestions]
    if sug_rows:
        sug_table = Table(sug_rows, colWidths=[90, 340])
        sug_table.setStyle(TableStyle([
            ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
            ('TOPPADDING',    (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('LINEBELOW',     (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('BACKGROUND',    (0, 0), (-1, 0), ROW_ALT),
        ]))
        elements.append(sug_table)
    elements.append(Spacer(1, 10))

    # ─── PAGE 3: FLOW CLASSIFICATIONS ────────────────────────────────────────
    if predictions:
        elements.append(PageBreak())
        elements.append(_section_header("Flow Classifications (Top 50)", styles))
        
        # Sort predictions: Malicious first, then by confidence highest to lowest
        sorted_preds = sorted(predictions, key=lambda x: (not x.get('is_malicious', False), -x.get('confidence', 0)))
        
        elements.append(Paragraph(
            f"{len(predictions)} network flows were classified. "
            f"{malicious_count} malicious ({threat_pct:.1f}%) · "
            f"{len(predictions) - malicious_count} benign. "
            "Showing top highest-confidence classifications.",
            styles['Body']
        ))
        elements.append(Spacer(1, 10))

        pred_header = ['#', 'Src IP', 'Dst IP', 'Category', 'Threat Type', 'Confidence', 'VPN']
        pred_rows = [pred_header]
        for i, p in enumerate(sorted_preds[:50], 1):
            pred_rows.append([
                str(i),
                p.get('src_ip', '—'),
                p.get('dst_ip', '—'),
                p.get('category', '—'),
                p.get('threat_type', '—'),
                f"{p.get('confidence', 0) * 100:.1f}%",
                'Yes' if p.get('is_vpn') else '—',
            ])
        if len(sorted_preds) > 50:
            pred_rows.append(['...', f'+ {len(sorted_preds) - 50} more flows', '', '', '', '', ''])

        pred_table = Table(pred_rows, colWidths=[22, 80, 80, 65, 80, 60, 33])
        pred_table.setStyle(_table_style(header_color=HEADER_BG))
        # Highlight malicious rows
        for i, p in enumerate(sorted_preds[:50], 1):
            if p.get('is_malicious'):
                pred_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, i), (-1, i), colors.HexColor('#fff1f1')),
                    ('TEXTCOLOR',  (4, i), (4, i), ACCENT_RED),
                ]))
        elements.append(pred_table)
        elements.append(Spacer(1, 20))

    # ─── PROTOCOL DISTRIBUTION ───────────────────────────────────────────────
    if analysis_data and analysis_data.get('protocol_distribution'):
        elements.append(_section_header("Protocol Distribution", styles))
        proto_header = ['Protocol', 'Packets', 'Bytes', 'Pkt %', 'Byte %']
        proto_rows = [proto_header]
        for p in analysis_data['protocol_distribution']:
            proto_rows.append([
                p['protocol'],
                f"{p['packet_count']:,}",
                _format_bytes(p['byte_count']),
                f"{p['packet_ratio'] * 100:.1f}%",
                f"{p['byte_ratio'] * 100:.1f}%",
            ])
        proto_table = Table(proto_rows, colWidths=[90, 80, 90, 80, 80])
        proto_table.setStyle(_table_style())
        elements.append(proto_table)
        elements.append(Spacer(1, 20))

    # ─── TOP FLOWS ───────────────────────────────────────────────────────────
    if analysis_data and analysis_data.get('flow_summaries'):
        elements.append(_section_header("Top Network Flows", styles))
        flow_header = ['Flow', 'Proto', 'Packets', 'Bytes', 'Duration']
        flow_rows = [flow_header]
        for f in analysis_data['flow_summaries'][:15]:
            flow_rows.append([
                Paragraph(f['flow'], styles['Mono']),
                f['protocol'],
                f"{f['total_packets']:,}",
                _format_bytes(f['total_bytes']),
                f"{f['duration']:.3f}s",
            ])
        flow_table = Table(flow_rows, colWidths=[175, 45, 65, 75, 60])
        flow_table.setStyle(_table_style())
        elements.append(flow_table)
        elements.append(Spacer(1, 20))



    # ─── DNS ANALYSIS ────────────────────────────────────────────────────────
    if analysis_data and analysis_data.get('dns_analysis'):
        elements.append(Spacer(1, 16))
        elements.append(_section_header("DNS Analysis", styles))
        dns = analysis_data['dns_analysis']
        dns_data = [
            ['Total DNS Queries', str(dns.get('total_dns_queries', 0))],
            ['DNS / Total Traffic Ratio', f"{dns.get('dns_ratio', 0) * 100:.2f}%"],
        ]
        dns_table = Table(dns_data, colWidths=[160, 270])
        dns_table.setStyle(TableStyle([
            ('FONTNAME',      (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE',      (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 7),
            ('TOPPADDING',    (0, 0), (-1, -1), 7),
            ('LINEBELOW',     (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ]))
        elements.append(dns_table)

    # ─── BUILD ───────────────────────────────────────────────────────────────
    doc.build(elements)
    return filepath


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _section_header(title, styles):
    return KeepTogether([
        HRFlowable(width="100%", thickness=0.5, color=BORDER_COLOR, spaceBefore=4, spaceAfter=0),
        Spacer(1, 6),
        Paragraph(title, styles['SectionHeading']),
        Spacer(1, 8),
    ])


def _callout(title, body, styles):
    data = [
        [Paragraph(f"<b>{title}</b>", styles['CalloutTitle'])],
        [Paragraph(body, styles['CalloutBody'])],
    ]
    t = Table(data, colWidths=[430])
    t.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, 0), colors.HexColor('#eff6ff')),
        ('BACKGROUND',    (0, 1), (-1, 1), colors.HexColor('#f8fafc')),
        ('LEFTPADDING',   (0, 0), (-1, -1), 14),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 14),
        ('TOPPADDING',    (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('TOPPADDING',    (0, 1), (-1, 1), 8),
        ('BOTTOMPADDING', (0, 1), (-1, 1), 12),
        ('BOX',           (0, 0), (-1, -1), 1.5, ACCENT_BLUE),
        ('LINEBELOW',     (0, 0), (-1, 0), 0.5, BORDER_COLOR),
    ]))
    return t


def _build_suggestions(predictions):
    malicious = [p for p in predictions if p.get('is_malicious')]
    threats   = list({p.get('threat_type', '') for p in malicious if p.get('threat_type')})
    sug = []

    if malicious:
        sug.append({'icon': '🔴', 'title': 'Immediate Review',
                    'text': f"{len(malicious)} malicious flow{'s' if len(malicious) > 1 else ''} detected. "
                            "Immediate investigation of flagged identities is recommended."})
        if threats:
            sug.append({'icon': '⚠️', 'title': 'Threat Attribution',
                        'text': f"Detected threat types: {', '.join(threats)}. "
                                "Cross-reference with MITRE ATT&CK framework for TTP attribution."})
        if any('ddos' in (t.lower() or '') for t in threats):
            sug.append({'icon': '🛡️', 'title': 'DDoS Mitigation',
                        'text': "DDoS pattern identified. Enable rate-limiting upstream and "
                                "consider blackhole routing for persistent source IPs."})
        if any(k in ' '.join(threats).lower() for k in ['botnet', 'c2', 'beacon', 'rat']):
            sug.append({'icon': '🔍', 'title': 'C2 / Botnet Response',
                        'text': "C2 beacon or botnet behavior detected. Isolate affected endpoints "
                                "and conduct memory forensics for persistence mechanisms."})
        sug.append({'icon': '📄', 'title': 'Documentation',
                    'text': "Export this PDF for court-admissible documentation and chain-of-custody records."})
    else:
        sug.append({'icon': '✅', 'title': 'Traffic Normal',
                    'text': "No malicious flows detected. Traffic patterns are within expected behavioral baselines."})
        sug.append({'icon': '📊', 'title': 'Baseline Archival',
                    'text': "Archive this capture as a baseline reference for future anomaly comparison."})

    vpn = [p for p in predictions if p.get('is_vpn')]
    if vpn:
        sug.append({'icon': '🔐', 'title': 'VPN-Masked Flows',
                    'text': f"{len(vpn)} VPN-masked flow{'s' if len(vpn) > 1 else ''} identified via behavioral fingerprint, "
                            "bypassing standard IP-based detection."})
    return sug


def _create_styles():
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle('Brand', parent=styles['Title'],
        fontSize=26, textColor=ACCENT_BLUE, spaceAfter=4,
        alignment=TA_CENTER, fontName='Helvetica-Bold', letterSpacing=4))

    styles.add(ParagraphStyle('BrandSub', parent=styles['Normal'],
        fontSize=9, textColor=TEXT_MUTED, alignment=TA_CENTER, spaceAfter=0))

    styles.add(ParagraphStyle('CoverTitle', parent=styles['Heading1'],
        fontSize=20, textColor=TEXT_PRIMARY, spaceAfter=14,
        alignment=TA_CENTER, fontName='Helvetica-Bold'))

    styles.add(ParagraphStyle('ThreatBadge', parent=styles['Normal'],
        fontSize=11, fontName='Helvetica-Bold', textColor=colors.white,
        alignment=TA_CENTER))

    styles.add(ParagraphStyle('SectionHeading', parent=styles['Heading2'],
        fontSize=13, textColor=ACCENT_BLUE, spaceBefore=4, spaceAfter=0,
        fontName='Helvetica-Bold'))

    styles.add(ParagraphStyle('Body', parent=styles['BodyText'],
        fontSize=9, leading=14, spaceAfter=4, textColor=TEXT_PRIMARY))

    styles.add(ParagraphStyle('Muted', parent=styles['BodyText'],
        fontSize=9, leading=14, textColor=TEXT_MUTED))

    styles.add(ParagraphStyle('Mono', parent=styles['Normal'],
        fontSize=7, fontName='Courier', leading=9))

    styles.add(ParagraphStyle('InsightTitle', parent=styles['BodyText'],
        fontSize=9, fontName='Helvetica-Bold', textColor=TEXT_PRIMARY, leading=13))

    styles.add(ParagraphStyle('InsightBody', parent=styles['BodyText'],
        fontSize=9, leading=14, textColor=TEXT_MUTED))

    styles.add(ParagraphStyle('CalloutTitle', parent=styles['BodyText'],
        fontSize=9, fontName='Helvetica-Bold', textColor=ACCENT_BLUE, leading=13))

    styles.add(ParagraphStyle('CalloutBody', parent=styles['BodyText'],
        fontSize=9, leading=14, textColor=TEXT_PRIMARY))

    styles.add(ParagraphStyle('SugTitle', parent=styles['BodyText'],
        fontSize=9, fontName='Helvetica-Bold', textColor=TEXT_PRIMARY, leading=13))

    return styles


def _table_style(header_color=ACCENT_BLUE):
    return TableStyle([
        ('FONTNAME',       (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE',       (0, 0), (-1, -1), 8),
        ('TEXTCOLOR',      (0, 0), (-1, 0), TEXT_WHITE),
        ('BACKGROUND',     (0, 0), (-1, 0), header_color),
        ('ALIGN',          (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN',         (0, 0), (-1, -1), 'MIDDLE'),
        ('BOTTOMPADDING',  (0, 0), (-1, -1), 6),
        ('TOPPADDING',     (0, 0), (-1, -1), 6),
        ('LINEBELOW',      (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, ROW_ALT]),
    ])


def _format_bytes(b):
    if not b:
        return '0 B'
    for unit in ['B', 'KB', 'MB', 'GB']:
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} TB"
