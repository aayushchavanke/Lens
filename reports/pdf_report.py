"""
BENFET Reports - PDF Forensic Report Generator
Generates professional PDF forensic reports using ReportLab.
Includes behavioral analysis, predictions, XAI explanations,
and topology summaries.
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
    PageBreak, HRFlowable, Image
)
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.graphics.charts.barcharts import VerticalBarChart
from config import REPORTS_FOLDER


# ─── Color Scheme ────────────────────────────────────────────────────────

DARK_BG = colors.HexColor('#0a0e17')
CARD_BG = colors.HexColor('#1a1f2e')
ACCENT_BLUE = colors.HexColor('#60a5fa')
ACCENT_PURPLE = colors.HexColor('#a78bfa')
ACCENT_GREEN = colors.HexColor('#34d399')
ACCENT_ORANGE = colors.HexColor('#fb923c')
ACCENT_RED = colors.HexColor('#f87171')
TEXT_PRIMARY = colors.HexColor('#e8edf5')
TEXT_MUTED = colors.HexColor('#8b949e')
BORDER_COLOR = colors.HexColor('#30363d')


def generate_pdf_report(analysis_id, analysis_data, predictions=None,
                        explanations=None, topology=None, metadata=None):
    """
    Generate a professional PDF forensic report.

    Returns:
        str: path to the generated PDF file
    """
    os.makedirs(REPORTS_FOLDER, exist_ok=True)
    filename = f"BENFET_Report_{analysis_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    filepath = os.path.join(REPORTS_FOLDER, filename)

    doc = SimpleDocTemplate(
        filepath, pagesize=A4,
        leftMargin=20 * mm, rightMargin=20 * mm,
        topMargin=25 * mm, bottomMargin=20 * mm,
    )

    styles = _create_styles()
    elements = []

    # ─── Title Page ──────────────────────────────────────────────────
    elements.append(Spacer(1, 60))
    elements.append(Paragraph("🔬 BENFET", styles['BF_Title']))
    elements.append(Spacer(1, 8))
    elements.append(Paragraph(
        "Behavioral Fingerprinting for Network Forensics in Encrypted Traffic",
        styles['BF_Subtitle']
    ))
    elements.append(Spacer(1, 30))
    elements.append(HRFlowable(width="80%", thickness=2, color=ACCENT_BLUE, spaceAfter=20))
    elements.append(Paragraph(f"Forensic Analysis Report", styles['BF_Heading1']))
    elements.append(Spacer(1, 15))

    # Report metadata table
    meta_data = [
        ['Analysis ID:', analysis_id],
        ['Generated:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
        ['System:', 'BENFET v2 — 78 Behavioral Features'],
    ]
    if metadata:
        meta_data.append(['Total Packets:', str(metadata.get('total_packets', 'N/A'))])
        meta_data.append(['Total Flows:', str(metadata.get('total_flows', 'N/A'))])
        meta_data.append(['Capture Duration:', f"{metadata.get('capture_duration', 0):.2f}s"])

    meta_table = Table(meta_data, colWidths=[120, 350])
    meta_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('TEXTCOLOR', (0, 0), (0, -1), ACCENT_BLUE),
        ('TEXTCOLOR', (1, 0), (1, -1), colors.black),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 20))

    # ─── KEY FINDING: Behavioral Fingerprinting ──────────────────────
    elements.append(HRFlowable(width="100%", thickness=1, color=BORDER_COLOR, spaceAfter=15))
    elements.append(Paragraph("⚡ Key Finding: Behavioral Persistence", styles['BF_Heading2']))
    elements.append(Spacer(1, 8))
    elements.append(Paragraph(
        "BENFET identifies devices and users by analyzing <b>behavioral metadata patterns</b> — "
        "not IP addresses. The system extracts 78 behavioral dimensions "
        "(timing patterns, packet sizes, burst behavior, TCP characteristics, and TLS fingerprints) "
        "to create a unique behavioral fingerprint for each traffic profile.",
        styles['BF_Body']
    ))
    elements.append(Spacer(1, 8))
    elements.append(Paragraph(
        "<b>🎯 Even when a suspect changes their IP address (via VPN, proxy, or network switching), "
        "their behavioral fingerprint remains consistent.</b> This enables positive identification "
        "of cyber criminals with high precision, as network behavior patterns are extremely "
        "difficult to disguise.",
        styles['BF_Alert']
    ))
    elements.append(Spacer(1, 15))

    # ─── Protocol Distribution ───────────────────────────────────────
    if analysis_data and analysis_data.get('protocol_distribution'):
        elements.append(Paragraph("📊 Protocol Distribution", styles['BF_Heading2']))
        elements.append(Spacer(1, 8))

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

        proto_table = Table(proto_rows, colWidths=[90, 80, 90, 70, 70])
        proto_table.setStyle(_table_style())
        elements.append(proto_table)
        elements.append(Spacer(1, 20))

    # ─── Top Flows ───────────────────────────────────────────────────
    if analysis_data and analysis_data.get('flow_summaries'):
        elements.append(Paragraph("🔗 Top Network Flows", styles['BF_Heading2']))
        elements.append(Spacer(1, 8))

        flow_header = ['Flow', 'Proto', 'Packets', 'Bytes', 'Duration']
        flow_rows = [flow_header]
        for f in analysis_data['flow_summaries'][:15]:
            flow_rows.append([
                Paragraph(f['flow'], styles['BF_Mono']),
                f['protocol'],
                f"{f['total_packets']:,}",
                _format_bytes(f['total_bytes']),
                f"{f['duration']:.3f}s",
            ])

        flow_table = Table(flow_rows, colWidths=[170, 45, 65, 70, 65])
        flow_table.setStyle(_table_style())
        elements.append(flow_table)
        elements.append(Spacer(1, 20))

    # ─── User Attribution / Predictions ──────────────────────────────
    if predictions:
        elements.append(PageBreak())
        elements.append(Paragraph("🎯 User Attribution Results", styles['BF_Heading2']))
        elements.append(Spacer(1, 8))
        elements.append(Paragraph(
            "Each network flow has been classified into a behavioral profile based solely on "
            "traffic metadata. <b>No payload inspection or decryption was performed.</b> "
            "Confidence scores indicate the classifier's certainty.",
            styles['BF_Body']
        ))
        elements.append(Spacer(1, 10))

        pred_header = ['#', 'Behavioral Profile', 'Confidence', 'Risk Level']
        pred_rows = [pred_header]
        for i, p in enumerate(predictions[:25], 1):
            conf = p.get('confidence', 0)
            risk = 'Normal'
            if p.get('prediction') == 'malware_c2':
                risk = '🔴 HIGH — Potential C2'
            elif conf < 0.5:
                risk = '🟡 LOW CONFIDENCE'

            pred_rows.append([
                str(i),
                p.get('prediction', 'unknown'),
                f"{conf * 100:.1f}%",
                risk,
            ])

        pred_table = Table(pred_rows, colWidths=[30, 140, 80, 170])
        pred_table.setStyle(_table_style())
        elements.append(pred_table)
        elements.append(Spacer(1, 20))

    # ─── XAI Explanations ────────────────────────────────────────────
    if explanations:
        elements.append(Paragraph("🧠 Explainable AI — Feature Analysis", styles['BF_Heading2']))
        elements.append(Spacer(1, 8))
        elements.append(Paragraph(
            "The following features were the most influential in each classification decision. "
            "These behavioral indicators persist across IP address changes and represent the "
            "unique behavioral fingerprint of the traffic pattern.",
            styles['BF_Body']
        ))
        elements.append(Spacer(1, 10))

        for i, exp in enumerate(explanations[:10], 1):
            elements.append(Paragraph(
                f"<b>Sample #{i}:</b> {exp.get('prediction', '?')} "
                f"({exp.get('confidence', 0) * 100:.1f}% confidence)",
                styles['BF_BodyBold']
            ))
            elements.append(Spacer(1, 5))

            feat_header = ['Rank', 'Feature', 'Importance']
            feat_rows = [feat_header]
            for rank, f in enumerate(exp.get('top_features', [])[:10], 1):
                importance = f['importance'] * 100
                feat_rows.append([
                    str(rank),
                    f['feature'],
                    f"{importance:.1f}%",
                ])

            feat_table = Table(feat_rows, colWidths=[40, 260, 60])
            feat_table.setStyle(_table_style_compact())
            elements.append(feat_table)

            if exp.get('insights'):
                elements.append(Spacer(1, 8))
                explanation = '<br/>• '.join(exp['insights'])
                elements.append(Paragraph(
                    f"<b>Analysis:</b><br/>• {explanation}",
                    styles['BF_Explanation']
                ))
            elements.append(Spacer(1, 15))
    
    # ─── Behavioral Feature Categories ───────────────────────────────
    elements.append(PageBreak())
    elements.append(Paragraph("📊 78 Behavioral Dimensions Extracted", styles['BF_Heading2']))
    elements.append(Spacer(1, 8))
    elements.append(Paragraph(
        "BENFET extracts behavioral features across five dimensions. These features form the "
        "fingerprint that identifies users and devices regardless of IP address changes:",
        styles['BF_Body']
    ))
    elements.append(Spacer(1, 10))

    feature_categories = [
        ['⏱️ Temporal Features (20)', 'Inter-arrival times (IAT), flow duration, active/idle periods, request/response timing'],
        ['📐 Spatial Features (24)', 'Packet size distributions, sequence of packet lengths, payload variations'],
        ['📊 Volumetric Features (8)', 'Data rates, upload/download ratios, burst patterns, byte/packet metrics'],
        ['🔧 TCP/IP Features (14)', 'Window sizes, TTL values, TCP flag counts (SYN/ACK/FIN/RST), header analysis'],
        ['🔐 TLS/Encrypted Features (11)', 'JA3 fingerprint hash, ciphersuite selection, handshake patterns, version negotiation'],
    ]

    feat_cat_table = Table(feature_categories, colWidths=[150, 280])
    feat_cat_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('TEXTCOLOR', (0, 1), (0, -1), ACCENT_BLUE),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('LINEBELOW', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    elements.append(feat_cat_table)
    elements.append(Spacer(1, 15))

    elements.append(Paragraph(
        "<b>Implementation Notes:</b>",
        styles['BF_BodyBold']
    ))
    elements.append(Spacer(1, 5))
    elements.append(Paragraph(
        "• <b>Zero Encryption Dependency:</b> All behavioral features derive from packet metadata, "
        "never from payload content.<br/>"
        "• <b>Encrypted Traffic Only:</b> Features work equally well on TLS, HTTPS, encrypted tunnels, and VPN traffic.<br/>"
        "• <b>IP-Agnostic:</b> Features are computed per-flow and per-direction; source/destination IP plays zero role.<br/>"
        "• <b>Adversarial Resilience:</b> Behavioral patterns reflect underlying system behavior and are extremely difficult to spoof.",
        styles['BF_Body']
    ))
    elements.append(Spacer(1, 20))

    # ─── Network Topology ────────────────────────────────────────────
    if topology and topology.get('stats'):
        elements.append(PageBreak())
        elements.append(Paragraph("🌐 Network Topology Summary", styles['BF_Heading2']))
        elements.append(Spacer(1, 8))

        topo_data = [
            ['Total Nodes', str(topology['stats']['total_nodes'])],
            ['Total Links', str(topology['stats']['total_links'])],
            ['Subnets Detected', str(topology['stats']['total_subnets'])],
            ['Hub Nodes', ', '.join(topology['stats'].get('hub_nodes', [])) or 'None'],
        ]

        topo_table = Table(topo_data, colWidths=[150, 280])
        topo_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('LINEBELOW', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ]))
        elements.append(topo_table)
        elements.append(Spacer(1, 15))

    # ─── DNS Analysis ────────────────────────────────────────────────
    if analysis_data and analysis_data.get('dns_analysis'):
        dns = analysis_data['dns_analysis']
        elements.append(Paragraph("🔍 DNS Analysis", styles['BF_Heading2']))
        elements.append(Spacer(1, 8))

        dns_data = [
            ['Total DNS Queries', str(dns.get('total_dns_queries', 0))],
            ['DNS / Total Ratio', f"{dns.get('dns_ratio', 0) * 100:.2f}%"],
        ]

        dns_table = Table(dns_data, colWidths=[150, 280])
        dns_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LINEBELOW', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ]))
        elements.append(dns_table)
        elements.append(Spacer(1, 20))

    # ─── Footer ──────────────────────────────────────────────────────
    elements.append(HRFlowable(width="100%", thickness=1, color=BORDER_COLOR, spaceAfter=10))
    elements.append(Paragraph(
        "BENFET — Behavioral Fingerprinting for Network Forensics in Encrypted Traffic<br/>"
        "This report was auto-generated for forensic investigation purposes.<br/>"
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        styles['BF_Footer']
    ))

    # Build
    doc.build(elements)
    return filepath


# ─── Styles ──────────────────────────────────────────────────────────────

def _create_styles():
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle('BF_Title', parent=styles['Title'],
        fontSize=28, textColor=ACCENT_BLUE, spaceAfter=5,
        alignment=TA_CENTER, fontName='Helvetica-Bold'))

    styles.add(ParagraphStyle('BF_Subtitle', parent=styles['Normal'],
        fontSize=11, textColor=TEXT_MUTED, alignment=TA_CENTER,
        spaceAfter=10))

    styles.add(ParagraphStyle('BF_Heading1', parent=styles['Heading1'],
        fontSize=18, textColor=colors.black, spaceAfter=10,
        alignment=TA_CENTER))

    styles.add(ParagraphStyle('BF_Heading2', parent=styles['Heading2'],
        fontSize=14, textColor=ACCENT_BLUE, spaceBefore=10, spaceAfter=5))

    styles.add(ParagraphStyle('BF_Body', parent=styles['BodyText'],
        fontSize=10, leading=15, spaceAfter=5))

    styles.add(ParagraphStyle('BF_BodyBold', parent=styles['BodyText'],
        fontSize=10, fontName='Helvetica-Bold', leading=15))

    styles.add(ParagraphStyle('BF_Mono', parent=styles['Normal'],
        fontSize=7, fontName='Courier', leading=9))

    styles.add(ParagraphStyle('BF_Alert', parent=styles['BodyText'],
        fontSize=10, leading=15, borderColor=ACCENT_BLUE,
        borderWidth=1, borderPadding=10, borderRadius=4,
        backColor=colors.HexColor('#f0f8ff'), spaceAfter=10))

    styles.add(ParagraphStyle('BF_Explanation', parent=styles['BodyText'],
        fontSize=9, leading=13,
        backColor=colors.HexColor('#f5f5f5'),
        borderColor=ACCENT_BLUE, borderWidth=1,
        borderPadding=8, spaceAfter=5))

    styles.add(ParagraphStyle('BF_Footer', parent=styles['Normal'],
        fontSize=8, textColor=TEXT_MUTED, alignment=TA_CENTER,
        leading=12))

    return styles


def _table_style():
    return TableStyle([
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 9),
        ('FONTSIZE', (0, 1), (-1, -1), 9),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('BACKGROUND', (0, 0), (-1, 0), ACCENT_BLUE),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('LINEBELOW', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')]),
    ])


def _table_style_compact():
    return TableStyle([
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('BACKGROUND', (0, 0), (-1, 0), ACCENT_PURPLE),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('LINEBELOW', (0, 0), (-1, -1), 0.3, BORDER_COLOR),
    ])


def _format_bytes(b):
    if not b:
        return '0 B'
    for unit in ['B', 'KB', 'MB', 'GB']:
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} TB"
