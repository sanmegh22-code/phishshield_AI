import io
import datetime
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.colors import HexColor

def generate_pdf_report(scan_data):
    """
    Generates a PDF report buffer for the given scan result.
    scan_data keys:
        - target (str): The URL or text scanned
        - scan_type (str): 'URL', 'Email', or 'QR'
        - risk_score (int): 0 to 100
        - classification (str): 'Safe', 'Suspicious', 'Phishing'
        - reasons (list of str): Detailed triggers
        - username (str): User who ran the scan
        - date (str): Date/Time of the scan
    """
    buffer = io.BytesIO()
    
    # 1. Page settings
    doc = SimpleDocTemplate(
        buffer, 
        pagesize=letter,
        rightMargin=40, leftMargin=40,
        topMargin=40, bottomMargin=40
    )
    
    story = []
    styles = getSampleStyleSheet()
    
    # 2. Color Palette
    primary_color = HexColor("#0f172a") # dark slate
    secondary_color = HexColor("#38bdf8") # light blue accent
    
    if scan_data['classification'] == 'Phishing':
        risk_color = HexColor("#ef4444") # Crimson Red
        risk_bg = HexColor("#fee2e2")
    elif scan_data['classification'] == 'Suspicious':
        risk_color = HexColor("#f59e0b") # Gold Amber
        risk_bg = HexColor("#fef3c7")
    else:
        risk_color = HexColor("#10b981") # Emerald Green
        risk_bg = HexColor("#d1fae5")
        
    # 3. Custom Paragraph Styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=24,
        textColor=primary_color,
        spaceAfter=6
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Oblique',
        fontSize=10,
        textColor=HexColor("#64748b"),
        spaceAfter=20
    )
    
    section_title = ParagraphStyle(
        'SecTitle',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=14,
        textColor=primary_color,
        spaceBefore=14,
        spaceAfter=8
    )
    
    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        textColor=HexColor("#1e293b"),
        leading=14
    )
    
    code_style = ParagraphStyle(
        'CodeText',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=9,
        textColor=HexColor("#0f172a"),
        leading=12
    )
    
    bullet_style = ParagraphStyle(
        'Bullet',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        textColor=HexColor("#ef4444"),
        leftIndent=15,
        firstLineIndent=-10,
        spaceAfter=4,
        leading=13
    )

    # 4. Header Section
    story.append(Paragraph("PhishShield AI - Threat Analysis Report", title_style))
    story.append(Paragraph(f"Generated on {scan_data.get('date', datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))} by {scan_data.get('username', 'System')}", subtitle_style))
    story.append(Spacer(1, 10))
    
    # 5. Metadata Table
    # Safe wrapping for long target text (e.g. long URLs or email text snippets)
    raw_target = scan_data['target']
    if len(raw_target) > 75:
        # Wrap or truncate target for display
        wrapped_target = raw_target[:75] + "..."
    else:
        wrapped_target = raw_target
        
    meta_data = [
        [Paragraph("<b>Scan Parameter</b>", body_style), Paragraph("<b>Details</b>", body_style)],
        [Paragraph("Scan Type:", body_style), Paragraph(scan_data['scan_type'], body_style)],
        [Paragraph("Scanned Target:", body_style), Paragraph(wrapped_target, code_style)],
        [Paragraph("Risk Score:", body_style), Paragraph(f"{scan_data['risk_score']}%", body_style)],
        [Paragraph("Classification:", body_style), Paragraph(f"<font color='{risk_color.hexval()}'><b>{scan_data['classification'].upper()}</b></font>", body_style)]
    ]
    
    meta_table = Table(meta_data, colWidths=[130, 400])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (1,0), HexColor("#f1f5f9")),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('GRID', (0,0), (-1,-1), 0.5, HexColor("#cbd5e1")),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 20))
    
    # 6. Risk Gauge Callout
    callout_data = [
        [Paragraph(f"<b>THREAT LEVEL EVALUATION: {scan_data['classification'].upper()}</b><br/>"
                   f"The system has calculated a <b>{scan_data['risk_score']}%</b> probability of malicious intent. "
                   f"Please review the explainable AI details below before interacting with this resource.", body_style)]
    ]
    callout_table = Table(callout_data, colWidths=[530])
    callout_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), risk_bg),
        ('BOX', (0,0), (-1,-1), 1.5, risk_color),
        ('TOPPADDING', (0,0), (-1,-1), 12),
        ('BOTTOMPADDING', (0,0), (-1,-1), 12),
        ('LEFTPADDING', (0,0), (-1,-1), 15),
        ('RIGHTPADDING', (0,0), (-1,-1), 15),
    ]))
    story.append(callout_table)
    story.append(Spacer(1, 15))
    
    # 7. Explainable AI Reasons
    story.append(Paragraph("AI Detection Factors & Heuristics", section_title))
    reasons = scan_data.get('reasons', [])
    if not reasons:
        story.append(Paragraph("✓ No suspicious patterns or known phishing triggers were detected.", body_style))
    else:
        for reason in reasons:
            story.append(Paragraph(f"• {reason}", bullet_style))
            
    story.append(Spacer(1, 15))
    
    # 8. Action Recommendations
    story.append(Paragraph("Security Recommendations", section_title))
    rec_style = ParagraphStyle(
        'Recommendation',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        textColor=HexColor("#334155"),
        leftIndent=15,
        firstLineIndent=-10,
        spaceAfter=5,
        leading=13
    )
    
    if scan_data['classification'] == 'Phishing':
        recommendations = [
            "<b>DO NOT visit</b> the website. Avoid entering login credentials, MFA codes, or financial details.",
            "<b>Delete the email</b> immediately. Do not click any embedded links or download files.",
            "If you have already entered data on this page, immediately <b>change your password</b> on the authentic site.",
            "Report this indicator to your local IT administrator or security operations center."
        ]
    elif scan_data['classification'] == 'Suspicious':
        recommendations = [
            "Proceed with extreme caution. Verify the domain spelling carefully for any typosquatting attempts.",
            "Do not open any email attachments or enable macros from this sender.",
            "Inspect the SSL/TLS certificate. Legitimate sites should have valid certificates matching their brand name.",
            "Use a secondary verification channel (e.g. phone or bookmarks) to reach the company."
        ]
    else:
        recommendations = [
            "The site shows standard safe heuristics, but always verify before inputting sensitive credentials.",
            "Ensure that you are on the correct, bookmarked domain for banking or secure transactions.",
            "Keep your browser, OS, and security patches updated to guard against zero-day browser exploits."
        ]
        
    for rec in recommendations:
        story.append(Paragraph(f"✓ {rec}", rec_style))
        
    story.append(Spacer(1, 30))
    
    # 9. Footer Disclaimer
    disclaimer_style = ParagraphStyle(
        'Disclaimer',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        textColor=HexColor("#94a3b8"),
        alignment=1, # Center
        leading=10
    )
    story.append(Paragraph("Disclaimer: PhishShield AI provides heuristic analysis based on artificial intelligence models. "
                           "While highly accurate, it should be used in conjunction with other corporate security guidelines. "
                           "PhishShield AI is not liable for bypasses or false alerts.", disclaimer_style))
    
    # Build Document
    doc.build(story)
    
    buffer.seek(0)
    return buffer
