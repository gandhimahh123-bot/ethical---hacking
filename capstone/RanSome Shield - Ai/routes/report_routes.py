import io
import csv
from datetime import datetime, timedelta
from flask import render_template, request, jsonify, send_file, Response
from . import report_bp
from models import FileEvent, SecurityAlert, IntegrityCheck, BackupRecord, RecoveryRecord, QuarantineRecord, AuditLog
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

@report_bp.route('/reports')
def index():
    return render_template('reports.html')

@report_bp.route('/api/reports/summary', methods=['GET'])
def get_report_summary():
    days = request.args.get('days', 7, type=int)
    since_date = datetime.utcnow() - timedelta(days=days)

    total_events = FileEvent.query.filter(FileEvent.timestamp >= since_date).count()
    suspicious_events = FileEvent.query.filter(FileEvent.timestamp >= since_date, FileEvent.is_suspicious == True).count()
    
    alerts = SecurityAlert.query.filter(SecurityAlert.timestamp >= since_date).all()
    sev_counts = {'Low': 0, 'Medium': 0, 'High': 0, 'Critical': 0}
    for a in alerts:
        if a.severity in sev_counts:
            sev_counts[a.severity] += 1

    checks_count = IntegrityCheck.query.filter(IntegrityCheck.checked_at >= since_date).count()
    backups_count = BackupRecord.query.filter(BackupRecord.created_at >= since_date).count()
    recoveries_count = RecoveryRecord.query.filter(RecoveryRecord.recovered_at >= since_date).count()
    quarantines_count = QuarantineRecord.query.filter(QuarantineRecord.quarantined_at >= since_date).count()

    return jsonify({
        'status': 'success',
        'data': {
            'period_days': days,
            'since': since_date.strftime('%Y-%m-%d %H:%M:%S'),
            'total_events': total_events,
            'suspicious_events': suspicious_events,
            'total_alerts': len(alerts),
            'severity_breakdown': sev_counts,
            'integrity_checks': checks_count,
            'backups_created': backups_count,
            'recoveries_performed': recoveries_count,
            'quarantined_files': quarantines_count
        }
    })

@report_bp.route('/api/reports/export/csv', methods=['GET'])
def export_csv():
    days = request.args.get('days', 30, type=int)
    since_date = datetime.utcnow() - timedelta(days=days)
    
    alerts = SecurityAlert.query.filter(SecurityAlert.timestamp >= since_date).order_by(SecurityAlert.timestamp.desc()).all()
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Headers
    writer.writerow([
        'Alert ID', 'Timestamp (UTC)', 'Severity', 'Risk Score (0-100)', 
        'Target File Path', 'Detection Reasons', 'Status', 'Investigation Notes'
    ])
    
    for a in alerts:
        reasons_str = "; ".join(a.get_reasons_list())
        writer.writerow([
            a.id,
            a.timestamp.strftime('%Y-%m-%d %H:%M:%S') if a.timestamp else '',
            a.severity,
            a.risk_score,
            a.file_path,
            reasons_str,
            a.status,
            a.investigation_notes or ''
        ])
        
    output.seek(0)
    filename = f"ransomshield_incident_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename={filename}"}
    )

@report_bp.route('/api/reports/export/pdf', methods=['GET'])
def export_pdf():
    days = request.args.get('days', 30, type=int)
    since_date = datetime.utcnow() - timedelta(days=days)
    
    alerts = SecurityAlert.query.filter(SecurityAlert.timestamp >= since_date).order_by(SecurityAlert.timestamp.desc()).limit(50).all()
    total_events = FileEvent.query.filter(FileEvent.timestamp >= since_date).count()
    suspicious_events = FileEvent.query.filter(FileEvent.timestamp >= since_date, FileEvent.is_suspicious == True).count()
    
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'TitleStyle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        textColor=colors.HexColor('#0F172A'),
        spaceAfter=6
    )
    subtitle_style = ParagraphStyle(
        'SubtitleStyle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        textColor=colors.HexColor('#64748B'),
        spaceAfter=14
    )
    h2_style = ParagraphStyle(
        'H2Style',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=13,
        textColor=colors.HexColor('#1E293B'),
        spaceBefore=12,
        spaceAfter=8
    )
    body_style = ParagraphStyle(
        'BodyStyle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        textColor=colors.HexColor('#334155'),
        leading=12
    )

    story = []
    
    # Title & Header
    story.append(Paragraph("RansomShield AI — Incident & Security Audit Report", title_style))
    gen_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
    story.append(Paragraph(f"Generated: {gen_time} | Scope: Past {days} Days | Platform: Defensive Endpoint Shield", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#CBD5E1'), spaceAfter=14))

    # Executive Metrics Table
    story.append(Paragraph("1. Executive Summary", h2_style))
    summary_data = [
        ["Metric", "Value", "Metric", "Value"],
        ["Total Monitored Events", str(total_events), "Suspicious Events Detected", str(suspicious_events)],
        ["Total Security Incidents", str(len(alerts)), "Critical Severity Alerts", str(sum(1 for a in alerts if a.severity == 'Critical'))],
        ["High Severity Alerts", str(sum(1 for a in alerts if a.severity == 'High')), "Resolved / False Positives", str(sum(1 for a in alerts if a.status in ('Resolved', 'False Positive')))]
    ]
    summary_table = Table(summary_data, colWidths=[2.0*inch, 1.5*inch, 2.0*inch, 1.5*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1E293B')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 9),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#F8FAFC')),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 8.5),
        ('PADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 14))

    # Recent Alerts Table
    story.append(Paragraph("2. Detected Security Alerts", h2_style))
    alert_rows = [["ID", "Timestamp", "Severity", "Risk", "File Target", "Status"]]
    
    for a in alerts[:25]:  # fit neatly in PDF
        alert_rows.append([
            f"#{a.id}",
            a.timestamp.strftime('%m-%d %H:%M') if a.timestamp else '',
            a.severity,
            f"{a.risk_score}/100",
            Paragraph(a.file_path[-36:], body_style),
            a.status
        ])

    if len(alert_rows) == 1:
        alert_rows.append(["None", "N/A", "Clean", "0/100", "No security incidents flagged during period", "Clean"])

    alert_table = Table(alert_rows, colWidths=[0.5*inch, 1.1*inch, 0.9*inch, 0.7*inch, 2.8*inch, 1.0*inch])
    alert_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0F172A')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 8.5),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('PADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(alert_table)
    story.append(Spacer(1, 16))

    # Defensive Disclaimer
    disclaimer = (
        "<b>Notice:</b> This report was automatically compiled by RansomShield AI endpoint defensive behavioral monitor. "
        "All telemetry, checksums, and heuristics reflect locally captured system events. "
        "This tool is designed for authorized defensive security operations."
    )
    story.append(Paragraph(disclaimer, ParagraphStyle('Disc', parent=styles['Italic'], fontSize=7.5, textColor=colors.HexColor('#64748B'))))

    doc.build(story)
    buffer.seek(0)
    
    filename = f"ransomshield_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
    return send_file(
        buffer,
        as_attachment=True,
        download_name=filename,
        mimetype='application/pdf'
    )
