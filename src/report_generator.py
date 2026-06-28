import os
import csv
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional
import logging

# ReportLab imports for PDF generation
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

# Jinja2 import for HTML generation
from jinja2 import Template

logger = logging.getLogger("phish_detect.report")

class ReportGenerator:
    """
    Generates scan reports in multiple formats: JSON, CSV, HTML, and PDF.
    Features detailed breakdown of domain checks, risk scores, and screenshots.
    """
    
    def __init__(self, output_dir: str = "output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    def generate_all(self, target_domain: str, results: List[Dict[str, Any]], comparison: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
        """
        Generates reports in JSON, CSV, HTML, and PDF.
        
        Returns:
            Dict[str, str]: Map of report formats to their saved file paths.
        """
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        report_base = f"scan_{target_domain.replace('.', '_')}_{timestamp}"
        
        paths = {}
        
        # 1. JSON Report
        json_path = self.output_dir / f"{report_base}.json"
        try:
            # Custom serialization for datetime values
            def dt_serializer(o):
                if isinstance(o, datetime):
                    return o.isoformat()
                return str(o)
                
            report_data = {
                "target_domain": target_domain,
                "timestamp": datetime.utcnow().isoformat(),
                "summary": {
                    "total_generated": len(results),
                    "registered_count": sum(1 for r in results if r.get("whois", {}).get("registered") or r.get("dns", {}).get("resolves")),
                    "critical_count": sum(1 for r in results if r.get("risk_level") == "Critical"),
                    "high_count": sum(1 for r in results if r.get("risk_level") == "High"),
                    "medium_count": sum(1 for r in results if r.get("risk_level") == "Medium"),
                    "low_count": sum(1 for r in results if r.get("risk_level") == "Low"),
                },
                "comparison": comparison,
                "results": results
            }
            
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(report_data, f, default=dt_serializer, indent=2)
            paths["json"] = str(json_path)
            logger.info(f"JSON report saved: {json_path}")
        except Exception as e:
            logger.error(f"Error generating JSON report: {e}")
            
        # 2. CSV Report
        csv_path = self.output_dir / f"{report_base}.csv"
        try:
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "Domain", "Registered", "Risk Score", "Risk Level", "Reasons",
                    "Registrar", "Creation Date", "IP Addresses", "MX Servers", "SSL Issuer", "Screenshot Path"
                ])
                for r in results:
                    whois_d = r.get("whois", {})
                    dns_d = r.get("dns", {})
                    ssl_d = r.get("ssl", {})
                    
                    reg = "Yes" if (whois_d.get("registered") or dns_d.get("resolves")) else "No"
                    ips = ", ".join(dns_d.get("a_records", []))
                    mx = ", ".join(dns_d.get("mx_records", []))
                    reasons = "; ".join(r.get("reasons", []))
                    
                    writer.writerow([
                        r["domain"], reg, r.get("score", 0), r.get("risk_level", "Low"), reasons,
                        whois_d.get("registrar", ""), whois_d.get("creation_date", ""),
                        ips, mx, ssl_d.get("issuer", ""), r.get("screenshot_path", "")
                    ])
            paths["csv"] = str(csv_path)
            logger.info(f"CSV report saved: {csv_path}")
        except Exception as e:
            logger.error(f"Error generating CSV report: {e}")
            
        # 3. HTML Report (Sleek UI dashboard complying with Premium Aesthetics)
        html_path = self.output_dir / f"{report_base}.html"
        try:
            self._generate_html_report(target_domain, results, report_data, html_path)
            paths["html"] = str(html_path)
            logger.info(f"HTML report saved: {html_path}")
        except Exception as e:
            logger.error(f"Error generating HTML report: {e}")
            
        # 4. PDF Report
        pdf_path = self.output_dir / f"{report_base}.pdf"
        try:
            self._generate_pdf_report(target_domain, results, report_data, pdf_path)
            paths["pdf"] = str(pdf_path)
            logger.info(f"PDF report saved: {pdf_path}")
        except Exception as e:
            logger.error(f"Error generating PDF report: {e}")
            
        return paths
        
    def _generate_html_report(self, target_domain: str, results: List[Dict[str, Any]], data: Dict[str, Any], output_path: Path) -> None:
        """Builds an interactive HTML report dashboard using a premium template."""
        # Clean results to keep only active/registered or high score domains for HTML layout visibility
        active_results = [r for r in results if r.get("whois", {}).get("registered") or r.get("dns", {}).get("resolves") or r.get("score", 0) > 0]
        
        # HTML Template with styling
        template_str = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Phishing Detection Dashboard: {{ target_domain }}</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-dark: #0a0f1d;
            --bg-card: #131b2e;
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --primary: #6366f1;
            --accent: #8b5cf6;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #22c55e;
            --border: #1f2937;
        }
        
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        
        body {
            font-family: 'Outfit', sans-serif;
            background-color: var(--bg-dark);
            color: var(--text-main);
            line-height: 1.6;
            padding: 2rem;
        }
        
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2rem;
            border-bottom: 1px solid var(--border);
            padding-bottom: 1.5rem;
        }
        
        h1 {
            font-size: 2rem;
            font-weight: 800;
            background: linear-gradient(135deg, var(--primary), var(--accent));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .timestamp {
            color: var(--text-muted);
            font-size: 0.9rem;
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2.5rem;
        }
        
        .summary-card {
            background-color: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 1.5rem;
            text-align: center;
            transition: transform 0.3s ease;
        }
        
        .summary-card:hover {
            transform: translateY(-5px);
        }
        
        .summary-card h3 {
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
            margin-bottom: 0.5rem;
        }
        
        .summary-card .value {
            font-size: 2.2rem;
            font-weight: 700;
        }
        
        .value.critical { color: var(--critical); }
        .value.high { color: var(--high); }
        .value.medium { color: var(--medium); }
        .value.low { color: var(--low); }
        
        .comparison-box {
            background: linear-gradient(135deg, rgba(99,102,241,0.1), rgba(139,92,246,0.1));
            border: 1px solid var(--primary);
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 2.5rem;
        }
        
        .comparison-box h2 {
            font-size: 1.2rem;
            margin-bottom: 0.75rem;
            color: var(--primary);
        }
        
        .comparison-box ul {
            list-style: none;
            padding-left: 0;
        }
        
        .comparison-box li {
            margin-bottom: 0.5rem;
            font-size: 0.95rem;
        }
        
        .comparison-box li strong {
            color: #fff;
        }
        
        .domain-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
            background-color: var(--bg-card);
            border-radius: 12px;
            overflow: hidden;
            border: 1px solid var(--border);
        }
        
        .domain-table th, .domain-table td {
            padding: 1rem 1.5rem;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }
        
        .domain-table th {
            background-color: #1a233d;
            font-weight: 600;
            color: var(--text-muted);
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        
        .domain-table tr:last-child td {
            border-bottom: none;
        }
        
        .badge {
            display: inline-block;
            padding: 0.25rem 0.6rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .badge.critical { background-color: rgba(239, 68, 68, 0.2); color: var(--critical); }
        .badge.high { background-color: rgba(249, 115, 22, 0.2); color: var(--high); }
        .badge.medium { background-color: rgba(234, 179, 8, 0.2); color: var(--medium); }
        .badge.low { background-color: rgba(34, 197, 94, 0.2); color: var(--low); }
        
        .reasons-list {
            font-size: 0.85rem;
            color: var(--text-muted);
            margin-top: 0.5rem;
            padding-left: 1rem;
        }
        
        .reasons-list li {
            margin-bottom: 0.25rem;
        }
        
        .screenshot-link {
            color: var(--primary);
            text-decoration: none;
            font-weight: 600;
        }
        
        .screenshot-link:hover {
            text-decoration: underline;
        }
        
        .no-records {
            text-align: center;
            padding: 3rem;
            color: var(--text-muted);
            font-size: 1.1rem;
        }
    </style>
</head>
<body>
    <header>
        <div>
            <h1>Spot Phishing Domains Automatically</h1>
            <p>Target Domain Monitor: <strong>{{ target_domain }}</strong></p>
        </div>
        <div class="timestamp">
            Scan Executed: {{ data.timestamp.split('T')[0] }} at {{ data.timestamp.split('T')[1][:8] }} UTC
        </div>
    </header>
    
    <div class="summary-grid">
        <div class="summary-card">
            <h3>Permutations Checked</h3>
            <div class="value">{{ data.summary.total_generated }}</div>
        </div>
        <div class="summary-card">
            <h3>Registered/Resolving</h3>
            <div class="value" style="color: var(--primary)">{{ data.summary.registered_count }}</div>
        </div>
        <div class="summary-card">
            <h3>Critical Risk</h3>
            <div class="value critical">{{ data.summary.critical_count }}</div>
        </div>
        <div class="summary-card">
            <h3>High Risk</h3>
            <div class="value high">{{ data.summary.high_count }}</div>
        </div>
        <div class="summary-card">
            <h3>Medium Risk</h3>
            <div class="value medium">{{ data.summary.medium_count }}</div>
        </div>
    </div>
    
    {% if data.comparison %}
    <div class="comparison-box">
        <h2>Scan Comparison (Changes Since Last Run)</h2>
        <ul>
            {% if data.comparison.new_registrations %}
                <li>🟢 <strong>New Registrations ({{ data.comparison.new_registrations|length }}):</strong> 
                    {% for reg in data.comparison.new_registrations %}
                        {{ reg.domain }} (Risk: {{ reg.current_risk }}){% if not loop.last %}, {% endif %}
                    {% endfor %}
                </li>
            {% endif %}
            {% if data.comparison.removed_registrations %}
                <li>🔴 <strong>Removed Domains ({{ data.comparison.removed_registrations|length }}):</strong> 
                    {{ data.comparison.removed_registrations|join(', ') }}
                </li>
            {% endif %}
            {% if data.comparison.risk_increased %}
                <li>⚠️ <strong>Risk Escalations ({{ data.comparison.risk_increased|length }}):</strong> 
                    {% for inc in data.comparison.risk_increased %}
                        {{ inc.domain }} ({{ inc.old_score }} &rarr; {{ inc.new_score }} pts){% if not loop.last %}, {% endif %}
                    {% endfor %}
                </li>
            {% endif %}
            {% if not data.comparison.new_registrations and not data.comparison.removed_registrations and not data.comparison.risk_increased %}
                <li>No changes detected compared to the previous scan.</li>
            {% endif %}
        </ul>
    </div>
    {% endif %}
    
    <h2>Registered / High-Threat Permutations</h2>
    {% if active_results %}
    <table class="domain-table">
        <thead>
            <tr>
                <th style="width: 25%">Domain Permutation</th>
                <th style="width: 15%">Risk Rating</th>
                <th style="width: 15%">Registrar / Age</th>
                <th style="width: 20%">IP Resolution</th>
                <th style="width: 15%">SSL Info</th>
                <th style="width: 10%">Screenshot</th>
            </tr>
        </thead>
        <tbody>
            {% for r in active_results %}
            <tr>
                <td>
                    <strong>{{ r.domain }}</strong>
                    <ul class="reasons-list">
                        {% for reason in r.reasons %}
                            <li>{{ reason }}</li>
                        {% endfor %}
                    </ul>
                </td>
                <td>
                    <span class="badge {{ r.risk_level.lower() }}">{{ r.risk_level }} ({{ r.score }}%)</span>
                </td>
                <td>
                    {% if r.registered %}
                        {{ r.registrar or 'Unknown Registrar' }}
                        <div style="font-size: 0.8rem; color: var(--text-muted)">
                            Created: {{ r.creation_date.split('T')[0] if r.creation_date else 'Unknown' }}
                        </div>
                    {% else %}
                        Unregistered
                    {% endif %}
                </td>
                <td>
                    {% if r.a_records %}
                        {{ r.a_records|join(', ') }}
                    {% else %}
                        <span style="color: var(--text-muted)">Does not resolve</span>
                    {% endif %}
                    {% if r.mx_records %}
                        <div style="font-size: 0.8rem; color: var(--text-muted); margin-top: 0.25rem">
                            MX: {{ r.mx_records|join(', ') }}
                        </div>
                    {% endif %}
                </td>
                <td>
                    {% if r.ssl_issuer %}
                        <span title="{{ r.ssl_issuer }}">{{ r.ssl_issuer.split('CN=')[-1].split(',')[0] }}</span>
                        <div style="font-size: 0.8rem; color: var(--text-muted)">
                            Expiry: {{ r.ssl_valid_to.split('T')[0] if r.ssl_valid_to else 'Unknown' }}
                        </div>
                    {% else %}
                        <span style="color: var(--text-muted)">No SSL cert</span>
                    {% endif %}
                </td>
                <td>
                    {% if r.screenshot_path %}
                        <a href="{{ r.screenshot_path }}" target="_blank" class="screenshot-link">View PNG</a>
                    {% else %}
                        <span style="color: var(--text-muted)">N/A</span>
                    {% endif %}
                </td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    {% else %}
    <div class="domain-table">
        <div class="no-records">
            No active or registered typosquatting variations detected during this scan run. All variants appear offline.
        </div>
    </div>
    {% endif %}
</body>
</html>
"""
        template = Template(template_str)
        rendered_html = template.render(
            target_domain=target_domain,
            results=results,
            active_results=active_results,
            data=data
        )
        
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(rendered_html)
            
    def _generate_pdf_report(self, target_domain: str, results: List[Dict[str, Any]], data: Dict[str, Any], output_path: Path) -> None:
        """Generates a clean PDF report using ReportLab Flowables."""
        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )
        
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            name="TitleStyle",
            parent=styles["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=24,
            leading=28,
            textColor=colors.HexColor("#6366f1"),
            spaceAfter=12
        )
        
        section_style = ParagraphStyle(
            name="SectionStyle",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#1e293b"),
            spaceBefore=15,
            spaceAfter=8
        )
        
        body_style = ParagraphStyle(
            name="BodyStyle",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#334155")
        )
        
        table_text = ParagraphStyle(
            name="TableText",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=8,
            leading=10
        )
        
        table_header = ParagraphStyle(
            name="TableHeader",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10,
            textColor=colors.white
        )
        
        story = []
        
        # Cover / Header
        story.append(Paragraph("Phishing Detection Assessment", title_style))
        story.append(Paragraph(f"Target Brand Domain: <b>{target_domain}</b>", body_style))
        story.append(Paragraph(f"Report Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}", body_style))
        story.append(Spacer(1, 0.2 * inch))
        
        # Summary Statistics Table
        summary_data = [
            [
                Paragraph("<b>Total Permutations</b>", table_header),
                Paragraph("<b>Registered Count</b>", table_header),
                Paragraph("<b>Critical Risk</b>", table_header),
                Paragraph("<b>High Risk</b>", table_header)
            ],
            [
                Paragraph(str(data["summary"]["total_generated"]), table_text),
                Paragraph(str(data["summary"]["registered_count"]), table_text),
                Paragraph(str(data["summary"]["critical_count"]), table_text),
                Paragraph(str(data["summary"]["high_count"]), table_text)
            ]
        ]
        
        summary_table = Table(summary_data, colWidths=[1.8*inch, 1.8*inch, 1.8*inch, 1.8*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#1e293b")),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('TOPPADDING', (0,0), (-1,-1), 6),
        ]))
        
        story.append(summary_table)
        story.append(Spacer(1, 0.25 * inch))
        
        # Threat Permutations details section
        story.append(Paragraph("Identified Threat Permutations", section_style))
        
        # Filter domains that are active/registered or have score > 0
        active_domains = [r for r in results if r.get("whois", {}).get("registered") or r.get("dns", {}).get("resolves") or r.get("score", 0) > 0]
        
        if active_domains:
            # Let's put up a table containing the critical findings
            table_rows = [
                [
                    Paragraph("Domain", table_header),
                    Paragraph("Risk Level (Score)", table_header),
                    Paragraph("Registrar", table_header),
                    Paragraph("IP Addresses", table_header)
                ]
            ]
            
            # Sort by risk score descending
            sorted_domains = sorted(active_domains, key=lambda x: x.get("score", 0), reverse=True)
            
            for item in sorted_domains:
                whois_d = item.get("whois", {})
                dns_d = item.get("dns", {})
                
                # Check for color weighting based on score
                level = item.get("risk_level", "Low")
                score = item.get("score", 0)
                
                level_str = f"<b>{level} ({score}%)</b>"
                
                ips = ", ".join(dns_d.get("a_records", []))
                
                table_rows.append([
                    Paragraph(item["domain"], table_text),
                    Paragraph(level_str, table_text),
                    Paragraph(whois_d.get("registrar") or "N/A", table_text),
                    Paragraph(ips or "N/A", table_text)
                ])
                
            details_table = Table(table_rows, colWidths=[2.2*inch, 1.5*inch, 1.8*inch, 1.7*inch])
            details_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#6366f1")),
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#f8fafc")]),
                ('BOTTOMPADDING', (0,0), (-1,-1), 6),
                ('TOPPADDING', (0,0), (-1,-1), 6),
            ]))
            story.append(details_table)
            
        else:
            story.append(Paragraph("No active brand permutations or threats resolved in the scan range.", body_style))
            
        # Build Document
        doc.build(story)
