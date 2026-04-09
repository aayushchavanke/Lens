"""
BENFET Reports - Forensic Report Generator
Compiles analysis results, XAI explanations, and topology data
into comprehensive HTML forensic reports.
"""

import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from config import REPORT_TEMPLATE_DIR, REPORTS_FOLDER


def generate_report(analysis_id, analysis_data, predictions=None, explanations=None, topology=None):
    """
    Generate an HTML forensic report.

    Args:
        analysis_id: unique identifier for this analysis
        analysis_data: dict from flow_analyzer.analyze_flows()
        predictions: list of prediction result dicts (optional)
        explanations: list of XAI explanation dicts (optional)
        topology: dict from topology_mapper.build_topology() (optional)

    Returns:
        str: path to the generated HTML report
    """
    env = Environment(loader=FileSystemLoader(REPORT_TEMPLATE_DIR))
    template = env.get_template('report_template.html')

    report_data = {
        'analysis_id': analysis_id,
        'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'analysis': analysis_data,
        'predictions': predictions or [],
        'explanations': explanations or [],
        'topology': topology or {},
        'has_predictions': bool(predictions),
        'has_explanations': bool(explanations),
        'has_topology': bool(topology),
    }

    html_content = template.render(**report_data)

    os.makedirs(REPORTS_FOLDER, exist_ok=True)
    filename = f"report_{analysis_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    filepath = os.path.join(REPORTS_FOLDER, filename)

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(html_content)

    return filepath
