from datetime import datetime
from html import escape
from collections import Counter
import json

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Secret Scanner Report</title>

    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

    <style>
        body {{
            font-family: Arial, sans-serif;
            background-color: #f5f7fa;
            padding: 20px;
        }}
        h1 {{
            color: #c0392b;
        }}
        .meta {{
            margin-bottom: 20px;
            color: #555;
        }}
        .chart-container {{
            width: 600px;
            margin-bottom: 40px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: #fff;
        }}
        th, td {{
            padding: 10px;
            border: 1px solid #ddd;
            text-align: left;
        }}
        th {{
            background-color: #2c3e50;
            color: #fff;
        }}
        tr:nth-child(even) {{
            background-color: #f2f2f2;
        }}
        .high {{
            color: #e74c3c;
            font-weight: bold;
        }}
        .medium {{
            color: #f39c12;
            font-weight: bold;
        }}
    </style>
</head>
<body>

<h1>🚨 Secret Scanner Report</h1>

<div class="meta">
    <p><strong>Date:</strong> {date}</p>
    <p><strong>Total findings:</strong> {count}</p>
</div>

<div class="chart-container">
    <canvas id="secretsChart"></canvas>
</div>

<table>
    <thead>
        <tr>
            <th>File</th>
            <th>Line</th>
            <th>Type</th>
            <th>Risk</th>
        </tr>
    </thead>
    <tbody>
        {rows}
    </tbody>
</table>

<script>
    const chartData = {chart_data};

    const ctx = document.getElementById('secretsChart').getContext('2d');
    new Chart(ctx, {{
        type: 'bar',
        data: {{
            labels: chartData.labels,
            datasets: [{{
                label: 'Secrets by Type',
                data: chartData.values,
                backgroundColor: [
                    '#e74c3c',
                    '#f39c12',
                    '#9b59b6',
                    '#3498db',
                    '#1abc9c'
                ]
            }}]
        }},
        options: {{
            responsive: true,
            plugins: {{
                legend: {{
                    display: false
                }}
            }},
            scales: {{
                y: {{
                    beginAtZero: true,
                    precision: 0
                }}
            }}
        }}
    }});
</script>

</body>
</html>
"""

def risk_level(secret_type):
    return "medium" if secret_type == "HIGH_ENTROPY" else "high"

def generate_html_report(findings, path="report.html"):
    rows = ""

    types = [str(item["type"]) for item in findings]
    counter = Counter(types)

    chart_data = {
        "labels": list(counter.keys()),
        "values": list(counter.values())
    }

    for item in findings:
        risk = risk_level(item["type"])
        rows += f"""
        <tr>
            <td>{escape(item['file'])}</td>
            <td>{item['line']}</td>
            <td>{escape(str(item['type']))}</td>
            <td class="{risk}">{risk.upper()}</td>
        </tr>
        """

    html = HTML_TEMPLATE.format(
        date=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        count=len(findings),
        rows=rows,
        chart_data=json.dumps(chart_data)
    )

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)

