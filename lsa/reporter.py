import html
from datetime import datetime


BADGE = {
    'pass': '<span class="badge badge-pass">PASS</span>',
    'fail': '<span class="badge badge-fail">FAIL</span>',
    'warn': '<span class="badge badge-warn">WARN</span>',
    'info': '<span class="badge badge-info">INFO</span>',
    'error': '<span class="badge badge-error">ERROR</span>',
}


CSS = '''
* { margin: 0; padding: 0; box-sizing: border-box; }
body { background: #0d1117; color: #c9d1d9; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; padding: 2rem; line-height: 1.6; }
.container { max-width: 960px; margin: 0 auto; }
h1 { font-size: 1.8rem; margin-bottom: 0.5rem; color: #f0f6fc; }
h2 { font-size: 1.2rem; margin-bottom: 1rem; color: #58a6ff; }
.summary { display: grid; grid-template-columns: 1fr 1fr 1fr 1fr; gap: 1rem; margin-bottom: 2rem; }
.score-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1.2rem; text-align: center; }
.score-card .num { font-size: 2.2rem; font-weight: 700; }
.score-card .lbl { font-size: 0.8rem; color: #8b949e; text-transform: uppercase; letter-spacing: 1px; }
.num-green { color: #3fb950; }
.num-red { color: #f85149; }
.num-yellow { color: #d29922; }
.num-blue { color: #58a6ff; }
.section { background: #161b22; border: 1px solid #30363d; border-radius: 8px; margin-bottom: 1rem; overflow: hidden; }
.section-header { padding: 0.8rem 1.2rem; cursor: pointer; display: flex; justify-content: space-between; align-items: center; user-select: none; }
.section-header:hover { background: #1c2128; }
.section-header h3 { font-size: 1rem; font-weight: 600; }
.section-header .arrow { font-size: 0.8rem; color: #8b949e; transition: transform 0.2s; }
.section-content { display: none; padding: 0; }
.section.open .section-content { display: block; }
.section.open .arrow { transform: rotate(90deg); }
table { width: 100%; border-collapse: collapse; }
th { text-align: left; padding: 0.6rem 1rem; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 1px; color: #8b949e; border-bottom: 1px solid #21262d; }
td { padding: 0.6rem 1rem; border-bottom: 1px solid #21262d; font-size: 0.9rem; vertical-align: top; }
tr:last-child td { border-bottom: none; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.7rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }
.badge-pass { background: rgba(63,185,80,0.15); color: #3fb950; border: 1px solid rgba(63,185,80,0.3); }
.badge-fail { background: rgba(248,81,73,0.15); color: #f85149; border: 1px solid rgba(248,81,73,0.3); }
.badge-warn { background: rgba(210,153,34,0.15); color: #d29922; border: 1px solid rgba(210,153,34,0.3); }
.badge-info { background: rgba(88,166,255,0.15); color: #58a6ff; border: 1px solid rgba(88,166,255,0.3); }
.badge-error { background: rgba(248,81,73,0.2); color: #f85149; border: 1px solid rgba(248,81,73,0.4); }
.details-cell { max-width: 400px; overflow-wrap: break-word; font-family: 'SFMono-Regular', Consolas, monospace; font-size: 0.8rem; color: #8b949e; }
.remediation { font-family: 'SFMono-Regular', Consolas, monospace; font-size: 0.8rem; color: #3fb950; }
.timestamp { color: #8b949e; font-size: 0.8rem; margin-bottom: 1.5rem; }
'''


def generate_html(results):
    from lsa.auditor import summarize
    summary = summarize(results)
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    rows = []
    for section_name, checks in results.items():
        section_id = section_name.lower().replace(' ', '-')
        pass_count = sum(1 for c in checks if c['status'] == 'pass')
        fail_count = sum(1 for c in checks if c['status'] == 'fail')
        warn_count = sum(1 for c in checks if c['status'] == 'warn')
        label = f'{pass_count}P / {fail_count}F / {warn_count}W'

        table_rows = ''
        for c in checks:
            details = html.escape(c['details'][:500]) if c['details'] else ''
            remediation = html.escape(c['remediation'][:300]) if c['remediation'] else ''
            badge = BADGE.get(c['status'], BADGE['info'])
            table_rows += f'''<tr>
                <td>{badge}</td>
                <td>{html.escape(c['name'])}</td>
                <td class="details-cell">{details}</td>
                <td class="remediation">{remediation}</td>
            </tr>'''

        rows.append(f'''<div class="section" id="{section_id}">
            <div class="section-header" onclick="toggle(this.parentElement)">
                <h3>{html.escape(section_name)} <span style="font-size:0.75rem;color:#8b949e;font-weight:400;">({label})</span></h3>
                <span class="arrow">&#9654;</span>
            </div>
            <div class="section-content">
                <table><thead><tr><th>Result</th><th>Check</th><th>Details</th><th>Remediation</th></tr></thead><tbody>{table_rows}</tbody></table>
            </div>
        </div>''')

    html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Linux Security Audit Report</title>
<style>{CSS}</style>
</head>
<body>
<div class="container">
<h1>Linux Security Audit Report</h1>
<p class="timestamp">Generated: {now} | Score: {summary["score"]}/100</p>

<div class="summary">
    <div class="score-card"><div class="num num-green">{summary["passed"]}</div><div class="lbl">Passed</div></div>
    <div class="score-card"><div class="num num-red">{summary["failed"]}</div><div class="lbl">Failed</div></div>
    <div class="score-card"><div class="num num-yellow">{summary["warned"]}</div><div class="lbl">Warnings</div></div>
    <div class="score-card"><div class="num num-blue">{summary["score"]}</div><div class="lbl">Score</div></div>
</div>

<h2>Audit Results</h2>
{"".join(rows)}

</div>
<script>
function toggle(el) {{ el.classList.toggle('open'); }}
if (window.location.hash) {{ var el = document.querySelector(window.location.hash); if(el) el.classList.add('open'); }}
</script>
</body>
</html>'''

    return html_content


def write_report(results, path='security-audit-report.html'):
    html_content = generate_html(results)
    with open(path, 'w') as f:
        f.write(html_content)
    return path
