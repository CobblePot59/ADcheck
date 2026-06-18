from adcheck.modules.constants import CHECKLIST, CVSS_VECTORS, DEFAULT_CVSS_VECTOR, CHECK_METADATA, ANSI, SEVERITY
from adcheck.modules.cvss import base_score, severity as cvss_severity
from jinja2 import Environment, FileSystemLoader
from os import path
from datetime import datetime


class ReportGenerator():
    def __init__(self, results, domain, additional_tables=None):
        self.results = results
        self.domain = domain
        self.env = Environment(loader=FileSystemLoader(path.dirname(__file__)))
        self.template = self.env.get_template('templates/report.html')
        self.filename = f"{self.domain}_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}"

        self.privs_list, _, self.privs_ids = self.checklist_parser('Privilege and Trust Management')
        self.user_list, _, self.user_ids = self.checklist_parser('User Account Management')
        self.domain_list, _, self.domain_ids = self.checklist_parser('Computer and Domain Management')
        self.policy_list, _, self.policy_ids = self.checklist_parser('Audit and Policy Management')

        self.total_list = self.privs_list + self.user_list + self.domain_list + self.policy_list
        self.additional_tables = additional_tables or []

        self.sections = {
            'privs': ('Privilege and Trust Management', self.privs_ids, 'privilege'),
            'user': ('User Account Management', self.user_ids, 'user'),
            'domain': ('Computer and Domain Management', self.domain_ids, 'domain'),
            'policy': ('Audit and Policy Management', self.policy_ids, 'policy'),
        }

        self._score_cache = {}

    def checklist_parser(self, section_name):
        modules = []
        modules2 = []
        for checklist_values in CHECKLIST.values():
            for section in checklist_values:
                if section_name in section:
                    for module in section[section_name]:
                        if 'INFO' not in module:
                            modules.append(module)
                        modules2.append(module)
        modules_ids_no_info = [module[0] for module in modules]
        modules_ids = [module[0] for module in modules2]
        return modules, modules_ids_no_info, modules_ids

    # ---------------------------------------------------------------- CVSS core

    def vector_for(self, name):
        return CVSS_VECTORS.get(name, DEFAULT_CVSS_VECTOR)

    def score_for(self, name):
        vector = self.vector_for(name)
        if vector not in self._score_cache:
            self._score_cache[vector] = base_score(vector)
        return self._score_cache[vector]

    def _name_to_section(self):
        mapping = {}
        for key, (title, ids, _cat) in self.sections.items():
            for i in ids:
                mapping[i] = (key, title)
        return mapping

    def metadata_for(self, name):
        meta = CHECK_METADATA.get(name, {})
        return {
            'exploit': meta.get('exploit', 'N/A'),
            'fix': meta.get('fix', 'Review this finding and apply vendor/security best-practice hardening.'),
        }

    def _findings(self, ids=None):
        """Return failed checks (color == 'red') enriched with CVSS + metadata,
        sorted from most to least critical. If ids is given, restrict to them."""
        n2s = self._name_to_section()
        findings = []
        for result in self.results:
            if result.get('color') != 'red':
                continue
            name = result.get('name')
            if ids is not None and name not in ids:
                continue
            vector = self.vector_for(name)
            score = self.score_for(name)
            meta = self.metadata_for(name)
            section_title = n2s.get(name, ('', ''))[1]
            findings.append({
                'name': name,
                'message': result.get('message', ''),
                'cvss': score,
                'vector': vector,
                'severity': cvss_severity(score),
                'category': section_title,
                'state': 'FAILED',
                'exploit': meta['exploit'],
                'fix': meta['fix'],
            })
        findings.sort(key=lambda f: (list(SEVERITY).index(f['severity']), -f['cvss']))
        return findings

    def _global_score(self):
        """Weighted posture score out of 100.

        Each performed check (red or green, INFO excluded) contributes a weight
        equal to its CVSS base score. A failed check loses all of its weight; a
        passed check keeps it. The score is the share of weighted checks passed.
        """
        performed = [r for r in self.results if r.get('color') in ('red', 'green')]
        if not performed:
            return 100, 0.0, 0

        total_weight = sum(self.score_for(r.get('name')) for r in performed)
        lost_weight = sum(self.score_for(r.get('name')) for r in performed if r.get('color') == 'red')

        score = int(round((1 - (lost_weight / total_weight)) * 100)) if total_weight else 100

        findings = self._findings()
        avg_cvss = round(sum(f['cvss'] for f in findings) / len(findings), 1) if findings else 0.0
        return score, avg_cvss, len(findings)

    def _severity_counts(self, findings):
        counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for f in findings:
            if f['severity'] in counts:
                counts[f['severity']] += 1
        return counts

    def _passed_count(self):
        return sum(1 for r in self.results if r.get('color') == 'green')

    # ---------------------------------------------------------------- CLI report

    def gen_cli_summary(self, summarize=True):
        """Print the criticality-first prioritized summary to the terminal.

        Shows the global posture, severity breakdown, then every finding with
        its category, state, CVSS vector, exploit command and fix.
        """
        score, avg_cvss, n = self._global_score()
        findings = self._findings()
        counts = self._severity_counts(findings)
        passed = self._passed_count()
        performed = n + passed

        bar = '=' * 78
        title = f"ADcheck Report – {self.domain}"
        print(f"\n{ANSI['cyan']}{bar}")
        print(f"{title.center(78)}")
        print(f"{bar}{ANSI['reset']}\n")

        score_color = (ANSI['green'] if score >= 75 else ANSI['yellow'] if score >= 50
                       else ANSI['red'] if score >= 25 else ANSI['bold_red'])
        print(f"  Global posture score : {score_color}{score}/100{ANSI['reset']}"
              f"   (CVSS-weighted over {performed} checks)")
        print(f"  Failed checks        : {len(findings)}")
        print(f"  Passed checks        : {ANSI['green']}{passed}{ANSI['reset']}")
        print(f"  Average CVSS         : {avg_cvss}")
        print(f"  By severity          : "
              f"{SEVERITY['Critical']['ansi']}Critical {counts['Critical']}{ANSI['reset']}  "
              f"{SEVERITY['High']['ansi']}High {counts['High']}{ANSI['reset']}  "
              f"{SEVERITY['Medium']['ansi']}Medium {counts['Medium']}{ANSI['reset']}  "
              f"{SEVERITY['Low']['ansi']}Low {counts['Low']}{ANSI['reset']}\n")

        if not findings:
            print(f"  {ANSI['green']}No failed checks. \\o/{ANSI['reset']}\n")
            return

        current_sev = None
        for f in findings:
            if f['severity'] != current_sev:
                current_sev = f['severity']
                color = SEVERITY[current_sev]['ansi']
                print(f"\n  {color}{'─' * 3} {current_sev.upper()} {'─' * (66 - len(current_sev))}{ANSI['reset']}")
            color = SEVERITY[f['severity']]['ansi']
            msg = f['message'].splitlines()[0] if f['message'] else f['name']
            print(f"\n  {color}\u25cf {f['cvss']:>4.1f}{ANSI['reset']}  {msg}")
            print(f"      {ANSI['dim']}Category   :{ANSI['reset']} {f['category']}")
            print(f"      {ANSI['dim']}State      :{ANSI['reset']} {ANSI['red']}FAILED{ANSI['reset']}")
            print(f"      {ANSI['dim']}CVSS vector:{ANSI['reset']} {f['vector']}")
            print(f"      {ANSI['dim']}Exploit    :{ANSI['reset']} {f['exploit']}")
            print(f"      {ANSI['dim']}Fix        :{ANSI['reset']} {f['fix']}")
        print()

    # ---------------------------------------------------------------- helpers

    def _get_tables_for_category(self, category):
        return [table for table in self.additional_tables if table.get('category') == category]

    # ---------------------------------------------------------------- Markdown

    def _format_markdown_table(self, table):
        content = f"{table['title']}\n\n"
        content += "| " + " | ".join(table['headers']) + " |\n"
        content += "| " + " | ".join(["---"] * len(table['headers'])) + " |\n"
        for row in table['rows']:
            formatted_row = [str(cell) if cell else " " for cell in row]
            content += "| " + " | ".join(formatted_row) + " |\n"
        return content + "\n"

    @staticmethod
    def _md_exploit(exploit):
        """Render an attack value: a Markdown link if it's a URL, else a fenced
        code block. Handles the '[https://...] cmd' convention from the project."""
        if not exploit:
            return "_N/A_"
        s = exploit.strip()
        # Pure URL.
        if s.startswith('http://') or s.startswith('https://'):
            return f"[{s}]({s})"
        # '[https://...] something' -> link the URL, keep the rest as code.
        if s.startswith('[http'):
            end = s.find(']')
            if end != -1:
                url = s[1:end]
                rest = s[end + 1:].strip()
                link = f"[{url}]({url})"
                if rest:
                    return f"{link}\n\n```\n{rest}\n```"
                return link
        # Otherwise: a shell command -> fenced code block.
        return f"```\n{s}\n```"

    def _markdown_priority_table(self, findings):
        if not findings:
            return "_No failed checks._\n\n"
        content = "| CVSS | Severity | Category | Finding |\n"
        content += "| :---: | :--- | :--- | :--- |\n"
        for f in findings:
            msg = f['message'].splitlines()[0].replace('|', '\\|') if f['message'] else f['name']
            badge = f"{SEVERITY[f['severity']]['emoji']} {f['severity']}"
            content += f"| **{f['cvss']:.1f}** | {badge} | {f['category']} | {msg} |\n"
        return content + "\n"

    def _format_markdown_section(self, title, ids, category):
        failed = self._findings(ids)
        passed = [r for r in self.results
                  if r.get('color') == 'green' and r.get('name') in ids]
        info = [r for r in self.results
                if r.get('color') == 'black' and r.get('name') in ids]
        tables = self._get_tables_for_category(category)

        if not (failed or passed or info or tables):
            return ""

        worst = failed[0]['severity'] if failed else 'None'
        badge = SEVERITY[worst]['emoji']
        summary = f"{badge} {title} — {len(failed)} failed, {len(passed)} passed"

        # Single-level collapsible category. Using `markdown="1"` so parsers that
        # support md-in-html (GitHub, python-markdown md_in_html) render the inner
        # Markdown; others still show readable content. Inner content is plain
        # Markdown (no nested tables) to stay robust across all viewers.
        open_attr = " open" if failed else ""
        body = f'<details{open_attr} markdown="1">\n<summary><strong>{summary}</strong></summary>\n\n'

        if failed:
            body += "#### Failed checks (by criticality)\n\n"
            for f in failed:
                emoji = SEVERITY[f['severity']]['emoji']
                first = f['message'].splitlines()[0]
                body += f"##### {emoji} {f['cvss']:.1f} {f['severity']} — {first}\n\n"
                body += f"- **State:** ❌ FAILED\n"
                body += f"- **Category:** {f['category']}\n"
                body += f"- **CVSS:** {f['cvss']:.1f} ({f['severity']})\n"
                body += f"- **Vector:** `{f['vector']}`\n"
                extra = "\n".join(f['message'].splitlines()[1:]).strip()
                if extra:
                    body += f"- **Detail:** `{extra}`\n"
                body += "\n**Attack / test command**\n\n"
                body += f"{self._md_exploit(f['exploit'])}\n\n"
                body += f"**Fix:** {f['fix']}\n\n"
                body += "---\n\n"

        if passed:
            body += "#### Passed checks\n\n"
            for r in passed:
                body += f"- ✅ {r.get('message', '').splitlines()[0]}\n"
            body += "\n"

        if info or tables:
            body += "#### Info\n\n"
            for r in info:
                lines = r.get('message', '').splitlines()
                if len(lines) > 1:
                    body += f"- ℹ️ {lines[0]}\n\n  ```\n"
                    body += "\n".join(f"  {l}" for l in lines[1:])
                    body += "\n  ```\n\n"
                else:
                    body += f"- ℹ️ {lines[0]}\n"
            if tables:
                body += "\n"
                for table in tables:
                    body += self._format_markdown_table(table)
            body += "\n"

        body += "</details>\n\n"
        return body

    def gen_markdown(self):
        score, avg_cvss, n = self._global_score()
        findings = self._findings()
        counts = self._severity_counts(findings)
        passed = self._passed_count()

        score_emoji = ('🟢' if score >= 75 else '🟡' if score >= 50
                       else '🟠' if score >= 25 else '🔴')

        md = f"# ADcheck Report — {self.domain}\n\n"
        md += f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"

        md += "## Executive summary\n\n"
        md += "| Metric | Value |\n| :--- | :--- |\n"
        md += f"| Global posture score | {score_emoji} **{score}/100** (CVSS-weighted) |\n"
        md += f"| Failed checks | {len(findings)} |\n"
        md += f"| Passed checks | {passed} |\n"
        md += f"| Average CVSS | {avg_cvss} |\n"
        md += (f"| By severity | 🔴 Critical {counts['Critical']} · 🟠 High {counts['High']} · "
               f"🟡 Medium {counts['Medium']} · 🔵 Low {counts['Low']} |\n\n")

        md += "## Top priorities\n\n"
        md += self._markdown_priority_table(findings)

        md += "## Findings by category\n\n"
        ordered = sorted(
            self.sections.items(),
            key=lambda kv: -max(
                [self.score_for(r.get('name'))
                 for r in self.results
                 if r.get('color') == 'red' and r.get('name') in kv[1][1]],
                default=0.0,
            ),
        )
        for _key, (title, ids, cat) in ordered:
            md += self._format_markdown_section(title, ids, cat)

        out_path = f"{self.filename}.md"
        with open(out_path, "w", encoding="utf-8") as md_file:
            md_file.write(md)
        return path.abspath(out_path)

    # ---------------------------------------------------------------- HTML

    def _section_payload(self, ids, category):
        items = []
        for r in self.results:
            if r.get('name') not in ids:
                continue
            color = r.get('color')
            entry = {'message': r.get('message'), 'color': color}
            if color == 'red':
                score = self.score_for(r.get('name'))
                entry['cvss'] = score
                entry['vector'] = self.vector_for(r.get('name'))
                entry['severity'] = cvss_severity(score)
            items.append(entry)

        def sort_key(e):
            if e['color'] == 'red':
                return (0, list(SEVERITY).index(e['severity']), -e['cvss'])
            if e['color'] == 'green':
                return (1, 0, 0)
            return (2, 0, 0)
        items.sort(key=sort_key)
        return {'results': items, 'tables': self._get_tables_for_category(category)}

    def gen_html(self):
        score, avg_cvss, n = self._global_score()
        findings = self._findings()
        counts = self._severity_counts(findings)

        section_meta = {}
        for key, (title, ids, _cat) in self.sections.items():
            sec_findings = self._findings(ids)
            worst = sec_findings[0]['cvss'] if sec_findings else 0.0
            section_meta[key] = {
                'title': title,
                'worst_cvss': worst,
                'worst_severity': cvss_severity(worst),
                'failed': len(sec_findings),
                'critical': sum(1 for f in sec_findings if f['severity'] == 'Critical'),
                'high': sum(1 for f in sec_findings if f['severity'] == 'High'),
            }

        ordered_keys = sorted(
            self.sections.keys(),
            key=lambda k: (-section_meta[k]['worst_cvss'], -section_meta[k]['failed']),
        )

        n2s = self._name_to_section()
        top_findings = [{
            'name': f['name'],
            'cvss': f['cvss'],
            'severity': f['severity'],
            'vector': f['vector'],
            'css': SEVERITY[f['severity']]['css'],
            'message': f['message'],
            'category': f['category'],
            'state': f['state'],
            'exploit': f['exploit'],
            'fix': f['fix'],
            'section_key': n2s.get(f['name'], ('', ''))[0],
            'section_title': f['category'],
        } for f in findings]

        # Per-category buckets: failed / passed / info / tables.
        cat_to_title = {cat: title for _key, (title, _ids, cat) in self.sections.items()}
        by_category = {title: [] for _key, (title, _ids, _cat) in self.sections.items()}
        passed_by_category = {title: [] for _key, (title, _ids, _cat) in self.sections.items()}
        info_by_category = {title: [] for _key, (title, _ids, _cat) in self.sections.items()}

        for tf in top_findings:
            by_category.setdefault(tf['category'], []).append(tf)

        for r in self.results:
            sec = n2s.get(r.get('name'), ('', ''))[1]
            color = r.get('color', '')
            if color == 'green' and sec:
                passed_by_category.setdefault(sec, []).append({'message': r.get('message', '')})
            elif color == 'black' and sec:
                info_by_category.setdefault(sec, []).append({'message': r.get('message', '')})

        tables_by_title = {}
        for t in self.additional_tables:
            title = cat_to_title.get(t.get('category'), t.get('category', ''))
            tables_by_title.setdefault(title, []).append(t)

        all_titles = (set(by_category) | set(passed_by_category) |
                      set(info_by_category) | set(tables_by_title))
        categories_ordered = []
        for title in all_titles:
            cat_f = by_category.get(title, [])
            cat_p = passed_by_category.get(title, [])
            cat_i = info_by_category.get(title, [])
            cat_t = tables_by_title.get(title, [])
            if not (cat_f or cat_p or cat_i or cat_t):
                continue
            worst = cat_f[0]['cvss'] if cat_f else 0.0
            worst_css = cat_f[0]['css'] if cat_f else 'sev-none'
            categories_ordered.append({
                'title': title,
                'findings': cat_f,
                'passed': cat_p,
                'info': cat_i,
                'tables': cat_t,
                'worst': worst,
                'worst_css': worst_css,
            })
        categories_ordered.sort(key=lambda c: (-c['worst'], c['title']))

        section_data = {}
        for key, (_title, ids, cat) in self.sections.items():
            payload = self._section_payload(ids, cat)
            section_data[f'{key}_list'] = payload['results']
            section_data[f'{key}_tables'] = payload['tables']

        html_content = self.template.render(
            domain=self.domain,
            date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            filename=self.filename,
            global_score=score,
            avg_cvss=avg_cvss,
            total_failed=len(findings),
            sev_counts=counts,
            section_meta=section_meta,
            ordered_keys=ordered_keys,
            top_findings=top_findings,
            categories_ordered=categories_ordered,
            **section_data
        )

        out_path = f'{self.filename}.html'
        with open(out_path, 'w', encoding='utf-8') as html_file:
            html_file.write(html_content)
        return path.abspath(out_path)