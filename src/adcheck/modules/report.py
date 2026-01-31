from adcheck.modules.constants import CHECKLIST
from jinja2 import Environment, FileSystemLoader
from os import path
from datetime import datetime
import math


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

    def _get_tables_for_category(self, category):
        return [table for table in self.additional_tables if table.get('category') == category]

    def _format_markdown_table(self, table):
        content = f"{table['title']}\n\n"
        content += "| " + " | ".join(table['headers']) + " |\n"
        content += "| " + " | ".join(["---"] * len(table['headers'])) + " |\n"
        
        for row in table['rows']:
            formatted_row = [str(cell) if cell else " " for cell in row]
            content += "| " + " | ".join(formatted_row) + " |\n"
        
        return content + "\n"

    def _format_markdown_section(self, title, ids, category):
        section_content = f"## {title}\n\n"
        
        for result in self.results:
            if result.get('name') in ids:
                color = result.get('color', '')
                message = result.get('message', '')

                if color == 'green':
                    message = f'<span style="color:#26b260">{message}</span>'
                elif color == 'red':
                    message = f'<span style="color:#c93131">{message}</span>'

                section_content += f"- {message}\n"
        
        tables = self._get_tables_for_category(category)
        if tables:
            section_content += "\n"
            for table in tables:
                section_content += self._format_markdown_table(table)
        
        return section_content + "\n"

    def gen_markdown(self):
        markdown_content = "# ADcheck Report\n\n"
        markdown_content += self._format_markdown_section('Privilege and Trust Management', self.privs_ids, 'privilege')
        markdown_content += self._format_markdown_section('User Account Management', self.user_ids, 'user')
        markdown_content += self._format_markdown_section('Computer and Domain Management', self.domain_ids, 'domain')
        markdown_content += self._format_markdown_section('Audit and Policy Management', self.policy_ids, 'policy')

        with open(f"{self.filename}.md", "w", encoding="utf-8") as md_file:
            md_file.write(markdown_content)

    def _get_section_data(self, ids, category):
        return {
            'results': [{'message': r.get('message'), 'color': r.get('color')} for r in self.results if r.get('name') in ids],
            'tables': self._get_tables_for_category(category)
        }

    def gen_html(self):
        sections = {
            'privs': (self.privs_ids, self.privs_list, 'privilege'),
            'user': (self.user_ids, self.user_list, 'user'),
            'domain': (self.domain_ids, self.domain_list, 'domain'),
            'policy': (self.policy_ids, self.policy_list, 'policy')
        }

        counts = {key: sum(1 for r in self.results if r.get('color') == 'green' and r.get('name') in ids) 
                  for key, (ids, _, _) in sections.items()}
        
        def calculate_percentage(count, total):
            return int(math.ceil(count * (100 / len(total)))) if total else 0

        scores = {key: calculate_percentage(counts[key], lst) for key, (_, lst, _) in sections.items()}
        scores['total'] = calculate_percentage(sum(counts.values()), self.total_list)

        section_data = {f'{key}_list': self._get_section_data(ids, cat)['results'] 
                        for key, (ids, _, cat) in sections.items()}
        section_data.update({f'{key}_tables': self._get_section_data(ids, cat)['tables'] 
                             for key, (ids, _, cat) in sections.items()})

        html_content = self.template.render(
            domain=self.domain,
            date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            filename=self.filename,
            scores=scores,
            **section_data
        )

        with open(f'{self.filename}.html', 'w', encoding='utf-8') as html_file:
            html_file.write(html_content)