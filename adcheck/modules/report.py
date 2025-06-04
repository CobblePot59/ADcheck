from adcheck.modules.constants import CHECKLIST
from jinja2 import Environment, FileSystemLoader
from os import path
from datetime import datetime
import math


class ReportGenerator():
    def __init__(self, results, domain):
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

    def gen_markdown(self):
        def format_markdown_section(title, ids):
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
            section_content += "\n"
            return section_content

        markdown_content = "# ADcheck Report\n\n"
        markdown_content += format_markdown_section('Privilege and Trust Management', self.privs_ids)
        markdown_content += format_markdown_section('User Account Management', self.user_ids)
        markdown_content += format_markdown_section('Computer and Domain Management', self.domain_ids)
        markdown_content += format_markdown_section('Audit and Policy Management', self.policy_ids)

        with open(f"{self.filename}.md", "w", encoding="utf-8") as md_file:
            md_file.write(markdown_content)

    def gen_html(self):
        cpt_user = cpt_domain = cpt_privs = cpt_policy = 0

        for result in self.results:
            name = result.get('name')
            color = result.get('color')
            if 'green' in color:
                if name in self.privs_ids:
                    cpt_privs += 1
                elif name in self.user_ids:
                    cpt_user += 1
                elif name in self.domain_ids:
                    cpt_domain += 1
                elif name in self.policy_ids:
                    cpt_policy += 1
        cpt_total = cpt_privs + cpt_user + cpt_domain + cpt_policy

        def calculate_percentage(count, total):
            return int(math.ceil(count * (100 / len(total)))) if total else 0

        scores = {
            "total": calculate_percentage(cpt_total, self.total_list),
            "privs": calculate_percentage(cpt_privs, self.privs_list),
            "user": calculate_percentage(cpt_user, self.user_list),
            "domain": calculate_percentage(cpt_domain, self.domain_list),
            "policy": calculate_percentage(cpt_policy, self.policy_list),
        }

        date_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        html_content = self.template.render(
            domain=self.domain,
            date=date_str,
            filename=self.filename,
            scores=scores,
            privs_list=[{'message': result.get('message'), 'color': result.get('color')} for result in self.results if result.get('name') in self.privs_ids],
            user_list=[{'message': result.get('message'), 'color': result.get('color')} for result in self.results if result.get('name') in self.user_ids],
            domain_list=[{'message': result.get('message'), 'color': result.get('color')} for result in self.results if result.get('name') in self.domain_ids],
            policy_list=[{'message': result.get('message'), 'color': result.get('color')} for result in self.results if result.get('name') in self.policy_ids]
        )


        with open(f'{self.filename}.html', 'w', encoding='utf-8') as html_file:
            html_file.write(html_content)
