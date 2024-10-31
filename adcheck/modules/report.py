from modules.constants import CHECKLIST
from jinja2 import Environment, FileSystemLoader
from os import path
import plotly.graph_objects as go
import math

class ReportGenerator():
    def __init__(self, results):
        self.results = results
        self.env = Environment(loader=FileSystemLoader(path.dirname(__file__)))
        self.template = self.env.get_template('templates/report.html')

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

    def gen_html(self):
        privs_list, privs_ids_no_info, privs_ids = self.checklist_parser('Privilege and Trust Management')
        user_list, user_ids_no_info, user_ids = self.checklist_parser('User Account Management')
        domain_list, domain_ids_no_info, domain_ids = self.checklist_parser('Computer and Domain Management')
        policy_list, policy_ids_no_info, policy_ids = self.checklist_parser('Audit and Policy Management')
        total_list = privs_list  + user_list + domain_list + policy_list

        cpt_user = 0
        cpt_domain = 0
        cpt_privs = 0
        cpt_policy = 0

        for result in self.results:
          name = result.get('name')
          color = result.get('color')
          if 'green' in color:
              if name in privs_ids_no_info:
                  cpt_privs += 1
              elif name in user_ids_no_info:
                  cpt_user += 1
              elif name in domain_ids_no_info:
                  cpt_domain += 1
              elif name in policy_ids_no_info:
                  cpt_policy += 1
        cpt_total = cpt_privs + cpt_user + cpt_domain + cpt_policy

        def calculate_percentage(count, total):
            return int(math.ceil(count * (100 / len(total))))

        privs_percentage = calculate_percentage(cpt_privs, privs_list)
        user_percentage = calculate_percentage(cpt_user, user_list)
        domain_percentage = calculate_percentage(cpt_domain, domain_list)
        policy_percentage = calculate_percentage(cpt_policy, policy_list)
        total_percentage = calculate_percentage(cpt_total, total_list)

        def gen_svg(gauge_value, title):
            tickvals = [0, 25, 50, 75, 100, gauge_value]
            fig = go.Figure(go.Indicator(
                mode='gauge+number',
                title={'text': f'{title}', 'font': {'size': 20}},
                value=gauge_value,
                gauge={
                    'axis': {
                        'range': [0, 100],
                        'tickmode': 'array',
                        'tickvals': tickvals,
                        'ticktext': [
                              f'<b style="color:black; font-size:16px;">{gauge_value}</b>' if gauge_value == val else f'{val}'
                              for val in tickvals
                        ],
                    },
                    'bar': {'color': 'rgba(0,0,0,0)'},
                    'steps': [
                        {'range': [0, 25], 'color': 'red'},
                        {'range': [25, 50], 'color': 'orange'},
                        {'range': [50, 75], 'color': 'yellow'},
                        {'range': [75, 100], 'color': 'green'},
                        {'range': [gauge_value-0.1, gauge_value+0.1], 'color': 'black'},
                    ],
                }
            ))

            config = {
              'displayModeBar': True,
              'modeBarButtonsToRemove': ['toImage'],
              'displaylogo': False
            }
            # fig.update_layout(width=400, height=400, margin=dict(t=0, b=0, l=0, r=0))
            return fig.to_html(full_html=False, config=config)

        # Render the template with generated SVGs and result
        output_html = self.template.render(
            total_svg = gen_svg(total_percentage, 'Total Score'),
            privs_svg = gen_svg(privs_percentage, 'Privilege and Trust Management'),
            user_svg = gen_svg(user_percentage, 'User Account Management'),
            domain_svg = gen_svg(domain_percentage, 'Computer and Domain Management'),
            policy_svg = gen_svg(policy_percentage, 'Audit and Policy Management'),
            privs_list = [{'message': result.get('message'), 'color': result.get('color')} for result in self.results if result.get('name') in privs_ids],
            user_list = [{'message': result.get('message'), 'color': result.get('color')} for result in self.results if result.get('name') in user_ids],
            domain_list = [{'message': result.get('message'), 'color': result.get('color')} for result in self.results if result.get('name') in domain_ids],
            policy_list = [{'message': result.get('message'), 'color': result.get('color')} for result in self.results if result.get('name') in policy_ids]
        )

        # Write to an output HTML file
        with open('report.html', 'w') as output_file:
            output_file.write(output_html)