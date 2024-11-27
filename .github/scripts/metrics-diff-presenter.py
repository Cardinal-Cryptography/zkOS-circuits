import re

import pandas as pd
from jinja2 import Template


def parse_file(file_path):
    data = []
    current_circuit = None
    with open(file_path, 'r') as file:
        for line in file:
            line = line.strip()
            if 'PhantomData' in line:
                continue
            if line.startswith('`'):
                current_circuit = re.match(r"`(.*?)`", line).group(1)
            if ': ' in line and current_circuit:
                key, value = map(str.strip, line.split(': ', 1))

                key = key.removeprefix(f'`{current_circuit}`').strip()
                value = value.removesuffix(',')

                data.append({
                    'Circuit': current_circuit,
                    'Metric': key,
                    'Value': value
                })
    return pd.DataFrame(data)


def highlight_diff(val, diff_flag):
    """Highlight the differences with HTML color formatting"""
    if diff_flag:
        return f'<span style="color: red;">{val}</span>'
    return val


def generate_diff_html(file1, file2):
    df1 = parse_file(file1).set_index(['Circuit', 'Metric'])
    df2 = parse_file(file2).set_index(['Circuit', 'Metric'])

    # Merge the two dataframes and compute the 'Different' flag
    diff = df1.merge(df2, how='outer', left_index=True, right_index=True, suffixes=('_MainBranch', '_NewCode'))
    diff['Different'] = diff.apply(lambda row: row['Value_MainBranch'] != row['Value_NewCode'], axis=1)

    # Filter out rows that are not different
    diff = diff[diff['Different']]

    # If there are no differences, handle gracefully
    if diff.empty:
        print("No differences found.")
        return

    # Function to calculate percentage change and return formatted HTML string
    def calculate_percentage_change(value1, value2):
        try:
            v1 = float(value1.replace('KB', '').replace('MB', '').strip())
            v2 = float(value2.replace('KB', '').replace('MB', '').strip())
            if v1 == 0:
                return "N/A"  # Avoid division by zero
            change = ((v2 - v1) / v1) * 100
            color = 'red' if change > 0 else 'green'
            return f'$${{\color{{{color}}}{change:.2f}\%}}$$'
        except (ValueError, TypeError, AttributeError):
            return "N/A"  # If calculation isn't possible, return "N/A"

    # Function to highlight values based on comparison
    def highlight_diff(value1, value2):
        try:
            v1 = float(value1.replace('KB', '').replace('MB', '').strip())
            v2 = float(value2.replace('KB', '').replace('MB', '').strip())
            if v1 > v2:
                return f'<span>$${{\color{{red}}{value1}}}$$</span>'
            elif v1 < v2:
                return f'<span>$${{\color{{green}}{value1}}}$$</span>'
        except (ValueError, TypeError, AttributeError):
            pass
        return value1

    # Apply the highlighting function and percentage change calculation
    diff.reset_index(inplace=True)  # Make 'Circuit' and 'Metric' columns regular columns for display
    diff['Main branch'] = diff.apply(lambda row: highlight_diff(row['Value_MainBranch'], row['Value_NewCode']), axis=1)
    diff['New code'] = diff.apply(lambda row: highlight_diff(row['Value_NewCode'], row['Value_MainBranch']), axis=1)
    diff['% Change'] = diff.apply(
        lambda row: calculate_percentage_change(row['Value_MainBranch'], row['Value_NewCode']), axis=1)

    # Drop the original columns and 'Different' column
    diff = diff[['Circuit', 'Metric', 'Main branch', 'New code', '% Change']]

    # Create HTML table
    html = diff.to_html(escape=False, index=False)

    # HTML template with some styles
    template = Template("""<html><body>
    {{ table|safe }}
</body></html>""")

    # Render the template
    html_content = template.render(table=html)

    # Save to file
    with open('comparison_diff.html', 'w') as f:
        f.write(html_content)
    print("Diff generated in 'comparison_diff.html'")


generate_diff_html('main-report.txt', 'current-report.txt')
