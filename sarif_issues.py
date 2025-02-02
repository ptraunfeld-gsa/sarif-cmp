import json
from pathlib import Path
from dataclasses import dataclass
import re
import pandas as pd
from pandas import DataFrame
import sys

level_to_severity = { 'note' : 'MEDIUM', 'warning' : 'HIGH', 'error': 'CRITICAL' }

cwe_pattern = re.compile(r'\b(cwe-\d+)\b', re.IGNORECASE)
cwe_id_pattern = re.compile(r'\bCWE ID (\d+)\b', re.IGNORECASE)

def has_cwe_top_25(cwe_ids: set[str]) -> bool:
    if cwe_ids is None:
        return False
    top_25 = {
        "CWE-79",
        "CWE-787",
        "CWE-89",
        "CWE-352",
        "CWE-22",
        "CWE-125",
        "CWE-78",
        "CWE-416",
        "CWE-862",
        "CWE-434",
        "CWE-94",
        "CWE-20",
        "CWE-77",
        "CWE-287",
        "CWE-269",
        "CWE-502",
        "CWE-200",
        "CWE-863",
        "CWE-918",
        "CWE-119",
        "CWE-476",
        "CWE-798",
        "CWE-190",
        "CWE-400",
        "CWE-306",
    }
    return len(top_25.intersection(cwe_ids)) > 0


def sarif_to_rule_map(rules: list[dict]) -> dict[str, set[str]]:
    rule_map = {}
    for rule in rules:
        
        # Bandit
        id = rule['id']
        rule_map[id] = set()
        if 'properties' in rule.keys() and 'tags' in rule['properties'].keys():
            for tag in rule['properties']['tags']:
                m = cwe_pattern.search(tag)
                if m:
                    rule_map[id].add(m.group(0).upper())

        
        # SpotBugs
        if 'relationships' in rule.keys():
            for rel in rule['relationships']:
                rel_id = rel['target']['id']
                if rel['target']['toolComponent']['name'] == "CWE":
                    rule_map[id].add(f"CWE-{rel_id}")


        # Fortify
        if 'help' in rule.keys() and 'text' in rule['help']:
            help_text = rule['help']['text']
            m = cwe_id_pattern.findall(help_text)
            if m is not None and len(m) > 0:
                rule_map[id].update([f"CWE-{int(cwe)}" for cwe in m])


        if len(rule_map[id]) < 1:
            del rule_map[id]


    return rule_map

TOOL = "tool"
RULE_ID = "ruleId"
DESC = "description"
FILENAME = "filename"
LINE = "startLine"
SEVERITY = 'severity'
IN_TOP_25 = "inCWETop25"
CWES = "CWEs"

COLUMNS = [
    TOOL,
    RULE_ID,
    DESC,
    FILENAME,
    SEVERITY,
    IN_TOP_25,
    CWES
]

def sarif_to_df(file_path: Path) -> DataFrame:
    with open(file_path, 'r') as f:
        sarif_data = json.load(f)

    if 'runs' not in sarif_data.keys() or len(sarif_data['runs']) < 1:
        print("Bad Sarif")
        sys.exit(1)

    sarif_df = pd.json_normalize(sarif_data['runs'][0]['results'])
    sarif_df[FILENAME] = sarif_df['locations'].apply(lambda locs: locs[0]['physicalLocation']['artifactLocation']['uri'])
    # sarif_df[LINE] = sarif_df['locations'].apply(lambda locs: locs[0]['physicalLocation']['region']['startLine'])
    # sarif_df['endLine'] = sarif_df['locations'].apply(lambda locs: locs[0]['physicalLocation']['region']['endLine'])
    # sarif_df['startColumn'] = sarif_df['locations'].apply(lambda locs: locs[0]['physicalLocation']['region']['startColumn'])
    # sarif_df['endColumn'] = sarif_df['locations'].apply(lambda locs: locs[0]['physicalLocation']['region']['endColumn'])
    sarif_df[DESC] = sarif_df['message.text']
    # sarif_df['severity'] = sarif_df['properties'].apply(lambda props: get_severity(props))
    if 'properties.issue_severity' in sarif_df.columns:
        # sarif_df['severity'] = sarif_df['properties.issue_severity']
        sarif_df.rename(columns={'properties.issue_severity': SEVERITY}, inplace=True)
    elif 'properties.fortify-severity' in sarif_df.columns:
        # sarif_df['severity'] = sarif_df['properties.fortify-severity']
        sarif_df.rename(columns={'properties.fortify-severity': SEVERITY}, inplace=True)

    elif 'level' in sarif_df.columns:
        sarif_df[SEVERITY] = sarif_df['level'].apply(lambda level: level_to_severity[level])

    sarif_df[SEVERITY] = sarif_df[SEVERITY].apply(lambda sev: sev.upper())


    if 'tool' in sarif_data['runs'][0].keys() and 'driver' in sarif_data['runs'][0]['tool'].keys():
        if 'name' in sarif_data['runs'][0]['tool']['driver'].keys():
            sarif_df = sarif_df.assign(tool=f"{sarif_data['runs'][0]['tool']['driver']['name']}")

        if 'rules' in sarif_data['runs'][0]['tool']['driver'].keys():
            rule_map = sarif_to_rule_map(sarif_data['runs'][0]['tool']['driver']['rules'])
        
            sarif_df[IN_TOP_25] = sarif_df[RULE_ID].apply(lambda rule_id: has_cwe_top_25(rule_map.get(rule_id)))
            sarif_df[CWES] = sarif_df[RULE_ID].apply(lambda rule_id: ",".join(rule_map.get(rule_id, "")))

    else:
        print("No rules!")

    return sarif_df[COLUMNS].copy()
    
@dataclass
class Metrics:
    tool: str
    loc_scanned: int
    total_issues: int
    num_files_with_issues: int
    num_critical_issues: int
    num_high_issues: int
    num_medium_issues: int
    num_top_25: int
    num_unique_cwes: int

def get_unique_cwes(df: DataFrame) -> set[str]:
    return set(",".join(filter(lambda x: x is not None and len(x) > 0, list(df['CWEs'].unique()))).split(","))

def print_sarif_metrics(sarif_file: Path, verbose=True):
    with open(sarif_file, 'r') as f:
        sarif_data = json.load(f)


    sarif_df = sarif_to_df(sarif_file)
    total_issues = len(sarif_df)
    tool = sarif_df['tool'].unique()[0]
    num_critical = len(sarif_df[ sarif_df[SEVERITY] == "CRITICAL" ])
    num_high = len(sarif_df[ sarif_df[SEVERITY] == "HIGH" ])
    num_medium = len(sarif_df[ sarif_df[SEVERITY] == "MEDIUM" ])
    num_low = len(sarif_df[ sarif_df[SEVERITY] == "LOW" ])
    num_top_25 = len(sarif_df[ sarif_df[IN_TOP_25] == True ])

    unique_cwes = get_unique_cwes(sarif_df)
    num_unique_cwes = len(unique_cwes)

    num_unique_files = len(sarif_df['filename'].unique())

    columns = [
        "Tool",
        "TotalIssues",
        "Critical",
        "High",
        "Medium",
        "Low",
        "Top25",
        "UniqueCWEs",
        "UniqueFiles"
    ]
    data = [ str(c) for c in (
        tool,
        total_issues,
        num_critical,
        num_high,
        num_medium,
        num_low,
        num_top_25,
        num_unique_cwes,
        num_unique_files
    ) ]

    if verbose:
        columns.append("CWEs")
        data.append(",".join(unique_cwes))

    header_row = "^".join(columns)
    data_row = "^".join(data)

    print(f"{header_row}\n{data_row}")
    
def sarif_to_csv(sarif_file: Path):
    with open(sarif_file, 'r') as f:
        sarif_data = json.load(f)
    sarif_df = sarif_to_df(sarif_file)
    sarif_df.to_csv(path_or_buf = sys.stdout, sep = '^', index=False)

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Must supply the name of a sarif file")
        sys.exit(1)

    sarif_file = Path(sys.argv[1])
    if not sarif_file.exists():
        print(f"File {sys.argv[1]} does not exist")
        sys.exit(1)

    # print_sarif_metrics(sarif_file)
    sarif_to_csv(sarif_file)

