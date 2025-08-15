from pathlib import Path
from sarif_issues import sarif_to_df,get_unique_cwes, SEVERITY,IN_TOP_25
from dataclasses import dataclass, astuple

@dataclass
class ScanMetrics:
    file: str
    tool: str
    total_issues: int
    critical: int
    high: int
    medium: int
    low: int
    top25: int
    unique_cwes: int
    unique_files: int


def get_sarif_metrics(sarif_file: Path) -> ScanMetrics:
    sarif_df = sarif_to_df(sarif_file)
    if sarif_df is None:
        return None
    total_issues = len(sarif_df[ sarif_df[SEVERITY].notna() ])
    tool = sarif_df['tool'].unique()[0]
    num_critical = len(sarif_df[ sarif_df[SEVERITY] == "CRITICAL" ])
    num_high = len(sarif_df[ sarif_df[SEVERITY] == "HIGH" ])
    num_medium = len(sarif_df[ sarif_df[SEVERITY] == "MEDIUM" ])
    num_low = len(sarif_df[ sarif_df[SEVERITY] == "LOW" ])
    num_top_25 = len(sarif_df[ sarif_df[IN_TOP_25] == True ])

    unique_cwes = get_unique_cwes(sarif_df)
    # print(type(unique_cwes))
    num_unique_cwes = len(unique_cwes)

    num_unique_files = len(sarif_df['filename'].unique())
    return ScanMetrics(
        f"{sarif_file.name}",
        tool, 
        total_issues, 
        num_critical, 
        num_high, 
        num_medium, 
        num_low, 
        num_top_25, 
        num_unique_cwes, 
        num_unique_files
    )
   
def get_metrics_rows(sarif_files: list[Path], sep='^') -> list[str]:
    metrics = [get_sarif_metrics(f) for f in sarif_files]
    rows = [ sep.join([f"{i}" for i in astuple(m)]) for m in metrics if m is not None]
    columns = [
        "File",
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
    return [ sep.join(columns), *rows]

def print_sarif_metrics(sarif_files: list[Path]):
    for row in get_metrics_rows(sarif_files):
        print(f"{row}")


if __name__ == "__main__":
    import sys
    def get_paths(strs: list[str]) -> list[Path]:
        paths = []
        for s in strs:
            p = Path(s)
            if p.exists():
                paths.append(p)
            else:
                print(f"File {s} does not exist", file=sys.stderr)
        return paths

    if len(sys.argv) < 2:
        print("Must supply the name of a sarif file", file=sys.stderr)
        sys.exit(1)

    sarif_files = get_paths(sys.argv[1:])
    print_sarif_metrics(sarif_files)