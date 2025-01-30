import xml.etree.ElementTree as ET
from pathlib import Path


def print_file_locs(report_path: Path):
    root = ET.parse(report_path)
    for elem in root.findall(".//*[FilePath]"):
        file_path = elem.find("./FilePath").text
        line_start = elem.find("./LineStart").text
        print(f"{file_path}:{line_start}")

def find_files_with_cwe(report_path: Path):
    root = ET.parse(report_path)
    external_category = root.findall(".//ExternalCategory[@type='CWE Top 25 2023']")
    if len(external_category) > 0:
        print(f"Found CWE Top 25: {report_path}")

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Must supply the name of a sarif file")
        sys.exit(1)

    report_file = Path(sys.argv[1])
    if not report_file.exists():
        print(f"File {sys.argv[1]} does not exist")
        sys.exit(1)

    # print_file_locs(report_file)
    find_files_with_cwe(report_file)


    