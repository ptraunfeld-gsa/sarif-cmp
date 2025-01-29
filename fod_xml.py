import xml.etree.ElementTree as ET
from pathlib import Path


def print_file_locs(report_path: Path):
    root = ET.parse(report_path)
    for elem in root.findall(".//*[FilePath]"):
        file_path = elem.find("./FilePath").text
        line_start = elem.find("./LineStart").text
        print(f"{file_path}:{line_start}")

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Must supply the name of a sarif file")
        sys.exit(1)

    report_file = Path(sys.argv[1])
    if not report_file.exists():
        print(f"File {sys.argv[1]} does not exist")
        sys.exit(1)

    print_file_locs(report_file)
