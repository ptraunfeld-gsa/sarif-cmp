# Sarif Comparison

## Setup
 - Create a virtual environment called "venv": `python -m venv venv`
 - Activate it by running  `. ./venv/Scripts/activate` or `. ./venv/bin/activate`
 - Run `python -m pip install pandas` 

## Generate Reports
 - Put sarif files in the `sarif_files/` directory
 - Run `./run_reports.sh`
 - CSV files will be in the `reports/` directory

## Generate a CSV Report of Issues for 1 SARIF file
```sh
python sarif_issues.py my_scan.sarif
```

The script writes CSV rows to stdout. To save it, redirect to a file:
```sh
python sarif_issues.py my_scan.sarif > my_scan_report.csv
```


