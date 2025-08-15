# Sarif Comparison

## Setup
 - Create a virtual environment called "venv": `python -m venv venv`
 - Activate it by running  `. ./venv/Scripts/activate` or `. ./venv/bin/activate`
 - Run `python -m pip install pandas` 

## Generate Metrics
Output CSV-formatted metrics including counts of findings by severity and counts of CWEs
```sh
python sarif_metrics.py sast_results.sarif
```
Save metrics from many SARIF files to a CSV:
```sh
python sarif_metrics *.sarif > sast_comparison.csv
```
Table-format the metrics for text output
```sh
python sarif_metrics *.sarif | column -t -s'^'
# outputs
File                Tool      TotalIssues  Critical  High  Medium  Low  Top25  UniqueCWEs  UniqueFiles
sast_report2.sarif  SnykCode  10           1         2     3       4    8      5           113
sast_report2.sarif  SnykCode  10           2         4     6       8    9      6           123
```



## Generate a CSV Report of Issues for 1 SARIF file
```sh
python sarif_issues.py my_scan.sarif
```
The script writes CSV rows to stdout. To save it, redirect to a file:
```sh
python sarif_issues.py my_scan.sarif > my_scan_report.csv
```

## Identify New Issues
Given two SAST scan result files, "old.sarif" and "new.sarif", 
```sh
# Output the issues in sorted order:
python sarif_issues.py old.sarif | sort -u > old_issues.csv
python sarif_issues.py new.sarif | sort -u > new_issues.csv

# Output the lines in new_issues.csv that are not in old_issues.csv 
comm -23 new_issues.csv old_issues.csv 
```


## Generate Many Reports 
 - Put sarif files in the `sarif_files/` directory
 - Run `./run_reports.sh`
 - CSV files will be in the `reports/` directory
