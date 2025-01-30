#!/usr/bin/env bash

shopt -s globstar

input_dir="sarif_files"
output_dir="reports"

for sarif_file in "${input_dir}"/*.* ; do
    printf '\n%s\n' "${sarif_file}"

    # printf '%s\n' "${sarif_file%.*}"
    # printf '%s\n' "${sarif_file##*/}"
    without_ext="${sarif_file%.*}"
    file_basename="${without_ext##*/}"
    # printf '%s\n' "${file_basename}"

    python sarif_issues.py "${sarif_file}" > "${output_dir}"/"${file_basename}_issues.csv"
done

for csv_file in "${output_dir}"/*.csv ; do
    dos2unix "${csv_file}"
done