#!/usr/bin/env bash

for xml_file in fod_xml_files/*.xml; do 
    # printf '%s\n' "${xml_file}"
    python fod_xml.py "${xml_file}"
done