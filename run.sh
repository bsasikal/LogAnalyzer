#!/usr/bin/env bash

#setting permissions
chmod a+x ./src/log_analyzer.py

# program expects to provide input file (absolute ot relative path) and output directory location as arguments
python ./src/log_analyzer.py ./log_input/log.txt ./log_output/

