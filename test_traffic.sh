#!/bin/bash

# Запуск iftop и сохранение вывода
iftop -i en0 -t -s 5 -B -P -N > iftop_output.txt &
IFTOP_PID=$!




wait $IFTOP_PID

