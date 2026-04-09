#!/bin/bash

# Dynamic Testing Script

echo "--- Starting dynamic operations ---"

# 1. File Creation
echo "1. Creating dynamic files..."
for i in {1..5}; do
  echo "This is file number $i" > "dynamic_file_$i.txt"
done
echo "Files created."

# 2. File Modification
echo "2. Modifying files..."
for i in {1..5}; do
  if [ -f "dynamic_file_$i.txt" ]; then
    echo "Appending text to file $i" >> "dynamic_file_$i.txt"
  else
    echo "Error: dynamic_file_$i.txt not found!" >&2
  fi
done
echo "Files modified."

# 3. Simulated Math Operations
echo "3. Performing math operations..."
# Deliberately causing an error by dividing by zero
num1=10
num2=0

# Subshell to catch error, but it won't crash the script immediately
echo "Attempting 10 / 0..."
result=$(expr $num1 / $num2 2>&1)
if [ $? -ne 0 ]; then
  echo "Math error: $result" >&2
else
  echo "Result: $result"
fi

echo "Attempting a valid operation: 10 * 5..."
result=$(expr 10 \* 5)
echo "Result: $result"

# 4. File Deletion
echo "4. Deleting files..."
for i in {1..5}; do
  rm -f "dynamic_file_$i.txt"
done
echo "Files deleted."

# 5. Directory Operations
echo "5. Directory operations..."
mkdir dynamic_dir
touch dynamic_dir/temp.txt
rm -rf dynamic_dir
echo "Directory operations complete."

# 6. Intentional Command Error
echo "6. Running an invalid command..."
invalid_command_xyz 2> error.log
if [ $? -ne 0 ]; then
  echo "Command error caught. See error.log" >&2
fi

echo "--- Dynamic operations complete ---"
