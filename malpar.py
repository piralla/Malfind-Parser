import re
import csv
import os
import sys

# Patterns to search for
patterns = {
    "MZ PE header": b"MZ",
    "Shellcode": b"\xeb\xfe",   
    "Call to ExitProcess": b"\xFF\x25",
    "Jump to Register": b"\xff\xe0",
    "Jump to Register": b"jmp eax",  
    "NOP slide": b"\x90"*10,
    "Stack pivot": b"\x94\xc3",
    "Stack pivot": b"xchg esp, eax",      
    "Heap Spray": b"\x0c\x0c\x0c\x0c",
    "Return-oriented programming (ROP bytes)": b"\xc3",
    "Return-oriented programming (ROP string)": "ret",
    "Syscall": b"\x0f\x05",
    "Syscall": "syscall",  
    "Software interrupt": "int 0x80",  
    "x86 function prologue (string-1)": b"push	ebp",   
    "x86 function prologue (string-2)": b"mov	ebp, esp",  
    "x64 function prologue (string-1)": b"push rbp",  
    "x64 function prologue (string-2)": b"mov rbp, rsp",  
    "x64 function prologue (USVWATA)": "USVWATA",  
    "x64 function prologue (UVWATAUAVAWH)": 'UVWATAUAVAWH', 
    "x64 function prologue (WATAUH)": 'WATAUH',
    "x64 function prologue (WATAUAVAWH)": 'WATAUAVAWH',
    "x64 function prologue (SUVWATAUAVAWH)": 'SUVWATAUAVAWH',
    "x64 function prologue (SUVWATH)": 'SUVWATH',
    "x64 function prologue (VWATAUAVH)": 'VWATAUAVH',
    "x64 function prologue (SUVWATAUH)": 'SUVWATAUH',
    "x64 function prologue (ATAUAVH)": 'ATAUAVH',
    "x64 function prologue (USVWATAUAVAWH)": 'USVWATAUAVAWH',
    "x64 function prologue (UVWATAUH)": 'UVWATAUH',
    "x64 function prologue (SUVWATAUAVH)": 'SUVWATAUAVH',
    "x64 function prologue (SVWATAUAVAWH)": 'SVWATAUAVAWH',
    "x64 function prologue (USVWATH)": 'USVWATH',
    "x64 function prologue (USVWATAUH)": 'USVWATAUH',
    "x64 function prologue (USVWATAUAVH)": 'USVWATAUAVH',
    "x64 function prologue (VWATAUAVAWH)": 'VWATAUAVAWH',
    "x64 function prologue (WAVAWH)": 'WAVAWH',
    "x64 function prologue (ATAUAVAWH)": 'ATAUAVAWH',
    "x64 function prologue (VWATAUAWH)": 'VWATAUAWH',
    "x64 function prologue (WATAVH)": 'WATAVH',
    "x64 function prologue (UVWATAUAVH)": 'UVWATAUAVH'
}

# Function to search for patterns in a file
def search_patterns(file_path):
    results = {}
    for pattern_name, pattern in patterns.items():
        try:
            with open(file_path, 'r') as f:
                data = f.read()
            if isinstance(pattern, bytes):
                # If the pattern is bytes, decode it to a string using the same encoding as the file
                pattern = pattern.decode('utf-8')
            matches = re.findall(pattern, data)
        except UnicodeDecodeError:  # This will be raised for non-text files
            with open(file_path, 'rb') as f:
                data = f.read()
            if isinstance(pattern, str):
                # If the pattern is a string, encode it to bytes to match the file's bytes
                pattern = pattern.encode('utf-8')
            matches = re.findall(pattern, data)
        if matches:
            results[pattern_name] = len(matches)
    return results

# Function to write results to CSV
def write_to_csv(results, csv_path):
    with open(csv_path, 'w', newline='') as csvfile:
        fieldnames = ['File', 'Pattern', 'Count']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for file, patterns in results.items():
            for pattern, count in patterns.items():
                writer.writerow({'File': file, 'Pattern': pattern, 'Count': count})

# Get the file or directory to analyze from the command line argument
path_to_analyze = sys.argv[1]

# Search for patterns in the specified file or all txt files in the specified directory
results = {}
if os.path.isfile(path_to_analyze):
    results[path_to_analyze] = search_patterns(path_to_analyze)
elif os.path.isdir(path_to_analyze):
    for file in os.listdir(path_to_analyze):
        if file.endswith('.txt'):
            results[file] = search_patterns(os.path.join(path_to_analyze, file))

# Write the results to a CSV file
write_to_csv(results, 'malfind-parser-results.csv')
