import os
import sys
import sqlite3
import difflib
import magic
from multiprocessing import Pool

def calculate_similarity(pattern, code):
    return difflib.SequenceMatcher(None, pattern, code).ratio()


def get_vulnerabilities():
    conn = sqlite3.connect('db/cwe.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * from cwe
    ''')
    vulnerabilities = cursor.fetchall()
    conn.close()
    
    return vulnerabilities

def search_pattern_in_file(file_path, pattern):
    ignore_array = ['.png', '.jpg', '.idx', '.jpeg', '.gif', '.bmp', '.tiff', '.tif', '.ico', '.svg', '.pdf', '.doc', '.docx', '.ppt', '.pptx','.rev', '.pack', '.xls', '.xlsx', '.zip', '.rar', '.tar', '.gz', '.7z', '.exe', '.dll', '.so', '.o', '.a', '.lib', '.obj', '.class', '.jar', '.war', '.ear', '.pyc', '.pyo', '.whl', '.ttf', '.woff', '.woff2', '.eot', '.mp3', '.mp4', '.wav', '.ogg', '.avi', '.mov', '.mpg', '.mpeg', '.flv', '.wmv', '.swf', '.fla', '.psd', '.ai', '.raw', '.bmp', '.ico', '.webp', '.apk', '.dmg', '.iso', '.img', '.csv', '.tsv', '.json', '.xml', '.yaml', '.yml', '.log', '.db', '.sql', '.sqlite', '.sqlite3', '.bak', '.tmp', '.temp', '.cache', '.bin', '.dat', '.exe', '.dll', '.so', '.o', '.a', '.lib', '.obj', '.class', '.jar', '.war', '.ear', '.pyc', '.pyo', '.whl', '.ttf', '.woff', '.woff2', '.eot', '.mp3', '.mp4', '.wav', '.ogg', '.avi', '.mov', '.mpg', '.mpeg', '.flv', '.wmv', '.swf', '.fla', '.psd', '.ai', '.raw', '.bmp', '.ico', '.webp', '.apk', '.dmg', '.iso', '.img', '.csv', '.tsv', '.json', '.xml', '.yaml', '.yml', '.log', '.db', '.sql', '.sqlite', '.sqlite3', '.bak', '.tmp', '.temp', '.cache', '.bin', '.dat', '.exe', '.dll', '.so', '.o', '.a', '.lib', '.obj', '.class', '.jar', '.war', '.ear', '.pyc', '.pyo', '.whl', '.ttf', '.woff', '.woff2', '.txt']
    
    # Ignore certain file types
    if os.path.splitext(file_path)[1] in ignore_array:
        return False

    # If the pattern is empty, return false
    if pattern == '':
        return False

    # Extract the first line from the pattern to see what programming language it is
    language = pattern.split('\n')[0].split(':')[1].strip().split(',')[0].strip()
    pattern = pattern.split('\n')[1:]

    # Check if file matches the pattern language
    with magic.Magic() as m:
        file_language = m.id_filename(file_path).split(',')[0].strip()
        if file_language.find(language) == -1:
            return False
    
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        for line in file:
            similarity = calculate_similarity(pattern, line)

            if similarity > 0.01:
                print(f"Similarity: {similarity} for {file_path}")
            
            if similarity > 0.7:
                return True
    return False

def worker(args):
    file_path, vulnerabilities = args
    results = []
    print(f"Analyzing file: {file_path}")
    for vulnerability in vulnerabilities:
        if search_pattern_in_file(file_path, vulnerability[3]):
            results.append((file_path, vulnerability[0], vulnerability[1]))
    return results


def analyze_repository(repo_path, vulnerabilities):
    results = []
    print(f"Analyzing repository for vulnerabilities... {repo_path}")

     # Get the total number of files in the repository
    total_files = []
    for root, dirs, files in os.walk(repo_path):
        for file in files:
            total_files.append(os.path.join(root, file))
    repo_file_len = len(total_files)

    # # Ignore certain file types
    # ignore_dir = ['.git', '.vscode', 'node_modules', 'build', 'dist', 'target', 'out', 'bin', 'obj', 'venv', 'env', 'virtualenv', 'venv3', 'env3', 'virtualenv3', 'venv2', 'env2', 'virtualenv2', 'venv3.6', 'env3.6', 'virtualenv3.6', 'venv3.7', 'env3.7', 'virtualenv3.7', 'venv3.8', 'env3.8', 'virtualenv3.8', 'venv3.9', 'env3.9', 'virtualenv3.9', 'venv3.10', 'env3.10', 'virtualenv3.10', 'venv3.11', 'env3.11', 'virtualenv3.11', 'venv3.12', 'env3.12', 'virtualenv3.12', 'venv3.13', 'env3.13', 'virtualenv3.13', 'venv3.14', 'env3.14', 'virtualenv3.14', 'venv3.15', 'env3.15', 'virtualenv3.15', 'venv3.16', 'env3.16', 'virtualenv3.16', 'venv3.17', 'env3.17', 'virtualenv3.17', 'venv3.18', 'env3.18', 'virtualenv3.18', 'venv3.19', 'env3.19', 'virtualenv3.19', 'venv3.20', 'env3.20', 'virtualenv3.20', 'venv3.21', 'env3.21', 'virtualenv3.21', 'venv3.22', 'env3.22', 'virtualenv3.22', 'venv3.23', 'env3.23', 'virtualenv3.23', 'venv3.24', 'env3.24', 'virtualenv3.24', 'venv3.25', 'env3.25', 'virtualenv3.25', 'venv3.26', 'env3.26', 'virtualenv3.26', 'venv3.27', 'env3.27', 'virtual']
    # for root, dirs, files in os.walk(repo_path):
    #     # Skip directories we don't want to analyze
    #     for ignore in ignore_dir:
    #         if ignore in root:
    #             continue

    # Create a multiprocessing pool
    with Pool() as pool:
        # Use starmap to concurrently process files
        results = pool.map(worker, [(file_path, vulnerabilities) for file_path in total_files])

    # Flatten the results
    results = [item for sublist in results for item in sublist]

    return results

def main():
    # Example usage
    repo_path = 'test_repositories/VulnerableWordpress'
    vulnerabilities = get_vulnerabilities()

    results = analyze_repository(repo_path, vulnerabilities)

    for result in results:
        print(f"Potential vulnerability found: {result[1]} in {result[0]}")

if __name__ == '__main__':
    main()