import os
import sqlite3

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
    ignore_array = ['.png', '.jpg', '.idx', '.jpeg', '.gif', '.bmp', '.tiff', '.tif', '.ico', '.svg', '.pdf', '.doc', '.docx', '.ppt', '.pptx','.rev', '.pack', '.xls', '.xlsx', '.zip', '.rar', '.tar', '.gz', '.7z', '.exe', '.dll', '.so', '.o', '.a', '.lib', '.obj', '.class', '.jar', '.war', '.ear', '.pyc', '.pyo', '.whl', '.ttf', '.woff', '.woff2', '.eot', '.mp3', '.mp4', '.wav', '.ogg', '.avi', '.mov', '.mpg', '.mpeg', '.flv', '.wmv', '.swf', '.fla', '.psd', '.ai', '.raw', '.bmp', '.ico', '.webp', '.apk', '.dmg', '.iso', '.img', '.csv', '.tsv', '.json', '.xml', '.yaml', '.yml', '.log', '.db', '.sql', '.sqlite', '.sqlite3', '.bak', '.tmp', '.temp', '.cache', '.bin', '.dat', '.exe', '.dll', '.so', '.o', '.a', '.lib', '.obj', '.class', '.jar', '.war', '.ear', '.pyc', '.pyo', '.whl', '.ttf', '.woff', '.woff2', '.eot', '.mp3', '.mp4', '.wav', '.ogg', '.avi', '.mov', '.mpg', '.mpeg', '.flv', '.wmv', '.swf', '.fla', '.psd', '.ai', '.raw', '.bmp', '.ico', '.webp', '.apk', '.dmg', '.iso', '.img', '.csv', '.tsv', '.json', '.xml', '.yaml', '.yml', '.log', '.db', '.sql', '.sqlite', '.sqlite3', '.bak', '.tmp', '.temp', '.cache', '.bin', '.dat', '.exe', '.dll', '.so', '.o', '.a', '.lib', '.obj', '.class', '.jar', '.war', '.ear', '.pyc', '.pyo', '.whl', '.ttf', '.woff', '.woff2']
     # TODO: Ignore any files that are not programming languages (e.g. images, etc.)
    if os.path.splitext(file_path)[1] in ignore_array:
        return False
    
    # Ignore the .git directory
    if '.git' in file_path:
        return False
    elif 'machine' in file_path:
        return False
    

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:

        for line in file:
            if pattern.lower() in line.lower() and pattern != '':
                return True
    return False


def analyze_repository(repo_path, vulnerabilities):
    results = []
    print(f"Analyzing repository for vulnerabilities... {repo_path}")

    # Get the total number of files in the repository
    total_files = []
    for root, dirs, files in os.walk(repo_path):
        for file in files:
            total_files.append(file)
    repo_file_len = len(total_files)

    file_no = 0
    for root, dirs, files in os.walk(repo_path):
        for file in files:
            file_no += 1
            file_path = os.path.join(root, file)
            # Keep track of the file number we're on
            print(f"Analyzing file {file_no} of {repo_file_len} - {file_path}")
            for vulnerability in vulnerabilities:
                if search_pattern_in_file(file_path, vulnerability[3]):
                    results.append((file_path, vulnerability[0], vulnerability[1]))
    return results


# Example usage
repo_path = 'test_repositories/core/'
vulnerabilities = get_vulnerabilities()

results = analyze_repository(repo_path, vulnerabilities)

for result in results:
    print(f"Potential vulnerability found: {result[1]} in {result[0]}")