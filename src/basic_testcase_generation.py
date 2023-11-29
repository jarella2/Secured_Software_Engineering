import sqlite3
import subprocess
import sys
import os
from database_extraction import main as build_database
from analyze_repository import main as analyze_repository

def help(status):
    print("Usage: python3 basic_testcase_generation.py <repo_path>")
    print("repo_path: path to the repository to scan for vulnerabilities")
    exit(status)

def get_vulnerabilities():
    conn = sqlite3.connect('db/cwe.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * from cwe
    ''')
    vulnerabilities = cursor.fetchall()
    conn.close()
    
    return vulnerabilities

# def analyze_repository(repo_path, vulnerabilities):



def main():
    # Parse the repo to scan from the command line
    if len(sys.argv) != 2:
        help(1)
    elif sys.argv[1] == '-h':
        help(0)
    
    # TODO: Change this so when a repo is presented that doesn't exist locally, we clone it
    repo_path = sys.argv[1]
    if not os.path.isdir(repo_path):
        print(f"Error: {repo_path} is not a valid directory")
        exit(1)

    # Create our database if it doesn't exist
    build_database()
    vulnerabilities = get_vulnerabilities()

    # Analyze the repo for vulnerabilities and generate test cases
    for vulnerability in vulnerabilities:
        test_cases = generate_test_cases(vulnerability)
        run_test_cases(repo_path, test_cases)

    # Generate a report of the results
    generate_report()
    
    exit(0)

if __name__ == '__main__':
    main()