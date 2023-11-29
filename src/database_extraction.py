import sqlite3
import xml.etree.ElementTree as ET

def get_text_or_default(element, default):
    return element.text if element is not None else default

def extract_example_code(weakness, namespace):
    example_code_element = weakness.find('.//ns:Example_Code', namespace)
    if example_code_element is not None:
        language = example_code_element.get('Language')
        code_structure = ''.join(example_code_element.itertext())
        return f"Language: {language}, Code: {code_structure}"

    print(f"Could not find example code for {weakness.get('Name')}")
    return ''

def parse_XML(root, cursor):
    # Extract namespace (if any) from the XML root element
    namespaces = {'ns': root.tag.split('}')[0].strip('{')} if '}' in root.tag else {}

    # Go to the next level of the XML tree

    # Parse and insert our data to the table
    for weakness in root.findall('.//ns:Weakness', namespaces):
        cwe_id = weakness.get('ID')
        name = weakness.get('Name')
        description = get_text_or_default(weakness.find('ns:Description', namespaces), '')

        # Extracting the code examples
        example_code_element = weakness.find('.//ns:Example_Code', namespaces)
        example_code = extract_example_code(weakness, namespaces)

        cursor.execute('''
            INSERT OR IGNORE INTO cwe (id, name, description, example_code)
            VALUES (?, ?, ?, ?)
        ''', (cwe_id, name, description, example_code))

def main():
    
    # Create our database if it doesn't exist
    conn = sqlite3.connect('db/cwe.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cwe (
            id TEXT PRIMARY KEY,
            name TEXT,
            description TEXT,
            example_code TEXT
        )
    ''')# Add more potentially for common_consequences and related weaknesses

    # Parse the XML file
    tree = ET.parse('xml/25_Common_Weaknesses.xml')
    root = tree.getroot()
    parse_XML(root, cursor)

    # Parse the OWASP XML file
    tree = ET.parse('xml/OWASP_Top_Ten.xml')
    root = tree.getroot()
    parse_XML(root, cursor)

    # Commit our changes and close
    conn.commit()
    conn.close()


if __name__ == '__main__':
    main()