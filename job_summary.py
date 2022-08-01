from cgitb import text
import json
from os.path import exists
from mdutils.mdutils import MdUtils
import sys
import traceback
from os import environ
import re

# mapping of level to severity
code_severity_map = {
    "error": 'high',
    "warning": 'medium',
    "info": 'low',
    "note": 'low',
}

severity_symbol_map = {
    'critical': " :red_circle: ",
    'high': " :red_circle: ",
    'medium': " :warning: ",
    'low': " :information_source: "
}

severity_priority_list = ['critical', 'high', 'medium', 'low']

SNYK_DEPENDENCIES_PATH = 'snyk_dependencies.json'
SNYK_CODE_PATH = 'snyk_code.json'

descriptions = {
        "code": {
            "resources":[("Static Code Analysis","https://owasp.org/www-community/controls/Static_Code_Analysis"),
                          ("Security Rules used by Snyk Code","https://docs.snyk.io/products/snyk-code/security-rules-used-by-snyk-code")],
            "summary": "The main goal of this scan is to have a look at the code and find any potential issues that could lead to a security vulnerability."
        },
        "dependencies": {
            "resources": [("Software Composition Analysis", "https://snyk.io/series/open-source-security/software-composition-analysis-sca/"),
                          ("Snyk Open Source", "https://docs.snyk.io/products/snyk-open-source/getting-started-snyk-open-source")],
            "summary": "Dependency-Check is a Software Composition Analysis (SCA) tool that attempts to detect publicly disclosed vulnerabilities contained within a project’s dependencies. It does this by determining if there is a Common Platform Enumeration (CPE) identifier for a given dependency. If found, it will generate a report linking to the associated CVE entries."
        },
        "licenses":{
            "resources": [("Licenses","https://docs.snyk.io/products/snyk-open-source/licenses")],
            "summary": "Every time you push your code, your repositories are scanned not only for vulnerabilities but also for license compliance. This includes all of your direct and indirect dependencies. Snyk scans your manifest files, and then checks for license issues against Snyk’s known licenses."
        }
    }

def get_json_object(path):
    """
        read the file and convert to json 
    Args:
        path (string): path of file to be read

    Returns:
        json object
    """    
    if exists(path):
        file = open(path)
        return json.load(file)
    return None

def get_dependencies_vulnerability_count(snyk_dependencies_data):
    """
    Takes the dependency file created by snyk and count dependency vulnerability

    Args:
        SNYK_DEPENDENCIES_PATH (string): path of snyk dependencies file which is created using `snyk test --all-projects --json-file-output=snyk_dependencies.json`

    Returns:
        count of dependency vulnerability with respect to severity
    """
    if not isinstance(snyk_dependencies_data, list):
        snyk_dependencies_data = [snyk_dependencies_data]

    synk_vulnerabilities_count = {}
    
    for data in snyk_dependencies_data:
        synk_vulnerabilities_results = data["vulnerabilities"]

        # count the different level of vulnerability
        for dependency in synk_vulnerabilities_results:
            vulnerability_severity = dependency["severity"].lower()
            synk_vulnerabilities_count[vulnerability_severity] = synk_vulnerabilities_count.get(
                vulnerability_severity, 0) + 1

    return synk_vulnerabilities_count

def get_licenses_vulnerability_count(snyk_licenses_data):
    """
    Takes the dependency file created by snyk and count licenses vulnerability

    Args:
        SNYK_DEPENDENCIES_PATH (string): path of snyk dependencies file which is created using `snyk test --all-projects --json-file-output=snyk_dependencies.json`

    Returns:
        count of licenses vulnerability with respect to severity
    """
    if not isinstance(snyk_licenses_data, list):
        snyk_licenses_data = [snyk_licenses_data]

    synk_licenses_count = {}

    for data in snyk_licenses_data:
        synk_licenses_results = data["licensesPolicy"]["orgLicenseRules"]

        for license_name, license_info in synk_licenses_results.items():
            
            license_severity = license_info["severity"].lower()
            synk_licenses_count[license_severity] = synk_licenses_count.get(
                license_severity, 0) + 1

    return synk_licenses_count


def get_code_vulnerability_count(snyk_code_data):
    """
    Takes the code file created by snyk and count code vulnerabilities

    Args:
        SNYK_CODE_PATH (string): path of snyk code file which is created using `snyk code test --all-projects --json-file-output=snyk_code.json`

    Returns:
        count of code vulnerability with respect to severity
    """
    if not isinstance(snyk_code_data, list):
        snyk_code_data = [snyk_code_data]

    synk_code_count = {}

    for data in snyk_code_data:
        synk_code_results = data["runs"][0]["results"]

        # count the different level of vulnerability
        for code_vulnerability in synk_code_results:
            vulnerability_level = code_severity_map[code_vulnerability["level"].lower()]
            synk_code_count[vulnerability_level] = synk_code_count.get(
                vulnerability_level, 0) + 1

    return synk_code_count


def dump_vulnerabilities(vulnerabilities_count, type, output, resources, summary):
    """
    store data into vulnerabilities.md file 
    Args:
        vulnerabilities_count (dict): store the count with respect to severity eg. {'high' : 10, 'low' : 16}
        type (string): type of vulnerability
        output (MdUtils): output .md file  
    """
    output.new_header(level=1, title=f"{type.capitalize()} Scanner Result Summary")
    output.new_line(summary, bold_italics_code='')
    total = 0
    display_list = ["Type", "Count"]
    vulnerability_list = list(vulnerabilities_count.items())
    resources_list = [f'[{name}]({link})' for name, link in resources]

    output.new_list(resources_list)

    if not vulnerability_list:
        output.new_paragraph("No Vulnerabilities Found")
        return

    vulnerability_list.sort(key=lambda x: severity_priority_list.index(x[0]))

    for vulnerability_type, count in vulnerability_list:
        total += count
        symbol = severity_symbol_map.get(vulnerability_type, "")
        display_list.extend(
            [symbol + vulnerability_type.capitalize(), str(count)])

    display_list.extend(["Total", total])

    output.new_line("Finding Summary", bold_italics_code='cib')
    
    output.new_table(columns=2, rows=len(display_list)//2, text=display_list)


def display_count(vulnerability_data, output, type_of_vulnerability):
    """ 
        display the count of vulnerabilities to output file ('vulnerabilities.md')
    Args:
        vulnerability_data (json)
        output (MdUtils): output file ('vulnerabilities.md')
        type_of_vulnerability (string): threee types -> ['code', 'dependencies', 'licenses']
    """    
    if vulnerability_data:
        if type_of_vulnerability == 'code':
            count = get_code_vulnerability_count(vulnerability_data)
        elif type_of_vulnerability == 'dependencies':
            count = get_dependencies_vulnerability_count(vulnerability_data)
        elif type_of_vulnerability == 'licenses':
            count = get_licenses_vulnerability_count(vulnerability_data)
                
        description = descriptions[type_of_vulnerability]
        resources = description['resources']
        summary = description['summary']
            
        dump_vulnerabilities(count, type_of_vulnerability, output, resources, summary)
    else:
        output.new_header(level=1, title=f"{type_of_vulnerability.capitalize()} Scanner Result Summary")
        output.new_paragraph("No Vulnerabilities Found")


try:
    command_line_args = sys.argv
    
    if len(command_line_args) > 1 and command_line_args[1].strip() != "":
        SNYK_DEPENDENCIES_PATH = command_line_args[1]
    
    if len(command_line_args) > 2 and command_line_args[2].strip() != "":
        SNYK_CODE_PATH = command_line_args[2]
    
    output = MdUtils(file_name="vulnerabilities")
    snyk_dependency_data = get_json_object(SNYK_DEPENDENCIES_PATH)
    snyk_code_data = get_json_object(SNYK_CODE_PATH)
    
    display_count(snyk_code_data, output, "code")
    display_count(snyk_dependency_data, output, "dependencies")
    display_count(snyk_dependency_data, output, "licenses")
    output.create_md_file()

except Exception as err:
    print(traceback.print_exc())
    sys.exit(1)
