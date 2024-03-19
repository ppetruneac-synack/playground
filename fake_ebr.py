""" Generate fake EBR data for testing purposes, for the Looker POC. Data to mimic: zerodawn-157320.ops_dashboard_v2.data_slicer  
"""


def get_argparser_configuration():
    
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate fake data')
    
    parser.add_argument('--org_count', type=int, help='Number of orgs to create', default=700) # now there are 700 orgs in the dataset
    parser.add_argument('--max_codename_per_org', type=int, help='Max number of tests per org - randomnly generated', default=869) # now there are 869 codenames per org in the dataset
    parser.add_argument('--max_vulns_per_codename', type=int, help='Max number of vulns per test - randomnly generated', default=1218) # now there are 1218 vulns per codename in the dataset
    parser.add_argument('--insert_to_bigquery', type=bool, help='Insert the data to BigQuery', default=False)
            
    args = parser.parse_args() 
    
    config = {
        'orgs_count_to_create': args.org_count,  
        'max_codename_per_org': args.max_codename_per_org,
        'max_vulns_per_codename': args.max_vulns_per_codename,
        'insert_to_bigquery': args.insert_to_bigquery
    }
    
    return config


def generate_data(config, save_to_file=True):
    
    import random 
    from numpy import random as np_random
    import json
    from tqdm import tqdm
    from faker import Faker
    import datetime
    from datetime import datetime, timedelta
    
    fake = Faker()
    final_data = []
    codename_prefixes = []


    def get_codename():
                
        codename = fake.word()
        codename = codename.upper()

        return codename
    
    def get_vuln_host():

        if random.choice([True, False]):
            host = fake.ipv4()
        else:
            host = fake.domain_name()
        
        return host
  

    for i_org in tqdm(range(config['orgs_count_to_create'])):

        codenames = []
        region = random.choice(['EMEA', 'APAC', 'US FEDERAL', 'US EAST', 'US WEST'])
        org_efficacy = random.randint(0, 100)
        org_avg_remediation_days = random.randint(0, 365)

        if len(set(codename_prefixes)) < config['orgs_count_to_create']:
            codename_prefix = get_codename()

            while codename_prefix in codename_prefixes: 
                codename_prefix = get_codename()
            codename_prefixes.append(codename_prefix)
            
        
        codename_counts = np_random.choice([10, 20, 30, 50, config['max_codename_per_org']], p=[0.28, 0.18, 0.1, 0.42, 0.02]) 
        vuln_counts = np_random.choice([10, 20, 30, 50, config['max_vulns_per_codename']], p=[0.64, 0.2, 0.054, 0.054, 0.052], size=codename_counts) 


        for j in range(codename_counts):
            
            codename = codename_prefix + get_codename()
            while codename in codenames:
                codename = codename_prefix + get_codename()
            codenames.append(codename)

            
            for k in range(vuln_counts[j]):
                vuln_id = codename.lower() + "-" + str(k)
                # Generate a random date in the past 5 years
                start_date = datetime.now() - timedelta(days=365*5)
                end_date = datetime.now()
                vuln_created_at = fake.date_time_between(start_date=start_date, end_date=end_date)
                vulnerability_category = random.choice([
                    'cross_site_scripting_xss',
                    'information_disclosure',
                    'authorization_permissions',
                    'cross_site_scripting',
                    'sql_injection',
                    'authentication_session',
                    'functional_logic',
                    'functional_business_logic',
                    'content_injection',
                    'brute_force',
                    'cross_site_request_forgery_csrf',
                    ])
                vulnerability_subcategory = {
                    'cross_site_scripting_xss': ['dom_based_xss_fixed', 'blind_xss', 'cookie_based_stored_xss'],
                    'information_disclosure': ['client_information', 'api_keys', 'leaked_credentials'],
                    'authorization_permissions': ['file_inclusion_no_execution', 'file_inclusion_execution', 'privilege_escalation', 'server_side_request_forgery_ssrf_full', 'server_side_request_forgery_ssrf_partial'],
                    'cross_site_scripting': ['dom_based', 'dom_based_xss', 'reflected_xss', 'stored_xss', 'xss'],
                    'sql_injection': ['sql_injection_partial', 'poorly_filtered_strings', 'incorrect_type_handling'],
                    'authentication_session': ['account_enumeration', 'cookies_compromised', 'session_fixation'],
                    'functional_logic': ['unvalidated_redirects', 'unrestricted_upload', 'improper_input_filtering'],
                    'functional_business_logic': ['unvalidated_redirect_bypass', 'dependency_confusion', 'client_side_validation'],
                    'content_injection': ['html_content', 'css_injection', 'xml_external_entity'],
                    'brute_force': ['user_login_credentials', 'login', 'login_credentials'],
                    'cross_site_request_forgery_csrf': ['dom_based_xss_fixed', 'blind_xss', 'cookie_based_stored_xss']
                }
                                    
                vuln_severity = random.choice(['low', 'medium', 'high', 'critical'])
                patch_attempts = random.randint(0, 35)
                vuln_status = random.choice([
                        'Fixed', 'Pending Review', 'Open', 'Closed', 'In Progress', 'Reopened', 'Deferred', 'Accepted',
                        'Rejected', 'Duplicate', 'Not Applicable', 'Not Fixed', 'Not Reproducible', 'Not a Vulnerability', 'Not a Security Issue'])

                record = {
                    'codename_prefix': codename_prefix,
                    'codename': codename,
                    'region': region,
                    'org_efficacy': org_efficacy,
                    'vuln_id': vuln_id,
                    'vuln_remediation_days': org_avg_remediation_days,
                    'vuln_created_at': vuln_created_at.strftime("%Y-%m-%d %H:%M:%S"),
                    'vulnerability_category': vulnerability_category,
                    'vulnerability_subcategory': random.choice(vulnerability_subcategory[vulnerability_category]),
                    'vuln_severity': vuln_severity,
                    'patch_attempts': patch_attempts,
                    'vuln_status': vuln_status,
                    'vuln_location_host': get_vuln_host(),
                    'vuln_location_host_count': random.randint(0, 1000),
                    'vuln_approved_at': (vuln_created_at + timedelta(days=random.randint(0, 30))).strftime("%Y-%m-%d %H:%M:%S"),
                    'pv_approved_at': (vuln_created_at + timedelta(days=random.randint(0, 30))).strftime("%Y-%m-%d %H:%M:%S")                    
                }

            
                final_data.append(record)

    
    if save_to_file: 
        # Save final_data as newline-delimited JSON
        with open(fname, 'w') as f:
            for record in final_data:
                json.dump(record, f)
                f.write('\n')


    return final_data   
        

def insert_into_bigquery(data):
    """Inserts data into BQ - data as NJSON"""

    import os 
    

    command = "bq rm -f looker_poc.fake_ebr"
    os.system(command)

    command = f"bq --location=US load --autodetect --replace --source_format=NEWLINE_DELIMITED_JSON --clustering_fields=codename_prefix,codename looker_poc.fake_ebr {fname}"
    os.system(command)    
    


if __name__ == "__main__":
    
    import time
    start_time = time.time()
 
    config = get_argparser_configuration()
    fname = './fake_ebr_data.json'
        
    data = generate_data(config)
    if config['insert_to_bigquery']:
        insert_into_bigquery(data)
    
    print(f"\nEntities are created for {config['orgs_count_to_create']} orgs.") 
    print("Time to generate fake data: --- %s seconds ---" % (time.time() - start_time))