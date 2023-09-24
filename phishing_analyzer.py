import PyPDF2
import requests
import json
import os
from email import message_from_bytes
import re
import urllib.parse
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
import time
from email import message_from_bytes
import whois
import datetime
import dkim
from email import policy
from email.parser import BytesParser
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# JotForm API key
jotform_api_key = "JOTFORM_API_KEY"
form_id = "FORM_ID"

# theHive API key
thehive_api_key = "HIVE_API_KEY"
thehive_url = "http://35.242.147.53:9000"

# File path
TEMP_FOLDER = "C:/Users/fatos/Automated Phishing Analysis/Emls"

def create_thehive_alert(response,observables,customFields, create_case=False):
    alert_data = {
        "title": f"Phishing Alert - {response['id']}",
        "description": f"Phishing attempt reported with ID {response['id']}",
        "type": "alert",
        "source": "JotForm",
        "severity": 2, # You can adjust the severity level as needed
        "sourceRef": f"jotform-{response['id']}",  # Add sourceRef field
        "observables": observables,  
        "customFields": customFields
    }
    
    headers = {
        "Authorization": f"Bearer {thehive_api_key}",
        "Content-Type": "application/json"
    }
    
    response = requests.post(thehive_url+"/api/v1/alert", json=alert_data, headers=headers)
    print(response.json())
    if response.status_code == 201:
        print("Alert created successfully.")

        if create_case:
            create_thehive_case(response.json())
    else:
        print("Failed to create alert. Status code:", response.status_code)
        print(response.text)
    return response

def create_thehive_case(alert_data):
    case_data = {
        "title": f"Phishing Case - {alert_data['_id']}",
        "description": f"Case created for phishing alert with ID {alert_data['_id']}",
        "severity": 2,
        "startDate": int(time.time() * 1000),  
        "tlp": 2,
        "status": "New",
        "flag": False,
        "alertId": alert_data['_id']  
    }
    
    headers = {
        "Authorization": f"Bearer {thehive_api_key}",
        "Content-Type": "application/json"
    }
    
    response = requests.post(thehive_url+"/api/v1/alert/"+alert_data['_id']+"/case", json=case_data, headers=headers)
    
    if response.status_code == 201:
        print("Case created successfully.")
    else:
        print("Failed to create case. Status code:", response.status_code)
        print(response.text)
    return response

result_attachment_download = ""  
result_url = ""

def process_submission(form_response):
    answers = form_response["answers"]
    result_message = ""
    result_attachments2 = ""

    for field, value in answers.items():
        answer_text = value.get('answer', '')
        if answer_text:  
            result_message += f"{value.get('text', '')}: {answer_text}\n"

        if value.get('text', '') == "Please attach the EML file(s) containing the original email(s) here":
            eml_files = answer_text
            for index, eml_url in enumerate(eml_files, start=1):
                eml_filename = os.path.basename(eml_url)
                eml_path = str(os.path.join(TEMP_FOLDER, eml_filename))
                try:
                    response = requests.get(eml_url)
                    response.raise_for_status()  
                    with open(eml_path, "wb") as f:
                        f.write(response.content)
                    print("EML indirildi:", eml_path)
                except requests.exceptions.RequestException as e:
                    print("EML indirilirken bir hata oluştu:", e)
                
                # To open browser settings and capture a screenshot
                options = webdriver.ChromeOptions()
                options.add_argument('--headless')
                driver = webdriver.Chrome(executable_path="C:/Users/fatos/Downloads/chromedriver-win64/chromedriver-win64/chromedriver.exe", options=options)

                # EML File URL Extraction Function
                def extract_urls(text):
                    urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
                    return urls

                with open(eml_path, 'rb') as eml_file:
                    eml_content = eml_file.read()

                msg = message_from_bytes(eml_content)

                # Accessing Header Fields
                from_header = msg.get("From")
                to_header = msg.get("To")
                cc_header = msg.get("Cc")
                subject_header = msg.get("Subject")

                print("From:", from_header)
                print("To:", to_header)
                print("Cc:", cc_header)
                print("Subject:", subject_header)

                # Reading EML Content and Extracting URLs Within
                eml_body = ""
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        eml_body = part.get_payload(decode=True).decode('utf-8')
                        break
                # Print EML Content
                print("EML Body:", eml_body)

                index = 0
                
                #-----------------------------------Checking-------------------------------------------------------------
                index = 0
                result_string = ""
                # Get the Sender's Email Address
                sender_email = re.search(r'<(.+?)>', from_header).group(1)

                # check if body contains shortened urls
                if eml_body:
                    urls = extract_urls(eml_body)
                    for index, url in enumerate(urls, start=1):

                        # Check if the URL is a shortened URL
                        if any(domain in url for domain in ["bit.ly", "goo.gl", "t.co"]):
                            index+=1
                            result_string += f"body contains shortened urls : Yes : {url}\n"
                            result_shortened_urls = f"body contains shortened urls : Yes : {url}\n"
                        else:
                            result_string += "body contains shortened urls : No\n"
                            result_shortened_urls = "body contains shortened urls : No\n"
                
                # check if sender has free domain
                # List of Free Email Service Providers' Domain Names
                free_email_domains = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com"]

                # Extracting the Domain from an Email Address
                def extract_domain(email):
                    return email.split("@")[1]

                # Extract the Domain
                domain = extract_domain(sender_email)

                # Check in the List of Free Domain Names
                if domain in free_email_domains:
                    index+=1
                    result_string += "sender has free domain : Yes \n"
                    result_free_domain= "sender has free domain : Yes\n"
                else:
                    result_string += "sender has free domain : No \n"
                    result_free_domain = "sender has free domain : No \n"

                # check if sender domain has non-ascii characters
                def extract_domain(email):
                    return email.split("@")[1]

                domain = extract_domain(sender_email)

                # Non-ASCII characters chek
                def has_non_ascii_characters(s):
                    return any(ord(c) > 127 for c in s)

                # Check for Non-ASCII Characters in the Domain Name
                if has_non_ascii_characters(domain):
                    index+=1
                    result_string += "sender domain has non-ascii characters: Yes \n"
                    result_characters = "sender domain has non-ascii characters: Yes \n"
                else:
                    result_string += "sender domain has non-ascii characters: No \n"
                    result_characters = "sender domain has non-ascii characters: No \n"

                # check sender domain age
                def get_domain_age(domain):
                    try:
                        whois_data = whois.whois(domain)
                        creation_date = whois_data.creation_date
                        if isinstance(creation_date, list):
                            creation_date = creation_date[0]
                        current_date = datetime.datetime.now()
                        domain_age = (current_date - creation_date).days
                        return domain_age
                    except Exception as e:
                        print("Error:", str(e))
                        return None

                # Extract the Domain from the Email Address
                def extract_domain(email):
                    return email.split("@")[1]


                domain = extract_domain(sender_email)

                domain_age = get_domain_age(domain)
                if domain_age is not None:
                    result_string += f"domain age : {domain_age} days old \n"
                    result_domain_age = f"domain age : {domain_age} days old \n"
                    if domain_age > 100:
                        index+=1
                else:
                    result_string += f"Unable to determine the age of the sender's domain '{domain}'. \n"
                    result_domain_age = f"Unable to determine the age of the sender's domain '{domain}'. \n"
                
                # contains password protected zip
                # Check for Password-Protected ZIP Files in Email Content
                def check_password_protected_zip(eml_body):
                    if "Content-Type: application/zip" in eml_body and "Content-Disposition: attachment;" in eml_body:
                        return True
                    return False

                if check_password_protected_zip(eml_body):
                    result_string += "Contains password protected zip : Yes\n "
                    result_password_protected_zip = "Contains password protected zip : Yes\n "
                    index+=1
                else:
                    result_string += "Contains password protected zip : No\n"
                    result_password_protected_zip = "Contains password protected zip : No\n "
                
                # check if dmarc,dkim,spf failed
                # DKIM checking
                if dkim.verify(msg.as_bytes()):
                    result_string += "DKIM Passed \n "
                    result_dkim = "DKIM Passed \n "
                else:
                    index+=1
                    result_string += "DKIM Failed \n "
                    result_dkim = "DKIM Failed \n "


                #check domain and url virustotal report 
                # Use the VirusTotal API Key Here
                virus_api_key = "VIRUS_API_KEY"

                # URL'yi VirusTotal API'ye sorgula
                def get_url_report(url):
                    params = {
                        'apikey': virus_api_key,
                        'resource': url
                    }
                    response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params)
                    return response.json()

                def get_domain_report(domain):
                    params = {
                        'apikey': virus_api_key,
                        'domain': domain
                    }
                    response = requests.get('https://www.virustotal.com/vtapi/v2/domain/report', params=params)
                    return response.json()
                # Extract URLs from the Email Content
                email_urls = extract_urls(eml_body)

                url_reports = []

                # Get a Report for Each URL
                for url in email_urls:
                    url_report = get_url_report(url)
                    url_reports.append(url_report)

                mail_domain = extract_domain(sender_email)
                # Get the Domain Report
                domain_report = get_domain_report(mail_domain)

                url_reports_str = ""  # Empty string

                # Get a Report for Each URL
                for idx, url_report in enumerate(url_reports, start=1):
                    url_reports_str += f"URL Report {idx}:\n"
                    url_reports_str += f"URL: {url_report['url']}\n"
                    url_reports_str += f"Scan Date: {url_report['scan_date']}\n"
                    url_reports_str += f"Positives: {url_report['positives']}\n"
                    url_reports_str += f"Total: {url_report['total']}\n"
                    url_reports_str += "-------------------------\n"
                # Get the Domain Report
                domain_report_str = "Domain Report:\n"
                if 'domain' in domain_report:
                    domain_report_str += f"Domain: {domain_report['domain']}\n"
                if 'whois' in domain_report and 'registrar' in domain_report['whois']:
                    domain_report_str += f"Owner: {domain_report['whois']['registrar']}\n"
                if 'whois' in domain_report and 'creation_date' in domain_report['whois']:
                    domain_report_str += f"Creation Date: {domain_report['whois']['creation_date']}\n"
                if 'whois' in domain_report and 'updated_date' in domain_report['whois']:
                    domain_report_str += f"Update Date: {domain_report['whois']['updated_date']}\n"


                print("VirusTotal url and domain raport created")
                result_string += "\n\nURL Reports:\n" + url_reports_str + domain_report_str
                result_virus_total= "URL Reports:\n" + url_reports_str + domain_report_str
                print(result_string)


                # attachment control
                attachment_list = []  
                with open(eml_path, "rb") as eml_file:
                    msg2 = BytesParser(policy=policy.default).parse(eml_file)
                        
                    # If there is an attachment, we list the attachments
                    for part in msg2.walk():
                            if part.get_content_maintype() != 'multipart' and part.get('Content-Disposition') is not None:
                                filename = part.get_filename()
                                if filename:
                                    attachment_list.append(filename)
                
                if attachment_list:
                    print("There are attachment(s) in this email.")
                    print("List of attachments:")
                    attachment_string = " - ".join(attachment_list)  # Ek isimlerini "-" ile birleştirir
                    print(attachment_string)
                    result_attachments = attachment_string +" "
                    result_attachments2 = ""
                     # Kendi kendine imzalanmış sertifikayı kabul et
                    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

                    # FleetDM API URL: The endpoint used to list computers
                    api_url = "https://t9b8e9e0a.sandbox.fleetdm.com/api/v1/fleet/hosts"
                    api_token = "YOUR_API_TOKEN"


                    # Header for FleetDM API Request
                    headers = {
                        "Authorization": f"Bearer {api_token}",
                        "Content-Type": "application/json"
                    }

                    # Send a Request to List All Computers
                    response = requests.get(api_url, headers=headers, verify=False)  # Disable SSL Certificate Verification
                    result22 = ""
                    if response.status_code == 200:
                        hosts = response.json().get("hosts", [])
                        
                        for bilgisayar in hosts:
                            hostname = bilgisayar.get("hostname", "Unknow Computer")
                            print(hostname)

                            # Query running
                            query_id = 95
                            run_query_url = f"https://t9b8e9e0a.sandbox.fleetdm.com/api/v1/fleet/queries/run"
                            run_query_data = {
                                    "query_ids": [query_id],
                                    "host_ids": [bilgisayar["id"]]
                            }
                            response2 = requests.get(run_query_url, json=run_query_data, headers=headers)
                            print(response2)
                            time.sleep(10)

                            if response2.status_code == 200:
                                    query_results = response2.json().get("live_query_results", [])
                                    print(query_results)

                                    all_filenames = []

                                    for result in query_results:
                                        results = result.get("results", [])  #Retrieve the 'results' List Within Each 'result'
                                        if results:
                                            rows = results[0].get("rows", [])  
                                            if rows:
                                                for file_info in rows:
                                                    filename = file_info.get("filename", "Unknow File")
                                                    all_filenames.append(filename)  
                                                    print(all_filenames)

                                    for i in attachment_list:
                                        if i in all_filenames:
                                            print(f"Host Name: {hostname}, File Name: {i}, Searched File Found!")
                                            result_attachments2 += f"Host Name: {hostname}, File Name: {i}, Searched File Found!"
                                        else:
                                            print(f"Host Name: {hostname}, File Name: {i}, No Searched Files!")
                                            
                                            result_attachments2 += f"Host Name: {hostname}, File Name: {i}, Searched File Found!"

                            
                            else:
                                    print(f"{hostname} Error in Executing the Query:", response2.status_code)
                            

                    else:
                        print("An error occurred while connecting to the FleetDM API", response.status_code)

                    result22 +=result_attachments     
                
                else:
                    print("There are no attachments in this email.")
                    result_attachments = "There are no attachments in this email"
                    result_attachments2 = "There are no attachments in this email"

                #-----------------------------------------------------------------------------------------------

                # Create Email Information
                email_info = f"From: {from_header}\nTo: {to_header}\nCc: {cc_header}\nSubject: {subject_header}\n\n{eml_body}"

                if eml_body:
                    urls = extract_urls(eml_body)
                    urls_as_string = "\n".join(urls)
                    for index, url in enumerate(urls, start=1):
                        print("URL found:", url)

                        try:
                            driver.get(url)
                            time.sleep(3)

                            screenshot_path = f"C:/Users/fatos/Automated Phishing Analysis/screenshots/screenshot_{index}_{url[8:13]}.png"
                            driver.save_screenshot(screenshot_path)

                            print("Screenshot saved:", screenshot_path)
                        except Exception as e:
                            print("Error taking screenshot for URL:", url)
                            print("Error details:", str(e))
                        
                       # Accept a Self-Signed Certificate
                        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

                        # FleetDM API URL: Endpoint Used to List Computers
                        api_url = "https://t9b8e9e0a.sandbox.fleetdm.com/api/v1/fleet/hosts"
                        api_token = "YOUR_API_TOKEN"

                        # Header for FleetDM API Request
                        headers = {
                            "Authorization": f"Bearer {api_token}",
                            "Content-Type": "application/json"
                        }

                        all_lines=[]

                        # Send a Request to List All Computers
                        response = requests.get(api_url, headers=headers, verify=False)  # Disable SSL Certificate Verification

                        if response.status_code == 200:
                            hosts = response.json().get("hosts", [])
                            
                            for bilgisayar in hosts:
                                hostname = bilgisayar.get("hostname", "Unknow Computer")
                                print(hostname)

                                # Query running
                                query_id = 96
                                run_query_url = f"https://t9b8e9e0a.sandbox.fleetdm.com/api/v1/fleet/queries/run"
                                run_query_data = {
                                        "query_ids": [query_id],
                                        "host_ids": [bilgisayar["id"]]
                                    }
                                response2 = requests.get(run_query_url, json=run_query_data, headers=headers)
                                print(response2)
                                time.sleep(5)

                                if response2.status_code == 200:
                                        query_results = response2.json().get("live_query_results", [])
                                        print(query_results)
                                        for result in query_results:
                                            results = result.get("results", [])  
                                            if results:
                                                rows = results[0].get("rows", [])  
                                                if rows:
                                                    for line_info in rows:
                                                        line = line_info.get("line", "Bilinmeyen Dosya")
                                                        all_lines.append(line)  
                                    
                                if url in all_lines:
                                        print("This url has been visited")
                                        result_url = "This url has been visited"
                                else:
                                        print("This url hasn't been visited")
                                        result_url = "This url hasn't been visited"



                        else:
                            print("An error occurred while connecting to the FleetDM API.", response.status_code)


                        
                       
                    # Create Observable Information
                    observables = [
                            {"dataType": "other", "data": urls_as_string},
                            {"dataType": "other", "data": eml_path},
                            {"dataType": "other", "data": email_info}     
                    ]

                    customFields = [
                            {
                                "name": "analysis-result",  
                                "value": result_string
                            },
                            {
                                "name": "domain-age",  
                                "value": result_domain_age
                            },
                            {
                                "name": "free-domain",  
                                "value": result_free_domain
                            },
                            {
                                "name": "non-ascii-characters",  
                                "value": result_characters
                            },
                            {
                                "name": "password-protected-zip",  
                                "value": result_password_protected_zip
                            },
                            {
                                "name": "shortened-urls",  
                                "value": result_shortened_urls
                            },
                            {
                                "name": "virustotal-report",  
                                "value": result_virus_total
                            },
                            {
                                "name": "dmarc-dkim-spf-failed",  
                                "value": result_dkim
                            },
                            {
                                "name": "attachments",  
                                "value": result_attachments
                            },
                            {
                                "name": "url-visiting-control",  
                                "value": result_url
                            },
                            {
                                "name": "attachments-download-control",  
                                "value": result_attachments2
                            }


                        ]

                        
                    # Create an Alert in TheHive and Generate Email Information and Observables. If the Analysis Result is Appropriate, Create a Case.
                    if index > 0:
                        create_thehive_alert(form_response, observables, customFields, create_case=True)
                    else:
                         create_thehive_alert(form_response, observables, customFields)
                else:


                         # Create Observable Information
                        observables = [
                            {"dataType": "other", "data": email_info}
                           
                        ]

                        customFields = [
                            {
                                "name": "analysis-result",  
                                "value": result_string
                            },
                            {
                                "name": "domain-age",  
                                "value": result_domain_age
                            },
                            {
                                "name": "free-domain",  
                                "value": result_free_domain
                            },
                            {
                                "name": "non-ascii-characters",  
                                "value": result_characters
                            },
                            {
                                "name": "password-protected-zip",  
                                "value": result_password_protected_zip
                            },
                            {
                                "name": "virustotal-report",  
                                "value": result_virus_total
                            },
                            {
                                "name": "dmarc-dkim-spf-failed",  
                                "value": result_dkim
                            },
                            {
                                "name": "attachments",  
                                "value": result_attachments
                            },
                            {
                                "name": "attachments-download-control",  
                                "value": result_attachments2
                            }


                        ]
                        
                        # Create an Alert in TheHive and Generate Email Information and Observables. If the Analysis Result is Appropriate, Create a Case
                        if index> 0:
                            create_thehive_alert(form_response, observables, customFields, create_case=True)
                        else:
                            create_thehive_alert(form_response, observables, customFields)


                driver.quit()
                    

def main():
    jotform_url = f"https://api.jotform.com/form/{form_id}/submissions?apiKey={jotform_api_key}"
    response = requests.get(jotform_url)
    form_responses = response.json()
    
    for form_response in form_responses['content']:
        answers = form_response.get("answers", {})
        for field, value in answers.items():
            if value.get('text', '') == "Type of Phishing":
                answer_text = value.get('answer', '')
                if answer_text == "Email":
                    #create_thehive_alert(form_response)
                    process_submission(form_response)
                    break
    
    print("Alerts and EML files downloaded successfully.")

if __name__ == "__main__":
    main()
