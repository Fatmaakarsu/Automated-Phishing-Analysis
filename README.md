# Automated-Phishing-Analysis
An automation project that automatically analyzes suspicious emails within the company and generates notifications for the security team. 

## Which Technologies Did I Use ?
During the development of this project, I coded it using Python. I created alarms and cases on the ThHive platform.TheHive is a security platform for incident response and threat analysis.
For centralized management and run sql queries on servers I used osquery and FleetDM. Additionally, I used APIs to automate the entire system.

![image](https://github.com/Fatmaakarsu/Automated-Phishing-Analysis/assets/79910837/a02f2965-6d84-4b73-86f5-1e43fbecbc3a)

## Project Workflow Steps

![image](https://github.com/Fatmaakarsu/Automated-Phishing-Analysis/assets/79910837/478c12b4-6366-4d9c-b254-9df8e611b23d)

As the first step of the project, I published a form where employees can report phishing incidents. They upload email files in EML format to this form.
You can access the project's JotForm survey [here](https://form.jotform.com/232286579803062).

In the second step ,For the automation between the form and alerts, I used TheHive and Jotform API keys.

In the third step, I conducted various checks for phishing suspicions on the EML files submitted through the form. I coded all these checks using Python. Some of the steps I looked into included: 
![image](https://github.com/Fatmaakarsu/Automated-Phishing-Analysis/assets/79910837/ac6f0ead-31c8-4667-acab-feb49541216c)

In the final step, I run an SQL query to check whether attachments from phishing emails have been downloaded on the company's computers and check the visited URLs. For this, I used Osquery and FleetDM.
![image](https://github.com/Fatmaakarsu/Automated-Phishing-Analysis/assets/79910837/6d20d883-999f-4fc0-9017-72228ccde797)

After all these steps, alarms are generated in TheHive platform for each email. I also add the checked features as custom fields to each alarm.  
Every time a form is submitted, an alert is created in TheHive.
![image](https://github.com/Fatmaakarsu/Automated-Phishing-Analysis/assets/79910837/09cd5608-bb5a-40df-a816-1f5847800dc5)

As a result, every phishing suspicion report is automatically and quickly scanned, and necessary investigations are carried out.


