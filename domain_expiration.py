import requests
import whois
import re
import subprocess
from bs4 import BeautifulSoup
from datetime import datetime, timedelta

dt = datetime.now()
print("Today's date is " + str(dt))


def query_domain(_domain_name):
    domain = whois.Domain
    try:
        domain = whois.query(_domain_name)
    except Exception as e:
        # Try running whois in commandline and return a dict
        print(f"Using whois command for {_domain_name}")
        output = subprocess.run(["whois", _domain_name], capture_output=True)
        result = re.findall(r'[\n\r].*Registry Expiry Date:\s*([^\n\r]*)', output.stdout.decode())
        for r in result:
            format = "%Y-%m-%dt%H:%M:%S.%fz"
            time = datetime.strptime(r, format).astimezone().replace(tzinfo=None)
            domain.expiration_date = time

    return domain


def check_domain_expiry(_domain_name, package_name):
    try:
        domain = query_domain(_domain_name)
        if domain is None or domain.expiration_date is None:
            print(f"[❓] {package_name} || {_domain_name} (Library is unable to retrieve expiration date info)")
        elif dt > domain.expiration_date:
            print(f"[🚨] {package_name} || {_domain_name} has expired since " + str(domain.expiration_date))
        else:
            print(f"[✅] {package_name} || {_domain_name} is valid till " + str(domain.expiration_date))
    except Exception as e:
        print(e.__str__(), _domain_name)


def sanitize_non_domain_chars(domain_name):
    return domain_name.replace(">", "").rstrip()


def extract_email_domains(package_url):
    email_domains = []
    response = requests.get(package_url)

    soup = BeautifulSoup(response.text, 'html.parser')
    mailtos = list(dict.fromkeys(soup.select('a[href^=mailto]')))

    for mail_list in mailtos:
        href = mail_list['href'].replace("%40", "@")
        if href.__contains__(","):
            # Contains more than one email
            emails = href.split(":")[1].split(",")
            for email in emails:
                email_domains.append(sanitize_non_domain_chars(email.split('@')[1]))
        else:
            try:
                prefix, domain = href.split('@')
            except ValueError:
                print("Error: " + href)
                break
            email_domains.append(sanitize_non_domain_chars(domain))

    return email_domains


with open('requirements.txt', 'r') as packages:
    lines = packages.readlines()
    for line in lines:
        if line.__contains__("=="):
            package_name = line.rstrip().split('==')[0]
            for domain_name in extract_email_domains(f"https://pypi.org/project/{package_name}"):
                check_domain_expiry(domain_name, package_name)
