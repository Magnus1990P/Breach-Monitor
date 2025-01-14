#!/usr/bin/env python3
#-*- coding: utf-8 -*-

from requests import get, post
from time import sleep
from datetime import datetime, timedelta
from os import listdir, getenv
from os.path import exists, isdir, isfile

import json
import logging.config
import logging.handlers
import pathlib
from sys import exit

import msal
import click


scan_time_threshold = (datetime.now() - timedelta(days=7)).timestamp()
scan_time = datetime.now().timestamp()
hibp_url = "https://haveibeenpwned.com/api/v3"
hibp_headers = {"hibp-api-key": None}
autosave_threshold = 25
user_info_tags = ["Email addresses", "Names", "Usernames", "Phone numbers", "Social media profiles"]
credential_tags = ["Passwords", "Auth tokens", "Password hints", "Email messages", "Survey results", "Website activity"]
fresh_header = {
    "Content-Type": "application/json",
    "authorization": None
}

logger = logging.getLogger(__name__)
base_directory = "/tmp/data"


def setup_logging():
    config_file = pathlib.Path("logging_config.json")
    with open(config_file) as f_in:
        config = json.load(f_in)
    logging.config.dictConfig(config)


def load_json(filename:str="monitored_emails.json"):
    filepath = f"{base_directory}/{filename}"
    data = {}
    if not isfile(filepath):
        logger.error(f"Not a file - '{filepath}'")
        return data
    try:
        with open(f"{filepath}", encoding="utf-8") as datafile:
            try:
                data = json.load(datafile)
                logger.debug(f"JSON file loaded {len(data)} objects from '{filepath}'")
            except json.JSONDecodeError:
                logger.error(f"Could not JSON-decode file contents - '{filepath}'")
                exit(1)
        save_data(data, filename=f".backup-{filename}")
    except FileNotFoundError:
        logger.error(f"Could not find file - '{filepath}'")
        exit(1)
    return data


def save_data(data, filename:str=".runtime-monitored_emails.json"):
    filepath = f"{base_directory}/{filename}"
    try:
        with open(filepath, "w", encoding="utf-8") as datafile:
            try:
                json.dump(data, datafile, indent=2, ensure_ascii=True)
                logger.debug(f"Saved {len(data)} JSON objects to '{filepath}'")
            except json.JSONDecodeError:
                logger.critical(f"Failed to decode JSON objects - '{filepath}'")
    except FileNotFoundError:
        logger.critical(f"Filepath not found - '{filepath}'")
    except PermissionError:
        logger.critical(f"Access denied- '{filepath}'")


def fetch_breach_info(breach):
    url = f"{hibp_url}/breach/{breach}"
    try:
        resp = get(url, headers=hibp_headers)
    except:
        logger.error(f"GET request failed '{url}'")
        return {}
    retry_count = 0
    while retry_count < 5 and resp.status_code == 429:
        logger.warning(f"Ratelimit reached, backing off for {1*retry_count}s")
        sleep(1*retry_count)
        try:
            resp = get(url, headers=hibp_headers)
        except:
            logger.error(f"GET request failed '{url}'")
            return {}
    if resp.status_code != 200:
        logger.error(f"{breach} returned a {resp.status_code} - {resp.text}")
        return {}
    try:
        data = resp.json()
    except:
        logger.error(f"{breach} returned a non-JSON element")
        return {}
    data.update({"KIT_NOTIFICATION": False})
    for tag in user_info_tags:
        if tag not in data["DataClasses"]:
            continue
        for subtag in credential_tags:
            if subtag in data["DataClasses"]:
                data["KIT_NOTIFICATION"] = True
                break
        break
    return data


def fetch_account(email):
    url = f"{hibp_url}/breachedaccount/{email}"
    try:
        resp = get(url, headers=hibp_headers)
    except:
        logger.warning(f"GET request failed '{url}'")
        return {}
    retry_count = 0
    while resp.status_code == 429 and retry_count < 5:
        retry_count += 1
        logger.warning(f"Ratelimit reached, backing off for {1*retry_count}s")
        sleep(1*retry_count)
        try:
            resp = get(url, headers=hibp_headers)
        except:
            logger.error(f"GET request failed '{url}'")
            return {}
    if resp.status_code == 200:
        return resp.json()
    elif resp.status_code != 404:
        logger.warning(f"GET request failed - {resp.status_code} - {resp.url} - {resp.text}")
    return {}


def load_breach_info(monitored_emails:dict={}):
    breach_information = load_json(filename="breach_information.json")
    breach_list = set([breach for email in monitored_emails for breach in monitored_emails[email]["breaches"]])
    for breach in breach_list:
        if breach in breach_information:
            continue
        data = fetch_breach_info(breach)
        if not data:
            logger.error(f"Breach '{breach}' not found")
            continue
        breach_information.update({breach:data})
    return breach_information


def load_emails_from_file(path:str="emails", email_list:dict={}):
    path = f"{base_directory}/{path}"
    if not exists(path):
        logger.warning(f"Filepath provided does not exist - '{path}'")
        exit(1)
    if isfile(path):
        with open(path, encoding="utf-8") as fh:
            for email in fh.readlines():
                email = email.lower().strip()
                if email not in email_list:
                    email_list.update({email: {"last_scanned": 1, "breaches": []}})
    elif isdir(path):
        for filename in listdir(path):
            if not isfile(f"{path}/{filename}"):
                logger.debug(f"Filepath is not a file - '{path}/{filename}'")
                continue
            with open(f"{path}/{filename}", encoding="utf-8") as fh:
                for email in fh.readlines():
                    email = email.lower().strip()
                    if not email:
                        logger.debug(f"Empty line in file detected - '{path}/{filename}'")
                        continue
                    if email not in email_list:
                        email_list.update({email: {"last_scanned": 1, "breaches": []}})
    return email_list


def msal_certificate_auth(clientID, tenantID, certfile:str="cert.pem", privKey:str="key.pem", cert_passphrase:str="", thumbprint:str=""):
    authority = f"https://login.microsoftonline.com/{tenantID}"
    app = msal.ConfidentialClientApplication(clientID,
                                             authority=authority, 
                                             client_credential={
                                                "thumbprint": thumbprint.replace(":", "").strip(), 
                                                "private_key": open(f"{base_directory}/{privKey}").read(),
                                                "public_certificate": open(f"{base_directory}/{certfile}").read(),
                                                "passphrase": getenv("MS365_CERT_PASSPHRASE") if not cert_passphrase else cert_passphrase
                                            })
    result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
    return result


def ms365_connect(passphrase:str=""):
    email_list = []
    with open(f"{base_directory}/ms365.json", encoding="utf-8") as ms365_file:
        ms365_info = json.load(ms365_file)
    for domain, info in ms365_info.items():
        requestHeaders = None
        accessToken = None
        logger.info(f"Obtaining access token for {domain} - {info['tenantID']} - {info['clientID']}")
        try:
            accessToken = msal_certificate_auth(clientID=info["clientID"], tenantID=info["tenantID"], passphrase=passphrase, thumbprint=info["certThumbprint"])
            requestHeaders = {'Authorization': 'Bearer ' + accessToken['access_token']}
            logger.info(f"Access token obtained - {domain}")
        except Exception as err:
            logger.error("Error acquiring authorization token. Check your tenantID, clientID and certficate thumbprint.")
            logger.error(err)
            continue
        if requestHeaders and accessToken:
            try:
                queryResults = get(info["graphQuery"], headers=requestHeaders).json()
            except Exception as err:
                logger.error(err)
                continue
            for user in queryResults["value"]:
                email_list.append(user["userPrincipalName"].lower())
                email_list.append(user["mail"].lower())
        else:
            logger.error("")
    email_list = list(set(email_list))
    return email_list


def create_table(breaches, findings):
    html = F"""<table><thead>
        <tr><td>Lekasje</td>
            <td>Dato for lekasje</td>
            <td>Tjeneste</td>
            <td>Tiltak nødvdendig?</td>
            <td>Brukerinfo lekket</td>
            <td>Lekket data</td>
            <td>Beskrivelse (Engelsk)</td></tr>
    </thead><tbody>"""
    for key in findings:
        html_row = f"""<tr><td>{breaches[key]['Title']}</td>
            <td>{breaches[key]['BreachDate']}</td>
            <td>{breaches[key]['Domain']}</td>
            <td>{'Ja' if breaches[key]['KIT_NOTIFICATION'] else 'Nei'}</td>
            <td>{", ".join(dc for dc in breaches[key]['DataClasses'])}</td>
            <td>{", ".join(dc for dc in breaches[key]['DataClasses'])}</td>
            <td>{breaches[key]['Description']}</td></tr>
        """
        html += html_row
    html += "</tbody></table>"
    return html


def create_ticket(email:str="", breaches:dict={}, new_findings:dict={}, old_findings:dict={}, fresh_domain:str=""):
    with open(f"{base_directory}/fresh_ticket_template.json", encoding="utf-8") as fh:
        ticket = json.load(fh)
    
    ticket["description"] = ticket["description"].replace("{ACCOUNT}", email)
    new_html = create_table(breaches, new_findings)
    ticket["description"] = ticket["description"].replace("{NEW_LEAK}", new_html)
    if old_findings:
        old_html = create_table(breaches, old_findings)
        ticket["description"] = ticket["description"].replace("{OLD_LEAK}", old_html)
    else:
        ticket["description"] = ticket["description"].replace("{OLD_LEAK}", "")
    resp = post(f"https://{fresh_domain}/api/v2/tickets", 
                headers=fresh_header, json=ticket)
    if resp.status_code != 201:
        logger.error(f"Ticket was not created.  Response code {resp.status_code}, message: {resp.json()}")
    else:
        logger.info(f"Ticket successfully created")


@click.command()
@click.option('-q', '--quiet', default=False, is_flag=True, help="Skip ticket generation")
@click.option('-f', '--force', default=False, is_flag=True, help="Force lookup, ignoring last scanned time")
@click.option('-d', '--directory', default="/tmp/data", help="Path of data directory")
@click.option('--ms365-passphrase', default="", help="Passphrase for private key")
@click.option('--hibp-key', default="", help="API key for HIBP")
@click.option('--fresh-domain', default="", help="FQDN of ticketing system endpoint")
@click.option('--fresh-key', default="", help="API key for FreshService instance")
@click.option('-Fd', '--filtered-domains', default="", help="Scan only the domains listed, separated by comma")
def main(quiet:bool=False, force:bool=False, directory:str="/tmp/data",
         hibp_key:str="", ms365_passphrase:str="",
         fresh_domain:str="", fresh_key:str=None,
         filtered_domains:str=""):
    global base_directory, hibp_headers, fresh_header
    base_directory = directory
    setup_logging()
    logging.basicConfig(level="INFO")

    filtered_domains = [domain.lower().strip() for domain in filtered_domains.split(",")]
    logger.info(f"Filter applied: {','.join(filtered_domains)}")

    try:
        key = getenv("HIBP_KEY") if not hibp_key else hibp_key
        if not key:
            raise KeyError
        hibp_headers = {"hibp-api-key": key}
    except:
        logger.critical("No API key for HIBP")
        exit(1)
    
    if not quiet:
        try:
            key = getenv("FRESH_KEY") if not fresh_key else fresh_key
            if not key:
                raise KeyError
            fresh_header.update({"authorization": f"Basic {key}"})
        except:
            logger.critical("No API key for Freshservice found")
            exit(1)
    
    try:
        key = getenv("MS365_CERT_PASSPHRASE") if not ms365_passphrase else ms365_passphrase
    except:
        logger.critical("No MS365 cert passphrase found")
    
    monitored_emails = load_json()
    monitored_emails = load_emails_from_file(email_list=monitored_emails)

    if key:
        temp_emails = ms365_connect(passphrase=ms365_passphrase) if ms365_passphrase else ms365_connect()
        for email in temp_emails:
            if email not in monitored_emails:
                logger.info(f"New email: {email}")
                monitored_emails.update({email:{"last_scanned": 1, "breaches": []}})
    
    breach_information = load_breach_info(monitored_emails=monitored_emails)

    save_data(monitored_emails, filename=".runtime-monitored_emails.json")
    save_data(breach_information, filename=".runtime-breach_information.json")

    since_saved = 0
    processed_emails = 0
    for email in monitored_emails:
        notification = False
        processed_emails += 1
        
        if (processed_emails%autosave_threshold) == 0:
            logger.info(f"Status - Processed {processed_emails}/{len(monitored_emails)} emails")
        
        if not force and monitored_emails[email]["last_scanned"] > scan_time_threshold:
            logger.debug(f"Skipping - {email} - Time remaining {monitored_emails[email]['last_scanned']-scan_time_threshold}s")
            continue
        
        if filtered_domains:
            if email[email.rfind("@")+1:] not in filtered_domains:
                logger.debug(f"Skip: {email}")
                continue
            else:
                logger.info(f"Processing: {email}")

        data = fetch_account(email)
        if data:
            new_breaches = [breach["Name"] for breach in data if breach["Name"] not in monitored_emails[email]["breaches"]]
            for new_breach in new_breaches:
                if new_breach not in breach_information:
                    breach_data = fetch_breach_info(new_breach)
                    if not breach_data:
                        logger.warning(f"Breach '{new_breach}' was not found")
                        continue
                    breach_information.update({new_breach:breach_data})
                    save_data(breach_information)
                if breach_information[new_breach]["KIT_NOTIFICATION"]:
                    notification = True
            if notification:
                logger.info(f"BREACH DETECTED - Critical - '{email}' - {', '.join(new_breaches)} - {', '.join(monitored_emails[email]['breaches'])}")
                if not quiet and fresh_domain:
                    create_ticket(email,
                                breaches=breach_information,
                                new_findings=new_breaches,
                                old_findings=monitored_emails[email]['breaches'],
                                fresh_domain=fresh_domain)
            elif new_breaches:
                logger.info(f"BREACH DETECTED - Info - '{email}' - {', '.join(new_breaches)} - {', '.join(monitored_emails[email]['breaches'])}")
            monitored_emails[email]["breaches"].extend(new_breaches)
            monitored_emails[email]["last_scanned"] = scan_time
            save_data(monitored_emails)
            since_saved = 0
        else:
            monitored_emails[email]["last_scanned"] = scan_time
            logger.debug(f"Failed to get data from HiBP for '{email}'")
            since_saved += 1
            if since_saved == autosave_threshold:
                save_data(monitored_emails)
                since_saved = 0
        sleep(1)
    
    logger.info(f"Status - Processed {processed_emails}/{len(monitored_emails)} emails")
    save_data(monitored_emails, filename="monitored_emails.json")
    save_data(breach_information, filename="breach_information.json")


if __name__ == "__main__":
    main()