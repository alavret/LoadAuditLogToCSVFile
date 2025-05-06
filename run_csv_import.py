from dotenv import load_dotenv
import requests
import logging
import json
import logging.handlers as handlers
import os
import sys
import re
from dataclasses import dataclass
import datetime
from dateutil.relativedelta import relativedelta
from http import HTTPStatus
import time
from os import environ
import csv

DEFAULT_360_API_URL = "https://api360.yandex.net"
LOG_FILE = "get_audit_logs.log"
FILTERED_MAIL_EVENTS = []
FILTERED_MAILBOXES = []
MAIL_LOG_MAX_PAGES = 20
OVERLAPPED_MINITS = 2
MAX_RETRIES = 3
RETRIES_DELAY_SEC = 2

MAIL_REC_CSV_FIELDS_NAMES = ["eventType", "date", "date_year", "date_month", "date_day",
                             "date_hour", "date_minits", "userLogin", "userName", "from",
                             "to", "subject", "folderName", "folderType", "labels",
                             "orgId", "requestId", "clientIp", "userUid", "msgId",
                             "uniqId", "source", "mid", "cc", "bcc",
                             "destMid", "actorUid"]

DISK_REC_CSV_FIELDS_NAMES = ["eventType", "date", "date_year", "date_month", "date_day",
                             "date_hour", "date_minits", "userLogin",
                             "userName", "ownerLogin", "ownerName", "resourceFileId",
                             "path", "size", "lastModificationDate", "modified_date_year", 
                             "modified_date_month", "modified_date_day", "modified_date_hour", 
                             "modified_date_minits", "rights",  "orgId", "userUid", "requestId", "ownerUid", 
                             "uniqId", "clientIp"]

EXIT_CODE = 1

logger = logging.getLogger("get_audit_log")
logger.setLevel(logging.DEBUG)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter('%(asctime)s.%(msecs)03d %(levelname)s:\t%(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
#file_handler = handlers.TimedRotatingFileHandler(LOG_FILE, when='D', interval=1, backupCount=30, encoding='utf-8')
file_handler = handlers.RotatingFileHandler(LOG_FILE, maxBytes=1024 * 1024,  backupCount=5, encoding='utf-8')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(logging.Formatter('%(asctime)s.%(msecs)03d %(levelname)s:\t%(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
logger.addHandler(console_handler)
logger.addHandler(file_handler)

def main():
    settings = get_settings()
    if settings is None:
        logger.error("Settings are not set.")
        sys.exit(EXIT_CODE)

    logger.info("Starting script...")

    logger.debug("Collect existing files names in log catalog.")

    log_params = []
    d = {}
    d["dir"] = settings.mail_dir_path
    d["file"] = settings.mail_file
    d["label"] = "mail"
    d['headers'] = MAIL_REC_CSV_FIELDS_NAMES
    log_params.append(d)
    d = {}
    d["dir"] = settings.disk_dir_path
    d["file"] = settings.disk_file
    d["label"] = "disk"
    d['headers'] = DISK_REC_CSV_FIELDS_NAMES
    log_params.append(d)

    for log_param in log_params:

        existing_records = []  
        files = [f for f in os.listdir(log_param['dir']) if re.match(log_param['file'] + r'_[0-9]{4}\-[0-9]{2}\-[0-9]{2}\.' + settings.ext, f)]

        if not files:
            logger.info(f"No files found in {log_param['dir']} catalog. Start full downloading data.")
        else:
            files.sort(reverse=True)
            for file in files:
                
                logger.debug(f"Check records in file {os.path.join(log_param['dir'], file)}.")

                with open(os.path.join(log_param['dir'], file), 'r', encoding="utf8") as f:
                    dict_reader = csv.DictReader(f, delimiter=';')
                    existing_records = list(dict_reader)

                if not existing_records:
                    logger.debug(f"No records found in file {os.path.join(log_param['dir'], log_param['file'])}. Selecting previous file.")
                else:
                    break

        records = []
        if existing_records:
            last_record = existing_records[-1]
            date = f"{last_record['date'][0:19]}"
            logger.info(f"Last record date for {log_param['label']} logs: {date}")
            logger.info(f"Start downloading data from {log_param['label']} audit logs.")
            if log_param["label"] == "mail":
                records = fetch_mail_audit_logs(settings, last_date = date)
            elif log_param["label"] == "disk":
                records = fetch_disk_audit_logs(settings, last_date = date)
        else:
            if log_param["label"] == "mail":
                records = fetch_mail_audit_logs(settings)
            elif log_param["label"] == "disk":
                records = fetch_disk_audit_logs(settings)

        if not records:
            logger.error(f"No records were recived from {log_param['label']} audit logs.")
            sys.exit(EXIT_CODE)
        else:
            logger.info(f"{len(records)} records were recived from {log_param['label']} audit logs.")

        decoded_records = []
        for r in [r.decode() for r in records]:
            if log_param["label"] == "mail":
                decoded_records.append(parse_mail_record_to_dict(json.loads(r)))
            elif log_param["label"] == "disk":
                decoded_records.append(parse_disk_record_to_dict(json.loads(r)))
        
        separated_list = {}
        for r in decoded_records:
            if r in existing_records:
                continue
            # diffkeys = [k for k in existing_records[-1] if existing_records[-1][k] != r[k]]
            # print("-"*100)
            # for k in diffkeys:
            #     print(f"{k}, ':', {existing_records[-1][k]}, '->', {r[k]}")
            search_result = r["date"]
            if search_result:
                date_part = search_result[0:10]
                if date_part not in separated_list.keys():
                    separated_list[date_part] = []
                sorted_dict = {}
                sorted_dict["full_time"] = r["date"]
                sorted_dict["data"] = r
                separated_list[date_part].append(sorted_dict)
            else:
                logger.error(f"No date found in record: {r}")
        
        for date, records in separated_list.items():
            if len(records) > 0:
                file_path = os.path.join(log_param['dir'], f"{log_param['file']}_{date}.csv")

                logger.info(f"Writing {len(records)} CSV records to {log_param['label']} audit file {file_path}")
                try:
                    if check_csv_file_exist(file_path, log_param["headers"]):
                        with open(file_path, 'a', encoding="utf8") as f:
                            writer = csv.DictWriter(f, fieldnames=log_param["headers"], delimiter=';')
                            for r in sorted(records, key=lambda d: d['full_time']):
                                writer.writerow(r['data'])
                    else:
                        with open(file_path, 'w', encoding="utf8") as f:
                            writer = csv.DictWriter(f, fieldnames=log_param["headers"], delimiter=';')
                            writer.writeheader()
                            for r in sorted(records, key=lambda d: d['full_time']):
                                writer.writerow(r['data'])

                except Exception as e:
                    logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
                        
    logger.info("Sript finished.")

@dataclass
class SettingParams:
    oauth_token: str
    organization_id: int  
    mail_dir_path : str
    disk_dir_path : str
    ext: str
    mail_file: str
    disk_file: str

def get_settings():
    exit_flag = False
    try:
        settings = SettingParams (
            oauth_token = os.environ.get("OAUTH_TOKEN_ARG"),
            organization_id = int(os.environ.get("ORGANIZATION_ID_ARG")),
            mail_dir_path = os.environ.get("MAIL_LOG_CATALOG_LOCATION"),
            disk_dir_path = os.environ.get("DISK_LOG_CATALOG_LOCATION"),
            ext = os.environ.get("LOG_FILE_EXTENSION"),
            mail_file = os.environ.get("MAIL_LOG_FILE_BASE_NAME"),
            disk_file = os.environ.get("DISK_LOG_FILE_BASE_NAME"),
        )
    except ValueError:
        logger.error("ORGANIZATION_ID_ARG params must be an integer")
        exit_flag = True

    if not settings.oauth_token:
        logger.error("OAUTH_TOKEN_ARG is not set")
        exit_flag = True

    if settings.organization_id == 0:
        logger.error("ORGANIZATION_ID_ARG is not set")
        exit_flag = True

    if not settings.mail_dir_path:
        logger.error("MAIL_LOG_CATALOG_LOCATION is not set")
        exit_flag = True
    else:
        if not os.path.isdir(settings.mail_dir_path):
            logger.error(f"Catalog {settings.mail_dir_path} is not exist.")
            exit_flag = True

    if not settings.disk_dir_path:
        logger.error("DISK_LOG_CATALOG_LOCATION is not set")
        exit_flag = True
    else:
        if not os.path.isdir(settings.disk_dir_path):
            logger.error(f"Catalog {settings.disk_dir_path} is not exist.")
            exit_flag = True

    if settings.mail_dir_path.endswith("/") or settings.mail_dir_path.endswith("\\"):
        settings.mail_dir_path = settings.mail_dir_path[:-1]

    if settings.disk_dir_path.endswith("/") or settings.disk_dir_path.endswith("\\"):
        settings.mail_dir_path = settings.mail_dir_path[:-1]

    if not settings.ext:
        logger.error("LOG_FILE_EXTENSION is not set")
        exit_flag = True

    if not settings.mail_file:
        logger.error("MAIL_LOG_FILE_BASE_NAME is not set")
        exit_flag = True

    if not settings.disk_file:
        logger.error("DISK_LOG_FILE_BASE_NAME is not set")
        exit_flag = True

    if exit_flag:
        return None
    
    return settings

def check_csv_file_exist(path, headers):
    if os.path.exists(path):
        with open(path, 'r', encoding="utf8") as f:
            line = f.readline()
            if line:
                if line.replace('\n', '') == ";".join(headers):
                    return True
    return False


def parse_mail_record_to_dict(data: dict):
    #obj = json.dumps(data)
    d = {}
    d["eventType"] = data.get("eventType",'')
    d["date"] = data.get("date").replace('T', ' ').replace('Z', '')
    d["date_day"] = data.get("date")[8:10]
    d["date_month"] = data.get("date")[5:7]
    d["date_year"] = data.get("date")[0:4]
    d["date_hour"] = data.get("date")[11:13]
    d["date_minits"] = data.get("date")[14:16]
    d["userLogin"] = data.get("userLogin",'')
    d["userName"] = data.get("userName",'')
    d["from"] = data.get("from",'')
    d["to"] = data.get("to",'')
    d["subject"] = data.get("subject",'').replace(';', '&_semicolon_&')
    d["folderName"] = data.get("folderName",'')
    d["folderType"] = data.get("folderType",'')
    t = data.get("labels",[])
    if t:
        d["labels"] = ",".join(t)
    else:
        d["labels"] = ""
    d["orgId"] = str(data.get("orgId"))
    d["requestId"] = data.get("requestId",'')
    d["clientIp"] = data.get("clientIp",'')
    d["userUid"] = data.get("userUid",'')
    d["msgId"] = data.get("msgId",'')
    d["uniqId"] = data.get("uniqId",'')
    d["source"] = data.get("source",'')
    d["mid"] = data.get("mid",'')
    d["cc"] = data.get("cc",'')
    d["bcc"] = data.get("bcc",'')
    d["destMid"] = data.get("destMid",'')
    d["actorUid"] = data.get("actorUid",'')
    return d

def parse_disk_record_to_dict(data: dict):
    #obj = json.dumps(data)
    d = {}
    d["eventType"] = data.get("eventType",'')
    d["date"] = data.get("date").replace('T', ' ').replace('Z', '')
    d["date_day"] = data.get("date")[8:10]
    d["date_month"] = data.get("date")[5:7]
    d["date_year"] = data.get("date")[0:4]
    d["date_hour"] = data.get("date")[11:13]
    d["date_minits"] = data.get("date")[14:16]
    d["orgId"] = str(data.get("orgId"))
    d["userUid"] = data.get("userUid",'')
    d["userLogin"] = data.get("userLogin",'')
    d["userName"] = data.get("userName",'')
    d["ownerUid"] = data.get("ownerUid",'')
    d["ownerLogin"] = data.get("ownerLogin",'')
    d["ownerName"] = data.get("ownerName",'')
    d["resourceFileId"] = data.get("resourceFileId",'')
    d["path"] = data.get("path")
    d["size"] = data.get("size",'')
    d["lastModificationDate"] = data.get("lastModificationDate".replace('T', ' ').replace('Z', ''),'')
    d["modified_date_day"] = data.get("lastModificationDate")[8:10]
    d["modified_date_month"] = data.get("lastModificationDate")[5:7]
    d["modified_date_year"] = data.get("lastModificationDate")[0:4]
    d["modified_date_hour"] = data.get("lastModificationDate")[11:13]
    d["modified_date_minits"] = data.get("lastModificationDate")[14:16]
    d["rights"] = data.get("rights",'')
    d["requestId"] = data.get("requestId",'')
    d["uniqId"] = data.get("uniqId",'')
    d["clientIp"] = data.get("clientIp",'')

    return d

def fetch_mail_audit_logs(settings: "SettingParams", last_date: str = ""):
  
    log_records = set()
    params = {}
    try:
        params["pageSize"] = 100
        if last_date:
            msg_date = datetime.datetime.strptime(last_date, "%Y-%m-%d %H:%M:%S")
            shifted_date = msg_date + relativedelta(minutes=-OVERLAPPED_MINITS)
            params["afterDate"] = shifted_date.strftime("%Y-%m-%dT%H:%M:%SZ")
        url = f"{DEFAULT_360_API_URL}/security/v1/org/{settings.organization_id}/audit_log/mail"
        headers = {"Authorization": f"OAuth {settings.oauth_token}"}
        pages_count = 0
        retries = 0
        while True:           
            response = requests.get(url, headers=headers, params=params)
            if response.status_code != HTTPStatus.OK.value:
                logger.error(f"Error during GET request: {response.status_code}. Error message: {response.text}")
                if retries < MAX_RETRIES:
                    logger.error(f"Retrying ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * retries)
                    retries += 1
                else:
                    logger.error(f"Forcing exit without getting data.")
                    return []
            else:
                retries = 1
                temp_list = response.json()["events"]
                logger.debug(f'Received {len(temp_list)} records, from {temp_list[-1]["date"]} to {temp_list[0]["date"]}')
                temp_json = [json.dumps(d, ensure_ascii=False).encode('utf8') for d in temp_list]
                log_records.update(temp_json)
                if response.json()["nextPageToken"] == "":
                    break
                else:
                    if pages_count < MAIL_LOG_MAX_PAGES:
                        pages_count += 1
                        params["pageToken"] = response.json()["nextPageToken"]
                    else:
                        if params.get('pageToken') : del params['pageToken']
                        params["beforeDate"] = temp_list[-10]["date"]
                        params["pageSize"] = 100
                        pages_count = 0

    except Exception as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        return []
        
    return list(log_records)[::-1]

def fetch_disk_audit_logs(settings: "SettingParams", last_date: str = ""):
  
    log_records = set()
    params = {}
    try:
        params["pageSize"] = 100
        if last_date:
            msg_date = datetime.datetime.strptime(last_date, "%Y-%m-%d %H:%M:%S")
            shifted_date = msg_date + relativedelta(minutes=-OVERLAPPED_MINITS)
            params["afterDate"] = shifted_date.strftime("%Y-%m-%dT%H:%M:%SZ")
        url = f"{DEFAULT_360_API_URL}/security/v1/org/{settings.organization_id}/audit_log/disk"
        headers = {"Authorization": f"OAuth {settings.oauth_token}"}
        pages_count = 0
        retries = 0
        while True:           
            response = requests.get(url, headers=headers, params=params)
            if response.status_code != HTTPStatus.OK.value:
                logger.error(f"Error during GET request: {response.status_code}. Error message: {response.text}")
                if retries < MAX_RETRIES:
                    logger.error(f"Retrying ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * retries)
                    retries += 1
                else:
                    logger.error(f"Forcing exit without getting data.")
                    return []
            else:
                retries = 1
                temp_list = response.json()["events"]
                logger.debug(f'Received {len(temp_list)} records, from {temp_list[-1]["date"]} to {temp_list[0]["date"]}')
                temp_json = [json.dumps(d, ensure_ascii=False).encode('utf8') for d in temp_list]
                log_records.update(temp_json)
                if response.json()["nextPageToken"] == "":
                    break
                else:
                    if pages_count < MAIL_LOG_MAX_PAGES:
                        pages_count += 1
                        params["pageToken"] = response.json()["nextPageToken"]
                    else:
                        if params.get('pageToken') : del params['pageToken']
                        params["beforeDate"] = temp_list[-10]["date"]
                        params["pageSize"] = 100
                        pages_count = 0

    except Exception as e:
        logger.error(f"{type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        return []
        
    return list(log_records)[::-1]

if __name__ == "__main__":

    denv_path = os.path.join(os.path.dirname(__file__), '.env')

    if os.path.exists(denv_path):
        load_dotenv(dotenv_path=denv_path,verbose=True, override=True)

    try:
        main()
    except Exception as exp:
        logging.exception(exp)
        sys.exit(EXIT_CODE)