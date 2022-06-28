import threading
import datetime
import certstream
import mysql.connector
import logging
import argparse
import re
from tld import is_tld, get_tld
from getpass import getpass
import sys
import pandas as pd
import requests
import json
import time

lock_query = threading.Lock()
logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.INFO)
parser = argparse.ArgumentParser(description='PHISHING DTECTOOL')
parser.add_argument('-bdd', metavar='--database', type=str, required=True, help='enter your database name')
parser.add_argument('-ip', metavar='--ip_address', type=str, required=True, help='enter your server IP')
args = parser.parse_args()
bdd = args.bdd
ip = args.ip

loginBDD = input("Entrez votre identifiant de database : ")
passwordBDD = getpass("Enter the password : ")

conn = mysql.connector.connect(host=ip, user=loginBDD, password=passwordBDD, database=bdd)
if (conn.is_connected()):
    print("Connected !")
else:
    print("Not connected !")
    print("Exiting the program")
    print(sys.exit())

cur = conn.cursor()
headers = {'API-Key': '81376bfb-cbce-419f-b822-655f7efc0ee4', 'Content-Type': 'application/json'}
suspect_keyword = ['bank', 'paypal', 'mail', 'itunes', 'appleid', 'gmail', 'bitcoin', 'amazon', 'leboncoin', 'login','github','help','account']
suspect_tld = ['.zip', '.review', '.country', '.kim', '.cricket', '.science','.party', '.buisness', '.gov','.io',
               '.gouv','.gq']
suspect_2tld = ['.work', '.link','.buzz']
cyrilique = ['xn', 'xn-', 'xn--']
top_sites = pd.read_csv("top-1m.csv")

class colors:
    VALID = '\033[92m'  # GREEN
    SUSPECT = '\033[41m'  # RED SURLIGNE
    PHISHING = '\033[91m'  # RED
    WARNING = '\033[93m'  # ORANGE
    RESET = '\033[0m'  # RESET COLOR



def has_cyrillic(text):
    return bool(re.search('[\u0400-\u04FF]', text))


def insert_db(nom_domain, score):
    # Met a jour la bdd avec le score final du domaine
    entree = (nom_domain, score)

    cur.execute("INSERT INTO scoring (Nom_domaine, Scoring) VALUES (%s, %s)", entree)
    conn.commit()
    if score>180:
        print(f"""{colors.SUSPECT}PHISHING : {nom_domain} (score:{score}){colors.RESET}""")
    if score >= 120 and score <=179:
        print(f"""{colors.PHISHING}Suspicieux : {nom_domain} (score:{score}){colors.RESET}""")
    if score >= 90 and score <= 109:
        print(f"""{colors.WARNING}Attention : {nom_domain} (score:{score}){colors.RESET}""")
    if score <= 70:
        print(f"""{colors.VALID}Valide : {nom_domain} (score:{score}){colors.RESET}""")

    
def calc_scoring(nom_domaine, top_sites):
    # Va chercher dans la liste si le nom de domaine existe
    resultat = top_sites.loc[top_sites['nom_domaine'] == nom_domaine]
    if not resultat.empty:
        # Si un nom de domaine correspond alors score = 0
        score = 0
    else:
        score = 50

    return score


def scoring(nom_domaine, all_domains, ca):

    # Initialisation
    score_trait = 0
    score_cyr = 0
    score_cyr2 = 0
    score_keyword = 0
    score_ca = 0
    score_dot = 0
    score_tld = 0
    score2_tld = 0
    score_csv = calc_scoring(nom_domaine, top_sites)

    ###############
    if "Let's Encrypt" == ca:
        score_ca = 20
    for keyword in suspect_keyword:
        if keyword in all_domains:
            score_keyword = 40
    for tld in suspect_tld:
        if tld in nom_domaine:
            score_tld = 70
        for tld2 in suspect_2tld:
            if tld2 in nom_domaine:
                score2_tld = 25
        for cyrxn in cyrilique:
            if cyrxn in nom_domaine:
                score_cyr2 = 20

    if 'xn--' not in nom_domaine and nom_domaine.count('.') >= 3:
        score_dot = 20
    if "workers" in nom_domaine:
        score2_tld = 0


    if has_cyrillic(nom_domaine) == True:
        score_cyr = 60
    if nom_domaine.count('-') >= 3:
        score_trait = 20
    # Donne un score a un nom de domaine à la fin de cette fonction


    score = score_csv + score_keyword + score_ca + score_cyr + score_dot + score_trait + score_tld + score2_tld + score_cyr2

    if score > 109:
        data = {"url": f"https://{nom_domaine}", "visibility": "public"}
        response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, data=json.dumps(data))
        reponse = response.json()
        result = reponse["result"]
        time.sleep(8)
        html = requests.get(result).content
        html = str(html)
        valide = "Malicious Activity!"
        if valide in html:
            score +=125
    insert_db(nom_domaine, score)


class ThreadsManager:
    def __init__(self):
        self.threads_cpt = 1

    def start_worker(self, message, context):
        t = threading.Thread(target=hit_certstream, args=(message, context), name=f"Worker N°{self.threads_cpt}")
        self.threads_cpt += 1
        while threading.active_count()>2000 :
            time.sleep(5)
        t.start()


def send_domain(all_domains):
    dmn = all_domains[0]
    domainurl = "".join(["http://", dmn])
    domaintldfinal = ""
    try:
        tld = get_tld(domainurl)
        domain_short = get_tld(domainurl, as_object=True)
        onlydomain = domain_short.domain
        domaintldfinal = ".".join([onlydomain, tld])
    except:
        if domaintldfinal == "":
            exit()
    return domaintldfinal


# process message here before insert
def hit_certstream(message, context):
    logging.debug("Message -> {}".format(message))
    all_domains = message['data']['leaf_cert']['all_domains']
    ca = message['data']['leaf_cert']['issuer']['O']

    # print(threading.current_thread().getName(), message)
    # Lock access to db to avoid concurrent access, while wait locker release. Queue is automatically manage.
    lock_query.acquire()
    try:
        # Affichage du contenu de message
        # print(f"{datetime.datetime.now().strftime('%m/%d/%Y, %H:%M:%S')} | Lock acquire: {threading.current_thread().getName()}\nReceived message, type is -> {message['message_type']}")
        domain_final = send_domain(all_domains)
        if domain_final == "":
            exit()
        else:
            cur.execute(f"SELECT Nom_domaine FROM scoring WHERE Nom_domaine = '{domain_final}'")
            rows = cur.fetchall()
            if not rows:
                scoring(domain_final, all_domains, ca)
            else:
                exit()

    finally:
        # Release lock on db access

        lock_query.release()
        # Stop worker properly to limit memory and cpu usage on long run
        exit()


def on_open():
    print("Connection successfully established!")


if __name__ == '__main__':
    threads_manager = ThreadsManager()

    certstream.listen_for_events(
        threads_manager.start_worker,
        on_open=on_open,
        url='wss://certstream.calidog.io/'
    )
