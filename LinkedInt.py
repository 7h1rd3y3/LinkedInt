# LinkedInt
# Scrapes LinkedIn without using LinkedIn API
# Original scraper by @DisK0nn3cT (https://github.com/DisK0nn3cT/linkedin-gatherer)
# Modified by @vysecurity
# - Additions:
# --- UI Updates
# --- Constrain to company filters
# --- Addition of Hunter for e-mail prediction

#!/usr/bin/python3

# stl
import argparse
import base64
import configparser
from dataclasses import dataclass
import json
import logging
import os
import math
import re
import sys
import textwrap

# 3rd party
import requests
import urllib
import urllib.parse
from bs4 import BeautifulSoup

baseDir = os.path.dirname(os.path.realpath(sys.argv[0])) + os.path.sep
logger = logging.getLogger(__file__)


@dataclass
class persondata:
    data_slug: str
    encoded_picture: str
    name: str
    email: str
    data_occupation: str
    data_location: str
    content_type: str
    data_firstname: str
    data_lastname: str

def getCookies(cookie_jar, domain):
    cookie_dict = cookie_jar.get_dict(domain=domain)
    found = [f"{name}={value}" for (name, value) in cookie_dict.items()]
    return "; ".join(found)


class souper(BeautifulSoup):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

    def findattr_value(self, attr_name):
        return self.find_all(attrs={"name": attr_name}).get("value")


def login(username: str, password: str):
    URL = "https://www.linkedin.com"
    _session = requests.Session()
    response = _session.get(
        URL + "/uas/login?trk=guest_homepage-basic_nav-header-signin"
    )
    p = souper(response.content, "html.parser")

    ac = p.findattr_value("ac")
    parentPageKey = p.findattr_value("parentPageKey")
    pageInstance = f"urn:li:page:{parentPageKey};"
    trk = p.findattr_value("trk")
    authUUID = p.findattr_value("authUUID")
    session_redirect = p.findattr_value("session_redirect")
    fp_data = p.findattr_value("fp_data")
    apfc = p.findattr_value("apfc")
    dval = p.findattr_value("_d")
    showGoogleOneTapLogin = p.findattr_value("showGoogleOneTapLogin")

    csrf = p.findattr_value("loginCsrfParam")
    csrf_token = p.findattr_value("csrfToken")
    sid_str = p.findattr_value("sIdString")

    postdata = {
        "csrfToken": csrf_token,
        "session_key": username,
        "ac": ac,
        "sIdString": sid_str,
        "parentPageKey": parentPageKey,
        "pageInstance": pageInstance,
        "trk": trk,
        "authUUID": authUUID,
        "session_redirect": session_redirect,
        "loginCsrfParam": csrf,
        "fp_data": fp_data,
        "apfc": apfc,
        "_d": dval,
        "showGoogleOneTapLogin": showGoogleOneTapLogin,
        "controlId": "d_checkpoint_lg_consumerLogin-login_submit_button",
        "session_password": password,
        "loginFlow": "REMEMBER_ME_OPTIN",
    }
    response = _session.post(URL + "/checkpoint/lg/login-submit", data=postdata)

    if "behaviour that can result in restriction" in response.text:
        raise SystemExit("[!] Your account is restricted, fix it before continuing")
    try:
        cookie = getCookies(_session.cookies, ".www.linkedin.com")
    except:
        raise SystemExit("[!] Cannot login")
    return cookie


def get_suffix() -> str:
    while True:
        suffix = input("[*] Enter e-mail domain suffix (eg. contoso.com): \n")
        domain_pattern = "^(((?!\-))(xn\-\-)?[a-z0-9\-_]{0,61}[a-z0-9]{1,1}\.)*(xn\-\-)?([a-z0-9\-]{1,61}|[a-z0-9\-]{1,30})\.[a-z]{2,}$"
        if re.match(domain_pattern, suffix):
            return suffix
        print(f"[!] Invalid domain {suffix=}, try again")


def process_company(use_company_filter, company_id, cookies, search, hunter_api_key):
    if use_company_filter:
        if not company_id:
            url = f"https://www.linkedin.com/voyager/api/typeahead/hits?q=blended&query={search}"
            headers = {
                "Csrf-Token": "ajax:0397788525211216810",
                "X-RestLi-Protocol-Version": "2.0.0",
            }
            cookies["JSESSIONID"] = "ajax:0397788525211216810"
            r = requests.get(url, cookies=cookies, headers=headers)
            content = json.loads(r.text)
            firstID = 0
            for i in range(0, len(content.get("elements", []))):
                try:
                    retrieved_id = (
                        content.get("elements", {})[i]
                        .get("hitInfo", {})
                        .get("com.linkedin.voyager.typeahead.TypeaheadCompany", {})
                        .get("id", "")
                    )
                    if retrieved_id:
                        print(f"[Notice] Found company ID: {retrieved_id}")
                        break
                except Exception as company_id_err:
                    print(f"[ERROR]:{company_id_err=}")
                    continue
            company_id = firstID
            if retrieved_id == 0:
                raise SystemExit("No valid company ID found in auto")
        print(f"[*] Using {company_id=}")

    if use_company_filter == False:
        url = f"https://www.linkedin.com/voyager/api/search/cluster?count=40&guides=List()&keywords={search}&origin=OTHER&q=guided&start=0"
    else:
        url = f"https://www.linkedin.com/voyager/api/search/cluster?count=40&guides=List(v->PEOPLE,facetCurrentCompany->{retrieved_id})&origin=OTHER&q=guided&start=0"

    print(f"{url=}")

    headers = {
        "Csrf-Token": "ajax:0397788525211216808",
        "X-RestLi-Protocol-Version": "2.0.0",
    }
    cookies["JSESSIONID"] = "ajax:0397788525211216808"
    r = requests.get(url, cookies=cookies, headers=headers)
    content = json.loads(r.text)
    data_total = content.get("elements", [{}])[0].get("total", 0)

    pages = int(math.ceil(data_total / 40.0))

    if pages == 0:
        pages = 1

    if data_total % 40 == 0:
        pages = pages - 1

    if pages == 0:
        raise SystemExit("[!] Try to use quotes in the search name")

    print(f"[*] {data_total=} Results Found")
    if data_total > 1000:
        pages = 25
        print(
            "[*] LinkedIn only allows 1000 results. Refine keywords to capture all data"
        )
    print(f"[*] Fetching {pages=} Pages")

    results = list

    for p in range(pages):
        if use_company_filter == False:
            url = f"https://www.linkedin.com/voyager/api/search/cluster?count=40&guides=List()&keywords={search}&origin=OTHER&q=guided&start={p*40}"
        else:
            url = f"https://www.linkedin.com/voyager/api/search/cluster?count=40&guides=List(v->PEOPLE,facetCurrentCompany->{retrieved_id})&origin=OTHER&q=guided&start={p*40}"
        r = requests.get(url, cookies=cookies, headers=headers)
        content = r.text.encode("UTF-8")
        content = json.loads(content)
        print(
            f'[*] Fetching page {p} with {len(content.get("elements", [{}])[0].get("elements", []))} results'
        )
        for c in content.get("elements", [{}])[0].get("elements", []):
            if (
                "com.linkedin.voyager.search.SearchProfile" in c.get("hitInfo", [])
                and c.get("hitInfo", {})
                .get("com.linkedin.voyager.search.SearchProfile", {})
                .get("headless")
                == False
            ):
                miniprofile = (
                    c.get("hitInfo", {})
                    .get("com.linkedin.voyager.search.SearchProfile", {})
                    .get("miniProfile", {})
                )
                data_firstname = miniprofile.get("firstName", "")
                data_lastname = miniprofile.get("lastName", "")
                data_slug = (
                    f'https://www.linkedin.com/in/{miniprofile.get("publicIdentifier")}'
                )
                data_occupation = miniprofile.get("occupation", "")
                data_location = ""  # c['hitInfo']['com.linkedin.voyager.search.SearchProfile']['location']
                try:
                    data_picture = textwrap.dedent(
                        f"""
                    {miniprofile.get('picture',{}).get('com.linkedin.common.VectorImage', {}).get('rootUrl', '')}
                    {miniprofile.get('picture',{}).get('com.linkedin.common.VectorImage', {}).get('artifacts', [{},{},{}])[2].get('fileIdentifyingUrlPathSegment', '')}
                    """
                    )
                except:
                    print(
                        f"[*] No picture found for {data_firstname} {data_lastname} {data_occupation}"
                    )
                    data_picture = ""

                suffix = get_suffix()
                name, user = parse_name(
                    data_firstname, data_lastname, hunter_api_key, suffix
                )
                if not all([name, user]):
                    continue
                email = f"{user}@{suffix}"
                if "http" in data_picture:
                    data = requests.get(data_picture)
                    encoded_picture = base64.b64encode(data.content).decode("ascii")
                    content_type = data.headers.get("Content-Type", "")
                else:
                    encoded_picture = base64.b64decode(
                        open("../asset/anonymous_avatar.jpg", "rb").read()
                    )
                    content_type = "image/jpeg"

                results.append(persondata(
                    data_slug,
                    encoded_picture,
                    name,
                    email,
                    data_occupation,
                    data_location,
                    content_type,
                    data_firstname,
                    data_lastname))
            else:
                print("[!] Headless profile found. Skipping")
                print("")
    return results


def render_pages(results: list, sort_key: None):
    logo_data = base64.encode(open("asset/header_image.png", "rb").read())
    # if sort_key and sort_key in 

def authenticate(username: str, password: str):
    try:
        a = login(username, password)
        session = a
        if len(session) == 0:
            raise SystemExit("[!] Unable to login to LinkedIn.com")
        print("[*] Obtained new session")
        return dict(li_at=session)
    except Exception as auth_exception:
        raise SystemExit(f"[!] Could not authenticate to linkedin. {auth_exception}")


def validate_choice(question: str, choices=["y", "Y", "n", "N"]):
    format_question = f"[*] {question} - {choices}?:\n"
    choice = input(format_question)
    while choice not in choices:
        print("[!] Incorrect choice")
        choice = input(format_question)
    return choice


def validate_bool(
    question: str, affirmative_choices=["y", "Y"], negative_choices=["n", "N"]
) -> bool:
    return (
        validate_choice(question, affirmative_choices + negative_choices)
        in affirmative_choices
    )


def validate_int(question: str) -> int:
    """
    Asks user for input.
      - returns 0 for blank input
      - converts input to integer or prompts and retries
    """
    while True:
        choice = input(f"[*]{question}:\n")
        if choice == "":
            return 0
        try:
            int(choice)
        except Exception as int_error:
            print("[!] Incorrect choice, either a number or blank")
            continue
        return int(choice)


def main(args):
    config = configparser.RawConfigParser()
    config.read(baseDir + "LinkedInt.cfg")
    api_key = config.get("API_KEYS", "hunter")
    username = config.get("CREDS", "linkedin_username")
    password = config.get("CREDS", "linkedin_password")
    search = args.keywords
    if use_company_filter := validate_bool("Filter by Company"):
        company_id = validate_int(
            "Specify a Company ID (Provide ID or leave blank to automate)"
        )
    search = urllib.parse.quote_plus(search)
    cookies = authenticate(username, password)

    results = process_company(use_company_filter, company_id, cookies, search, api_key)
    render_pages(results)
    print("[+] Complete")


if __name__ == "__main__":
    print(open(baseDir + "banner.txt", "r").read())
    print("Version: 1.1 FIXED - March 27, 2021")
    print("Author: Vincent Yiu @vysecurity")
    """ Setup Argument Parameters """
    parser = argparse.ArgumentParser(description="Discovery LinkedIn")
    parser.add_argument("-u", "--keywords", help="Keywords to search", required=True)
    parser.add_argument(
        "-o",
        "--output",
        help="Output file (do not include extensions)",
        default="linked_int_results",
    )
    args = parser.parse_args()
    main(args)


def parse_name(data_firstname, data_lastname, hunter_api_key, suffix):
    # TODO: What the fuck is this name parser doing?
    parts = data_lastname.split()
    name = data_firstname + " " + data_lastname

    match len(parts):
        case [1]:
            first = data_firstname
            middle = "?"
            last = parts[0]
        case [2]:
            first = data_firstname
            middle = parts[0]
            last = parts[1]
        case [3]:
            first = data_firstname
            last = parts[0]
        case _:
            first = data_firstname
            last = "?"

    # delete the non alpha characters
    delete_non_alpha = lambda s: re.sub("[^A-Za-z]+", "", s)
    first = delete_non_alpha(first)
    middle = delete_non_alpha(middle)
    last = delete_non_alpha(last)

    if len(first) == 0 or len(last) == 0:
        return [None, None]

    f = first[0]
    m = middle[0] if len(middle)>0 else ''
    l = last[0]
    formats = {
        "full": f"{first}{middle}{last}",
        "firstlast": f"{first}{last}",
        "firstmlast": f"{first}{m}{last}",
        "flast": f"{f}{last}",
        "firstl": f"{first}{l}",
        "first.last": f"{first}{last}",
        "first_last": f"{first}_{last}",
        "fmlast": f"{f}{m}{last}",
        "lastfirst": f"{last}{first}",
        "first": f"{first}",
    }

    prefix_choices = list(formats.keys)
    prefix = validate_choice(
        "[*] Select a prefix for e-mail generation", prefix_choices + ["auto"]
    )

    if prefix == "auto":
        print("[*] Automatically using Hunter IO to determine best Prefix")
        url = f"https://api.hunter.io/v2/domain-search?domain={suffix}&api_key={hunter_api_key}"
        r = requests.get(url)
        content = json.loads(r.text)
        prefix = content.get("data", {}).get("pattern", "")
        # debug log print("[!] %s" % prefix)
        if prefix:
            prefix = prefix.replace("{", "").replace("}", "")
            if prefix in prefix_choices:
                print(f"[+] Found {prefix=}")
            else:
                print(
                    "[!] Automatic prefix search failed, please insert a manual choice"
                )
                prefix = validate_choice(
                    "[*] Select a manual prefix for e-mail generation", prefix_choices
                )
    user = formats[prefix]
    return name, user
