import requests
import time
import re
import hashlib
import tomllib

header = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.26 Safari/537.36"
}


def init_get_ip(url):
    init_res = requests.get(url, headers=header)
    ip = re.search('ip     : "(.*?)"', init_res.text).group(1)
    return ip


def get_sha1(value):
    return hashlib.sha1(value.encode()).hexdigest()


def gen_params(ip, username):
    return {
        "ip": ip,
        "username": username,
        "time": str(int(time.time() * 1000)),
        "unbind": "1",
        "sign": get_sha1(
            f"{int(time.time() * 1000)}{username}{ip}1{int(time.time() * 1000)}"
        ),
    }


if __name__ == "__main__":
    with open("config.toml", "rb") as f:
        config = tomllib.load(f)
    base_url = config["base_url"]
    info_api = base_url + "/cgi-bin/rad_user_info"
    logout_api = base_url + "/cgi-bin/rad_user_dm"
    ip = init_get_ip(base_url)
    info_res = requests.get(info_api, headers=header)
    username = info_res.text.split(",")[0]
    print("USERNAME:", username)
    params = gen_params(ip, username)
    logout_res = requests.get(logout_api, params=params, headers=header)
    if "ok" in logout_res.text:
        print("Logout successfully!")
