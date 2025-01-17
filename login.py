import requests
import time
import re
import hashlib
import hmac
import math
import tomllib


def get_md5(password, token):
    return hmac.new(token.encode(), password.encode(), hashlib.md5).hexdigest()


def get_sha1(value):
    return hashlib.sha1(value.encode()).hexdigest()


_PADCHAR = "="
_ALPHA = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"


def _getbyte(s, i):
    # print(s,' ',i)
    x = ord(s[i])
    if x > 255:
        print("INVALID_CHARACTER_ERR: DOM Exception 5")
        exit(0)
    return x


def get_base64(s):
    i = 0
    b10 = 0
    x = []
    imax = len(s) - len(s) % 3
    if len(s) == 0:
        return s
    for i in range(0, imax, 3):
        b10 = (_getbyte(s, i) << 16) | (_getbyte(s, i + 1) << 8) | _getbyte(s, i + 2)
        x.append(_ALPHA[(b10 >> 18)])
        x.append(_ALPHA[((b10 >> 12) & 63)])
        x.append(_ALPHA[((b10 >> 6) & 63)])
        x.append(_ALPHA[(b10 & 63)])
    i = imax
    if len(s) - imax == 1:
        b10 = _getbyte(s, i) << 16
        x.append(_ALPHA[(b10 >> 18)] + _ALPHA[((b10 >> 12) & 63)] + _PADCHAR + _PADCHAR)
    elif len(s) - imax == 2:
        b10 = (_getbyte(s, i) << 16) | (_getbyte(s, i + 1) << 8)
        x.append(
            _ALPHA[(b10 >> 18)]
            + _ALPHA[((b10 >> 12) & 63)]
            + _ALPHA[((b10 >> 6) & 63)]
            + _PADCHAR
        )
    return "".join(x)


def force(msg):
    ret = []
    for w in msg:
        ret.append(ord(w))
    return bytes(ret)


def ordat(msg, idx):
    if len(msg) > idx:
        return ord(msg[idx])
    return 0


def sencode(msg, key):
    l = len(msg)
    pwd = []
    for i in range(0, l, 4):
        pwd.append(
            ordat(msg, i)
            | ordat(msg, i + 1) << 8
            | ordat(msg, i + 2) << 16
            | ordat(msg, i + 3) << 24
        )
    if key:
        pwd.append(l)
    return pwd


def lencode(msg, key):
    l = len(msg)
    ll = (l - 1) << 2
    if key:
        m = msg[l - 1]
        if m < ll - 3 or m > ll:
            return
        ll = m
    for i in range(0, l):
        msg[i] = (
            chr(msg[i] & 0xFF)
            + chr(msg[i] >> 8 & 0xFF)
            + chr(msg[i] >> 16 & 0xFF)
            + chr(msg[i] >> 24 & 0xFF)
        )
    if key:
        return "".join(msg)[0:ll]
    return "".join(msg)


def get_xencode(msg, key):
    if msg == "":
        return ""
    pwd = sencode(msg, True)
    pwdk = sencode(key, False)
    if len(pwdk) < 4:
        pwdk = pwdk + [0] * (4 - len(pwdk))
    n = len(pwd) - 1
    z = pwd[n]
    y = pwd[0]
    c = 0x86014019 | 0x183639A0
    m = 0
    e = 0
    p = 0
    q = math.floor(6 + 52 / (n + 1))
    d = 0
    while 0 < q:
        d = d + c & (0x8CE0D9BF | 0x731F2640)
        e = d >> 2 & 3
        p = 0
        while p < n:
            y = pwd[p + 1]
            m = z >> 5 ^ y << 2
            m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
            m = m + (pwdk[(p & 3) ^ e] ^ z)
            pwd[p] = pwd[p] + m & (0xEFB8D130 | 0x10472ECF)
            z = pwd[p]
            p = p + 1
        y = pwd[0]
        m = z >> 5 ^ y << 2
        m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
        m = m + (pwdk[(p & 3) ^ e] ^ z)
        pwd[n] = pwd[n] + m & (0xBB390742 | 0x44C6F8BD)
        z = pwd[n]
        q = q - 1
    return lencode(pwd, False)


header = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.26 Safari/537.36"
}


def get_chksum(token, username, hmd5, ip, i):
    chkstr = token + username
    chkstr += token + hmd5
    chkstr += token + "0"
    chkstr += token + ip
    chkstr += token + "200"
    chkstr += token + "1"
    chkstr += token + i
    return chkstr


def get_info():
    info_temp = {
        "username": username,
        "password": password,
        "ip": ip,
        "acid": "0",
        "enc_ver": "srun_bx1",
    }
    i = re.sub("'", '"', str(info_temp))
    i = re.sub(" ", "", i)
    return i


def init_get_ip(init_url):
    init_res = requests.get(init_url, headers=header)
    ip = re.search('ip     : "(.*?)"', init_res.text).group(1)
    return ip


def get_token(username, ip, get_challenge_api):
    get_challenge_params = {
        "callback": "jQuery112406608265734960486_" + str(int(time.time() * 1000)),
        "username": username,
        "ip": ip,
        "_": int(time.time() * 1000),
    }
    get_challenge_res = requests.get(
        get_challenge_api, params=get_challenge_params, headers=header
    )
    token = re.search('"challenge":"(.*?)"', get_challenge_res.text).group(1)
    return token


def do_complex_work(username, password, token, ip):
    i = get_info()
    i = "{SRBX1}" + get_base64(get_xencode(i, token))
    hmd5 = get_md5(password, token)
    chksum = get_sha1(get_chksum(token, username, hmd5, ip, i))
    return i, hmd5, chksum


def login(username, ip, i, hmd5, chksum, srun_portal_api):
    srun_portal_params = {
        "callback": "jQuery112404450565644662372" + str(int(time.time() * 1000)),
        "action": "login",
        "username": username,
        "password": "{MD5}" + hmd5,
        "ac_id": "0",
        "ip": ip,
        "chksum": chksum,
        "info": i,
        "n": "200",
        "type": "1",
        "os": "windows+10",
        "name": "windows",
        "double_stack": 0,
        "_": int(time.time() * 1000),
    }
    # print(srun_portal_params)
    srun_portal_res = requests.get(
        srun_portal_api, params=srun_portal_params, headers=header
    )
    if "ok" in srun_portal_res.text:
        return True
    else:
        print(srun_portal_res.text)
        return False


if __name__ == "__main__":

    with open("config.toml", "rb") as f:
        config = tomllib.load(f)
    username = config["username"]
    password = config["password"]

    init_url = config["base_url"]
    get_challenge_api = init_url + "/cgi-bin/get_challenge"
    srun_portal_api = init_url + "/cgi-bin/srun_portal"
    ip = init_get_ip(init_url)
    print(f"IP: {ip}")
    token = get_token(username, ip, get_challenge_api)
    print(f"Token: {token}")
    i, hmd5, chksum = do_complex_work(username, password, token, ip)
    res = login(username, ip, i, hmd5, chksum, srun_portal_api)
    if res:
        print("Login Success!")
        print(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}")
    else:
        print("Login Failed!")
