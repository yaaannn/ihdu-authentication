package main

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	_PADCHAR          = "="
	_ALPHA            = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
	_BASE_URL         = "http://192.168.112.30"
	_GetChallengeAPI  = _BASE_URL + "/cgi-bin/get_challenge"
	_SrunPortalAPI    = _BASE_URL + "/cgi-bin/srun_portal"
	_GetOnlineInfoAPI = _BASE_URL + "/cgi-bin/rad_user_info"
	_LogoutAPI        = _BASE_URL + "/cgi-bin/rad_user_dm"
)

type Info struct {
	Username string `json:"username"`
	Password string `json:"password"`
	IP       string `json:"ip"`
	Acid     string `json:"acid"`
	EncVer   string `json:"enc_ver"`
}

func getMD5(password, token string) string {
	h := hmac.New(md5.New, []byte(token))
	h.Write([]byte(password))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func getSHA1(value string) string {
	h := sha1.New()
	h.Write([]byte(value))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func getBase64(s string) string {

	_get_byte := func(s string, i int) byte {
		x := s[i]
		return x
	}

	i := 0
	var b10 uint32
	var x []byte
	imax := len(s) - len(s)%3
	if len(s) == 0 {
		return s
	}

	for i = 0; i < imax; i += 3 {
		b10 = uint32(_get_byte(s, i))<<16 | uint32(_get_byte(s, i+1))<<8 | uint32(_get_byte(s, i+2))
		x = append(x, _ALPHA[(b10>>18)])
		x = append(x, _ALPHA[(b10>>12)&63])
		x = append(x, _ALPHA[(b10>>6)&63])
		x = append(x, _ALPHA[b10&63])
	}
	i = imax
	switch len(s) - imax {
	case 1:
		b10 = uint32(_get_byte(s, i)) << 16
		x = append(x, _ALPHA[(b10>>18)])
		x = append(x, _ALPHA[(b10>>12)&63])
		x = append(x, _PADCHAR[0])
		x = append(x, _PADCHAR[0])
	case 2:
		b10 = (uint32(_get_byte(s, i)) << 16) | (uint32(_get_byte(s, i+1)) << 8)
		x = append(x, _ALPHA[(b10>>18)])
		x = append(x, _ALPHA[(b10>>12)&63])
		x = append(x, _ALPHA[(b10>>6)&63])
		x = append(x, _PADCHAR[0])
	}
	return string(x)
}

func getXEncode(msg, key string) string {
	if msg == "" {
		return "ERROR"
	}
	sencode := func(msg string, key bool) []uint32 {
		l := len(msg)
		pwd := make([]uint32, 0, (l+3)/4)
		for i := 0; i < l; i += 4 {
			var val uint32
			for j := 0; j < 4 && i+j < l; j++ {
				val |= uint32(msg[i+j]) << (8 * j)
			}
			pwd = append(pwd, val)
		}
		if key {
			pwd = append(pwd, uint32(l))
		}
		return pwd
	}

	lencode := func(msg []uint32, key bool) string {
		l := len(msg)
		ll := (l - 1) << 2

		if key {
			m := msg[l-1]
			if m < uint32(ll-3) || m > uint32(ll) {
				return ""
			}
			ll = int(m)
		}

		var builder strings.Builder

		for i := 0; i < l; i++ {
			val := msg[i]
			builder.WriteByte(byte(val & 0xFF))
			builder.WriteByte(byte(val >> 8 & 0xFF))
			builder.WriteByte(byte(val >> 16 & 0xFF))
			builder.WriteByte(byte(val >> 24 & 0xFF))
		}

		result := builder.String()

		if key {
			if ll > len(result) {
				return result
			}
			return result[0:ll]
		}
		return result
	}

	pwd := sencode(msg, true)
	pwdk := sencode(key, false)
	if len(pwdk) < 4 {
		pwdk = append(pwdk, make([]uint32, 4-len(pwdk))...)
	}
	n := len(pwd) - 1
	z := pwd[n]
	y := pwd[0]
	c := uint32(0x86014019 | 0x183639A0)
	var m, e, p, d uint32
	q := math.Floor(6 + 52/float64(n+1))

	for q > 0 {
		d = d + c&uint32(0x8CE0D9BF|0x731F2640)
		e = d >> 2 & 3
		p = 0
		for p < uint32(n) {
			y = pwd[p+1]
			m = z>>5 ^ y<<2
			m += (y>>3 ^ z<<4) ^ (d ^ y)
			m += pwdk[(p&3)^e] ^ z
			pwd[p] = pwd[p] + m&uint32(0xEFB8D130|0x10472ECF)
			z = pwd[p]
			p++
		}
		y = pwd[0]
		m = z>>5 ^ y<<2
		m += (y>>3 ^ z<<4) ^ (d ^ y)
		m += pwdk[(p&3)^e] ^ z
		pwd[n] = pwd[n] + m&uint32(0xBB390742|0x44C6F8BD)
		z = pwd[n]
		q--
	}
	return lencode(pwd, false)
}

func getInfo(username, password, ip string) string {
	info := Info{username, password, ip, "0", "srun_bx1"}
	jsonData, _ := json.Marshal(info)
	return strings.ReplaceAll(string(jsonData), " ", "")
}

func initGetIP() string {
	resp, err := http.Get(_BASE_URL)
	if err != nil {
		return "ERROR"
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	reg := regexp.MustCompile(`ip\s+:\s+"(.*?)"`)
	match := reg.FindStringSubmatch(string(body))
	if len(match) > 1 {
		return match[1]
	}
	return "ERROR"
}

func getToken(username, ip string) string {
	timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
	callback := "jQuery112406608265734960486_" + timestamp

	params := strings.Join([]string{
		"?callback=", callback,
		"&username=", username,
		"&ip=", ip,
		"&_=", timestamp,
	}, "")

	resp, err := http.Get(_GetChallengeAPI + params)
	if err != nil {
		return "ERROR"
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "ERROR"
	}
	re := regexp.MustCompile(`"challenge":"(.*?)"`)
	match := re.FindStringSubmatch(string(body))
	if len(match) > 1 {
		return match[1]
	}
	return "ERROR"
}

func getChecksum(token, username, hmd5, ip, i string) string {
	parts := []string{
		token, username,
		token, hmd5,
		token, "0",
		token, ip,
		token, "200",
		token, "1",
		token, i,
	}
	return getSHA1(strings.Join(parts, ""))
}

func login(username, password string) bool {
	// 获取 IP
	ip := initGetIP()
	// 获取TOKEN
	token := getToken(username, ip)
	// 获取X_ENCODE
	x_encode := getXEncode(getInfo(username, password, ip), token)
	// 编码info
	i := "{SRBX1}" + getBase64(x_encode)
	// password 加密
	hmd5 := getMD5(password, token)
	// 获取校验码
	chksum := getChecksum(token, username, hmd5, ip, i)
	// 获取登录参数
	timestamp := time.Now().UnixMilli()

	params := strings.Join([]string{
		"?callback=jQuery112404450565644662372", strconv.FormatInt(timestamp, 10),
		"&action=login",
		"&username=", username,
		"&password={MD5}", hmd5,
		"&ac_id=0",
		"&ip=", ip,
		"&chksum=", chksum,
		"&info=", i,
		"&n=200",
		"&type=1",
		"&os=windows+10",
		"&name=windows",
		"&double_stack=0",
		"&_=", strconv.FormatInt(timestamp, 10),
	}, "")

	// 构建完整 URL
	url := _SrunPortalAPI + params
	// 对 URL 中的特殊字符进行编码
	url = strings.ReplaceAll(url, "+", "%2B")
	// 发起 HTTP GET 请求
	resp, err := http.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	// 读取响应内容
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}
	// 判断是否包含登录成功标志
	return strings.Contains(string(body), "ok")

}

func checkOnline() string {
	resp, err := http.Get(_GetOnlineInfoAPI)
	if err != nil {
		return "ERROR"
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		// 处理读取响应体时的错误
		fmt.Println("Error reading response body:", err)
		return "ERROR"
	}

	// 提取 username
	parts := strings.Split(string(body), ",")
	// 如果parts[0] 是数字，则为用户名，返回用户名
	if _, err := strconv.Atoi(parts[0]); err == nil {
		return parts[0]
	}
	return parts[0]
}

func logout() bool {
	ip := initGetIP()

	username := checkOnline()
	if username == "not_online_error" {
		return false
	}
	timestamp := time.Now().UnixMilli()
	sign := getSHA1(strconv.FormatInt(timestamp, 10) +
		username +
		ip +
		"1" +
		strconv.FormatInt(timestamp, 10))
	params := strings.Join([]string{
		"ip=", ip,
		"&username=", username,
		"&time=", strconv.FormatInt(timestamp, 10),
		"&unbind=1",
		"&sign=", sign,
	}, "")

	resp, err := http.Get(_LogoutAPI + "?" + params)
	if err != nil {
		// 处理请求错误
		fmt.Println("Error making request:", err)
		return false
	}
	defer resp.Body.Close()
	// 读取响应内容
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}
	// 判断是否包含登录成功标志
	return strings.Contains(string(body), "ok")

}

func main() {
	var choice int
	// 清空屏幕
	fmt.Print("\033[H\033[2J")
	// 提供用户选择
	fmt.Println("请选择操作：")
	fmt.Println("1. 登录")
	fmt.Println("2. 登出")
	fmt.Println("3. 退出")
	fmt.Print("请输入数字 (1-3): ")
	_, err := fmt.Scanf("%d", &choice)
	if err != nil {
		fmt.Println("输入无效!")
		os.Exit(1)
	}
	// 清空屏幕
	fmt.Print("\033[H\033[2J")
	if choice == 1 {
		// 用户选择登录
		var username, password string
		fmt.Print("请输入用户名: ")
		fmt.Scanf("%s", &username)
		fmt.Print("请输入密码: ")
		fmt.Scanf("%s", &password)
		// 清空屏幕
		fmt.Print("\033[H\033[2J")
		// 执行登录
		if login(username, password) {
			fmt.Println("登录成功!")
			fmt.Println("登录时间:", time.Now().Format("2006-01-02 15:04:05"))
			fmt.Println("登录用户:", username)
		} else {
			fmt.Println("登录失败!")
		}
	} else if choice == 2 {
		// 用户选择登出
		if logout() {
			// 获取登出用户
			username := checkOnline()
			if username == "not_online_error" {
				fmt.Println("当前没有在线用户!")
			} else {
				fmt.Println("当前用户:", username)
			}
			fmt.Println("登出成功!")
			fmt.Println("登出时间:", time.Now().Format("2006-01-02 15:04:05"))
		} else {
			fmt.Println("登出失败!")
		}
	} else if choice == 3 {
		// 用户选择退出
		fmt.Println("退出程序...")
		os.Exit(0)
	} else {
		fmt.Println("无效的选择!")
		os.Exit(1)
	}

}
