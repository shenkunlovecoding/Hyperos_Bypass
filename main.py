import subprocess
import time
import json
import requests
import base64
import hmac
import adbutils 
import os.path as op
# 定义全局变量
from Crypto.Cipher import AES
import hashlib
use_global = False

if use_global:
    api = "https://unlock.update.intl.miui.com/v1/"
else:
    api = "https://unlock.update.miui.com/v1/"
adb_bin = 'adb.exe'
version = "1.0"
adb = adbutils.AdbClient(host="127.0.0.1", port=5037)
device = adb.device()
sign_key = "10f29ff413c89c8de02349cb3eb9a5f510f29ff413c89c8de02349cb3eb9a5f5"
data_pass = "20nr1aobv2xi8ax4"
data_iv = "0102030405060708"

def logf(message, color='g', symbol='*'):
    print(f"{symbol} {message}")
def decrypt_data(data: str) -> str:
    decoded_data = base64.b64decode(data)
    cipher = AES.new(data_pass.encode('utf-8'), AES.MODE_CBC, data_iv.encode('utf-8'))
    decrypted = cipher.decrypt(decoded_data)
    return decrypted.decode('utf-8')
def sign_data(data: str) -> str:
    # 构建待签名的字符串
    message = "POST\n/v1/unlock/applyBind\ndata=" + data + "&sid=miui_sec_android"
    # 使用SHA-1 HMAC算法进行签名，其中密钥为sign_key
    signature = hmac.new(sign_key.encode('utf-8'), msg=message.encode('utf-8'), digestmod=hashlib.sha1).hexdigest()
    # 返回小写的十六进制字符串
    return signature.lower()

def post_api(endpoint, data, headers, ignore=False):
    url = f"{api}{endpoint}"
    response = requests.post(url, data=data, headers=headers)
    if response.ok:
        return response.json()
    return None

logf("************************************")
logf("* Xiaomi HyperOS BootLoader Bypass Python*")
logf("* By Shenziqian          Version 1.1 *")
logf("************************************")
logf("成功几率看脸，多试几次")
logf("请确保您已安装旧版设置")
logf("************************************")

# Main Logic
logf(f"链接设备中...")

device.logcat(clear=True)
device.shell("svc data enable")
app_info = device.app_current()
focus = app_info.activity
if focus != "com.android.settings":
    if focus != "NotificationShade":
        device.shell(f"shell am start -a android.settings.APPLICATION_DEVELOPMENT_SETTINGS")
else:
    if focus != "com.android.settings.bootloader.BootloaderStatusActivity":
        device.shell(f"shell am start -a android.settings.APPLICATION_DEVELOPMENT_SETTINGS")
import os
os.sleep(5)
logf("请绑定账号", "y", "*")

args = headers = None

with subprocess.Popen(f"{adb_bin} logcat *:S CloudDeviceStatus:V",
                      shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
    for output in process.stdout:
        output = output.decode('utf-8').strip()
        
        if "CloudDeviceStatus: args:" in output:
            args = output.split("args:")[1].strip()
            device.shell(f"shell svc data disable")
        
        if "CloudDeviceStatus: headers:" in output:
            headers = output.split("headers:")[1].strip()
            logf("拦截到请求...")
            process.kill()
            break
            
logf("重构参数中...")
data = decrypt_data(args)
data = data.rstrip()
logf(data)
data = json.loads(data.rstrip())

data["rom_version"] = data["rom_version"].replace("V816", "V14")

data = json.dumps(data)
sign = sign_data(data)

headers_decrypted = decrypt_data(headers)
cookies = None

if "Cookie=[" in headers_decrypted:
    cookies = headers_decrypted.split("Cookie=[")[1].split("]")[0].strip()

logf("Sending POST request...")
res = post_api("unlock/applyBind", {
    "data": data,
    "sid": "miui_sec_android",
    "sign": sign
}, {
    "Cookie": cookies,
    "Content-Type": "application/x-www-form-urlencoded"
}, True)

device.shell(f"shell svc data enable")

if not res:
    logf("错误：网络连接问题", "r", "!")
else:
    code = res.get("code")
    if code == 0:
        logf(f"已绑定账号: {res['data']['userId']}", "g")
        logf("绕过完毕，请使用解锁工具", "g")
    elif code == 401:
        logf("重新登陆账号 (401)", "y")
    elif code == 20086:
        logf("证书到期 (20086)", "y")
    elif code == 30001:
        logf("绕过失败，小米已强行验证该账号 (30001)", "y")
    elif code == 86015:
        logf("绕过失败 (86015)", "y")
    else:
        logf(f"{res.get('descEN')} ({code})", "y")