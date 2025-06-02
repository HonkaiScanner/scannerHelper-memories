import asyncio
import hashlib
import hmac
import json
import os.path
import sys
import time
import webbrowser
from json.decoder import JSONDecodeError
from threading import Thread

import requests
from flask import Flask, abort, render_template, request
from PIL import Image, ImageGrab
from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtWidgets import QApplication, QMainWindow
from pyzbar.pyzbar import decode

import loginDialog
# import bsgamesdk
import mainWindow

# import mihoyosdk

# 组播组IP和端口
m_cast_group_ip = '239.0.1.255'
m_cast_group_port = 12585
bh_info = {}
config = {}
data = {}
cap = None
global ui, window


def init_conf():
    # 配置文件检查
    global config
    conf_loop = True
    while conf_loop:
        if not os.path.isfile('./config.json'):
            write_conf()
        try:
            with open('./config.json') as fp:
                config = json.loads(fp.read())
                try:
                    if config['ver'] != 6:
                        print('配置文件已更新，请注意重新修改文件')
                        write_conf(config)
                        continue
                except KeyError:
                    print('配置文件已更新，请注意重新修改文件')
                    write_conf(config)
                    continue
        except JSONDecodeError:
            print('配置文件格式不正确 重新写入中...')
            write_conf()
            continue
        conf_loop = False
    print("配置文件检查完成")
    config['account_login'] = False


def write_conf(old=None):
    config_temp = json.loads('{"account":"","password":"","sleep_time":3,"ver":5,"clip_check":false,'
                             '"auto_close":false,"uid":0,"access_key":"","last_login_succ":false,"bh_ver":"7.8.0","uname":"","auto_clip":false,"oa_token":"ebdda08dce6feb6bc552d393bae58c81"}')
    if old is not None:
        for key in config_temp:
            try:
                config_temp[key] = old[key]
            except KeyError:
                continue
    config_temp['ver'] = 6
    with open('./config.json', 'w') as f:
        output = json.dumps(config_temp, sort_keys=True,
                            indent=4, separators=(',', ': '))
        f.write(output)


class LoginThread(QThread):
    update_log = pyqtSignal(str)

    def run(self):
        asyncio.run(self.login())

    async def login(self):
        global config, bh_info
        # ui.loginBiliBtn.setText('登陆中...')
        import bsgamesdk
        if config['last_login_succ']:
            self.printLog(f'验证缓存账号 {config["uname"]} 中...')
            bs_user_info = await bsgamesdk.getUserInfo(config['uid'], config['access_key'])
            if 'uname' in bs_user_info:
                self.printLog(f'登录B站账号 {bs_user_info["uname"]} 成功！')
                bs_info = {}
                bs_info['uid'] = config['uid']
                bs_info['access_key'] = config['access_key']
            else:
                config['last_login_succ'] = False
                config['uid'] = 0
                config['access_key'] = ""
                config['uname'] = ""
                write_conf(config)
                self.printLog(f'缓存已失效，重新登录B站账号 {config["account"]} 中...')
                bs_info = await bsgamesdk.login(config['account'], config['password'], cap)
                if "access_key" not in bs_info:
                    if 'need_captch' in bs_info:
                        self.printLog('需要验证码！请打开下方网址进行操作！')
                        self.printLog(bs_info['cap_url'])
                        webbrowser.open_new(bs_info['cap_url'])
                    else:
                        self.printLog('登录失败！')
                        self.printLog(bs_info)
                    ui.loginBiliBtn.setText("登陆账号")
                    ui.loginBiliBtn.setDisabled(False)
                    return
                bs_user_info = await bsgamesdk.getUserInfo(bs_info['uid'], bs_info['access_key'])

                self.printLog(f'登录B站账号 {bs_user_info["uname"]} 成功！')
                config['uid'] = bs_info['uid']
                config['access_key'] = bs_info['access_key']
                config['last_login_succ'] = True
                config['uname'] = bs_user_info["uname"]

                write_conf(config)
        else:
            self.printLog(f'登录B站账号 {config["account"]} 中...')
            import bsgamesdk
            bs_info = await bsgamesdk.login(config['account'], config['password'], cap)
            if "access_key" not in bs_info:
                if 'message' in bs_info:
                    self.printLog("登录失败！")
                    if bs_info['message'] == 'PWD_INVALID':
                        self.printLog('账号或密码错误！')
                        ui.loginBiliBtn.setText("登陆账号")
                        ui.loginBiliBtn.setDisabled(False)
                        return
                    else:
                        self.printLog("原始返回： " + bs_info['message'])
                if 'need_captch' in bs_info:
                    self.printLog('需要验证码！请打开下方网址进行操作！')
                    self.printLog(bs_info['cap_url'])
                    webbrowser.open_new(bs_info['cap_url'])
                else:
                    self.printLog('登录失败！')
                    self.printLog(bs_info)
                ui.loginBiliBtn.setText("登陆账号")
                ui.loginBiliBtn.setDisabled(False)
                return
            bs_user_info = await bsgamesdk.getUserInfo(bs_info['uid'], bs_info['access_key'])

            self.printLog(f'登录B站账号 {bs_user_info["uname"]} 成功！')
            config['uid'] = bs_info['uid']
            config['access_key'] = bs_info['access_key']
            config['last_login_succ'] = True
            config['uname'] = bs_user_info["uname"]

            write_conf(config)

        self.printLog('登录崩坏3账号中...')
        import mihoyosdk
        bh_info = await mihoyosdk.verify(bs_info['uid'], bs_info['access_key'])
        if bh_info['retcode'] != 0:
            self.printLog('登录失败！')
            self.printLog(bh_info)
            return
        self.printLog('登录成功！')

        self.printLog('获取OA服务器信息中...')

        bh_ver = await mihoyosdk.getBHVer(config)

        config['bh_ver'] = bh_ver

        write_conf(config)

        self.printLog(f'当前崩坏3版本: {bh_ver}')

        oa = await mihoyosdk.getOAServer(config['oa_token'])
        if len(oa) < 100:
            self.printLog('获取OA服务器失败！请检查Token后重试')
            # self.printLog(oa)
            return

        self.printLog('获取OA服务器成功！')
        ui.loginBiliBtn.setText("账号已登录")
        # ui.loginBiliBtn.setDisabled(True)
        config['account_login'] = True

        write_conf(config)

    def printLog(self, msg):
        print(str(msg))
        ui.logText.append(str(msg))
        # self.update_log.emit(str(msg))


class ParseThread(QThread):
    update_log = pyqtSignal(str)

    def run(self):
        asyncio.run(self.check())

    async def check(self):
        while True:
            if config['auto_close']:
                if config['auto_clip']:
                    import pyautogui
                    import pygetwindow as gw
                    if gw.getActiveWindowTitle() == '崩坏3':
                        window = gw.getWindowsWithTitle('崩坏3')[0]  # 获取窗口对象
                        if window:
                            # 获取窗口的边界信息
                            left, top, right, bottom = window.left, window.top, window.right, window.bottom

                            # 使用pyautogui截取窗口的区域截图
                            screenshot = pyautogui.screenshot(
                                region=(left, top, right - left, bottom - top))

                            await parse_pic_raw(screenshot, self.printLog)

                if config['clip_check']:
                    await parse_pic(self.printLog)
                time.sleep(config['sleep_time'])

    def printLog(self, msg):
        print(str(msg))
        self.update_log.emit(str(msg))


async def parse_pic(printLog):

    if config['account_login']:

        # print('getting img...')
        # print(config)
        im = ImageGrab.grabclipboard()

        if isinstance(im, Image.Image):
            return await parse_pic_raw(im, printLog)

    else:
        print('当前未登录或登陆中，跳过当前图片处理')


async def parse_pic_raw(im, printLog):

    global bh_info

    if isinstance(im, Image.Image):
        printLog('识别到图片,开始检测是否为崩坏3登陆码')
        result = decode(im)
        if len(result) >= 1:
            url = result[0].data.decode('utf-8')
            param = url.split('?')[1]
            params = param.split('&')
            ticket = ''
            for element in params:
                if element.split('=')[0] == 'ticket':
                    ticket = element.split('=')[1]
                    break
            # print(ticket)
            if config['account_login']:
                printLog('二维码识别成功，开始请求崩坏3服务器完成扫码')
                import mihoyosdk
                await mihoyosdk.scanCheck(printLog, bh_info, ticket, config)
            # else:
            #     if config['auto_close']:
            #         printLog('开始发送广播')
            #         send(printLog, url)
                # printLog('local login mode')

            time.sleep(1)
            clear_clipboard()
        else:
            printLog('非登陆码,跳过')


def clear_clipboard():
    from ctypes import windll
    if windll.user32.OpenClipboard(None):  # 打开剪切板
        windll.user32.EmptyClipboard()  # 清空剪切板
        windll.user32.CloseClipboard()  # 关闭剪切板


# def send(printLog, url):
#     info = psutil.net_if_addrs()
#     for k, v in info.items():
#         for item in v:
#             if item[0] == 2 and not item[1] == '127.0.0.1':
#                 printLog('开始在网卡 ' + k + ' 发送广播')
#                 send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
#                 try:
#                     local_ip = socket.gethostbyname(item[1])
#                     send_sock.bind((local_ip, m_cast_group_port))
#                     message = "{\"scanner_data\":{\"url\":\"%s\",\"t\":%d}}" % (url, int(time.time()))
#                     send_sock.sendto(message.encode(), (m_cast_group_ip, m_cast_group_port))
#                     printLog('在网卡 ' + k + ' 发送广播成功')
#                 except OSError:
#                     printLog('在网卡 ' + k + ' 发送广播失败')


def login_accept():
    ui.backendLogin = LoginThread()
    ui.backendLogin.update_log.connect(window.printLog)
    ui.backendLogin.start()


def deal_password(string):
    global config
    config['password'] = string


def deal_account(string):
    global config
    config['account'] = string


def printLog(msg):
    try:
        ui.logText.append(str(msg))
    except:
        print(str(msg))


class SelfMainWindow(QMainWindow):
    def __init__(self, parent=None):
        super(SelfMainWindow, self).__init__(parent)

    @staticmethod
    def printLog(msg):
        print(msg)
        ui.logText.append(msg)

    @staticmethod
    def login():
        global config
        if config['account_login']:
            ui.logText.append("账号已登录")
            ui.loginBiliBtn.setText("账号已登录")
            # ui.loginBiliBtn.setDisabled(True)
        ui.logText.append("开始登陆账号")
        # self.loginBiliBtn.setText("test")
        # asyncio.run(main())
        ui.loginBiliBtn.setText("登陆中")
        ui.loginBiliBtn.setDisabled(True)

        dialog = loginDialog.LoginDialog(window)
        dialog.account.textChanged.connect(deal_account)
        dialog.password.textChanged.connect(deal_password)
        dialog.show()
        dialog.accepted.connect(login_accept)

    # ui.autoLoginCheck.clicked.connect()

    # asyncio.run(main())

    @staticmethod
    def qrCodeSwitch(boolean):
        if boolean:
            ui.clipCheck.setText("当前状态:启用")
        else:
            ui.clipCheck.setText("当前状态:关闭")
        config['clip_check'] = boolean
        write_conf(config)

    @staticmethod
    def autoCloseSwitch(boolean):
        if boolean:
            ui.autoCloseCheck.setText("当前状态:启用")
        else:
            ui.autoCloseCheck.setText("当前状态:关闭")
        config['auto_close'] = boolean
        write_conf(config)

    @staticmethod
    def autoClipSwitch(boolean):
        if boolean:
            ui.autoClipCheck.setText("当前状态:启用")
        else:
            ui.autoClipCheck.setText("当前状态:关闭")
        config['auto_clip'] = boolean
        write_conf(config)


if __name__ == '__main__':
    init_conf()

    fapp = Flask(__name__)

    @fapp.route("/")
    def index():
        return render_template("index.html")

    @fapp.route("/geetest")
    def geetest():
        return render_template("geetest.html")

    @fapp.route('/ret', methods=["GET", "POST"])
    def ret():
        if not request.json:
            print(request)
            abort(400)
        print('Input = ' + str(request.json))
        global cap
        cap = request.json
        ui.backendLogin = LoginThread()
        ui.backendLogin.update_log.connect(window.printLog)
        ui.backendLogin.start()
        return "1"

    kwargs = {'host': '0.0.0.0', 'port': 12983,
              'threaded': True, 'use_reloader': False, 'debug': False}

#   running flask thread
    flaskThread = Thread(target=fapp.run, daemon=True, kwargs=kwargs).start()

    app = QApplication(sys.argv)
    window = SelfMainWindow()
    ui = mainWindow.Ui_MainWindow()
    ui.setupUi(window)
    try:
        if config['account'] != '':
            ui.logText.append("配置文件已有账号，尝试登录中...")
            ui.backendLogin = LoginThread()
            ui.backendLogin.update_log.connect(window.printLog)
            ui.backendLogin.start()
        if config['clip_check']:
            ui.clipCheck.setText("当前状态:启用")
        else:
            ui.clipCheck.setText("当前状态:关闭")
        ui.clipCheck.setChecked(config['clip_check'])
        if config['auto_close']:
            ui.autoCloseCheck.setText("当前状态:启用")
        else:
            ui.autoCloseCheck.setText("当前状态:关闭")
        ui.autoCloseCheck.setChecked(config['auto_close'])
        if config['auto_clip']:
            ui.autoClipCheck.setText("当前状态:启用")
        else:
            ui.autoClipCheck.setText("当前状态:关闭")
        ui.autoClipCheck.setChecked(config['auto_clip'])
    except KeyError:
        write_conf(config)
        print("配置文件异常，重置并跳过登录")
    ui.backendClipCheck = ParseThread()
    ui.backendClipCheck.update_log.connect(window.printLog)
    ui.backendClipCheck.start()
    window.show()

    sys.exit(app.exec_())


async def sendPost(target, data, noReturn=False):
    session = requests.Session()
    session.trust_env = False
    res = session.post(url=target, data=data)
    if noReturn:
        return
    if res is None:
        printLog(res)
        printLog("请求错误，正在重试...")
        return sendPost(target, data, noReturn)
    return res.json()


async def sendGet(target, default_ret=None):
    session = requests.Session()
    session.trust_env = False
    res = session.get(url=target)
    if res is None:
        if default_ret is None:
            printLog(res)
            printLog("请求错误，正在重试...")
            return sendGet(target)
        else:
            return default_ret
    return res.json()


async def sendGetRaw(target, default_ret=None):
    session = requests.Session()
    session.trust_env = False
    res = session.get(url=target)
    if res is None:
        if default_ret is None:
            printLog(res)
            printLog("请求错误，正在重试...")
            return sendGetRaw(target)
        else:
            return default_ret
    return res.text


def bh3Sign(data):
    # print("data:"+data)
    key = '0ebc517adb1b62c6b408df153331f9aa'
    sign = hmac.new(key.encode(), data.encode(), hashlib.sha256).hexdigest()
    # print("sign:"+sign)
    return sign


async def sendBiliPost(url, data):
    header = {
        "User-Agent": "Mozilla/5.0 BSGameSDK",
        "Content-Type": "application/x-www-form-urlencoded",
        "Host": "line1-sdk-center-login-sh.biligame.net"
    }
    session = requests.Session()
    session.trust_env = False
    try:
        res = session.post(url=url, data=data, headers=header)
    except:

        printLog("请求错误，3s后重试...")
        time.sleep(3)
        return sendBiliPost(url, data)
    if res is None:
        printLog(res)
        printLog("请求错误，正在重试...")
        return sendBiliPost(url, data)
    print(res.json())
    return res.json()


# package cmd --> pyinstaller --clean -Fw main.py --collect-all pyzbar --add-data="templates;templates" ### 请用32位环境打包 ###
