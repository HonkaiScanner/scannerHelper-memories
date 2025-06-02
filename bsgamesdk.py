## using https://github.com/cc004/pcrjjc2/blob/main/bsgamesdk.py

import hashlib
import json
import time
import urllib

import rsacr
from main import sendBiliPost

bililogin = "https://line1-sdk-center-login-sh.biligame.net/"

def setSign(data):
    data["timestamp"] = int(time.time())
    data["client_timestamp"] = int(time.time())
    sign = ""
    data2 = ""
    for key in data:
        if key == "pwd":
            pwd = urllib.parse.quote(data["pwd"])
            data2 += f"{key}={pwd}&"
        data2 += f"{key}={data[key]}&"
    for key in sorted(data):
        sign += f"{data[key]}"
    sign = sign + "dbf8f1b4496f430b8a3c0f436a35b931"
    sign = hashlib.md5(sign.encode()).hexdigest()
    data2 += "sign=" + sign
    return data2

userinfoParam = '{"cur_buvid":"XZA2FA4AC240F665E2F27F603ABF98C615C29","client_timestamp":"1667057013442","sdk_type":"1","isRoot":"0","merchant_id":"590","dp":"1280*720","mac":"08:00:27:53:DD:12","uid":"437470182","support_abis":"x86,armeabi-v7a,armeabi","apk_sign":"4502a02a00395dec05a4134ad593224d","platform_type":"3","old_buvid":"XZA2FA4AC240F665E2F27F603ABF98C615C29","operators":"5","fingerprint":"","model":"MuMu","udid":"XXA31CBAB6CBA63E432E087B58411A213BFB7","net":"5","app_id":"180","brand":"Android","oaid":"","game_id":"180","timestamp":"1667057013275","ver":"6.1.0","c":"1","version_code":"510","server_id":"378","version":"1","domain_switch_count":"0","pf_ver":"12","access_key":"","domain":"line1-sdk-center-login-sh.biligame.net","original_domain":"","imei":"","sdk_log_type":"1","sdk_ver":"3.4.2","android_id":"84567e2dda72d1d4","channel_id":1}'
rsaParam = '{"operators":"5","merchant_id":"590","isRoot":"0","domain_switch_count":"0","sdk_type":"1",' \
           '"sdk_log_type":"1","timestamp":"1613035485639","support_abis":"x86,armeabi-v7a,armeabi","access_key":"",' \
           '"sdk_ver":"3.4.2","oaid":"","dp":"1280*720","original_domain":"","imei":"","version":"1",' \
           '"udid":"KREhESMUIhUjFnJKNko2TDQFYlZkB3cdeQ==","apk_sign":"4502a02a00395dec05a4134ad593224d",' \
           '"platform_type":"3","old_buvid":"XZA2FA4AC240F665E2F27F603ABF98C615C29","android_id":"84567e2dda72d1d4",' \
           '"fingerprint":"","mac":"08:00:27:53:DD:12","server_id":"378",' \
           '"domain":"line1-sdk-center-login-sh.biligame.net","app_id":"180","version_code":"510","net":"4",' \
           '"pf_ver":"12","cur_buvid":"XZA2FA4AC240F665E2F27F603ABF98C615C29","c":"1","brand":"Android",' \
           '"client_timestamp":"1613035486888","channel_id":"1","uid":"","game_id":"180","ver":"6.1.0",' \
           '"model":"MuMu"} '
loginParam = '{"operators":"5","merchant_id":"590","isRoot":"0","domain_switch_count":"0","sdk_type":"1",' \
             '"sdk_log_type":"1","timestamp":"1613035508188","support_abis":"x86,armeabi-v7a,armeabi",' \
             '"access_key":"","sdk_ver":"3.4.2","oaid":"","dp":"1280*720","original_domain":"",' \
             '"imei":"227656364311444","gt_user_id":"fac83ce4326d47e1ac277a4d552bd2af","seccode":"","version":"1",' \
             '"udid":"KREhESMUIhUjFnJKNko2TDQFYlZkB3cdeQ==","apk_sign":"4502a02a00395dec05a4134ad593224d",' \
             '"platform_type":"3","old_buvid":"XZA2FA4AC240F665E2F27F603ABF98C615C29",' \
             '"android_id":"84567e2dda72d1d4","fingerprint":"","validate":"84ec07cff0d9c30acb9fe46b8745e8df",' \
             '"mac":"08:00:27:53:DD:12","server_id":"378","domain":"line1-sdk-center-login-sh.biligame.net",' \
             '"app_id":"180","pwd":"rxwA8J+GcVdqa3qlvXFppusRg4Ss83tH6HqxcciVsTdwxSpsoz2WuAFFGgQKWM1' \
             '+GtFovrLkpeMieEwOmQdzvDiLTtHeQNBOiqHDfJEKtLj7h1nvKZ1Op6vOgs6hxM6fPqFGQC2ncbAR5NNkESpSWeYTO4IT58ZIJcC0DdWQqh4=","version_code":"510","net":"4","pf_ver":"12","cur_buvid":"XZA2FA4AC240F665E2F27F603ABF98C615C29","c":"1","brand":"Android","client_timestamp":"1613035509437","channel_id":"1","uid":"","captcha_type":"1","game_id":"180","challenge":"efc825eaaef2405c954a91ad9faf29a2","user_id":"doo349","ver":"6.1.0","model":"MuMu"} '
captchaParam = '{"operators":"5","merchant_id":"590","isRoot":"0","domain_switch_count":"0","sdk_type":"1",' \
              '"sdk_log_type":"1","timestamp":"1613035486182","support_abis":"x86,armeabi-v7a,armeabi",' \
              '"access_key":"","sdk_ver":"3.4.2","oaid":"","dp":"1280*720","original_domain":"",' \
              '"imei":"227656364311444","version":"1","udid":"KREhESMUIhUjFnJKNko2TDQFYlZkB3cdeQ==",' \
              '"apk_sign":"4502a02a00395dec05a4134ad593224d","platform_type":"3",' \
              '"old_buvid":"XZA2FA4AC240F665E2F27F603ABF98C615C29","android_id":"84567e2dda72d1d4","fingerprint":"",' \
              '"mac":"08:00:27:53:DD:12","server_id":"378","domain":"line1-sdk-center-login-sh.biligame.net",' \
              '"app_id":"180","version_code":"510","net":"4","pf_ver":"12",' \
              '"cur_buvid":"XZA2FA4AC240F665E2F27F603ABF98C615C29","c":"1","brand":"Android",' \
              '"client_timestamp":"1613035487431","channel_id":"1","uid":"","game_id":"180","ver":"6.1.0",' \
              '"model":"MuMu"} '

async def getUserInfo(uid,access_key):
    data = json.loads(userinfoParam)
    data['uid'] = uid
    data['access_key'] = access_key
    data = setSign(data)
    return await sendBiliPost(bililogin+ '/api/client/user.info', data)

async def login1(account, password):
    data = json.loads(rsaParam)
    data = setSign(data)
    rsa = await sendBiliPost(bililogin + "api/client/rsa", data)
    data = json.loads(loginParam)
    public_key = rsa['rsa_key']
    data["access_key"] = ""
    data["gt_user_id"] = ""
    data["uid"] = ""
    data["challenge"] = ""
    data["user_id"] = account
    data["validate"] = ""
    data["pwd"] = rsacr.rsacreate(rsa['hash'] + password, public_key)
    data = setSign(data)
    return await sendBiliPost(bililogin + "api/client/login", data)


async def login2(account, password, challenge, gt_user, validate):
    data = json.loads(rsaParam)
    data = setSign(data)
    rsa = await sendBiliPost(bililogin + "api/client/rsa", data)
    data = json.loads(loginParam)
    public_key = rsa['rsa_key']
    data["access_key"] = ""
    data["gt_user_id"] = gt_user
    data["uid"] = ""
    data["challenge"] = challenge
    data["user_id"] = account
    data["validate"] = validate
    data["seccode"] = validate + "|jordan"
    data["pwd"] = rsacr.rsacreate(rsa['hash'] + password, public_key)
    data = setSign(data)
    return await sendBiliPost(bililogin + "api/client/login", data)


async def captcha():
    data = json.loads(captchaParam)
    data = setSign(data)
    return await sendBiliPost(bililogin + "api/client/start_captcha", data)

def make_captch(gt,challenge,gt_user):
    capurl=f"http://127.0.0.1:12983/?captcha_type=1&challenge={challenge}&gt={gt}&userid={gt_user}&gs=1"
    print(capurl)
    return capurl

async def login(bili_account, bili_pwd,cap=None):
    print(f'logging in with acc={bili_account}')
    print(cap)
    if cap is not None:
        login_sta = await login2(bili_account,bili_pwd,cap['challenge'],cap['userid'],cap['validate'])
    else:
        login_sta = await login1(bili_account, bili_pwd)
    if "access_key" not in login_sta:
        cap_data = await captcha()
        login_sta['cap_url'] = make_captch(cap_data['gt'],cap_data['challenge'],cap_data['gt_user_id'])
        print('登录失败，可能需要验证码，请联系开发者补充代码')
        print(login_sta)
    return login_sta


# async def captchaVerifier(gt, challenge, userid):
#     url = f"https://help.tencentbot.top/geetest/?captcha_type=1&challenge={challenge}&gt={gt}&userid={userid}&gs=1"
#     print(f'账号登录需要验证码，请完成以下链接中的验证内容后将第一行validate=后面的内容复制，并用指令/pcrval xxxx将内容发送给机器人完成验证\n验证链接：{url}')
#     validating = True
#     await captcha_lck.acquire()
#     validating = False
#     return validate
