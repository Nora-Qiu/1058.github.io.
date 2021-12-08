
import requests
import sys, getopt, os, base64, json
import yaml
from termcolor import colored, cprint
import pandas as pd
from sphinx.util import requests
from tqdm import tqdm

pd.set_option('display.max_columns', 50)
pd.set_option('display.max_rows', 300)

HEADERS = {
    "Accept": "application/json, text/javascript, */*; q=0.01",
    "Accept-Language": "zh-CN,zh;q=0.9",
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36",
}


# 发起请求
def url_get(url):
    try:
        r = requests.get(url=url, headers=HEADERS, timeout=1)
        status_code = r.status_code
        response_text = r.content.decode('utf-8')
        return status_code, response_text
    except:
        return 'no','no'
        # cprint('[*]网络连接超时，请稍后重试', 'yellow', 'on_red')
        # sys.exit(2)
print(url_get('https://01alchemist.github.io.'))

# 指纹读取 存储到json_dicts中
def providers_read(bd):
    try:
        with open('providers.json', 'r') as f:
            str_json = f.read()
            json_dicts = json.loads(str_json)
        for json_dict in json_dicts:
            if bd == json_dict['name']:
                return json_dict['response'], json_dict['cname']
            # fingerprint_lists = json_dict['response']  # 存储指纹信息
            # fingercname_lists = json_dict['cname']  # 存储cname信息
    except:
        pass
        # cprint('[*]加载指纹文件失败，请检查是否存在providers.json文件', 'yellow', 'on_red')


# 检查是否存在子域接管漏洞
# def takeover_check(url,cname, fingerprints_lists):
#     global cnameresponse_text, url_response_text
#     check_cname = 'http://' + cname
#     check_url = 'http://' + url
#     if url_get(check_cname)[1] != 'no':
#         cnameresponse_text = url_get(check_cname)[1]  # 解析cname返回文本
#         # 与指纹对比查看cname对比判断是否存在接管风险，与url对比判断是否已被接管
#         for fingerprint in fingerprints_lists:
#             if fingerprint in cnameresponse_text:
#                 # cprint('[+]' + url + '存在子域接管风险', 'green')
#                 # cprint('[*]正在检测当前是否已经被接管...', 'yellow')
#                 if url_get(check_url)[1] != 'no':
#                     url_response_text = url_get(check_url)[1]  # 解析url返回文本
#                     if fingerprint in url_response_text:
#                         cprint('[+]当前未被接管，url：' + url + ',CNMAE：' + cname, 'green')
#                     else:
#                         cprint('[*]当前可能已被接管，url：' + url + ',CNMAE：' + cname, 'yellow', 'on_red')
#             else:
#                 pass
def takeover_check(cname, fingerprints_lists):
    global cnameresponse_text
    check_cname = 'http://' + cname
    # check_url = 'http://' + url
    if url_get(check_cname)[1] != 'no':
        cnameresponse_text = url_get(check_cname)[1]  # 解析cname返回文本
        # url_response_text = url_get(check_url)[1]  # 解析url返回文本
        # 与指纹对比查看cname对比判断是否存在接管风险，与url对比判断是否已被接管
        #print(cnameresponse_text)
        for fingerprint in fingerprints_lists:
            if fingerprint in cnameresponse_text:
                return 1
            else:
                return 0


# def detection(cname, fingercname_lists, fingerprint_lists):
#     for fingercname in fingercname_lists:
#         # 查看cname解析值是否在指纹列表中
#         if fingercname in cname:
#             # cprint('[*]存在于指纹列表中，正在检测子域接管风险...', 'green')
#             return takeover_check(cname, fingerprint_lists)  # 检查是否有风险以及是否已经被接管
#         else:
#             return 0
# cdl = []
# with open('cloud_domain_10.txt', 'r') as f:
#     for line in f:
#         cdl.append(line.strip('\n').lower())
# print(cdl)
cdl = ['github']

for i in tqdm(range(0, 1)):
    df = pd.read_csv('newdata/%s.csv' % cdl[i], encoding='utf-8', chunksize=100000)
    #df = pd.read_csv('newdata/%s.csv'%cdl[i], encoding='utf-8', chunksize=10000)
    print('processing' + ' ' + '%s'%cdl[i] + '--------------------')
    fingerprints, fingercname = providers_read(cdl[i])  # 接收指纹信息
    f = 1
    for chunk in tqdm(df):
        print('processing' + ' ' + '%s' % cdl[i] + 'chunk',f,'--------------------')
        if f==1:
            f = f+1
            continue
        result = []
        grouped = chunk.groupby('value')
        for cname, g in grouped:
            #if 'myshopify' not in cname:
            for fcname in fingercname:
                #print(cname)
                cname = cname.split(cdl[i])[0]+fcname
                #print(cname)
                if takeover_check(cname,fingerprints) == 1:
                    if f==1:
                        g.to_csv('newresult/result_2%s.csv' % cdl[i], encoding='utf_8_sig', header=True, mode='a', index=False)
                        f = f+1
                    else:
                        g.to_csv('newresult/result_2%s.csv'%cdl[i], encoding='utf_8_sig', header=False, mode='a', index=False)
                    continue
    print('done' + ' ' + '%s' % cdl[i] + '--------------------')
            # else:
            #     if takeover_check(cname, fingerprints) == 1:
            #         if f == 1:
            #             g.to_csv('newresult/result_%s.csv' % name, encoding='utf_8_sig', header=True, mode='a', index=False)
            #             f = f + 1
            #         else:
            #             g.to_csv('newresult/result_%s.csv' % name, encoding='utf_8_sig', header=False, mode='a',
            #                      index=False)







    #         if url_get('http://' + cname)[1] != 'no':
    #             for i in fin:
    #                 if i in url_get('http://' + cname)[1]:
    #                     print('bad!!!')
    #                     continue
    # for index, row in chunk.iterrows():
    #     if detection(row['name'], row['value'], fingercname, fingerprints) == 1:
    #         result.append(1)
    #     else:
    #         result.append(0)
    # chunk['result'] = result
    # chunk = chunk[chunk['result'] == 1]
    # if f == 1:
    #     chunk.to_csv('result_%s.csv'%name, encoding='utf_8_sig', header=True, mode='a', index=False)
    # else:
    #     chunk.to_csv('result_%s.csv'%name, encoding='utf_8_sig', header=False, mode='a', index=False)
    # f = f + 1
