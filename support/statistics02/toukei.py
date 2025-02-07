import argparse
import csv
from datetime import datetime as dt
import html
import json
import os

import requests

ORG_APPLICATIONS_LIMIT = 100
ORG_TRACES_LIMIT = 100
ORG_LIBRARIES_LIMIT = 50

CSV_HEADER_SUMMARY = [
    'アプリケーション名',
    '総合スコア',
    'カスタムコードのスコア',
    'ライブラリのスコア',
    'ルート疎通率',
    '今までの検出されて+B32すべての脆弱性数（総数）',
    '新規検出脆弱性数(重大)',
    '新規検出脆弱性数(高)',
    '新規検出脆弱性数(中)',
    '新規検出脆弱性数(低)',
    '新規検出脆弱性数(注意)',
    '残存脆弱性数(重大)',
    '残存脆弱性数(高)',
    '残存脆弱性数(中)',
    '残存脆弱性数(低)',
    '残存脆弱性数(注意)',
    '修正済脆弱性数(重大)',
    '修正済脆弱性数(高)',
    '修正済脆弱性数(中)',
    '修正済脆弱性数(低)',
    '修正済脆弱性数(注意)',
]

CSV_HEADER_VUL = [
    'アプリケーション名',
    '深刻度',
    '脆弱性',
    'ステータス',
    '検出URL',
    'アクティビティ(変更内容)',
    'アクティビティ(変更者)',
]

CSV_HEADER_LIB = [
    'アプリケーション名',
    'スコア',
    'ライブラリ名',
    '脆弱性',
    'ステータス',
    '利用バージョン',
    '最新バージョン',
    'アクティビティ(変更者)',
]


def main():

    parser = argparse.ArgumentParser(
        prog='collector.py',  # プログラム名
        usage='python collector.py',  # プログラムの利用方法
        description='引数なしで実行すると、すべての情報（アプリケーション、脆弱性、ライブラリ）を取得します。',  # 引数のヘルプの前に表示
        epilog='end',  # 引数のヘルプの後で表示
        add_help=True,  # -h/–help オプションの追加
    )
    parser.add_argument('--app', action='store_true', help='アプリケーションの情報のみ取得')
    parser.add_argument('--vul', action='store_true', help='脆弱性の情報のみ取得')
    parser.add_argument('--lib', action='store_true', help='ライブラリの情報のみ取得')
    args = parser.parse_args()

    env_not_found = False
    for env_key in ['CONTRAST_BASEURL', 'CONTRAST_AUTHORIZATION', 'CONTRAST_API_KEY', 'CONTRAST_ORG_ID']:
        if not env_key in os.environ:
            print('Environment variable %s is not set' % env_key)
            env_not_found |= True
    if env_not_found:
        print()
        print('CONTRAST_BASEURL                   : https://app.contrastsecurity.com/Contrast')
        print('CONTRAST_AUTHORIZATION             : XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX==')
        print('CONTRAST_API_KEY                   : XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX')
        print('CONTRAST_ORG_ID                    : XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX')
        print()
        return

    base_dir = os.path.dirname(__file__)
    now = dt.now()
    timestamp_full = now.strftime("%Y%m%d%H%M")
    timestamp_ym = now.strftime("%Y%m%d")
    folder_path = os.path.join(base_dir, timestamp_full)
    folder_path_sum = os.path.join(base_dir, "Sum")
    folder_path_ap = os.path.join(base_dir, "AP")
    folder_path_lib = os.path.join(base_dir, "Lib")
    try:
        os.makedirs(folder_path, exist_ok=True)  # exist_ok=True で既存フォルダの上書きを回避
        os.makedirs(folder_path_sum, exist_ok=True)  # exist_ok=True で既存フォルダの上書きを回避
        os.makedirs(folder_path_ap, exist_ok=True)  # exist_ok=True で既存フォルダの上書きを回避
        os.makedirs(folder_path_lib, exist_ok=True)  # exist_ok=True で既存フォルダの上書きを回避
        print(f"フォルダ '{folder_path}' を作成しました。")
        print(f"フォルダ '{folder_path_sum}' を作成しました。")
        print(f"フォルダ '{folder_path_ap}' を作成しました。")
        print(f"フォルダ '{folder_path_lib}' を作成しました。")
    except Exception as e:
        print(f"フォルダ作成中にエラーが発生しました: {e}")
        return
    
    BASEURL = os.environ['CONTRAST_BASEURL']
    API_KEY = os.environ['CONTRAST_API_KEY']
    AUTHORIZATION = os.environ['CONTRAST_AUTHORIZATION']
    ORG_ID = os.environ['CONTRAST_ORG_ID']
    headers = {"Accept": "application/json", "content-type": "application/json", "API-Key": API_KEY, "Authorization": AUTHORIZATION}
    API_URL = "%s/api/ng" % (BASEURL)

    # =============== 組織全体のアプリケーション一覧を取得 ===============
    all_applications = []
    if args.app:
        print('Applications Loading...')
        url_applications = '%s/%s/applications/filter?offset=%d&limit=%d&expand=scores,kip_links' % (API_URL, ORG_ID, len(all_applications), ORG_APPLICATIONS_LIMIT)
        payload = '{"quickFilter":"ALL","filterTechs":[],"filterLanguages":[],"filterTags":[],"scoreLetterGrades":[],"filterServers":[],"filterCompliance":[],"filterVulnSeverities":[],"environment":[],"appImportances":[],"metadataFilters":[]}'
        r = requests.post(url_applications, headers=headers, data=payload)
        data = r.json()
        totalCnt = data['count']
        print(totalCnt)
        for app in data['applications']:
            print(app['name'])
            all_applications.append(app)
    
        orgApplicationsIncompleteFlg = True
        orgApplicationsIncompleteFlg = totalCnt > len(all_applications)
        while orgApplicationsIncompleteFlg:
            url_applications = '%s/%s/applications/filter?offset=%d&limit=%d&expand=scores,skip_links' % (API_URL, ORG_ID, len(all_applications), ORG_APPLICATIONS_LIMIT)
            r = requests.post(url_applications, headers=headers, data=payload)
            data = r.json()
            for app in data['applications']:
                print(app['name'])
                all_applications.append(app)
                orgApplicationsIncompleteFlg = totalCnt > len(all_applications)
        print('Total(Applications): ', len(all_applications))
    
        # ファイルにJSONとして出力
        json_path = os.path.join(folder_path, "applications.json")
        with open(json_path, "w") as f:
           json.dump(all_applications, f, indent=4)

        csv_lines = []
        for app in all_applications:
            csv_line = []
            csv_line.append(app['name'])
            csv_line.append(app['scores']['letter_grade'])
            csv_lines.append(csv_line)
        
        csv_path = os.path.join(folder_path_sum, 'CA_Summary%s.csv' % (timestamp_ym))
        with open(csv_path, 'w', encoding='shift_jis') as f:
           writer = csv.writer(f, lineterminator='\n')
           writer.writerow(CSV_HEADER_SUMMARY)
           writer.writerows(csv_lines)

    # =============== 組織全体の脆弱性一覧を取得 ===============
    if args.vul:
        print('OrgTraces Loading...')
        all_orgtraces = []
        url_orgtraces = '%s/organizations/%s/orgtraces/ui?expand=application&offset=%d&limit=%d' % (API_URL, ORG_ID, len(all_orgtraces), ORG_TRACES_LIMIT)
        payload = '{"quickFilter":"ALL","modules":[],"servers":[],"filterTags":[],"severities":[],"status":[],"substatus":[],"vulnTypes":[],"environments":[],"urls":[],"sinks":[],"securityStandards":[],"appVersionTags":[],"routes":[],"tracked":false,"untracked":false,"technologies":[],"applicationTags":[],"applicationMetadataFilters":[],"applicationImportances":[],"languages":[],"licensedOnly":false}'
        r = requests.post(url_orgtraces, headers=headers, data=payload)
        data = r.json()
        totalCnt = data['count']
        print(totalCnt)
        for vuln in data['items']:
            print(vuln['vulnerability']['uuid'])
            url_notes = '%s/%s/applications/%s/traces/%s/notes?expand=skip_links' % (API_URL, ORG_ID, vuln['vulnerability']['application']['id'], vuln['vulnerability']['uuid'])
            r = requests.get(url_notes, headers=headers)
            data = r.json()
            if data['success']:
                vuln['vulnerability']['notes'] = data['notes']
            all_orgtraces.append(vuln['vulnerability'])
    
        orgTracesIncompleteFlg = True
        orgTracesIncompleteFlg = totalCnt > len(all_orgtraces)
        while orgTracesIncompleteFlg:
            url_orgtraces = '%s/organizations/%s/orgtraces/ui?expand=application&offset=%d&limit=%d' % (API_URL, ORG_ID, len(all_orgtraces), ORG_TRACES_LIMIT)
            r = requests.post(url_orgtraces, headers=headers, data=payload)
            data = r.json()
            for vuln in data['items']:
                print(vuln['vulnerability']['uuid'])
                url_notes = '%s/%s/applications/%s/traces/%s/notes?expand=skip_links' % (API_URL, ORG_ID, vuln['vulnerability']['application']['id'], vuln['vulnerability']['uuid'])
                r = requests.get(url_notes, headers=headers)
                data = r.json()
                if data['success']:
                    vuln['vulnerability']['notes'] = data['notes']
                all_orgtraces.append(vuln['vulnerability'])
                orgTracesIncompleteFlg = totalCnt > len(all_orgtraces)
        print('Total(OrgTraces): ', len(all_orgtraces))
    
        # ファイルにJSONとして出力
        json_path = os.path.join(folder_path, "orgtraces.json")
        with open(json_path, "w") as f:
           json.dump(all_orgtraces, f, indent=4)

    # =============== 組織全体のライブラリ一覧を取得 ===============
    if args.lib:
        print('Libraries Loading...')
        all_libraries = []
        url_libraries = '%s/%s/libraries/filter?expand=skip_links,apps,status,vulns&offset=%d&limit=%d' % (API_URL, ORG_ID, len(all_libraries), ORG_LIBRARIES_LIMIT)
        payload = '{"q":"","quickFilter":"ALL","apps":[],"servers":[],"environments":[],"grades":[],"languages":[],"licenses":[],"status":[],"severities":[],"tags":[],"includeUnused":false,"includeUsed":false}'
        r = requests.post(url_libraries, headers=headers, data=payload)
        data = r.json()
        print(data['success'])
        print(data['messages'])
        totalCnt = data['count']
        print(totalCnt)
        for lib in data['libraries']:
            print(lib['file_name'])
            all_libraries.append(lib)
    
        orgLibrariesIncompleteFlg = True
        orgLibrariesIncompleteFlg = totalCnt > len(all_libraries)
        while orgLibrariesIncompleteFlg:
            url_libraries = '%s/%s/libraries/filter?expand=skip_links,apps,status,vulns&offset=%d&limit=%d' % (API_URL, ORG_ID, len(all_libraries), ORG_LIBRARIES_LIMIT)
            r = requests.post(url_libraries, headers=headers, data=payload)
            data = r.json()
            for lib in data['libraries']:
                print(lib['file_name'])
                all_libraries.append(lib)
                orgLibrariesIncompleteFlg = totalCnt > len(all_libraries)
        print('Total(Libraries): ', len(all_libraries))
    
        # ファイルにJSONとして出力
        json_path = os.path.join(folder_path, "libraries.json")
        with open(json_path, "w") as f:
           json.dump(all_libraries, f, indent=4)

        for app in all_applications:
            csv_lines = []
            for lib in all_libraries:
                exist_flg = False
                for lib_app in lib['apps']:
                    if lib_app['app_id'] == app['app_id']:
                        exist_flg |= True
                if exist_flg:
                    csv_line = []
                    csv_line.append(app['name'])
                    csv_line.append(lib['grade'])
                    csv_line.append(lib['file_name'])
                    csv_lines.append(csv_line)
                        
            csv_path = os.path.join(folder_path_lib, 'CA_%sLibrary%s.csv' % (app['name'].replace('/', '_'), timestamp_ym))
            with open(csv_path, 'w', encoding='shift_jis') as f:
               writer = csv.writer(f, lineterminator='\n')
               writer.writerow(CSV_HEADER_LIB)
               writer.writerows(csv_lines)


if __name__ == '__main__':
    main()
