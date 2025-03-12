import argparse
from datetime import datetime as dt
import html
import json
import os
import sys

import requests

ORG_APPLICATIONS_LIMIT = 100
ORG_TRACES_LIMIT = 100
ORG_LIBRARIES_LIMIT = 50


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
    parser.add_argument('--licensed', action='store_true', help='ASSESSライセンスが付与されているアプリのみ対象')
    parser.add_argument('--vul_open', action='store_true', help='OPENな脆弱性の情報のみ取得')
    parser.add_argument('--lib_vuln', action='store_true', help='脆弱性を含むライブラリの情報のみ取得')
    parser.add_argument('--app_filter', help='アプリケーション名フィルタ(例: PetClinic(デバッグ用))')
    args = parser.parse_args()

    env_not_found = False
    for env_key in ['CONTRAST_BASEURL', 'CONTRAST_AUTHORIZATION', 'CONTRAST_API_KEY', 'CONTRAST_ORG_ID']:
        if not env_key in os.environ:
            print(f"環境変数'{env_key}'が設定されていません。")
            env_not_found |= True
    if env_not_found:
        print()
        print('CONTRAST_BASEURL       : https://app.contrastsecurity.com/Contrast')
        print('CONTRAST_AUTHORIZATION : XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX==')
        print('CONTRAST_API_KEY       : XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX')
        print('CONTRAST_ORG_ID        : XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX')
        print()
        return

    if not (args.app or args.vul or args.lib):
        args.app = args.vul = args.lib = True

    if args.vul or args.lib:
        args.app = True

    base_dir = os.path.dirname(__file__)
    now = dt.now()
    timestamp_full = now.strftime("%Y%m%d%H%M")
    timestamp_ym = now.strftime("%Y%m%d")
    folder_path = os.path.join(base_dir, timestamp_full)
    folder_path_sum = os.path.join(base_dir, "Sum")
    folder_path_ap = os.path.join(base_dir, "AP")
    folder_path_lib = os.path.join(base_dir, "Lib")
    try:
        os.makedirs(folder_path, exist_ok=True)
        print(f"フォルダ '{folder_path}' を作成しました。")
    except Exception as e:
        print(f"フォルダ作成中にエラーが発生しました: {e}")
        return

    BASEURL = os.environ['CONTRAST_BASEURL']
    API_KEY = os.environ['CONTRAST_API_KEY']
    AUTHORIZATION = os.environ['CONTRAST_AUTHORIZATION']
    ORG_ID = os.environ['CONTRAST_ORG_ID']
    headers = {"Accept": "application/json", "content-type": "application/json", "API-Key": API_KEY, "Authorization": AUTHORIZATION}
    API_URL = "%s/api/ng" % (BASEURL)

    specify_application_ids = []

    # =============== 組織全体のアプリケーション一覧を取得 ===============
    app_name_dict = {}
    all_app_dict = {}
    if args.app:
        print('Applications Loading...')
        url_applications = '%s/%s/applications/filter?offset=%d&limit=%d&expand=scores,coverage,kip_links' % (API_URL, ORG_ID, len(all_app_dict), ORG_APPLICATIONS_LIMIT)
        payload = '{"quickFilter":"%s","filterTechs":[],"filterLanguages":[],"filterTags":[],"scoreLetterGrades":[],"filterServers":[],"filterCompliance":[],"filterVulnSeverities":[],"environment":[],"appImportances":[],"metadataFilters":[]}' % (
            'LICENSED' if args.licensed else 'ALL'
            )
        if args.app_filter:
            payload = '{"quickFilter":"%s","filterTechs":[],"filterLanguages":[],"filterTags":[],"scoreLetterGrades":[],"filterServers":[],"filterCompliance":[],"filterVulnSeverities":[],"environment":[],"appImportances":[],"metadataFilters":[], "filterText":"%s"}' % (
                'LICENSED' if args.licensed else 'ALL',
                args.app_filter
                )
        r = requests.post(url_applications, headers=headers, data=payload)
        data = r.json()
        totalCnt = data['count']
        for app in data['applications']:
            print(app['name'])
            url_libraries_stats = '%s/%s/applications/%s/libraries/stats?expand=skip_links' % (API_URL, ORG_ID, app['app_id'])
            r = requests.get(url_libraries_stats, headers=headers)
            data = r.json()
            if data['success']:
                app['stats'] = data['stats']
            else:
                app['stats'] = {}
            app_name_dict[app['app_id']] = app['name']
            all_app_dict[app['app_id']] = app

        orgApplicationsIncompleteFlg = True
        orgApplicationsIncompleteFlg = totalCnt > len(all_app_dict)
        while orgApplicationsIncompleteFlg:
            url_applications = '%s/%s/applications/filter?offset=%d&limit=%d&expand=scores,coverage,skip_links' % (API_URL, ORG_ID, len(all_app_dict), ORG_APPLICATIONS_LIMIT)
            r = requests.post(url_applications, headers=headers, data=payload)
            data = r.json()
            for app in data['applications']:
                print(app['name'])
                url_libraries_stats = '%s/%s/applications/%s/libraries/stats?expand=skip_links' % (API_URL, ORG_ID, app['app_id'])
                r = requests.get(url_libraries_stats, headers=headers)
                data = r.json()
                if data['success']:
                    app['stats'] = data['stats']
                else:
                    app['stats'] = {}
                app_name_dict[app['app_id']] = app['name']
                all_app_dict[app['app_id']] = app
                orgApplicationsIncompleteFlg = totalCnt > len(all_app_dict)
        print('Total(Applications): ', len(all_app_dict))
        print('')

        # ファイルにJSONとして出力
        json_path = os.path.join(folder_path, "applications.json")
        with open(json_path, "w") as f:
           json.dump(all_app_dict, f, indent=4)

    # =============== 組織全体の脆弱性一覧を取得 ===============
    if args.vul:
        print('OrgTraces Loading...')
        all_orgtraces = []
        orgtraces_dict = {}
        url_orgtraces = '%s/organizations/%s/orgtraces/ui?expand=application&offset=%d&limit=%d' % (API_URL, ORG_ID, len(orgtraces_dict), ORG_TRACES_LIMIT)
        payload = '{"quickFilter":"%s","modules":[],"servers":[],"filterTags":[],"severities":[],"status":[],"substatus":[],"vulnTypes":[],"environments":[],"urls":[],"sinks":[],"securityStandards":[],"appVersionTags":[],"routes":[],"tracked":false,"untracked":false,"technologies":[],"applicationTags":[],"applicationMetadataFilters":[],"applicationImportances":[],"languages":[],"licensedOnly":false}' % (
            'OPEN' if args.vul_open else 'ALL'
            )
        if args.app_filter:
            modules = []
            for app_id, app in all_app_dict.items():
                module_id = f'"{app["app_id"]}"'
                modules.append(module_id)
            payload = '{"quickFilter":"%s","modules":[%s],"servers":[],"filterTags":[],"severities":[],"status":[],"substatus":[],"vulnTypes":[],"environments":[],"urls":[],"sinks":[],"securityStandards":[],"appVersionTags":[],"routes":[],"tracked":false,"untracked":false,"technologies":[],"applicationTags":[],"applicationMetadataFilters":[],"applicationImportances":[],"languages":[],"licensedOnly":false}' % (
                'OPEN' if args.vul_open else 'ALL',
                ','.join(modules)
                )
        r = requests.post(url_orgtraces, headers=headers, data=payload)
        data = r.json()
        totalCnt = data['count']
        for vuln in data['items']:
            print(vuln['vulnerability']['uuid'])
            # Activity
            url_notes = '%s/%s/applications/%s/traces/%s/notes?expand=skip_links' % (API_URL, ORG_ID, vuln['vulnerability']['application']['id'], vuln['vulnerability']['uuid'])
            r = requests.get(url_notes, headers=headers)
            data = r.json()
            if data['success']:
                vuln['vulnerability']['notes'] = data['notes']
            else:
                vuln['vulnerability']['notes'] = []
            # Route
            url_routes = '%s/%s/traces/%s/trace/%s/routes?expand=skip_links' % (API_URL, ORG_ID, vuln['vulnerability']['application']['id'], vuln['vulnerability']['uuid'])
            r = requests.get(url_routes, headers=headers)
            data = r.json()
            if data['success']:
                vuln['vulnerability']['routes'] = data['routes']
            else:
                vuln['vulnerability']['routes'] = []
            all_orgtraces.append(vuln['vulnerability'])
            orgtraces_dict[vuln['vulnerability']['uuid']] = vuln['vulnerability']

        orgTracesIncompleteFlg = True
        orgTracesIncompleteFlg = totalCnt > len(orgtraces_dict)
        while orgTracesIncompleteFlg:
            url_orgtraces = '%s/organizations/%s/orgtraces/ui?expand=application&offset=%d&limit=%d' % (API_URL, ORG_ID, len(orgtraces_dict), ORG_TRACES_LIMIT)
            r = requests.post(url_orgtraces, headers=headers, data=payload)
            data = r.json()
            for vuln in data['items']:
                print(vuln['vulnerability']['uuid'])
                # Activity
                url_notes = '%s/%s/applications/%s/traces/%s/notes?expand=skip_links' % (API_URL, ORG_ID, vuln['vulnerability']['application']['id'], vuln['vulnerability']['uuid'])
                r = requests.get(url_notes, headers=headers)
                data = r.json()
                if data['success']:
                    vuln['vulnerability']['notes'] = data['notes']
                else:
                    vuln['vulnerability']['notes'] = []
                # Route
                url_routes = '%s/%s/traces/%s/trace/%s/routes?expand=skip_links' % (API_URL, ORG_ID, vuln['vulnerability']['application']['id'], vuln['vulnerability']['uuid'])
                r = requests.get(url_routes, headers=headers)
                data = r.json()
                if data['success']:
                    vuln['vulnerability']['routes'] = data['routes']
                else:
                    vuln['vulnerability']['routes'] = []
                all_orgtraces.append(vuln['vulnerability'])
                orgtraces_dict[vuln['vulnerability']['uuid']] = vuln['vulnerability']
                orgTracesIncompleteFlg = totalCnt > len(orgtraces_dict)
        print('Total(OrgTraces): ', len(orgtraces_dict))
        print('')

        # ファイルにJSONとして出力
        json_path = os.path.join(folder_path, "orgtraces.json")
        with open(json_path, "w") as f:
           json.dump(orgtraces_dict, f, indent=4)

    # =============== 組織全体のライブラリ一覧を取得 ===============
    if args.lib:
        print('Libraries Loading...')
        all_libraries_dict = {}
        for app_id, app in all_app_dict.items():
            print(app['name'])
            all_libraries_by_app = []
            module_id = f'"{app["app_id"]}"'
            url_libraries = '%s/%s/libraries/filter?expand=skip_links,apps,status,vulns&offset=%d&limit=%d&sort=score' % (API_URL, ORG_ID, len(all_libraries_by_app), ORG_LIBRARIES_LIMIT)
            payload = '{"q":"","quickFilter":"%s","apps":[%s],"servers":[],"environments":[],"grades":[],"languages":[],"licenses":[],"status":[],"severities":[],"tags":[],"includeUnused":false,"includeUsed":false}' % (
                'VULNERABLE' if args.lib_vuln else 'ALL',
                module_id
                )
            r = requests.post(url_libraries, headers=headers, data=payload)
            data = r.json()
            print(data['success'])
            print(data['messages'])
            totalCnt = data['count']
            print(totalCnt)
            for lib in data['libraries']:
                print(lib['file_name'])
                all_libraries_by_app.append(lib)

            orgLibrariesIncompleteFlg = True
            orgLibrariesIncompleteFlg = totalCnt > len(all_libraries_by_app)
            while orgLibrariesIncompleteFlg:
                url_libraries = '%s/%s/libraries/filter?expand=skip_links,apps,status,vulns&offset=%d&limit=%d&sort=score' % (API_URL, ORG_ID, len(all_libraries_by_app), ORG_LIBRARIES_LIMIT)
                r = requests.post(url_libraries, headers=headers, data=payload)
                data = r.json()
                for lib in data['libraries']:
                    print(lib['file_name'])
                    all_libraries_by_app.append(lib)
                    orgLibrariesIncompleteFlg = totalCnt > len(all_libraries_by_app)

            all_libraries_dict[app['app_id']] = all_libraries_by_app
        print('Total(Libraries):')
        for key, value in all_libraries_dict.items():
            print(' - %s: %d' % (app_name_dict[key], len(value)))
        print('')

        # ファイルにJSONとして出力
        json_path = os.path.join(folder_path, "libraries.json")
        with open(json_path, "w") as f:
           json.dump(all_libraries_dict, f, indent=4)


if __name__ == '__main__':
    main()
