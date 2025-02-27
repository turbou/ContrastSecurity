import argparse
import csv
from datetime import datetime as dt
import html
import json
import os
import sys
import re
from dateutil.relativedelta import relativedelta

from pathlib import Path

import requests
import yaml

ORG_APPLICATIONS_LIMIT = 100
ORG_TRACES_LIMIT = 100
ORG_LIBRARIES_LIMIT = 50

CSV_HEADER_SUMMARY = [
    'アプリケーション名',
    '総合スコア',
    'カスタムコードのスコア',
    'ライブラリのスコア',
    'ルート疎通率',
    '今までの検出されたすべての脆弱性数（総数）',
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
    '削除済脆弱性数(重大)',
    '削除済脆弱性数(高)',
    '削除済脆弱性数(中)',
    '削除済脆弱性数(低)',
    '削除済脆弱性数(注意)',
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
]

OUTPUT_CONFIG = {
    "sam": [
        {"field": "app_name", "column": "アプリケーション名", "output": True},
        {"field": "letter_grade", "column": "総合スコア", "output": True},
        {"field": "security_grade", "column": "カスタムコードのスコア", "output": True},
        {"field": "platform_grade", "column": "ライブラリのスコア", "output": True},
    ],
    "vul": [
        {"field": "app_name", "column": "アプリケーション名", "output": True},
        {"field": "severity", "column": "深刻度", "output": True},
        {"field": "rule_name", "column": "脆弱性", "output": True},
    ],
    "lib": [
        {"field": "app_name", "column": "アプリケーション名", "output": True},
        {"field": "grade", "column": "スコア", "output": True},
        {"field": "library_name", "column": "ライブラリ名", "output": True},
    ],
}


def main():

    parser = argparse.ArgumentParser(
        prog='collector.py',  # プログラム名
        usage='python collector.py',  # プログラムの利用方法
        description='引数なしで実行すると、すべての情報（アプリケーション、脆弱性、ライブラリ）を取得します。',  # 引数のヘルプの前に表示
        epilog='end',  # 引数のヘルプの後で表示
        add_help=True,  # -h/–help オプションの追加
    )
    parser.add_argument('--dir', default='./', help='解析対象のディレクトリ')
    parser.add_argument('--app_filter', help='アプリケーション名フィルタ(例: PetClinic(デバッグ用))')
    parser.add_argument('--last_month', action='store_true', help='先月分の解析')
    parser.add_argument('--this_month', action='store_true', help='今月分の解析')
    parser.add_argument('--date_from', help='解析開始日（YYYYMMDD）')
    parser.add_argument('--date_to', help='解析終了日（YYYYMMDD）')
    parser.add_argument('--output_template', action='store_true', help='出力設定のテンプレートファイル生成')
    args = parser.parse_args()

    if args.output_template:
        with open("output.yaml.template", "w", encoding="utf-8") as f:
            yaml.dump(OUTPUT_CONFIG, f, allow_unicode=True, indent=2)
        return

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

    now = dt.now()
    new_threshold_datetime = None
    if args.last_month:
        previous_month = now + relativedelta(months=-1, day=1)
        new_threshold_datetime = dt(previous_month.year, previous_month.month, previous_month.day, 0, 0, 0)
    if args.this_month:
        previous_month = now + relativedelta(day=1)
        new_threshold_datetime = dt(previous_month.year, previous_month.month, previous_month.day, 0, 0, 0)
    print(f'New Threshold Date: {new_threshold_datetime}')

    # toukei_base_dir = os.path.dirname(__file__)
    toukei_path = Path(args.dir)
    if not toukei_path.is_dir():
        print(f"エラー: 指定されたパス '{toukei_path}' はフォルダではない、または存在しません。")
        return

    applications_dict = {}
    orgtraces_dict = {}
    libraries_dict = {}

    pattern = r"^\d{12}$"
    for child in toukei_path.iterdir():
        if child.is_dir():
            match = re.match(pattern, child.name)
            if bool(match):
                print(child.name)
                applications_json = os.path.join(child, "applications.json")
                orgtraces_json = os.path.join(child, "orgtraces.json")
                libraries_json = os.path.join(child, "libraries.json")
                try:
                    # Applications
                    with open(applications_json, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        for app_id, app in data.items():
                            applications_dict[app_id] = app

                    # OrgTraces
                    removed_traces = []
                    with open(orgtraces_json, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        # 削除されたかチェック
                        for org_trace_uuid, org_trace in orgtraces_dict.items():
                            exist_trace_flg = False
                            for trace_uuid, trace in data.items():
                                if org_trace_uuid == trace_uuid:
                                    exist_trace_flg |= True
                            if not exist_trace_flg:
                                org_trace['status'] = 'Removed'
                                removed_traces.append(org_trace_uuid)
                        
                        for trace_uuid, trace in data.items():
                            if trace_uuid in orgtraces_dict:
                                cur_trace = orgtraces_dict[trace_uuid]
                                if len(trace['notes']) > 0:
                                    add_notes = []
                                    for note in trace['notes']:
                                        known_note = False
                                        for cur_note in cur_trace['notes']:
                                            if note['id'] == cur_note['id']:
                                                known_note |= True
                                        if not known_note:
                                            add_notes.append(note)
                                    cur_trace['notes'].extend(add_notes)
                            else:
                                orgtraces_dict[trace_uuid] = trace

                    # Libraries
                    with open(libraries_json, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        for app_id, library in data.items():
                            if app_id in libraries_dict:
                                cur_library = libraries_dict[app_id]
                            else:
                                libraries_dict[app_id] = library

                except FileNotFoundError:
                    print(f"エラー: ファイル '{file_path}' が見つかりません。")
                except json.JSONDecodeError:
                    print(f"エラー: ファイル '{file_path}' は有効なJSONではありません。")
    # print(applications_dict)
    # print(orgtraces_dict)
    json_path = os.path.join(".", "check.json")
    with open(json_path, "w") as f:
       json.dump(orgtraces_dict, f, indent=4)
    # print(libraries_dict)

    base_dir = os.path.dirname(__file__)
    now = dt.now()
    timestamp_full = now.strftime("%Y%m%d%H%M")
    timestamp_ym = now.strftime("%Y%m%d")
    folder_path_sum = os.path.join(base_dir, "Sum")
    folder_path_ap = os.path.join(base_dir, "AP")
    folder_path_lib = os.path.join(base_dir, "Lib")
    try:
        os.makedirs(folder_path_sum, exist_ok=True)
        os.makedirs(folder_path_ap, exist_ok=True)
        os.makedirs(folder_path_lib, exist_ok=True)
        print(f"フォルダ '{folder_path_sum}' を作成しました。")
        print(f"フォルダ '{folder_path_ap}' を作成しました。")
        print(f"フォルダ '{folder_path_lib}' を作成しました。")
    except Exception as e:
        print(f"フォルダ作成中にエラーが発生しました: {e}")
        return

    csv_lines_sum = []
    for app_id, app in applications_dict.items():
        csv_line_sum = []
        csv_line_sum.append(app['name'])
        csv_line_sum.append(app['scores']['letter_grade'])
        csv_line_sum.append(app['scores']['security']['grade'])
        csv_line_sum.append(app['scores']['platform']['grade'])
        try:
            coverage = (app['routes']['exercised'] / app['routes']['discovered']) * 100
        except ZeroDivisionError:
            coverage = 0
        csv_line_sum.append('%d%%' % coverage)

        count_map = {key: [] for key in [
            'new_critical', 'new_high', 'new_medium', 'new_low', 'new_note',
            'remain_critical', 'remain_high', 'remain_medium', 'remain_low', 'remain_note',
            'fixed_critical', 'fixed_high', 'fixed_medium', 'fixed_low', 'fixed_note'
            'removed_critical', 'removed_high', 'removed_medium', 'removed_low', 'removed_note'
        ]}
        csv_lines_vul = []
        for trace_uuid, trace in orgtraces_dict.items():
            if trace['application']['id'] == app['app_id']:
                csv_line = []
                csv_line.append(app['name'])
                csv_line.append(trace['severity'])
                csv_line.append(trace['ruleName'])
                csv_line.append(trace['status'])
                route_urls = ['%s(%s)' % (observation['url'], observation['verb']) for route in trace['routes'] for observation in route['observations']]
                csv_line.append(', '.join(route_urls))
                note_buffer = []
                note_creators = []
                for note in trace["notes"]:
                    status_before = None
                    status_after = None
                    if 'properties' in note:
                        for prop in note['properties']:
                            if prop['name'] == 'status.change.previous.status':
                                status_before = prop['value']
                            if prop['name'] == 'status.change.status':
                                status_after = prop['value']
                    status_chg_str = ''
                    if status_before and status_after:
                        status_chg_str = '(%s -> %s)' % (status_before, status_after)
                    note_buffer.append('%s%s' % (html.unescape(note['note']), status_chg_str))
                    note_creators.append(note['creator'] if note['creator'] else '')
                csv_line.append(', '.join(note_buffer))
                csv_line.append(', '.join(note_creators))
                csv_lines_vul.append(csv_line)
                # Count
                first_detected = dt.fromtimestamp(trace['firstDetected'] / 1000)
                if trace['status'] == 'Fixed':
                    count_map[f"fixed_{trace['severity'].lower()}"].append(trace['uuid'])
                elif trace['status'] == 'Removed':
                    count_map[f"removed_{trace['severity'].lower()}"].append(trace['uuid'])
                else:
                    if first_detected >= new_threshold_datetime:
                        count_map[f"new_{trace['severity'].lower()}"].append(trace['uuid'])
                    else:
                        count_map[f"remain_{trace['severity'].lower()}"].append(trace['uuid'])
        if len(csv_lines_vul) > 0:
            try:
                csv_path = os.path.join(folder_path_ap, 'CA_%s%s.csv' % (app['name'].replace('/', '_'), timestamp_ym))
                with open(csv_path, 'w', encoding='shift_jis') as f:
                   writer = csv.writer(f, lineterminator='\n')
                   writer.writerow(CSV_HEADER_VUL)
                   writer.writerows(csv_lines_vul)
            except PermissionError:
                print('%sを書き込みモードで開くことができません。' % csv_path)
                sys.exit(1)

        list_of_values = list(count_map.values())
        lengths_of_lists = [len(value) for value in list_of_values]
        total_length = sum(lengths_of_lists)
        csv_line_sum.append(total_length)
        for key in count_map:
            csv_line_sum.append(len(count_map[key]))
        csv_lines_sum.append(csv_line_sum)

    try:
        csv_path_sum = os.path.join(folder_path_sum, 'CA_Summary%s.csv' % (timestamp_ym))
        with open(csv_path_sum, 'w', encoding='shift_jis') as f:
           writer = csv.writer(f, lineterminator='\n')
           writer.writerow(CSV_HEADER_SUMMARY)
           writer.writerows(csv_lines_sum)
    except PermissionError:
        print('%sを書き込みモードで開くことができません。' % csv_path_sum)
        sys.exit(1)

    for app_id, app in applications_dict.items():
        csv_lines_lib = []
        for app_id, libraries in libraries_dict.items():
            if app_id == app['app_id']:
                for lib in libraries:
                    csv_line = []
                    csv_line.append(app['name'])
                    csv_line.append(lib['grade'])
                    csv_line.append(lib['file_name'])
                    cves = [vuln["name"] for vuln in lib["vulns"]]
                    csv_line.append(', '.join(cves))
                    csv_line.append(lib['apps'][0]['app_library_status'])
                    csv_line.append(lib['file_version'])
                    csv_line.append(lib['latest_version'])
                    csv_lines_lib.append(csv_line)

        if len(csv_lines_lib) > 0:
            try:
                csv_path = os.path.join(folder_path_lib, 'CA_%sLibrary%s.csv' % (app['name'].replace('/', '_'), timestamp_ym))
                with open(csv_path, 'w', encoding='shift_jis') as f:
                   writer = csv.writer(f, lineterminator='\n')
                   writer.writerow(CSV_HEADER_LIB)
                   writer.writerows(csv_lines_lib)
            except PermissionError:
                print('%sを書き込みモードで開くことができません。' % csv_path)
                sys.exit(1)


if __name__ == '__main__':
    main()
