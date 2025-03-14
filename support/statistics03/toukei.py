import argparse
import csv
from datetime import timedelta, datetime as dt
import html
import json
import os
import sys
import re
from dateutil.relativedelta import relativedelta

from pathlib import Path

import yaml

OUTPUT_CONFIG = {
    "sum": [
        {"field": "app_name", "column": "アプリケーション名", "output": True},
        {"field": "letter_grade", "column": "総合スコア", "output": True},
        {"field": "security_grade", "column": "カスタムコードのスコア", "output": True},
        {"field": "platform_grade", "column": "ライブラリのスコア", "output": True},
        {"field": "route_coverage", "column": "ルート疎通率", "output": True},
        {"field": "route_exercised", "column": "疎通済みルート数", "output": True},
        {"field": "route_discovered", "column": "全ルート数", "output": True},
        {"field": "vuln_library_count", "column": "脆弱ライブラリ数", "output": False},
        {"field": "library_count", "column": "ライブラリ総数", "output": False},
        {"field": "created", "column": "オンボード日時", "output": False},
        {"field": "archived", "column": "アーカイブ", "output": False},
        {"field": "removed", "column": "削除フラグ", "output": False},
        {"field": "vul_total", "column": "今までの検出されたすべての脆弱性数（総数）", "output": True},
        {"field": "new_critical", "column": "新規検出脆弱性数(重大)", "output": True},
        {"field": "new_high", "column": "新規検出脆弱性数(高)", "output": True},
        {"field": "new_medium", "column": "新規検出脆弱性数(中)", "output": True},
        {"field": "new_low", "column": "新規検出脆弱性数(低)", "output": True},
        {"field": "new_note", "column": "新規検出脆弱性数(注意)", "output": True},
        {"field": "remain_critical", "column": "残存脆弱性数(重大)", "output": True},
        {"field": "remain_high", "column": "残存脆弱性数(高)", "output": True},
        {"field": "remain_medium", "column": "残存脆弱性数(中)", "output": True},
        {"field": "remain_low", "column": "残存脆弱性数(低)", "output": True},
        {"field": "remain_note", "column": "残存脆弱性数(注意)", "output": True},
        {"field": "fixed_critical", "column": "修正済脆弱性数(重大)", "output": True},
        {"field": "fixed_high", "column": "修正済脆弱性数(高)", "output": True},
        {"field": "fixed_medium", "column": "修正済脆弱性数(中)", "output": True},
        {"field": "fixed_low", "column": "修正済脆弱性数(低)", "output": True},
        {"field": "fixed_note", "column": "修正済脆弱性数(注意)", "output": True},
        {"field": "removed_critical", "column": "削除済脆弱性数(重大)", "output": True},
        {"field": "removed_high", "column": "削除済脆弱性数(高)", "output": True},
        {"field": "removed_medium", "column": "削除済脆弱性数(中)", "output": True},
        {"field": "removed_low", "column": "削除済脆弱性数(低)", "output": True},
        {"field": "removed_note", "column": "削除済脆弱性数(注意)", "output": True},
    ],
    "vul": [
        {"field": "app_name", "column": "アプリケーション名", "output": True},
        {"field": "severity", "column": "深刻度", "output": True},
        {"field": "rule_name", "column": "脆弱性", "output": True},
        {"field": "status", "column": "ステータス", "output": True},
        {"field": "routes", "column": "検出URL", "output": True, "separator": ", "},
        {"field": "activities_desc", "column": "アクティビティ(変更内容)", "output": True, "separator": ", "},
        {"field": "activities_user", "column": "アクティビティ(変更者)", "output": True, "separator": ", "},
        {"field": "first_detected", "column": "最初の検出日時", "output": False},
        {"field": "last_detected", "column": "最後の検出日時", "output": False},
    ],
    "lib": [
        {"field": "app_name", "column": "アプリケーション名", "output": True},
        {"field": "grade", "column": "スコア", "output": True},
        {"field": "library_name", "column": "ライブラリ名", "output": True},
        {"field": "vulns", "column": "脆弱性", "output": True, "separator": ", "},
        {"field": "status", "column": "ステータス", "output": True},
        {"field": "current_version", "column": "利用バージョン", "output": True},
        {"field": "latest_version", "column": "最新バージョン", "output": True},
        {"field": "use_class_count", "column": "使用クラス数", "output": False},
        {"field": "all_class_count", "column": "全体クラス数", "output": False},
        {"field": "license", "column": "ライセンス", "output": False, "separator": ", "},
    ],
}


def main():

    parser = argparse.ArgumentParser(
        prog='collector.py',  # プログラム名
        usage='python collector.py',  # プログラムの利用方法
        description='--last_month, --this_month, --date_rangeのいずれかの指定が必須です。',  # 引数のヘルプの前に表示
        epilog='end',  # 引数のヘルプの後で表示
        add_help=True,  # -h/–help オプションの追加
    )
    parser.add_argument('--dir', default='./', help='解析対象のディレクトリ')
    parser.add_argument('--last_month', action='store_true', help='先月分の解析')
    parser.add_argument('--this_month', action='store_true', help='今月分の解析')
    parser.add_argument('--date_range', help='解析期間（YYYYMMDD-YYYYMMDD）')
    parser.add_argument('--output_template', action='store_true', help='出力設定のテンプレートファイル生成')
    args = parser.parse_args()

    if args.output_template:
        with open("output.yaml.template", "w", encoding="utf-8") as f:
            yaml.dump(OUTPUT_CONFIG, f, allow_unicode=True, indent=2)
        return

    now = dt.now()
    new_threshold_datetime = None
    patterns = []
    if args.last_month:
        previous_month = now + relativedelta(months=-1, day=1)
        new_threshold_datetime = dt(previous_month.year, previous_month.month, previous_month.day, 0, 0, 0)
        yyyymmdd_str = new_threshold_datetime.strftime('%Y%m')
        patterns = [r"^%s\d{6}$" % yyyymmdd_str]
    if args.this_month:
        previous_month = now + relativedelta(day=1)
        new_threshold_datetime = dt(previous_month.year, previous_month.month, previous_month.day, 0, 0, 0)
        yyyymmdd_str = new_threshold_datetime.strftime('%Y%m')
        patterns = [r"^%s\d{6}$" % yyyymmdd_str]
    if args.date_range:
        from_date_obj = dt.strptime(args.date_range.split('-')[0], "%Y%m%d")
        new_threshold_datetime = dt(from_date_obj.year, from_date_obj.month, from_date_obj.day, 0, 0, 0)
        to_date_obj = dt.strptime(args.date_range.split('-')[1], "%Y%m%d")
        days = (to_date_obj - from_date_obj).days + 1  # 期間の日数
        date_list = [from_date_obj + timedelta(days=i) for i in range(days)]
        date_strings = [date.strftime("%Y%m%d") for date in date_list]
        for date_string in date_strings:
            patterns.append(r"^%s\d{4}$" % date_string)
    if len(patterns) == 0:
        patterns.append(r"^\d{12}$")

    if new_threshold_datetime is None:
        print()
        print(f"--last_month, --this_month, --date_rangeのいずれかの引数が設定されていません。")
        print()
        return
    print(f'New Threshold Date: {new_threshold_datetime}')

    # toukei_base_dir = os.path.dirname(__file__)
    toukei_path = Path(args.dir)
    if not toukei_path.is_dir():
        print(f"エラー: 指定されたパス '{toukei_path}' はフォルダではない、または存在しません。")
        return

    output_settings = None
    this_script_dir = os.path.dirname(os.path.abspath(__file__))
    output_yaml_path = os.path.join(this_script_dir, 'output.yaml')
    if os.path.exists(output_yaml_path):
        with open(output_yaml_path, 'r', encoding="utf-8") as file:
            output_settings = yaml.safe_load(file)
    else:
        output_settings = OUTPUT_CONFIG

    applications_dict = {}
    # removed_apps = []
    application_histories = []
    archived_application_dict = {}
    for child in sorted(toukei_path.iterdir()):
        if child.is_dir():
            match_flg = False
            for pattern in patterns:
                match = re.match(pattern, child.name)
                if bool(match):
                    match_flg |= True
            if match_flg:
                print(child.name)
                applications_json = os.path.join(child, "applications.json")
                try:
                    # Applications
                    with open(applications_json, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        this_applications = []
                        for app_id, app in data.items():
                            this_applications.append(app_id)
                            applications_dict[app_id] = app
                            archived_application_dict[app_id] = app['archived']
                        application_histories.append(this_applications)

                except FileNotFoundError:
                    print(f"エラー: ファイル '{file_path}' が見つかりません。")
                except json.JSONDecodeError:
                    print(f"エラー: ファイル '{file_path}' は有効なJSONではありません。")

    # アプリケーションが削除されたかどうか
    application_set = set()
    for apps in application_histories[:-1]:
        for app_id in apps:
            application_set.add(app_id)
    removed_apps = list(application_set - set(application_histories[-1]))

    orgtraces_dict = {}
    libraries_dict = {}
    for child in sorted(toukei_path.iterdir()):
        if child.is_dir():
            match_flg = False
            for pattern in patterns:
                match = re.match(pattern, child.name)
                if bool(match):
                    match_flg |= True
            if match_flg:
                # print(child.name)
                orgtraces_json = os.path.join(child, "orgtraces.json")
                libraries_json = os.path.join(child, "libraries.json")
                try:
                    # Applications
                    with open(applications_json, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        # 削除されたかチェック
                        for org_app_id, org_app in applications_dict.items():
                            exist_app_flg = False
                            for app_id, app in data.items():
                                if org_app_id == app_id:
                                    exist_app_flg |= True
                            if not exist_app_flg:
                                # org_app['removed'] = True
                                removed_apps.append(org_app_id)
                            # else:
                            #     org_app['removed'] = False

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
                            if not exist_trace_flg and not org_trace['application']['id'] in removed_apps:  # アプリが削除してしまった場合を考慮
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

    csv_sum_headers = []
    for sum_output in output_settings['sum']:
        if not sum_output['output']:
            continue
        csv_sum_headers.append(sum_output['column'])

    csv_vul_headers = []
    for vul_output in output_settings['vul']:
        if not vul_output['output']:
            continue
        csv_vul_headers.append(vul_output['column'])

    csv_lines_sum = []
    for app_id, app in applications_dict.items():
        count_map = {key: [] for key in [
            'new_critical', 'new_high', 'new_medium', 'new_low', 'new_note',
            'remain_critical', 'remain_high', 'remain_medium', 'remain_low', 'remain_note',
            'fixed_critical', 'fixed_high', 'fixed_medium', 'fixed_low', 'fixed_note',
            'removed_critical', 'removed_high', 'removed_medium', 'removed_low', 'removed_note',
        ]}
        csv_lines_vul = []
        for trace_uuid, trace in orgtraces_dict.items():
            if trace['application']['id'] == app['app_id']:
                csv_line = []
                for vul_output in output_settings['vul']:
                    if not vul_output['output']:
                        continue
                    match vul_output['field']:
                        case 'app_name':
                            csv_line.append(app['name'])
                        case 'severity':
                            csv_line.append(trace['severity'])
                        case 'rule_name':
                            csv_line.append(trace['ruleName'])
                        case 'status':
                            csv_line.append(trace['status'])
                        case 'routes':
                            route_urls = ['%s(%s)' % (observation['url'], observation['verb']) for route in trace['routes'] for observation in route['observations']]
                            csv_line.append(', '.join(route_urls))
                        case 'activities_desc':
                            note_buffer = []
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
                            csv_line.append(', '.join(note_buffer))
                        case 'activities_user':
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
                                note_creators.append(note['creator'] if note['creator'] else '')
                            csv_line.append(', '.join(note_creators))
                        case 'first_detected':
                            first_detected = dt.fromtimestamp(trace['firstDetected'] / 1000)
                            csv_line.append(first_detected)
                        case 'last_detected':
                            last_detected = dt.fromtimestamp(trace['lastDetected'] / 1000)
                            csv_line.append(last_detected)
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
                csv_path = os.path.join(folder_path_ap, 'CA_%s_%s.csv' % (app['name'].replace('/', '_'), timestamp_ym))
                with open(csv_path, 'w', encoding='shift_jis') as f:
                   writer = csv.writer(f, lineterminator='\n')
                   writer.writerow(csv_vul_headers)
                   writer.writerows(csv_lines_vul)
            except PermissionError:
                print('%sを書き込みモードで開くことができません。' % csv_path)
                sys.exit(1)

        list_of_values = list(count_map.values())
        lengths_of_lists = [len(value) for value in list_of_values]
        total_length = sum(lengths_of_lists)
        csv_line_sum = []
        for sum_output in output_settings['sum']:
            if not sum_output['output']:
                continue
            match sum_output['field']:
                case 'app_name':
                    csv_line_sum.append(app['name'])
                case 'letter_grade':
                    csv_line_sum.append(app['scores']['letter_grade'])
                case 'security_grade':
                    csv_line_sum.append(app['scores']['security']['grade'])
                case 'platform_grade':
                    csv_line_sum.append(app['scores']['platform']['grade'])
                case 'route_coverage':
                    try:
                        coverage = (app['routes']['exercised'] / app['routes']['discovered']) * 100
                    except ZeroDivisionError:
                        coverage = 0
                    csv_line_sum.append('%d%%' % coverage)
                case 'route_exercised':
                    csv_line_sum.append(app['routes']['exercised'])
                case 'route_discovered':
                    csv_line_sum.append(app['routes']['discovered'])
                case 'vuln_library_count':
                    csv_line_sum.append(app['stats']['vulnerables'])
                case 'library_count':
                    csv_line_sum.append(app['stats']['total'])
                case 'created':
                    created = dt.fromtimestamp(app['created'] / 1000)
                    csv_line_sum.append(created)
                case 'archived':
                    archived = archived_application_dict.get(app['app_id'], False)
                    csv_line_sum.append(archived)
                case 'removed':
                    csv_line_sum.append(app['app_id'] in removed_apps)
                case 'vul_total':
                    csv_line_sum.append(total_length)
                case _:
                    csv_line_sum.append(len(count_map[sum_output['field']]))
        csv_lines_sum.append(csv_line_sum)

    try:
        csv_path_sum = os.path.join(folder_path_sum, 'CA_Summary_%s.csv' % (timestamp_ym))
        with open(csv_path_sum, 'w', encoding='shift_jis') as f:
           writer = csv.writer(f, lineterminator='\n')
           writer.writerow(csv_sum_headers)
           writer.writerows(csv_lines_sum)
    except PermissionError:
        print('%sを書き込みモードで開くことができません。' % csv_path_sum)
        sys.exit(1)

    csv_lib_headers = []
    for lib_output in output_settings['lib']:
        if not lib_output['output']:
            continue
        csv_lib_headers.append(lib_output['column'])
                                
    for app_id, app in applications_dict.items():
        csv_lines_lib = []
        for app_id, libraries in libraries_dict.items():
            if app_id == app['app_id']:
                for lib in libraries:
                    csv_line = []
                    for lib_output in output_settings['lib']:
                        if not lib_output['output']:
                            continue
                        match lib_output['field']:
                            case 'app_name':
                                csv_line.append(app['name'])
                            case 'grade':
                                csv_line.append(lib['grade'])
                            case 'library_name':
                                csv_line.append(lib['file_name'])
                            case 'vulns':
                                cves = [vuln["name"] for vuln in lib["vulns"]]
                                separator = lib_output['separator']
                                csv_line.append(separator.join(cves))
                            case 'status':
                                csv_line.append(lib['apps'][0]['app_library_status'])
                            case 'current_version':
                                csv_line.append(lib['file_version'])
                            case 'latest_version':
                                csv_line.append(lib['latest_version'])
                            case 'use_class_count':
                                csv_line.append(lib['classes_used'])
                            case 'all_class_count':
                                csv_line.append(lib['class_count'])
                            case 'license':
                                licenses = [license for license in lib["licenses"]]
                                separator = lib_output['separator']
                                csv_line.append(separator.join(licenses))
                    csv_lines_lib.append(csv_line)

        if len(csv_lines_lib) > 0:
            try:
                csv_path = os.path.join(folder_path_lib, 'CA_%s_Library_%s.csv' % (app['name'].replace('/', '_'), timestamp_ym))
                with open(csv_path, 'w', encoding='shift_jis') as f:
                   writer = csv.writer(f, lineterminator='\n')
                   writer.writerow(csv_lib_headers)
                   writer.writerows(csv_lines_lib)
            except PermissionError:
                print('%sを書き込みモードで開くことができません。' % csv_path)
                sys.exit(1)


if __name__ == '__main__':
    main()

