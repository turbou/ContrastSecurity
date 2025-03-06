# ContrastのAPIを使った統計のサンプル1

## 前提条件
Python3.10のmatch文を使っているので、Python3.10以上の動作環境が必要となります。

## 環境準備
Python3はWindowsまたはMacにインストール済みの前提です。  
3.13.1で動作確認をしています。
- 仮想環境作成

```cmd
python3 -m venv .sample_venv
```
- アクティベート

Windows  

```cmd
.\.sample_venv\Scripts\activate
```

Mac  

```bash
source ./.sample_venv/bin/activate
```

- 必要なパッケージをインストール

```cmd
pip install -r requirements.txt
```

## 環境変数のセットアップ
以下の環境変数を設定しておいてください。
- CONTRAST_BASEURL
- CONTRAST_AUTHORIZATION
- CONTRAST_API_KEY
- CONTRAST_ORG_ID

*いずれもTeamServerのユーザーメニューから取得可能です。*

## 実行方法
```
usage: python collector.py

引数なしで実行すると、すべての情報（アプリケーション、脆弱性、ライブラリ）を取得します。

options:
  -h, --help            show this help message and exit
  --app                 アプリケーションの情報のみ取得
  --vul                 脆弱性の情報のみ取得
  --lib                 ライブラリの情報のみ取得
  --vul_open            OPENな脆弱性の情報のみ取得
  --lib_vuln            脆弱性を含むライブラリの情報のみ取得
  --no_json             JSONファイルの出力を抑制
  --app_filter APP_FILTER
                        アプリケーション名フィルタ(例: PetClinic(デバッグ用))
```
### 通常の実行方法
- 実行オプションの確認
  ```cmd
  python toukei.py --help
  ```
- 全量を取得する場合（通常の使用方法）
  ```cmd
  python toukei.py
  ```
### 動作確認（デバッグ）を行う際の実行方法の例
- アプリケーション名を指定（equals検索ではなく、contains検索なので複数マッチする場合があります）
  ```cmd
  python toukei.py --app_filter PetClinic_8001
  ```
- Openな脆弱性、CVEを含むライブラリに限定する場合
  ```cmd
  python toukei.py --vul_open --app--lib_vuln
  ```
  - --app_filterと組み合わせることも可能です。

## 実行後の出力結果について
```
statistics02
│  README.md
│  requirements.txt
│  toukei.bat
│  toukei.py
│
├─202502130850
│      applications.json
│      libraries.json
│      orgtraces.json
│
├─AP
│      CA_PetClinic_8001-320250213.csv
│      CA_PetClinic_8001-CentOS20250213.csv
│      CA_PetClinic_8001-ubuntu20250213.csv
│      CA_PetClinic_8001-Yuya-Training20250213.csv
│      CA_PetClinic_800120250213.csv
│      CA_PetClinic_8001_Docker20250213.csv
│      CA_PetClinic_8001_GitlabDemo20250213.csv
│
├─Lib
│      CA_PetClinic_8001-3Library20250213.csv
│      CA_PetClinic_8001-CentOSLibrary20250213.csv
│      CA_PetClinic_8001-ubuntuLibrary20250213.csv
│      CA_PetClinic_8001Library20250213.csv
│      CA_PetClinic_8001_GitlabDemoLibrary20250213.csv
│      CA_PetClinic_8001_JenkinsDemoLibrary20250213.csv
│
└─Sum
        CA_Summary20250213.csv
```
- 202502130850はAPI実行のレスポンス生データです。（複数のAPI実行の結果をマージしてる部分もあります）
- --app_filterにPetClinic_8001を指定したサンプルです。
