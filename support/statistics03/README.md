# ContrastのAPIを使った統計のサンプル1

## 前提条件
Python3.10のmatch文を使っているので、Python3.10以上の動作環境が必要となります。

## 環境準備
Python3はWindowsまたはMacOSにインストール済みの前提です。  
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

**認証プロキシなどを経由させる場合は下の環境変数も設定してください。**
- CONTRAST_PROXY  
  例）http://username:password@192.168.100.20:3128

## 動作について
- 定期的にデータを取得・蓄積  
  collector.pyを実行します。  
  実行タイミングは毎日決まった時間などに実施でも１週間に１回でも構いません。  
- 蓄積データから集計  
  toukei.pyを実行します。  
  前月の一ヶ月分の集計を行う場合は月初めなどに実行します。（任意の期間を指定して集計も可能です）

## 実行方法
### データ取得
#### 実行オプションの確認
```cmd
python collector.py --help
```

```
usage: python collector.py

引数なしで実行すると、すべての情報（アプリケーション、脆弱性、ライブラリ）を取得します。

options:
  -h, --help            show this help message and exit
  --app                 アプリケーションの情報のみ取得
  --vul                 脆弱性の情報のみ取得
  --lib                 ライブラリの情報のみ取得
  --licensed            ASSESSライセンスが付与されているアプリのみ対象
  --vul_open            OPENな脆弱性の情報のみ取得
  --lib_vuln            脆弱性を含むライブラリの情報のみ取得
  --app_filter APP_FILTER
                        アプリケーション名フィルタ(例: PetClinic(デバッグ用))
  --ssl_verify_skip     SSL検証回避を有効にします。
```
#### 通常の実行方法
- 全量を取得する場合（通常の使用方法）  

```cmd
python collector.py
```
#### 動作確認（デバッグ）を行う際の実行方法の例
- アプリケーション名を指定（equals検索ではなく、contains検索なので複数マッチする場合があります）  

```cmd
python collector.py --app_filter PetClinic_8001
```
- Openな脆弱性、CVEを含むライブラリに限定する場合  

```cmd
python collector.py --vul_open --app--lib_vuln
```
- --app_filterと組み合わせることも可能です。

#### 実行後の出力結果について
```
statistics03
│  README.md
│  requirements.txt
│  collector.bat
│  collector.py
│  output.yaml
│  toukei.py
│
└─202502130850
       applications.json
       libraries.json
       orgtraces.json
```
- 202502130850はAPI実行のレスポンス生データです。（複数のAPI実行の結果をマージしてる部分もあります）
- --app_filterにPetClinic_8001を指定したサンプルです。

### 集計
#### 実行オプションの確認
```cmd
python toukei.py --help
```

```
usage: python collector.py

--last_month, --this_month, --date_rangeのいずれかの指定が必須です。

options:
  -h, --help            show this help message and exit
  --dir DIR             解析対象のディレクトリ
  --sjis                結果をShift-JISで出力します。デフォルトはUTF-8です。
  --last_month          先月分の解析
  --this_month          今月分の解析
  --date_range DATE_RANGE
                        解析期間（YYYYMMDD-YYYYMMDD）
  --output_template     出力設定のテンプレートファイル生成
```
#### 通常の実行方法
- 先月分の集計を行う場合（月初めに先月分を集計する場合など）  

```cmd
python toukei.py --last_month
```
- 今月分の集計を行う場合（デバッグや途中経過を確認する場合など）  

```cmd
python toukei.py --this_month
```
- 範囲を指定して集計を行う場合（デバッグや途中経過を確認する場合など）  

```cmd
python toukei.py --date_range 20250216-20250315
```

#### 実行後の出力結果について

```
statistics03
│  README.md
│  requirements.txt
│  collector.bat
│  collector.py
│  output.yaml
│  toukei.py
│
├─202502130850
│      applications.json
│      libraries.json
│      orgtraces.json
│
├─AP
│      CA_PetClinic_8001-3_20250213.csv
│      CA_PetClinic_8001-CentOS_20250213.csv
│      CA_PetClinic_8001-ubuntu_20250213.csv
│      CA_PetClinic_8001-Yuya-Training_20250213.csv
│      CA_PetClinic_8001_20250213.csv
│      CA_PetClinic_8001_Docker_20250213.csv
│      CA_PetClinic_8001_GitlabDemo_20250213.csv
│
├─Lib
│      CA_PetClinic_8001-3_Library_20250213.csv
│      CA_PetClinic_8001-CentOS_Library_20250213.csv
│      CA_PetClinic_8001-ubuntu_Library_20250213.csv
│      CA_PetClinic_8001_Library_20250213.csv
│      CA_PetClinic_8001_GitlabDemo_Library_20250213.csv
│      CA_PetClinic_8001_JenkinsDemo_Library_20250213.csv
│
└─Sum
        CA_Summary_20250213.csv
```

## その他
### 出力項目のカスタマイズについて
output.yamlを変更することで以下の出力方法を変更することができます。
- 出力項目のon/off
- 出力項目の並び
- 値が複数の場合の区切り文字（ライブラリのCVEなど）

output.ymlはデフォルトでは存在しませんが、以下のコマンドでテンプレートが出力できます。  

```cmd
python toukei.py --output_template
```
これによって、`output.yaml.template` が出力されます。
内容を変更することで、csvの出力内容を変更することができます。

### collector.pyの定期実行について
#### Windows
`collector.bat`内のパスを適宜修正し、Windowsのタスクスケジューラにこのbatファイルを設定してください。

#### MacOS
cronを使って定期実行する例は以下となります。  

```bash
crontab -e
```

以下は5分おきに実行する例となります。  
cronのログは以下のようにリダイレクトを使うほうが簡単な確認方法としてオススメです。

```properties
CONTRAST_BASEURL=https://app.contrastsecurity.com/Contrast
CONTRAST_AUTHORIZATION=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX==
CONTRAST_API_KEY=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
CONTRAST_ORG_ID=XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
*/5 * * * * /bin/bash -c "source /Users/hoge/git/ContrastSecurity/support/statistics03/.sample_venv/bin/activate && python /Users/hoge/git/ContrastSecurity/support/statistics03/collector.py --app_filter PetClinic_8001_Taka >> /Users/hoge/git/ContrastSecurity/support/statistics03/cron.log 2>&1"
```

以上


