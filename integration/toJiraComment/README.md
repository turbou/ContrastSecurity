### 前提

Python3.12.5でテストしています。Python3系なら動くと思います。

```bash
(ocbc) MacBookAir13:ocbc_work turbou$ pip freeze
certifi==2024.8.30
charset-normalizer==3.3.2
idna==3.10
requests==2.32.3
urllib3==2.2.3
```

### 事前準備

環境変数をセットしてください。
情報はTeamServerのユーザーメニューから取得できます。

```bash
export CONTRAST_BASEURL=https://eval.contrastsecurity.com/Contrast
export CONTRAST_AUTHORIZATION=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX==
export CONTRAST_API_KEY=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
export CONTRAST_ORG_ID=XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
export CONTRAST_APP_ID=XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
```

特定のアプリケーションを指定する場合は以下の環境変数もセットしてください。

```bash
export CONTRAST_APP_IDS=XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX,XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX,...
```

特定のアプリケーションを除外する場合は以下の環境変数もセットしてください。

```bash
export CONTRAST_EXCLUDE_APP_IDS=XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX,XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX,...
```

CONTRAST_APP_IDSとCONTRAST_EXCLUDE_APP_IDSの両方をセットすることはできません。

環境変数の解除については以下です。

```bash
export -n CONTRAST_APP_IDS
# または以下でも大丈夫です。
export CONTRAST_APP_IDS=
```

### 実行方法

アプリケーションを指定する場合

例）EasyBuggy4Django_KajiDocker、PetClinic_8001を指定する。

```bash
export CONTRAST_APP_IDS=598087fa-ad64-4180-a2af-73878bac4857,5be21fa1-e0d8-45d7-baed-a2fd4a3de1c8
```

アプリケーションを除外する場合

例）BenchMarkOyoyo、OWASP Benchmarkを除外する。

```bash
export CONTRAST_EXCLUDE_APP_IDS=6e7572aa-783b-4334-9110-8128267a5ea2,3b7100e5-3d78-49c6-9974-daf973f2ea4c
```

```bash
python ./sample.py
```

### 結果の確認

```./result.csv```が生成されています。

