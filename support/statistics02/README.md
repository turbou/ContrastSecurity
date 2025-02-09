# ContrastのAPIを使った統計のサンプル1

## 環境準備
Python3はWindowsにインストール済みの前提です。  
3.13.1で動作確認をしています。
- 仮想環境作成

```cmd
python -m venv sample_venv
```
- アクティベート

```cmd
.\sample_venv\Scripts\activate
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

```cmd
python toukei.py
```

