# ContrastエージェントのログをDataDogで円グラフ出すまで

## 前提条件
- コントラストのProtectライセンスを持っていること
- DataDogにアカウントがあり、Logエクスプローラー、パイプラインやダッシュボードを作成する権限を持っていること
- DataDogエージェントのインストールも済んでいること

## 使用するアプリケーション
- やられアプリ  
  WebGoat v2025.3  
  https://github.com/webgoat/webgoat/releases  
  webgoat-2025.3.jar をダウンロード

- 攻撃テストアプリ  
  Nikto  
  https://github.com/sullo/nikto

## 事前準備
### DataDogエージェント
```bash
vim ~/.datadog-agent/datadog.yaml
```
```yaml
logs_enabled: true
```
```bash
mkdir -p ~/.datadog-agent/conf.d/java.d
vim conf.yaml
```
```yaml
logs:
  - type: file
    path: /Users/turbou/Downloads/contrast-work/security.log
    service: contrast
    source: java
```
pathの値はContrastエージェントログの出力先に合わせて変更してください。

## WebGoatの起動
### JavaエージェントのDL
適当な場所にダウンロードしてください。

