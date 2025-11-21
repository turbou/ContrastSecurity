# OpenLibertyでPetClinicデモ

## デモ実行環境
- MacOS Tahoe 26.1
- JDK17 (mavenも)
- OpenLiberty 24.0.0.12

## OpenLibertyのインストール
### OpenLibertyのzipを取得
[openliberty-24.0.0.12.zip](https://public.dhe.ibm.com/ibmdl/export/pub/software/openliberty/runtime/release/24.0.0.12/openliberty-24.0.0.12.zip) をダウンロード。

(参考) [Supported technologies for Java (Kotlin, Scala) agent](https://docs.contrastsecurity.com/en/java-supported-technologies.html)

### インストール（解凍と配置）
```bash
unzip penliberty-24.0.0.12.zip
# 解凍ディレクトリはwlpになる。
mkdir ~/servers
mv wlp ~/servers/
```

### デモ用のサーバを作成して起動
```bash
cd ~/servers/wlp/bin
./server create demo
./server start demo
```
http://localhost:9080/

### 管理コンソールを有効化（任意）
`vim ~/servers/wlp/usr/servers/demo/server.xml`
`jsp-2.3`は無効化しつつ、以下のようにしてください。  
```xml
    <featureManager>
        <!--<feature>jsp-2.3</feature>-->
        <feature>webProfile-10.0</feature>
        <feature>adminCenter-1.0</feature>
    </featureManager>
    <basicRegistry id="basic">
        <user name="admin" password="adminpwd" />
        <user name="reader" password="readerpwd" />
    </basicRegistry>
    <administrator-role>
        <user>admin</user>
    </administrator-role>
    <reader-role>
        <user>reader</user>
    </reader-role>
```
https://localhost:9443/adminCenter

## Contrastエージェントのセットアップ
### contrast.jarのダウンロード
今回はJavaエージェントのダウンロードはcurlでやります。  
詳細はチームサーバの「新規登録」のウイザードから実施してください。  

`contrast.jar`は以下の場所に取得したとします。
`~/servers/wlp/usr/servers/demo`の直下

### contrast_security.yamlのダウンロード
こちらも「新規登録」のウイザードを参考に取得してください。  
`contrast_security.yaml`はエージェントと同じく以下の場所に取得したとします。
`~/servers/wlp/usr/servers/demo`の直下

### demoサーバへのContrastエージェントの組み込み
`~/servers/wlp/usr/servers/demo`下に`jvm.options`を作成します。  
内容は以下のとおりです。  
```
-javaagent:/Users/turbou/servers/wlp/usr/servers/demo/contrast.jar
-Dcontrast.config.path=/Users/turbou/servers/wlp/usr/servers/demo/contrast_security.yaml
-Dcontrast.server.name=Mac_OpenLiberty_Demo
```

### demoサーバの再起動
```bash
cd ~/servers/wlp/bin
./server stop demo
./server start demo
```

### チームサーバに以下オンボードされることを確認
以下いずれもオンボードされ、オンラインになっていること
- サーバ一覧  
  `Mac_OpenLiberty_Demo`
- アプリケーション一覧  
  `ibm/api`と`The Liberty `で始まるアプリケーションが３つ

## やられアプリのPetClinicをオンボードさせる
### PetClinicをgit clone
```bash
cd ~/Downloads
git clone https://github.com/turbou/PetClinicDemoJDK17.git
```

### warを作成
```bash
cd ~/Downloads/PetClinicDemoJDK17
# JDK17が前提です。
./mvnw -DskipTests -Dcheckstyle.skip clean package
```

### warをdemoサーバにデプロイ
```bash
cp ./target/petclinic.war ~/servers/wlp/usr/servers/demo/dropins/
```

### チームサーバに以下オンボードされることを確認
- アプリケーション一覧  
  `petclinic`というアプリケーションがオンボードされ、オンラインとなっていること

  **ルートカバレッジ、ライブラリ数などもの情報も確認します。**

## petclinicの画面疎通・打鍵
http://localhost:9080/petclinic/
にアクセスして、いくつか画面疎通を行い、チームサーバ上でAssessの結果を確認します。  


以上
