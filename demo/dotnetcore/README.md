# .Net Coreデモ
やられアプリのサンプルである**vulnerable_net_core-PoC**を使わせてもらいます。

### デモ実行環境
- Amazon Linux 2023.9.20251117
- dotnet 8.0.21(x64)
- Contrast TeamServer Eval v3.12.9

### やられアプリのセットアップ
#### まずは取得
```bash
git clone https://github.com/GSA/vulnerable_net_core-PoC.git
```
#### SDKが古いので、新しいのに変更します。
```bash
cd vulnerable_net_core-PoC
sed -i 's/netcoreapp3.1/net8.0/g' ./vulnerable_asp_net_core/vulnerable_asp_net_core.csproj
```

#### ビルドと起動
```bash
dotnet restore
dotnet build vulnerable_asp_net_core.sln
export ASPNETCORE_URLS="http://0.0.0.0:5000"
dotnet run --project vulnerable_asp_net_core
```
http://18.176.117.9:5000/ で接続できます。

### Contrastエージェントのセットアップ
上で起動したアプリを`Ctrl + C`で一旦停止。
#### エージェントの取得  
```bash
# 取得崎は任意ですが、ここではやられアプリの直下で実行してください。
curl -L https://www.nuget.org/api/v2/package/Contrast.SensorsNetCore/ --output Contrast.SensorsNetCore.nupkg &&
unzip Contrast.SensorsNetCore.nupkg -d Contrast.SensorsNetCore &&
mv Contrast.SensorsNetCore/contentFiles/any/netstandard2.0/contrast ./
```
*※ 新規ウイザードの指定どおりでよいです。*

#### contrast_security.yamlを取得
```bash
# 取得崎は任意ですが、ここではやられアプリの直下に落とすように実行してください。
curl --location --request GET 'https://eval-agents.contrastsecurity.com/Contrast/agents/v1.0/agents/configuration' \
-o ./contrast_security.yaml \
-H 'Authorization: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX==' \
-H 'API-Key: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX' \
-H 'Content-Type: application/x-yaml'  \
-H "Accept: application/x-yaml"
```
*※ これも新規ウイザードの指定どおりでよいです。ただしダウンロード箇所は適宜修正してください。*

#### 環境変数をセット
```bash
export CORECLR_PROFILER={8B2CE134-0948-48CA-A4B2-80DDAD9F5791}
export CORECLR_ENABLE_PROFILING=1
# 以下のパスは適宜、エージェント、yamlを落とした場所に変更してください。
export CORECLR_PROFILER_PATH_64=/root/git/vulnerable_net_core-PoC/contrast/runtimes/linux-x64/native/ContrastProfiler.so
export CONTRAST_CONFIG_PATH=/root/git/vulnerable_net_core-PoC/contrast_security.yaml
```
*※ ここも新規ウイザードの指定を参考にしてください。*

#### Contrastエージェント付きで起動
```bash
dotnet run --project vulnerable_asp_net_core
```
Contrastチームサーバにサーバ、アプリがオンボードされていることを確認します。

### 脆弱性を出すための自動テスト
#### 一部環境に合わせて修正
```bash
cd exploits
find . -maxdepth 1 -type f -name "*.sh" -print0 | xargs -0 sed -i 's|https://localhost:5001/|http://localhost:5000/|g'
```
#### Exploit実行
```bash
# exploits/の下で
./run_all.sh
```
これによって、Contrastチームサーバにいくつか重大、高の脆弱性が検知されます。

以上
