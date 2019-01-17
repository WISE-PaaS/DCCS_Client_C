# REST API 說明
```sh
GET {連線憑證兌換服務網址}/v1/serviceCredentials/{服務金鑰名稱}
```
- 連線憑證兌換服務網址：與雲平台網域有關，格式為 https://api-dccs.{雲平台網域} 。例如雲平台網域為 wise-pass.com ，連線憑證兌換服務網址為 https://api-dccs.wise-pass.com。
- 服務金鑰名稱：可從 Management Portal 服務金鑰清單中取得。
### 進行 REST 連線時須注意以下幾個要點：

- 為了資安考量，建議您使用 HTTPS 連線，若您使用 HTTP 連線，系統會強制重導成 HTTPS 。
- 您傳送的 HTTP Header 須包含內容格式參數 Content-Type = application/json 。
### 您可以使用 HTTP status code 來判斷 REST 運作情況：

- 當成功取得連線憑證時，會取得 HTTP status code 200 (OK)
- 若是找不到連線憑證時，會取得 HTTP status code 404 (Not Found)
- 當系統運作極度忙碌，導致暫時無法回應，造成連線失敗時，會取得 HTTP status code 503 (Service Unavailable)