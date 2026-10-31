# SSH Failed Login Parser

解析 Linux `auth.log` 中的 SSH 登入失敗事件，輸出結構化資料，
並依來源 IP 統計失敗次數，協助辨識可能的暴力破解行為。

## 功能

- 逐行串流讀取日誌，不會一次載入整個檔案
- 解析 `Failed password`（含 `invalid user`）事件，擷取時間、使用者、來源 IP、Port
- 記錄原始行號，方便回頭追查
- 依來源 IP 統計失敗次數，並列出超過門檻的 IP

## 環境需求

- Python 3.10+
- 只使用標準函式庫，無需安裝套件

## 使用方式

```bash
git clone <repo-url>
cd <project>
python main.py
```

預設讀取專案目錄下的 `auth.log`，可在程式中修改 `LOG_FILE`。

## 範例

輸入（`auth.log`）：

```
Oct 29 16:10:04 myhost sshd[652]: Failed password for invalid user test from 203.0.113.11 port 34290 ssh2
```

輸出：

```
[+] 成功抓取到 1 筆 SSH 登入失敗，前三筆為：
    {'time': 'Oct 29 16:10:04', 'user': 'test', 'ip': '203.0.113.11', 'port': '34290', 'log_line_number': 1}
[+] 失敗次數 >= 10 的來源IP
    183.63.110.206     17340
```

## 專案結構

```
.
├── main.py     # 主程式
├── auth.log   # 測試用範例日誌（假資料）
└── README.md
```

## 已知限制

- 支援傳統 syslog 時間格式（不含年份）及RFC3339 格式
- 支援 IPv4、IPv6
- 僅解析 `Failed password`，不含 `Failed publickey` 與其他事件

## 授權

MIT License