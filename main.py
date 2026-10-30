import re
from pathlib import Path
from collections import Counter

LOG_FILE = Path("auth.log")

# 2. 修正：利用 re.VERBOSE 參數，可以優雅地寫多行 Regex，並在字串間補上必要的空格 \s+
# 傳統syslog時間：Dec 10 08:33:31 LabSZ sshd[24389]: Failed password for invalid user admin from 103.207.39.212 port 58447 ssh2
# RFC3339（2026-10-29T16:09:39+08:00 ...）
PATTERN = re.compile(
    r"^(?P<time>(?:[A-Z][a-z]{2}\s+\d{1,2}\s[\d:]{8})|(?:\d{4}-\d{2}-\d{2}T\S+))\s+" # 擷取時間，包含傳統時間格式或RFC3339
    r"\S+\s+\S+?(?:\[\d+\])?:\s+"          # 主機名稱與程序名稱，取代 .*?，減少測試效能消耗
    r"Failed\s+\w+\s+for\s+(?:invalid\s+user\s+)?"        # 比對失敗關鍵字，且不論有無 invalid user
    r"(?P<user>\S+)\s+from\s+"             # 擷取被攻擊的使用者名稱
    r"(?P<ip>[0-9a-fA-F:.]+)\s+"           # 同時容納 IPv4 / IPv6
    r"port\s+(?P<port>\d+)"                # 擷取攻擊來源 Port
)

def parse_line(line):
    match = PATTERN.search(line) #search 在字串任意位置尋找第一個符合處
    return match.groupdict() if match else None #如果有match，就回傳groupdict()，沒有就none

def main():
    if not LOG_FILE.exists(): 
        raise SystemExit(f"Missing File: {LOG_FILE}") #SystemExit立刻中止跳出執行程式
        
    events = [] #定義輸出結果清單

    # 逐行串流讀取，避免一次載入整個檔案。
    with LOG_FILE.open(encoding="utf-8") as log: # log代表讀出的內容
        for number, line in enumerate(log, 1):   # number行號、line內容，enumerate將log包裝成Tuple，從1開始計數
            event = parse_line(line)
            if event: #event不是空，就會成立
                event["log_line_number"] = number
                events.append(event)
                
    # 測試印出抓到的結構化資料
    print(f"[+] 成功抓取到 {len(events)} 筆 SSH 登入失敗，前三筆為：")
    for ev in events[:3]:
        print(f"    {ev}")

    by_ip = Counter(ev["ip"] for ev in events) #對 events 裡每一筆 ev，取出 ev["ip"]，把這些值餵給 Counter 去計數，變成dict
    THRESHOLD = 10  # 門檻值，依環境調整
    print(f"[+] 失敗次數 >= {THRESHOLD} 的來源IP：")
    for ip, count in by_ip.most_common(): #.most_common()由大到小排序
        if count < THRESHOLD:
            break
        print(f"    {ip:<18} {count}") #<靠左，預留18字元給IP

if __name__ == "__main__":
    main()