# 動作チェック用のダミーファイル（シークレット ＋ インフラ情報の複合検知テスト）

# 1. シークレットキー（Gitleaksが検知）
OPENAI_API_KEY = "sk-1234567890abcdef1234567890abcdef1234567890abcdef"

# 2. プライベートIPアドレス (正規表現が検知)
DB_HOST_PRIMARY = "192.168.1.50"
DB_HOST_REPLICA = "192.168.1.50"  # 同じIPを使い回す

# 3. 内部ドメイン (正規表現が検知)
INTERNAL_API_URL = "https://auth-service.internal/v1/login"

# 4. localhost とポート番号 (正規表現が検知)
LOCAL_DEV_SERVER = "http://localhost:8080/debug"

def connect():
    print(f"Key: {OPENAI_API_KEY}")
    print(f"Connecting to {DB_HOST_PRIMARY} and replica {DB_HOST_REPLICA}")
    print(f"Internal Domain: {INTERNAL_API_URL}")
    print(f"Dev server: {LOCAL_DEV_SERVER}")