FROM python:3.11-slim

# Gitleaksのダウンロードに必要なパッケージと、実行に必要なgitをインストール
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Gitleaks バイナリのインストール (v8.18.2)
RUN wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.2/gitleaks_8.18.2_linux_x64.tar.gz \
    && tar -zxvf gitleaks_8.18.2_linux_x64.tar.gz \
    && mv gitleaks /usr/local/bin/ \
    && rm gitleaks_8.18.2_linux_x64.tar.gz

# ワーキングディレクトリの設定
WORKDIR /app

# Ruff（フォーマッター）、tiktoken（トークン計算用）をインストール
RUN pip install --no-cache-dir ruff tiktoken