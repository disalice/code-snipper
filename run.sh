#!/bin/bash
# =========================================================================
# 引数のチェック（モード と 設定ファイル）
# =========================================================================
MODE="$1"
CONFIG_FILE="$2"

if [[ "$MODE" != "all" && "$MODE" != "ast" ]] || [ -z "$CONFIG_FILE" ]; then
    echo "❌ エラー: モード(all/ast) と 設定ファイルのパスを指定してください。"
    echo "使用方法: $0 <all|ast> <設定JSONのパス>"
    echo "実行例:  $0 all ./configs/all/sample.json"
    exit 1
fi

TOOL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE_ABS="$(cd "$(dirname "$CONFIG_FILE")" && pwd)/$(basename "$CONFIG_FILE")"

if [ ! -f "$CONFIG_FILE_ABS" ]; then
    echo "❌ エラー: 設定ファイルが見つかりません -> $CONFIG_FILE"
    exit 1
fi

# =========================================================================
# JSON から target_dir を自動抽出・絶対パス化 (従来と同じ処理)
# =========================================================================
TARGET_DIR_RAW=$(grep '"target_dir"' "$CONFIG_FILE_ABS" | sed -E 's/.*"target_dir"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/')
if [[ "$TARGET_DIR_RAW" == *'"target_dir"'* ]] || [ -z "$TARGET_DIR_RAW" ]; then
    echo "❌ エラー: JSONのパース失敗、または target_dir が空です。"
    exit 1
fi

if [[ "$TARGET_DIR_RAW" != /* ]]; then
    CONFIG_DIR="$(cd "$(dirname "$CONFIG_FILE_ABS")" && pwd)"
    TARGET_DIR_RAW="${CONFIG_DIR}/${TARGET_DIR_RAW}"
fi

if [ -d "$TARGET_DIR_RAW" ]; then
    export TARGET_DIR="$(cd "$TARGET_DIR_RAW" && pwd)"
else
    echo "❌ エラー: target_dir が存在しません -> $TARGET_DIR_RAW"
    exit 1
fi

# =========================================================================
# Docker Compose 実行
# =========================================================================
export HOST_PWD="$TOOL_DIR"
cd "$TOOL_DIR/core"

echo "🚀 抽出を開始します (モード: $MODE) ..."
echo "⚙️ 設定ファイル: $CONFIG_FILE_ABS"
echo "📂 解析対象     : $TARGET_DIR"

if [ "$MODE" = "all" ]; then
    # generatorコンテナで generate_all_snippets.py を実行
    cat "$CONFIG_FILE_ABS" | docker compose run -T --rm --build generator python generate_all_snippets.py
else
    # generatorコンテナで generate_ast_snippets.py を実行
    cat "$CONFIG_FILE_ABS" | docker compose run -T --rm --build generator python generate_ast_snippets.py
fi