import fnmatch
import json
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict
from os import environ
from pathlib import Path

import tiktoken

# 100KB
MAX_FILE_SIZE = 100 * 1024


class BaseSnippetGenerator:
    def __init__(
        self,
        container_base_dir: str = "/src",
        enable_tree: bool = True,
        max_excluded_depth: int = 2,
    ):
        self.container_base_dir = Path(container_base_dir)
        self.collected_files = {}  # key: str (絶対パス), value: str (コード)
        self.excluded_paths = {}  # key: 絶対パス, value: (is_dir, reason)
        self.enable_tree = enable_tree
        self.max_excluded_depth = max_excluded_depth

        # シークレット・インフラ情報管理用プロパティ
        self.secret_registry = {}  # key: マスク対象文字列, value: ナンバー(int)
        self.secret_counter = 1
        self.detected_secrets_by_file = defaultdict(
            set
        )  # key: 絶対パス, value: {シークレット文字列}

        # デフォルトで除外するブラックリスト
        self.default_excludes = [
            "__pycache__",
            ".git",
            ".pytest_cache",
            ".mypy_cache",
            ".ruff_cache",
            "node_modules",
            ".venv",
            "venv",
            "*.pyc",
            "*.svg",
        ]

        # インスタンス生成時にGitleaksによる事前シークレットスキャンを実行
        self.run_gitleaks_scan()

    def run_gitleaks_scan(self):
        """Gitleaksを使用して、対象ディレクトリ全体のシークレットを事前に検出・リスト化する"""
        report_path = "/tmp/gitleaks_report.json"
        if os.path.exists(report_path):
            os.remove(report_path)

        # git管理外のファイルも検証するため --no-git を指定
        cmd = [
            "gitleaks",
            "detect",
            "--source",
            str(self.container_base_dir),
            "--no-git",
            "--exit-code",
            "0",
            "--report-format",
            "json",
            "--report-path",
            report_path,
        ]

        try:
            # Gitleaksの実行（ログを汚さないよう標準出力等は破棄）
            subprocess.run(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True
            )

            if os.path.exists(report_path) and os.path.getsize(report_path) > 0:
                with open(report_path, "r", encoding="utf-8") as f:
                    findings = json.load(f)
                    for finding in findings:
                        file_path = finding.get("File")
                        secret_str = finding.get("Secret")
                        if file_path and secret_str:
                            # ファイルの絶対パスをキーとしてシークレットを登録
                            abs_file_path = str(Path(file_path).resolve())
                            self.detected_secrets_by_file[abs_file_path].add(secret_str)
        except Exception as e:
            print(f"⚠️ Gitleaksによるシークレットスキャン中にエラーが発生しました: {e}")

    def _mask_callback(self, match) -> str:
        """マッチしたシークレット・インフラ情報に対して動的に共通のナンバーを割り当てるコールバック関数"""
        secret_str = match.group(0)
        if secret_str in self.secret_registry:
            num = self.secret_registry[secret_str]
        else:
            num = self.secret_counter
            self.secret_registry[secret_str] = num
            self.secret_counter += 1
        return f"[MASKED_SECRET_{num}]"

    def _apply_masking(self, code: str, abs_path_str: str) -> str:
        """ファイル内で検出されたシークレットや内部インフラ・ネットワーク情報をナンバリングマスクする"""
        # Gitleaksで検出されたシークレットのコピーを作成
        secrets_to_mask = set(self.detected_secrets_by_file.get(abs_path_str, set()))

        # 内部インフラ・ネットワーク情報を検出する正規表現パターン
        infra_patterns = [
            # プライベートIPアドレス (10.x.x.x, 172.16.x.x-172.31.x.x, 192.168.x.x)
            r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
            r"\b172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}\b",
            r"\b192\.168\.\d{1,3}\.\d{1,3}\b",
            # 内部ドメイン (例: db.internal, api.local, corp.lan, company.corp など)
            r"\b[a-zA-Z0-9.-]+\.(?:internal|local|corp|lan)\b",
            # ローカルホスト（ポート番号付きも含む。例: localhost, localhost:8080）
            r"\blocalhost(?::\d+)?\b",
        ]

        # コード内からインフラ情報を抽出してマスク対象リストに追加
        for pattern in infra_patterns:
            matches = re.findall(pattern, code)
            for match in matches:
                secrets_to_mask.add(match)

        if not secrets_to_mask:
            return code

        # 短い文字列が長い文字列の一部を誤って置換するのを防ぐため、文字数の長い順にソート
        sorted_secrets = sorted(list(secrets_to_mask), key=len, reverse=True)

        # 正規表現特殊文字のエスケープを行い、一括マッチ用のパターンを構築
        pattern_str = "|".join(f"({re.escape(s)})" for s in sorted_secrets)

        if pattern_str:
            return re.sub(pattern_str, self._mask_callback, code)
        return code

    @staticmethod
    def load_config_from_stdin() -> dict:
        try:
            return json.load(sys.stdin)
        except json.JSONDecodeError as e:
            print(f"❌ エラー: 標準入力からのJSONパースに失敗しました -> {e}")
            sys.exit(1)

    def _is_excluded(self, file_path: Path, exclude_patterns: list) -> bool:
        # デフォルトの除外パターンと、ユーザー指定の除外パターンを結合して判定
        all_patterns = exclude_patterns + self.default_excludes
        for part in file_path.parts:
            for pattern in all_patterns:
                if fnmatch.fnmatch(part, pattern):
                    return True
        return False

    def _remove_empty_lines(self, code: str) -> str:
        """コード内の完全な空行を削除してトークンを節約する（インデントやスペースのみの行も削除対象）"""
        return "\n".join(line for line in code.splitlines() if line.strip())

    def read_and_collect_file(self, abs_path: str, verbose: bool = False) -> bool:
        path_obj = Path(abs_path).resolve()
        abs_path_str = str(path_obj)
        if abs_path_str in self.collected_files:
            return True
        # 1. サイズ超過の判定
        if path_obj.exists() and path_obj.stat().st_size > MAX_FILE_SIZE:
            if verbose:
                print(f"\nℹ️ サイズ超過のためスキップ (>100KB): {abs_path_str}")
            self.excluded_paths[abs_path_str] = (False, "size exceeded")
            return False
        try:
            with path_obj.open("r", encoding="utf-8") as f:
                source_code = f.read()
                if source_code.strip():
                    # 収集・整形処理の前に機密情報（シークレット＋インフラ）を安全にナンバリングマスク
                    source_code = self._apply_masking(source_code, abs_path_str)

                    # コメントは残し、空行のみを削除する
                    source_code = self._remove_empty_lines(source_code)
                    if source_code.strip():
                        self.collected_files[abs_path_str] = source_code
                        return True
                    else:
                        # 改行やスペースのみで構成されていた場合
                        if verbose:
                            print(
                                f"\nℹ️ 空行削除により内容がなくなったためスキップ: {abs_path_str}"
                            )
                        self.excluded_paths[abs_path_str] = (False, "empty file")
                else:
                    # 最初から完全に空のファイルだった場合
                    if verbose:
                        print(f"\nℹ️ 空ファイルのためスキップ: {abs_path_str}")
                    self.excluded_paths[abs_path_str] = (False, "empty file")
        except (UnicodeDecodeError, PermissionError, FileNotFoundError) as e:
            if verbose:
                print(
                    f"\nℹ️ 読み込み不可のためスキップ ({type(e).__name__}): {abs_path_str}"
                )
            # 画像や各種バイナリ、エンコードエラーを包括
            self.excluded_paths[abs_path_str] = (False, "non-text")
        return False

    def _is_relevant_to_includes(
        self, check_path: Path, target_dir: Path, include_targets: list
    ) -> tuple[bool, bool]:
        """
        対象パスが includes の条件を満たすか判定する。
        戻り値: (is_target: 収集対象か, should_traverse: 内部を走査すべきか)
        """
        if not include_targets:
            # includesが空の場合はすべて対象
            return True, True
        try:
            rel_path = check_path.relative_to(target_dir)
        except ValueError:
            return False, False
        if rel_path == Path("."):
            # ルートディレクトリ自体は収集対象ではないが走査はする
            return False, True
        for inc in include_targets:
            inc_path = Path(inc)

            # 1. パスが完全に一致する場合
            if rel_path == inc_path:
                return True, True

            # 2. check_path が includes の子孫である場合 (例: inc="core", check="core/file.py")
            if inc_path in rel_path.parents:
                return True, True

            # 3. check_path が includes の祖先である場合 (例: inc="core/file.py", check="core")
            if rel_path in inc_path.parents:
                return False, True  # 収集対象ではないが、内部の走査は続ける

        return False, False

    def scan_and_collect_includes(
        self,
        target_dir: Path,
        include_targets: list,
        exclude_patterns: list,
        max_files: int = 1000,
        verbose: bool = False,
    ) -> None:
        """includes と excludes に基づいてファイル群を走査・収集する"""
        if not target_dir.exists():
            print(
                f"⚠️ 警告: 指定されたルートディレクトリが見つかりません -> {target_dir}"
            )
            return
        files_to_process = set()
        for root, dirs, files in os.walk(target_dir):
            root_path = Path(root)
            try:
                # プロジェクトルートからの深度（target_dir自体は0）
                current_depth = len(root_path.relative_to(target_dir).parts)
            except ValueError:
                current_depth = 0

            # --- ディレクトリの枝刈り ---
            kept_dirs = []
            for d in dirs:
                d_path = root_path / d

                # 1. デフォルト除外対象（.gitや.venvなど）は完全に探索を打ち切る
                is_default_excluded = any(
                    fnmatch.fnmatch(d, pattern) for pattern in self.default_excludes
                )
                if is_default_excluded:
                    # enable_tree が True の場合のみ除外ツリー用に記録
                    if self.enable_tree:
                        self.excluded_paths[str(d_path.resolve())] = (
                            True,
                            "default excluded",
                        )
                    continue

                # 2. excluded の判定（ユーザー指定の除外）
                is_excluded_by_pattern = self._is_excluded(d_path, exclude_patterns)
                if is_excluded_by_pattern:
                    if self.enable_tree:
                        self.excluded_paths[str(d_path.resolve())] = (True, "excluded")
                        if current_depth + 1 <= self.max_excluded_depth:
                            kept_dirs.append(d)
                    continue

                # 3. not included の判定（includes対象外）
                _, should_traverse = self._is_relevant_to_includes(
                    d_path, target_dir, include_targets
                )
                if not should_traverse:
                    if self.enable_tree:
                        self.excluded_paths[str(d_path.resolve())] = (
                            True,
                            "not included",
                        )
                        if current_depth + 1 <= self.max_excluded_depth:
                            kept_dirs.append(d)
                    continue
                kept_dirs.append(d)
            dirs[:] = kept_dirs

            # --- ファイルの収集判定 ---
            for file_name in files:
                file_path = root_path / file_name

                # 1. default excluded
                is_default_excluded = any(
                    fnmatch.fnmatch(file_name, pattern)
                    for pattern in self.default_excludes
                )
                if is_default_excluded:
                    if self.enable_tree:
                        self.excluded_paths[str(file_path.resolve())] = (
                            False,
                            "default excluded",
                        )
                    continue

                # 2. excluded
                is_excluded_by_pattern = self._is_excluded(file_path, exclude_patterns)
                if is_excluded_by_pattern:
                    if self.enable_tree:
                        self.excluded_paths[str(file_path.resolve())] = (
                            False,
                            "excluded",
                        )
                    continue

                # 3. not included
                is_target, _ = self._is_relevant_to_includes(
                    file_path, target_dir, include_targets
                )
                if not is_target:
                    if self.enable_tree and (
                        current_depth + 1 <= self.max_excluded_depth
                    ):
                        self.excluded_paths[str(file_path.resolve())] = (
                            False,
                            "not included",
                        )
                    continue

                # すべてクリアしたものを収集対象にする
                files_to_process.add(file_path.resolve())
                if len(files_to_process) > max_files:
                    print(
                        f"\n🚨 警告: スキャン途中でファイル数が上限（{max_files}）を超過したため、処理を中断します。"
                    )
                    self._print_top_heavy_directories(files_to_process, target_dir)
                    sys.exit(1)
        total_files = len(files_to_process)
        if total_files == 0:
            return
        if verbose:
            print(f"  - 検出した総ファイル数: {total_files}")
            print("▶ [プロセス 2/3: ファイルの読み込み・収集]")
        for i, path_obj in enumerate(sorted(files_to_process), start=1):
            self.read_and_collect_file(str(path_obj), verbose=verbose)
            if verbose:
                print(
                    f"\r  - 進捗: {i}/{total_files} ファイルまで処理済み",
                    end="",
                    flush=True,
                )
        if verbose:
            print()

    def _print_top_heavy_directories(
        self, files_to_process: set, target_dir: Path
    ) -> None:
        dir_counts = Counter()
        for p in files_to_process:
            try:
                rel_path = p.relative_to(target_dir)
                current_dir = Path()
                for part in rel_path.parent.parts:
                    current_dir = current_dir / part
                    dir_counts[str(current_dir)] += 1
            except ValueError:
                pass
        print("  - [ファイル数が多いディレクトリ 上位10]")
        for i, (d, count) in enumerate(dir_counts.most_common(10), start=1):
            print(f"    {i}. {d}/ ({count} ファイル)")
        print("\n💡 ヒント: excludes に上記ディレクトリを追加して除外してください。")

    def _generate_file_tree(self, project_root: Path) -> str:
        """収集したファイルと除外したファイルを統合してマークダウン形式の階層ツリーを生成する"""
        tree_dict = {}

        def add_to_tree(file_path_str: str, reason: str, is_dir: bool):
            file_path = Path(file_path_str)
            try:
                rel_path = file_path.relative_to(project_root)
            except ValueError:
                rel_path = file_path
            current = tree_dict
            parts = rel_path.parts
            for i, part in enumerate(parts):
                if part not in current:
                    current[part] = {}

                # 最後の要素（ファイル名 or ディレクトリ名）にメタデータを付与
                if i == len(parts) - 1:
                    if reason:
                        current[part]["__excluded_reason__"] = reason
                    if is_dir:
                        current[part]["__is_dir__"] = True
                current = current[part]

        # 1. 収集対象となったファイルを追加
        for file_path_str in self.collected_files.keys():
            add_to_tree(file_path_str, reason="", is_dir=False)

        # 2. 除外されたパスを追加
        if hasattr(self, "excluded_paths"):
            for file_path_str, (is_dir, reason) in self.excluded_paths.items():
                add_to_tree(file_path_str, reason=reason, is_dir=is_dir)

        def build_lines(node, depth):
            lines = []
            indent = "  " * depth

            # メタデータ（__excluded__, __is_dir__）を除外してアルファベット順にソート
            items = [(k, v) for k, v in node.items() if not k.startswith("__")]
            for name, children in sorted(items):
                reason = children.get("__excluded_reason__", "")
                is_dir_explicit = children.get("__is_dir__", False)

                # 除外理由ラベルが存在する場合はそれを付与
                suffix = f" ({reason})" if reason else ""

                # 子要素を持っているか、ディレクトリとして明示されていれば末尾に / をつける
                if (
                    any(k for k in children.keys() if not k.startswith("__"))
                    or is_dir_explicit
                ):
                    lines.append(f"{indent}- {name}/{suffix}")
                    lines.extend(build_lines(children, depth + 1))
                else:
                    lines.append(f"{indent}- {name}{suffix}")
            return lines

        tree_lines = build_lines(tree_dict, 0)
        return "## ディレクトリ構成\n" + "\n".join(tree_lines) + "\n\n"

    def generate_markdown(self, project_root: Path) -> str:
        output = []

        # enable_tree が True の場合のみツリーを先頭に差し込む
        if self.enable_tree:
            tree_md = self._generate_file_tree(project_root)
            output.append(tree_md)
        output.append("## ソースコード")
        for file_path_str in sorted(self.collected_files.keys()):
            code = self.collected_files[file_path_str]
            file_path = Path(file_path_str)
            try:
                rel_path = file_path.relative_to(project_root)
            except ValueError:
                rel_path = file_path
            ext = file_path.suffix.lower()
            lang = ext.lstrip(".") if ext else "text"
            backticks = "`````" if ext == ".md" else "```"
            output.append(f"\n### File: `{rel_path}`")
            output.append(f"{backticks}{lang}")
            output.append(code.rstrip())
            output.append(backticks)
        return "\n".join(output) + "\n"

    def write_output_file(self, markdown_result: str, output_file_name: str):
        output_path = Path("output") / output_file_name
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as f:
            f.write(markdown_result)
        if host_pwd := environ.get("HOST_PWD"):
            display_path = Path(host_pwd) / "output" / output_file_name
        else:
            display_path = output_path
        print(f"✅ 抽出が完了しました -> {display_path}")

    def print_token_stats(
        self,
        project_root: Path,
        markdown_result: str,
        includes: list = None,
        excludes: list = None,
    ) -> None:
        """生成したマークダウンのトークン数を集計し、ターミナルに出力する"""
        includes = includes or []
        excludes = excludes or []

        try:
            # 一般的なOpenAIモデル (GPT-4/GPT-3.5) のエンコーディングを使用
            enc = tiktoken.get_encoding("cl100k_base")
        except Exception as e:
            print(f"⚠️ tiktokenの読み込みに失敗しました: {e}")
            return

        # 全体のトークン数（ディレクトリ構成を含むマークダウン全体）
        total_tokens = len(enc.encode(markdown_result))
        file_tokens = {}
        dir_tokens = defaultdict(int)

        # 各ファイルのトークン数を個別に計算
        for file_path_str, code in self.collected_files.items():
            file_path = Path(file_path_str)
            try:
                rel_path = file_path.relative_to(project_root)
            except ValueError:
                rel_path = file_path

            # 各ファイルのマークダウン構成部分を再現して計算
            ext = file_path.suffix.lower()
            lang = ext.lstrip(".") if ext else "text"
            backticks = "`````" if ext == ".md" else "```"
            chunk_str = f"\n### File: `{rel_path}`\n{backticks}{lang}\n{code.rstrip()}\n{backticks}\n"
            tokens = len(enc.encode(chunk_str))
            file_tokens[str(rel_path)] = tokens
            parent_dir = str(rel_path.parent)
            if parent_dir != ".":
                dir_tokens[parent_dir] += tokens

        # ターミナルへ結果を出力
        print("\n⚙️ [実行時の設定情報]")
        display_includes = (
            ", ".join(includes)
            if includes
            else "(指定なし -> 解析対象ディレクトリ配下を全て抽出 / または AST追跡のみ)"
        )
        display_excludes = ", ".join(excludes) if excludes else "(指定なし)"
        display_default_excludes = ", ".join(self.default_excludes)

        host_target_dir = environ.get("HOST_TARGET_DIR")
        if host_target_dir:
            # コンテナ内のベースディレクトリ (デフォルト: /src) をホスト側の絶対パスに置換する
            container_base_str = str(self.container_base_dir)
            project_root_str = str(project_root)
            if project_root_str.startswith(container_base_str):
                display_target_dir = project_root_str.replace(
                    container_base_str, host_target_dir, 1
                )
            else:
                display_target_dir = project_root_str
        else:
            display_target_dir = project_root

        print(f"  - 📂 解析対象       : {display_target_dir}")
        print(f"  - 🎯 抽出対象       : {display_includes}")
        print(f"  - 🚫 デフォルト除外 : {display_default_excludes}")
        print(f"  - 🚫 指定除外       : {display_excludes}")
        print(
            f"  - 🌳 構成ツリー     : {'ON' if self.enable_tree else 'OFF'} (除外ディレクトリ探索最大深度: {self.max_excluded_depth})"
        )

        print("\n📊 [抽出結果のトークン集計情報]")
        print(f"  - 📝 全体の推定トークン数: {total_tokens:,} トークン")

        # enable_tree が True の場合のみ、ツリーの消費トークンを内訳に表示
        if self.enable_tree:
            tree_md = self._generate_file_tree(project_root)
            tree_tokens = len(enc.encode(tree_md))
            print(f"  - 🌳 構成ツリーの消費    : {tree_tokens:,} トークン")

        print("\n  - 📄 トークン数が多いファイル (上位5件):")
        sorted_files = sorted(file_tokens.items(), key=lambda x: x[1], reverse=True)[:5]
        for i, (f, t) in enumerate(sorted_files, start=1):
            print(f"    {i}. {f} ({t:,} トークン)")

        print("\n  - 📁 トークン数が多いディレクトリ (上位5件 / ルート除く):")
        sorted_dirs = sorted(dir_tokens.items(), key=lambda x: x[1], reverse=True)[:5]
        for i, (d, t) in enumerate(sorted_dirs, start=1):
            print(f"    {i}. {d}/ ({t:,} トークン)")
        print()

        # マスクが実行された場合のみセキュリティ統計情報を出力
        if self.secret_registry:
            print(f"🔒 [セキュリティ安全対策レポート]")
            print(
                f"  - 🛡️ マスクされた機密情報・インフラ情報: {len(self.secret_registry)} 件"
            )
            print(
                f"  - 📝 [MASKED_SECRET_1] 〜 [MASKED_SECRET_{self.secret_counter - 1}] をコード内の文脈・不整合が起きないよう割り振りました。"
            )
            print()
