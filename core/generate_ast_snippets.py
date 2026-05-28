import ast
import importlib.util
import sys
from pathlib import Path

from base_generator import BaseSnippetGenerator


class ModuleAnalyzer(ast.NodeVisitor):
    """モジュール全体のインポートや定義、ターゲットノードを見つけるVisitor"""

    def __init__(self, target_name):
        self.target_name = target_name
        self.imports = {}
        self.from_imports = {}
        self.local_defs = set()
        self.target_node = None
        self.enclosing_class = None
        self._current_class = None

    def visit_Import(self, node):
        for alias in node.names:
            self.imports[alias.asname or alias.name] = alias.name

    def visit_ImportFrom(self, node):
        if node.module:
            for alias in node.names:
                self.from_imports[alias.asname or alias.name] = (
                    node.module,
                    alias.name,
                )

    def visit_ClassDef(self, node):
        self.local_defs.add(node.name)
        if node.name == self.target_name and not self.target_node:
            self.target_node = node
            self.enclosing_class = node
        prev_class = self._current_class
        self._current_class = node
        self.generic_visit(node)
        self._current_class = prev_class

    def visit_FunctionDef(self, node):
        self.local_defs.add(node.name)
        if node.name == self.target_name and not self.target_node:
            self.target_node = node
            self.enclosing_class = self._current_class
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node):
        self.visit_FunctionDef(node)


class ReferenceFinder(ast.NodeVisitor):
    """見つけたターゲットノード内から Name と Attribute を抽出するVisitor"""

    def __init__(self):
        self.referenced_names = set()
        self.referenced_attributes = set()

    def visit_Name(self, node):
        self.referenced_names.add(node.id)

    def visit_Attribute(self, node):
        if isinstance(node.value, ast.Name):
            self.referenced_attributes.add((node.value.id, node.attr))
        self.generic_visit(node)


class ASTSnippetGenerator(BaseSnippetGenerator):
    def __init__(self, entry_file: str, enable_tree: bool, max_excluded_depth: int):
        super().__init__(enable_tree=enable_tree, max_excluded_depth=max_excluded_depth)
        entry_path = Path(entry_file).resolve()
        self.entry_file = entry_path
        self.project_root = self._find_project_root(entry_path)

        # エントリファイルと同階層やプロジェクトルートをインポートパスに追加
        entry_dir_str = str(entry_path.parent)
        project_root_str = str(self.project_root)
        if entry_dir_str not in sys.path:
            sys.path.insert(0, entry_dir_str)
        if project_root_str not in sys.path:
            sys.path.insert(0, project_root_str)

        # 無限ループ防止用 {(file_path_obj, entry_point_name)}
        self.visited_nodes = set()

    def _find_project_root(self, path: Path) -> Path:
        current = path.parent
        for parent in [current] + list(current.parents):
            if (parent / ".git").exists():
                return parent
        return current

    def resolve_to_path(self, module_name: str) -> Path | None:
        try:
            spec = importlib.util.find_spec(module_name)
            if spec and spec.origin:
                origin_path = Path(spec.origin).resolve()
                if origin_path.suffix == ".py":
                    # プロジェクトルート配下のファイルのみを対象にする
                    # Python 3.9+ で使える is_relative_to を使用
                    if origin_path.is_relative_to(self.project_root):
                        return origin_path
        except Exception:
            pass
        return None

    def get_ast_info(self, tree, target_name):
        # 1. モジュール全体を走査してインポートとターゲットノードを特定
        analyzer = ModuleAnalyzer(target_name)
        analyzer.visit(tree)

        # 2. ターゲットノード内の参照を抽出
        finder = ReferenceFinder()
        if analyzer.target_node:
            finder.visit(analyzer.target_node)
        if analyzer.enclosing_class:
            for base in analyzer.enclosing_class.bases:
                finder.visit(base)
        if not analyzer.target_node and target_name:
            finder.referenced_names.add(target_name)

        return (
            finder.referenced_names,
            finder.referenced_attributes,
            analyzer.imports,
            analyzer.from_imports,
            analyzer.local_defs,
        )

    def trace_and_extract(self, file_path: Path, target_name: str):
        file_path = file_path.resolve()
        if (file_path, target_name) in self.visited_nodes:
            return
        self.visited_nodes.add((file_path, target_name))
        if not self.read_and_collect_file(str(file_path)):
            return

        source_code = self.collected_files[str(file_path)]
        try:
            tree = ast.parse(source_code)
        except SyntaxError:
            return

        (
            referenced_names,
            referenced_attributes,
            imports,
            from_imports,
            local_defs,
        ) = self.get_ast_info(tree, target_name)

        for base_name, attr_name in referenced_attributes:
            if base_name in from_imports:
                mod_name, original_name = from_imports[base_name]
                full_mod_name = f"{mod_name}.{original_name}"
                path = self.resolve_to_path(full_mod_name)
                if path:
                    self.trace_and_extract(path, attr_name)
                else:
                    path = self.resolve_to_path(mod_name)
                    if path:
                        self.trace_and_extract(path, original_name)
            elif base_name in imports:
                mod_name = imports[base_name]
                path = self.resolve_to_path(mod_name)
                if path:
                    self.trace_and_extract(path, attr_name)
            elif base_name == "self":
                self.trace_and_extract(file_path, attr_name)

        for name in referenced_names:
            if name in from_imports:
                mod_name, original_name = from_imports[name]
                path = self.resolve_to_path(mod_name)
                if path:
                    self.trace_and_extract(path, original_name)
            elif name in imports:
                mod_name = imports[name]
                path = self.resolve_to_path(mod_name)
                if path:
                    self.trace_and_extract(path, "")
            elif name in local_defs and name != target_name:
                self.trace_and_extract(file_path, name)

    def run(
        self,
        start_func: str,
        include_targets: list | None = None,
        exclude_patterns: list | None = None,
    ) -> str:
        """[メイン処理] AST探索 + includesファイルの追加"""
        include_targets = include_targets or []
        exclude_patterns = exclude_patterns or []

        print(f"▶ [プロセス 1/2: entry_file からのAST解析・追跡を開始]")
        # 1. 指定された関数から紐づくファイルを追跡・収集
        self.trace_and_extract(self.entry_file, start_func)

        # 2. includes の指定があれば、コンテナベースディレクトリ(/src)を基準に追加ファイルを強制追加
        if include_targets:
            print(f"▶ [プロセス 2/2: includes で指定された追加ファイルの走査]")
            self.scan_and_collect_includes(
                target_dir=self.container_base_dir,
                include_targets=include_targets,
                exclude_patterns=exclude_patterns,
                verbose=False,
            )

        # マークダウン生成の基準パスも /src に統一 (01とファイルパス表現を揃える)
        return self.generate_markdown(self.container_base_dir)


if __name__ == "__main__":
    config_data = BaseSnippetGenerator.load_config_from_stdin()

    entry_file_setting = config_data.get("entry_file")
    entry_point_name = config_data.get("entry_point_name")
    includes = config_data.get("includes", [])
    excludes = config_data.get("excludes", [])
    output_file_name = config_data.get("output_file_name", "context.md")
    enable_tree = config_data.get("enable_tree", True)
    max_excluded_depth = config_data.get("max_excluded_depth", 2)

    if not entry_file_setting or not entry_point_name:
        print(
            "❌ エラー: entry_file と entry_point_name は必須です。設定JSONファイルで指定してください"
        )
        sys.exit(1)

    container_base_dir = Path("/src")

    # パス設定の解決
    setting_path = Path(entry_file_setting)
    if setting_path.is_absolute():
        entry_file = setting_path
    else:
        entry_file = (container_base_dir / setting_path).resolve()

    # チェイサーの初期化と実行
    generator = ASTSnippetGenerator(
        str(entry_file), enable_tree=enable_tree, max_excluded_depth=max_excluded_depth
    )

    markdown_result = generator.run(
        entry_point_name, include_targets=includes, exclude_patterns=excludes
    )

    # ファイル出力
    generator.write_output_file(markdown_result, output_file_name)

    # ターミナルログ出力への引数渡し
    generator.print_token_stats(container_base_dir, markdown_result, includes, excludes)

    # AST固有の実行設定のログ出力（最後に表示）
    print(
        f"  - 🎯 AST起点情報   : Entry={entry_file_setting}, Func={entry_point_name}\n"
    )
