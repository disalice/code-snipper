from pathlib import Path

from base_generator import BaseSnippetGenerator


class AllSnippetGenerator(BaseSnippetGenerator):
    def __init__(
        self,
        target_dir: str,
        include_targets: list,
        exclude_patterns: list,
        enable_tree: bool,
        max_excluded_depth: int,
    ) -> None:
        super().__init__(enable_tree=enable_tree, max_excluded_depth=max_excluded_depth)
        self.target_dir = Path(target_dir).resolve()
        self.include_targets = include_targets
        self.exclude_patterns = exclude_patterns

    def collect_files(self) -> None:
        print("▶ [プロセス 1/3: ファイルリストの走査・検出]")
        self.scan_and_collect_includes(
            target_dir=self.target_dir,
            include_targets=self.include_targets,
            exclude_patterns=self.exclude_patterns,
            verbose=True,
        )
        print("▶ [プロセス 3/3: マークダウン生成準備完了]")


if __name__ == "__main__":
    config_data = BaseSnippetGenerator.load_config_from_stdin()
    container_base_dir = Path("/src")

    includes = config_data.get("includes", [])
    excludes = config_data.get("excludes", [])
    output_file_name = config_data.get("output_file_name", "all_context.md")
    enable_tree = config_data.get("enable_tree", True)
    max_excluded_depth = config_data.get("max_excluded_depth", 2)

    generator = AllSnippetGenerator(
        str(container_base_dir),
        include_targets=includes,
        exclude_patterns=excludes,
        enable_tree=enable_tree,
        max_excluded_depth=max_excluded_depth,
    )

    generator.collect_files()

    if not generator.collected_files:
        print("⚠️ 条件に一致するテキストファイルが見つかりませんでした。")

    markdown_result = generator.generate_markdown(container_base_dir)
    generator.write_output_file(markdown_result, output_file_name)

    # ターミナルログ出力への引数渡し
    generator.print_token_stats(container_base_dir, markdown_result, includes, excludes)
