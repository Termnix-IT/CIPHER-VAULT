# CLAUDE.md

このリポジトリの作業ルール、構成、コマンド、検証方法は `AGENTS.md` に集約している。同じ内容を二重に管理しないよう、ここでは読み込みとClaude Code向けの読み替えだけを記載する。

@AGENTS.md

## Claude Code向けの読み替え

- `AGENTS.md` とグローバル設定が矛盾する場合は `AGENTS.md` を優先する。たとえばstage・commit・push・リリース公開は、ユーザーの明示的な依頼があるまで行わない。
- Codex固有の記述は、`codex/` ブランチ接頭辞を `claude/`、`explorer` サブエージェントを `Explore`、`worker` サブエージェントを `general-purpose` と読み替える。
- 構成・コマンド・検証手順を変更した場合は、このファイルではなく `AGENTS.md` と `docs/` の該当箇所を更新する。
