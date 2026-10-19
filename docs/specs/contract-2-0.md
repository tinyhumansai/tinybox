# Contract 2.0: remove command policy from TinyBox

Contract 2.0 is a breaking major version. `tinybox_bus::is_compatible` accepts
only a module with the same major and a minor version at least as new as the
host contract. A 1.x host must reject a 2.x module, and a 2.x host must reject a
1.x module. There is no compatibility fallback that applies TinyBox command
policy or reconstructs removed results.

Contract 2.0 removes the `AnalyzeCommand` method and its command-analysis
vocabulary: `CommandClass`, `CommandSegment`, `CommandAnalysis`, command
classification, executor signals, leading-environment-assignment signals,
environment guards, hidden-execution detection, expansion, tee, background,
and literal-word results. TinyBox does not decide whether a command is safe,
requires approval, or may run.

`AnalyzeShell` remains a structural scanner. Its result contains only live
segments after quoted heredoc bodies are removed and whether an unquoted output
redirect occurs outside heredoc data. It does not report whether shell syntax
executes hidden commands. Shell quoting, argument-vector rendering, and script
transport helpers remain for TinyBox's SSH and detached-process transports.

Hosts that need command classification or execution policy must use
TinySecurity's policy contract. The 1.22 deprecation window and this breaking
removal are separate from package release versions.
