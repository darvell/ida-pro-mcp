# IDA Pro MCP

An [MCP server](https://modelcontextprotocol.io/introduction) that connects AI assistants to IDA Pro. Ask your AI to analyze a binary, rename variables, decompile functions, and annotate code, all through natural language.

## Prerequisites

- [Python](https://www.python.org/downloads/) 3.11 or higher
- [IDA Pro](https://hex-rays.com/ida-pro) 9.x (8.3+ may work, IDA Free is not supported)
- A supported MCP client: [Claude](https://claude.ai/download), [Cursor](https://cursor.com), [Cline](https://cline.bot), [Roo Code](https://roocode.com), [Windsurf](https://windsurf.com), or [any other MCP client](https://modelcontextprotocol.io/clients)

## Installation

Install the package and set up the IDA plugin and MCP client configs in one step:

```sh
pip install https://github.com/darvell/ida-pro-mcp/archive/refs/heads/main.zip
ida-pro-mcp --install
```

This installs the IDA plugin (symlinked into your IDA plugins folder) and writes the MCP server config for Claude, Cursor, and Claude Code automatically.

Restart IDA and your MCP client after installing. You need to open a binary in IDA before the plugin appears under Edit > Plugins > MCP.

To uninstall:

```sh
ida-pro-mcp --uninstall
```

## SSE Transport

To run the server over SSE instead of stdio (useful for remote clients):

```sh
ida-pro-mcp --transport http://127.0.0.1:8744/sse
```

## Available Tools

Every tool that targets a specific IDA database accepts `database` as its first argument. Pass the filename of the IDB (IDA database file) and the server routes to the right IDA instance.

### Discovery & Navigation

- `list_instances()`: list all active IDA Pro instances
- `info(database)`: database info, architecture, entry point, cursor position
- `overview(database)`: one-call binary overview with segments, top functions, and sample strings
- `survey_binary(database)`: ranked triage of interesting strings, functions, and imports by xref count
- `get_segments(database)`: memory segments and sections
- `list_functions(database)`: list functions with regex filter and pagination
- `list_globals(database)`: list global variables
- `entity_query(database, name)`: look up any named entity (function, global, import, string)
- `func_query(database, selector)`: detailed info for a single function
- `imports_list(database)`: all imports grouped by module
- `imports_query(database, filter)`: search imports by name pattern
- `search(database, query)`: search for bytes, immediates, or text patterns
- `search_strings(database, pattern)`: find strings in the binary

### Analysis

- `decompile(database, selector)`: Hex-Rays pseudocode for a function
- `decompile_batch(database, selectors)`: decompile multiple functions in one call
- `disassemble(database, selector)`: assembly for a function or address range
- `analyze_function_compact(database, selector)`: deep single-function analysis with decompilation, string refs, constants, and callers/callees
- `analyze_component(database, selectors)`: multi-function group analysis with call graph and shared globals
- `get_callgraph(database, target)`: callers and/or callees as a nested tree
- `get_xrefs(database, target)`: cross-references to or from an address
- `basic_blocks(database, selector)`: basic block boundaries for CFG analysis
- `find_insns(database, selector)`: find instructions matching a mnemonic or operand pattern
- `trace_data_flow(database, start)`: BFS xref traversal forward or backward from an address
- `infer_types(database, selector)`: auto-infer types using Hex-Rays

### Memory & Data

- `read_bytes(database, address)`: hex dump at an address
- `get_int(database, address)`: read a typed integer at an address
- `get_string(database, address)`: read a null-terminated string
- `get_global_value(database, name)`: read a named global variable's value
- `read_struct(database, address, struct_name)`: read memory as a struct

### Renaming & Annotation

- `rename(database, target, new_name)`: rename a function, global, or struct field (batch supported)
- `set_type(database, target, type_str)`: set a function or variable type
- `set_comment(database, address, comment)`: add a comment at an address
- `append_comments(database, address, comment)`: append to an existing comment
- `diff_before_after(database, selector)`: apply rename/type/comment and show before/after decompilation

### Types & Structures

- `create_struct(database, name, definition)`: create a struct from a C definition
- `declare_type(database, declaration)`: register a C type declaration
- `enum_upsert(database, name, members)`: create or update an enum
- `type_query(database)`: query the local type library
- `type_inspect(database, name)`: get full details of a named type
- `type_apply_batch(database, items)`: apply types to multiple addresses at once
- `search_structs(database, filter)`: search struct/union definitions

### Stack Frames

- `stack_frame(database, selector)`: get the stack frame layout for a function
- `declare_stack(database, selector, offset, name)`: add or modify a stack variable
- `delete_stack(database, selector, offset)`: remove a stack variable

### Patching

- `patch_bytes(database, address, hex_bytes)`: write raw bytes
- `put_int(database, address, value)`: write a typed integer
- `patch_asm(database, address, assembly)`: assemble and patch an instruction
- `define_func(database, address)`: create a function at an address
- `define_code(database, address)`: convert bytes to instructions
- `undefine(database, address)`: revert bytes to raw data

### Scripting

- `script_exec(database, script)`: execute arbitrary Python in IDA's environment
- `py_eval(database, code)`: Jupyter-style Python expression evaluation
- `py_exec_file(database, path)`: run a Python script file in IDA

### Async Jobs

Some long-running operations (large decompilations, batch analysis) may exceed the request timeout. When they do, the server returns a `job_id` instead of blocking; the operation continues in the background. Poll with `job_status` until it finishes, then retrieve the result with `job_result`.

- `job_status(database, job_id)`: check whether a background job has finished
- `job_result(database, job_id)`: retrieve the result once it completes

### Utilities

- `int_convert(value)`: convert between hex, decimal, octal, binary, and ASCII
- `idb_save(database)`: save the IDA database
- `open_file(database, path)`: launch a new IDA instance with a binary

### Debugger

These tools require an active debug session.

- `dbg_start(database)`: start a debugger session
- `dbg_exit(database)`: terminate the debugger
- `dbg_continue(database)`: continue execution
- `dbg_run_to(database, address)`: run to an address
- `dbg_step_into(database)`: step into the next instruction
- `dbg_step_over(database)`: step over the next instruction
- `dbg_bps(database)`: list breakpoints
- `dbg_add_bp(database, address)`: add a breakpoint
- `dbg_delete_bp(database, address)`: delete a breakpoint
- `dbg_toggle_bp(database, address)`: toggle a breakpoint
- `dbg_regs(database)`: read general purpose registers
- `dbg_regs_all(database)`: read all register groups
- `dbg_stacktrace(database)`: get the call stack
- `dbg_read(database, address)`: read memory from the debuggee
- `dbg_write(database, address, hex_bytes)`: write memory to the debuggee

## Prompt Engineering

LLMs hallucinate, so give them explicit instructions. A minimal starting prompt for crackme analysis:

> Analyze this binary in IDA Pro using the MCP tools.
> - Start with `overview` or `survey_binary` to orient yourself
> - Decompile interesting functions, add comments, rename variables
> - Fix pointer and array types where needed
> - Use `int_convert` for number conversion — never convert bases yourself
> - Do not brute-force; derive solutions from the disassembly
> - Write a report.md summarizing your findings

## Tips

- Run FLIRT/Lumina before starting to resolve library functions. LLMs do much better without noise from unidentified standard library code.
- Strip obfuscation (string encryption, control flow flattening, import hashing) before handing the binary to an LLM.
- Use `analyze_function_compact` or `analyze_component` for richer context in a single call.
- `decompile_batch` cuts round-trips significantly when following a call chain.

## Development

To test the MCP server locally:

```sh
uv run mcp dev src/ida_pro_mcp/server.py
```

This opens a web UI at http://localhost:5173 for interactive tool testing.

The plugin is split into a modular package under `src/ida_pro_mcp/plugin/`. Each `api_*.py` file covers a domain (analysis, types, debug, memory, etc.). The shim `mcp-plugin.py` loads the package automatically.

To add a new tool, add a `@jsonrpc` function to the appropriate `plugin/api_*.py` module and a corresponding `@mcp.tool()` wrapper in `server.py`.

Generate a changelog of commits since a tag:

```sh
git log --first-parent --no-merges 2.0.0..main "--pretty=- %s"
```
