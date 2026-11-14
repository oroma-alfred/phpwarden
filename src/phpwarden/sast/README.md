# phpwarden SAST engine — layers 1 and 2

The foundation of the PHP security analyser. Layer 1 is a real PHP 8.3 parser;
layer 2 is a whole-program model on top of it. Later layers (taint engine, type
inference, framework models) consume these; the existing token-based scanner
(`phpwarden/code.py`) is untouched and keeps working until they replace it.
Standard library only, Python 3.8+.

```python
from phpwarden.sast import parse
from phpwarden.sast.project import Project

res = parse(open("x.php", encoding="latin-1").read(), "x.php")
res.stmts, res.errors, res.comments          # never raises

proj = Project.load("/path/to/app")          # parse + index + call graph
proj.method_lookup("App\\Repo\\Users", "find")
proj.callgraph.callers_of("m:app\\db\\db::query")
```

## Layer 1: lexer and parser

* `lexer.py` — hand-written lexer. Tokens are `(type, value, offset)`. Inline
  HTML, `<?php` / `<?=` / `?>`, every string form, heredoc/nowdoc (indented
  closing markers), casts, attributes, docblocks. Interpolated strings carry
  parts whose expressions are already tokenised with offsets into the same
  source. Source is decoded as latin-1, so offsets are byte offsets and
  identifiers follow PHP's byte rules.
* `parser.py` — recursive descent for statements, Pratt parsing for
  expressions with PHP's precedence table (incl. the assignment-inside-`&&`
  quirk, `!` below `instanceof`, `+` above `.`). Error recovery skips to the
  next `;` or closing brace at the same depth, records a `ParseError` with
  line and column, and carries on; a lexer error keeps everything before it.
* `ast.py` — one `Node` class: `kind`, `line`, `col` and kind-specific fields.
  `walk()`, `find()`, `dump()` traverse generically.

### Node kinds and fields

Statements: `InlineHTML(text)`, `Echo(exprs, short)`, `ExprStmt(expr)`,
`If(cond, body, elifs[ElseIf(cond, body)], else_, alt)`, `While(cond, body)`,
`DoWhile`, `For(init, cond, step, body)`, `Foreach(subject, key, value, byref, body)`,
`Switch(cond, cases[Case(test, body)])`, `Break/Continue(levels)`, `Return(expr)`,
`Global(vars)`, `Static(vars[StaticVar(name, default)])`, `Unset(vars)`,
`Try(body, catches[Catch(types, var, body)], finally_)`, `Goto(label)`, `Label(name)`,
`Block(body)`, `Declare(directives, body)`, `Namespace(name, body, braced)`,
`Use(uses[UseItem(name, alias, type)])`, `Const(consts[ConstItem(name, value)])`,
`HaltCompiler`.

Declarations: `Function(name, params, byref, rtype, body, attrs, doc)`,
`Class(type: class|interface|trait|enum, name, parent, interfaces, flags, members, attrs, doc, backing)`,
members `Method(name, params, flags, byref, rtype, body|None, attrs, doc)`,
`Property(props[PropItem(name, default)], flags, type, attrs, doc)`,
`ClassConst(consts, flags, type)`, `EnumCase(name, value)`,
`TraitUse(traits, adaptations[TraitInsteadof | TraitAlias])`,
`Param(name, type, byref, variadic, default, flags, attrs)`, `Type(names, nullable, text)`,
`Attribute(name, args)`.

Expressions: `Var(name: str | Node)`, `Name(name)`, `MagicConst(name)`, `Int`, `Float`,
`String(value, raw, quote)`, `Interp(parts, quote)`, `ShellExec(parts)`,
`Array/List(items[ArrayItem(key, value, byref, unpack)])`, `BinOp(op, left, right)`,
`Assign(op, target, value)`, `AssignRef(target, value)`, `UnaryOp(op, expr)`,
`Cast(type, expr)`, `IncDec(op, prefix, var)`, `Ternary(cond, then|None, else_)`,
`Instanceof(expr, cls)`, `Clone(expr)`, `New(cls: Name | expr | Class, args)`,
`Call(func, args, callable)`, `MethodCall(obj, name, args, nullsafe, callable)`,
`StaticCall(cls, name, args, callable)`, `PropFetch(obj, name, nullsafe)`,
`StaticProp(cls, name)`, `ClassConst(cls, name)`, `ArrayDim(var, dim)`,
`Arg(value, name, unpack)`, `Closure(params, uses[ClosureUse], byref, static, rtype, body)`,
`ArrowFn(params, byref, static, rtype, expr)`, `Match(subject, arms[MatchArm(conds|None, body)])`,
`Throw(expr)`, `Isset(vars)`, `Empty(expr)`, `Exit(expr)`, `Print(expr)`,
`Include(type, expr)`, `Eval(expr)`, `Yield(key, value)`, `YieldFrom(expr)`, `Ref(expr)`.
`callable=True` marks first-class callable syntax `f(...)`.

## Layer 2: whole-program model

* `symbols.py` — `NameCtx` (namespace, `use` imports, enclosing class) and
  `qualify()` implementing PHP's name resolution; `ClassSym`, `MethodSym`,
  `FuncSym`, `PropSym`; docblock parsing (`@param`, `@var`, `@return`, `@property`).
* `project.py` — `Project`: discovers files, reads Composer autoload
  (psr-4, psr-0, classmap, files) for the project and every vendor package,
  parses and indexes every file. Vendor is resolution-only: in the default
  `vendor="lazy"` mode a vendor class is parsed the first time it is needed,
  vendor `files` autoloads (helpers) are parsed up front, and `FileInfo.vendor`
  tells later layers not to report there. Query API: `resolve_class`,
  `get_class`, `resolve_function`, `method_lookup` (own → traits with
  insteadof/as → parents → interfaces), `implementations`, `prop_types`,
  `const_values`, `iter_functions`.
* `FunctionRec` — the unit later layers analyse: every function, method,
  closure/arrow fn (`c:<file>:<line>:<col>`), and each file's top-level code
  (`file:<rel path>`). Keys: `f:<fq lower>`, `m:<class fq lower>::<name lower>`.
* `callgraph.py` — edges per unit: `call`, `static`, `method` (receiver typed
  by `$this`, `new`, typed params/properties/promoted ctor params, declared
  return types, `@var`/`@param`/`@return`), `method-impl` (interface or
  abstract receiver → implementations), `method-name` (unknown receiver, only
  if the name is unique in the project), `new`, `callback` (call_user_func*,
  array_map, usort, preg_replace_callback, add_action/add_filter,
  register_rest_route, ...), `route` (Laravel `Route::get(..., [Ctl::class, 'm'])`
  and `'Ctl@m'`), `include`, `defines` (unit → its closures).
* Include resolution — paths are evaluated to sets of alternatives
  (literals, `__DIR__`/`__FILE__`, `dirname()`, `define()`/`const` constants,
  string variables assigned earlier in the unit, with branch assignments kept as
  alternatives). A path with a run-time part becomes a pattern matched against
  the project's files (`"…/source/{$file}"` → every file in `source/`); a
  leading run-time root (`DOL_DOCUMENT_ROOT . '/core/x.php'`) matches any
  directory prefix; a pattern matching more than 40 files is marked `broad` and
  not expanded. `IncludeSite` records targets, `dynamic`, `pattern`, `broad`.

## How later layers plug in

* **Taint engine (layer 3+)**: iterate `project.iter_functions()`, walk each
  `FunctionRec.body` with the AST, and compute per-unit summaries
  (parameter → sink, parameter → return, source → return, property writes);
  propagate across `callgraph` edges to a fixed point. Include edges give the
  file-to-file flow for top-level code (`file:` units). Findings use the same
  result shape as `code.scan_project` (rule, severity, cwe, file, line, column,
  snippet, message, fix, context) so `to_sarif` and the CLI stay unchanged.
* **Type inference**: replaces `callgraph._Unit.infer` with a flow-sensitive
  version (per-branch environments, generics from docblocks); the call graph is
  rebuilt with it, nothing else changes.
* **Framework models**: add entries to the source/sink/sanitizer tables and to
  the call graph (routes, hooks, container bindings) keyed by fully-qualified
  names, e.g. `Illuminate\Http\Request::input` as a source, `wpdb::query` as a
  sink — resolution through `method_lookup` makes subclasses and traits work.

## Known gaps

* Property hooks (PHP 8.4) are skipped, not modelled; asymmetric visibility is
  accepted. Nothing else in PHP 8.3 is known to be unsupported.
* Type inference is flow-insensitive within a unit (last assignment wins), and
  does not follow array element types or generics.
* Dynamic calls `$f()`, `$obj->$name()` and `new $class` with run-time names
  produce no edges unless the value is a closure or a literal.
* Include alternatives come from one unit; values assigned in another file are
  only seen through constants.
