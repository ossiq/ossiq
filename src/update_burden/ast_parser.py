"""Main module."""

from collections import namedtuple

from pathlib import Path
from tree_sitter import Language, Parser, Query, QueryCursor

import tree_sitter_javascript as js
import tree_sitter_typescript as ts


Entry = namedtuple("Entry", ["file", "signature", "params", "doc"])


# ---- Tree-sitter setup ----
JS_LANGUAGE = Language(js.language())
TS_LANGUAGE = Language(ts.language_typescript())
TSX_LANGUAGE = Language(ts.language_tsx())

EXTENSIONS = {
    JS_LANGUAGE: "**/*.js",
    TS_LANGUAGE: "**/*.ts",
    TSX_LANGUAGE: "*.tsx",
    # TODO: jsx
}

# ---- Parsing helpers ----
def get_jsdoc_above(node, source_code):
    start_byte = node.start_byte
    prefix = source_code[:start_byte]
    lines = prefix.splitlines()
    docs = []
    for line in reversed(lines):
        if line.strip().startswith(("/**", "*", "*/", "//", "/*")):
            docs.insert(0, line.strip())
        elif line.strip() == "":
            continue
        else:
            break
    return "\n".join(docs)

def extract_params(node, source_code):
    params = []
    for child in node.children:
        if child.type in ("formal_parameters", "parameters"):
            for p in child.children:
                if p.type == "identifier":
                    params.append({"name": source_code[p.start_byte:p.end_byte], "type": None})
                elif p.type == "required_parameter":
                    ident = p.child_by_field_name("name")
                    ts_type = p.child_by_field_name("type")
                    params.append({
                        "name": source_code[ident.start_byte:ident.end_byte] if ident else None,
                        "type": source_code[ts_type.start_byte:ts_type.end_byte] if ts_type else None,
                    })
    return params

def parse_files_with_tree_sitter(root_dir, language):
    parser = Parser(language)

    exports = {"functions": {}, "classes": {}, "methods": {}, "constructors": {}}
    print(root_dir, "lookup", EXTENSIONS[language])
    for path in Path(root_dir).rglob(EXTENSIONS[language]):
        print(path)
        source_code = path.read_text(encoding="utf8")
        tree = parser.parse(bytes(source_code, "utf8"))
        
        query = Query(
            language, 
            """
              (export_statement
                  (function_declaration
                    name: (identifier) @func_name)) @func_decl

              (export_statement
                  (class_declaration
                    name: (identifier) @class_name)) @class_decl

              (method_definition
                  name: (property_identifier) @method_name) @method_decl
              (pair
                  (property_identifier) @property_name
                  .
                  (function_expression
                    parameters: (formal_parameters) @func_params)) @method_decl

              (assignment_expression
                  left: (member_expression
                    property: (property_identifier) @property_name)
                  right: (function_expression
                    parameters: (formal_parameters) @func_params)) @method_decl

            """)
        """
        (constructor
                parameters: (formal_parameters) @ctor_params) @ctor_decl
        """
        
        query_cursor = QueryCursor(query)
        captures = query_cursor.captures(tree.root_node)

        # import pdb; pdb.set_trace()
        for capture_name, nodes in captures.items():
            for node in nodes:
                import pdb; pdb.set_trace()

                # TODO: let's cover assignment declarations, e.g. i18n.$tc = function () { ... }
                # TODO: we would need to trace back to i18n.$tc assignment declaration if i18n exported down in the bottom
                entry = Entry(
                    file=str(path),
                    signature=source_code[node.start_byte:node.end_byte][:200],
                    params=extract_params(node, source_code),
                    doc=get_jsdoc_above(node, source_code),
                )

                # then export const x = () => ...
                # export const f = function () { }
                # const f = () => ...; export f;
                # const f = () => ...; export { f };
                # const f = () => ...; export default f;
                # 
            """
            entry = {
                "file": str(path),
                "signature": source_code[node.start_byte:node.end_byte][:200],
                "params": extract_params(node, source_code),
                "doc": get_jsdoc_above(node, source_code),
            }

            if cap == "func_name":
                name = source_code[node.start_byte:node.end_byte]
                exports["functions"][name] = entry
            elif cap == "class_name":
                name = source_code[node.start_byte:node.end_byte]
                exports["classes"][name] = entry
            elif cap == "method_name":
                name = source_code[node.start_byte:node.end_byte]
                exports["methods"][f"{name}@{entry['file']}:{node.start_point[0]}"] = entry
            elif cap == "ctor_params":
                exports["constructors"][f"{entry['file']}:{node.start_point[0]}"] = entry
            """
    return exports
