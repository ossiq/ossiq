"""Main module."""

import pprint
from collections import namedtuple
from typing import List

from pathlib import Path
from tree_sitter import Language, Parser, Query, QueryCursor

import tree_sitter_javascript as js
import tree_sitter_typescript as ts

from .api_index import PackageApiIndex, Params, Entry

ASSIGNMENT_EXPRESSION = 210
MEMBER_EXPRESSION = 208
FUNCTION_EXPRESSION = 200
IDNETIFIER = 1
FORMAL_PARAMETERS = 232

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


def extract_function_params(node) -> List[Params]:
    """
    Extract function parameters.
    """
    name = None
    params: List[Params] = []
    for child in node.children:
        if child.kind_id == IDNETIFIER:
            name = child.text.decode("utf-8")
        if child.kind_id == FORMAL_PARAMETERS:
            params = []
            for p in child.children:
                if p.kind_id == IDNETIFIER:
                    # FIXME: take care of types later
                    # TODO: make use of p.is_named
                    params.append({
                        "name": p.text,
                        "type": None
                    })
                elif p.type == "required_parameter":
                    import ipdb
                    ipdb.set_trace()

    return name, params


def parse_files_with_tree_sitter(index: PackageApiIndex, root_dir: str, language):
    parser = Parser(language)

    exports = {"functions": {}, "classes": {},
               "methods": {}, "constructors": {}}
    # print(root_dir, "lookup", EXTENSIONS[language])
    for path in Path(root_dir).rglob(EXTENSIONS[language]):
        # print(path)
        source_code = path.read_text(encoding="utf8")
        tree = parser.parse(bytes(source_code, "utf8"))

        query = Query(
            language,
            """
              (assignment_expression
                  left: (member_expression
                    property: (property_identifier) @property_name)
                  right: (function_expression
                    parameters: (formal_parameters) @func_params)) @method_decl

            """)

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

        (constructor
                parameters: (formal_parameters) @ctor_params) @ctor_decl


        [[
            (export_statement (declaration)) @capture
            ]])
        """

        query_cursor = QueryCursor(query)
        captures = query_cursor.captures(tree.root_node)

        # import pdb; pdb.set_trace()
        for capture_name, nodes in captures.items():
            for node in nodes:
                # TODO: let's cover assignment declarations, e.g. i18n.$tc = function () { ... }
                # TODO: we would need to trace back to i18n.$tc assignment declaration if i18n exported down in the bottom
                file_path = str(path)
                doc = get_jsdoc_above(node, source_code)
                signature = source_code[node.start_byte:node.end_byte]

                # NOTE: this is what was requested via query, so no worries about multiple assignments in a row
                if node.kind_id == ASSIGNMENT_EXPRESSION and len(node.children) == 3:
                    left_side, _, right_side = node.children
                    member_id = None
                    if left_side.kind_id == MEMBER_EXPRESSION:
                        member_id = left_side.text

                    if right_side.kind_id == FUNCTION_EXPRESSION:
                        fn_name, params = extract_function_params(right_side)

                        # child_by_field_name("property").text
                    index.register(
                        Entry(
                            file=file_path,
                            member_id=member_id.decode("utf-8"),
                            name=fn_name,
                            params=params,
                            signature=signature,
                            doc=doc
                        )
                    )
                else:
                    # import ipdb; ipdb.set_trace()
                    print("\n")
                    pprint.pprint({
                        "type": node.type,
                        "signature": signature,
                        "name": node.text,
                        "parent": node.parent
                    })

                # TODO: also probably parse exported constants changes, would be nice
                # FIXME: if there are multiple assignments parse differently
                # e.g. const a = b = c = () => { return 0 };

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
    # import ipdb; ipdb.set_trace()
    return index
