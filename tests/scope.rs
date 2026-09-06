use obf::scope::{self, Analysis, BindingKind, PreserveReason, ScopeKind};
use obf::{minify, minify_with_options, MinifyOptions, Target};

fn bindings(analysis: &Analysis, name: &str) -> Vec<usize> {
    analysis
        .bindings
        .iter()
        .enumerate()
        .filter_map(|(id, binding)| (binding.name == name).then_some(id))
        .collect()
}

fn references(analysis: &Analysis, name: &str) -> Vec<Option<usize>> {
    analysis
        .references
        .iter()
        .filter(|reference| reference.name == name)
        .map(|reference| reference.binding)
        .collect()
}

#[test]
fn initializers_see_previous_bindings_not_new_siblings() {
    for target in [Target::Lua51, Target::Luau] {
        let source =
            "local value=1 local value,other=value,function() return other end return value,other";
        let analysis = scope::analyze(source, target).unwrap();
        let values = bindings(&analysis, "value");
        let other = bindings(&analysis, "other")[0];
        assert_eq!(
            references(&analysis, "value"),
            [Some(values[0]), Some(values[1])]
        );
        assert_eq!(references(&analysis, "other"), [None, Some(other)]);
        assert!(analysis.globals.contains("other"));
        for reference in &analysis.references {
            assert_eq!(
                &source[reference.span.start..reference.span.end],
                reference.name
            );
        }
    }
}

#[test]
fn recursive_declarations_and_anonymous_initializers_differ() {
    for target in [Target::Lua51, Target::Luau] {
        let analysis = scope::analyze(
            "local recursiveName=1 do local recursiveName=function() return recursiveName end end local function recursiveName() return recursiveName end return recursiveName",
            target,
        ).unwrap();
        let ids = bindings(&analysis, "recursiveName");
        assert_eq!(ids.len(), 3);
        assert_eq!(
            references(&analysis, "recursiveName"),
            [Some(ids[0]), Some(ids[2]), Some(ids[2])]
        );
        assert!(analysis.bindings[ids[0]].captured);
        assert!(!analysis.bindings[ids[1]].captured);
        assert!(analysis.bindings[ids[2]].captured);
    }
}

#[test]
fn transitive_upvalues_cross_each_enclosing_function() {
    let analysis = scope::analyze(
        "local capturedValue=1 local function outerFunction() local function innerFunction() capturedValue=capturedValue+1 return capturedValue end return innerFunction end",
        Target::Lua51,
    ).unwrap();
    let captured = bindings(&analysis, "capturedValue")[0];
    assert!(analysis.bindings[captured].captured);
    let functions: Vec<_> = analysis
        .scopes
        .iter()
        .filter(|scope| scope.kind == ScopeKind::Function)
        .collect();
    assert_eq!(functions.len(), 2);
    assert!(functions
        .iter()
        .all(|scope| scope.upvalues.contains(&captured)));
}

#[test]
fn loop_initializers_and_repeat_conditions_have_distinct_visibility() {
    for target in [Target::Lua51, Target::Luau] {
        let analysis = scope::analyze(
            "local count=3 for count=count,count+1 do print(count) end repeat local repeatName=count count=repeatName until repeatName>0 return count,repeatName",
            target,
        ).unwrap();
        let count = bindings(&analysis, "count");
        assert_eq!(
            references(&analysis, "count"),
            [
                Some(count[0]),
                Some(count[0]),
                Some(count[1]),
                Some(count[0]),
                Some(count[0]),
                Some(count[0])
            ]
        );
        let repeated = bindings(&analysis, "repeatName")[0];
        assert_eq!(
            references(&analysis, "repeatName"),
            [Some(repeated), Some(repeated), None]
        );
        let analysis = scope::analyze(
            "local iterator={1} for key,iterator in ipairs(iterator) do print(iterator) end return iterator",
            target,
        ).unwrap();
        let iterator = bindings(&analysis, "iterator");
        assert_eq!(
            references(&analysis, "iterator"),
            [Some(iterator[0]), Some(iterator[1]), Some(iterator[0])]
        );
        assert_eq!(analysis.bindings[iterator[1]].kind, BindingKind::GenericFor);
    }
}

#[test]
fn method_self_and_explicit_self_are_different_bindings() {
    for target in [Target::Lua51, Target::Luau] {
        let analysis = scope::analyze(
            "local self=1 local object={} function object:method() return function() return self end end function object:explicit(self) return self end return self",
            target,
        ).unwrap();
        let ids = bindings(&analysis, "self");
        assert_eq!(ids.len(), 4);
        assert_eq!(analysis.bindings[ids[1]].kind, BindingKind::ImplicitSelf);
        assert_eq!(analysis.bindings[ids[1]].declaration, None);
        assert!(analysis.bindings[ids[1]].captured);
        assert_eq!(analysis.bindings[ids[2]].kind, BindingKind::ImplicitSelf);
        assert_eq!(analysis.bindings[ids[3]].kind, BindingKind::Parameter);
        assert_eq!(
            references(&analysis, "self"),
            [Some(ids[1]), Some(ids[3]), Some(ids[0])]
        );
        assert!(!analysis
            .references
            .iter()
            .any(|reference| reference.name == "method" || reference.name == "explicit"));
    }
}

#[test]
fn untyped_vararg_records_lua51_implicit_arg_after_explicit_parameters() {
    let source = "local arg=1 local function arguments(arg,...) return function() return arg end end return arg";
    let chunk = obf::parse(source, Target::Lua51).unwrap();
    let obf::ast::StatementKind::LocalFunction { body, .. } = &chunk.block.statements[1].kind
    else {
        panic!()
    };
    assert!(body.has_vararg);
    assert!(body.vararg.is_none());
    let lua = scope::analyze(source, Target::Lua51).unwrap();
    let ids = bindings(&lua, "arg");
    assert_eq!(ids.len(), 3);
    assert_eq!(lua.bindings[ids[2]].kind, BindingKind::ImplicitArg);
    assert_eq!(references(&lua, "arg"), [Some(ids[2]), Some(ids[0])]);
    let luau = scope::analyze(source, Target::Luau).unwrap();
    let ids = bindings(&luau, "arg");
    assert_eq!(ids.len(), 2);
    assert_eq!(references(&luau, "arg"), [Some(ids[1]), Some(ids[0])]);
    assert!(scope::analyze("return arg,...", Target::Lua51)
        .unwrap()
        .bindings
        .is_empty());
}

#[test]
fn luau_entire_function_signature_uses_the_enclosing_value_scope() {
    let source = "local functionName,parameterName=1,2 local function functionName(parameterName:typeof(functionName)):typeof(parameterName) return functionName,parameterName end";
    let analysis = scope::analyze(source, Target::Luau).unwrap();
    let functions = bindings(&analysis, "functionName");
    let parameters = bindings(&analysis, "parameterName");
    assert_eq!(
        references(&analysis, "functionName"),
        [Some(functions[0]), Some(functions[1])]
    );
    assert_eq!(
        references(&analysis, "parameterName"),
        [Some(parameters[0]), Some(parameters[1])]
    );
    minify(source, Target::Luau).unwrap();
}

#[test]
fn luau_type_names_are_separate_but_qualified_prefixes_and_typeof_are_values() {
    let source = "local namespaceValue={} type namespaceValue=number type Imported=namespaceValue.Member local instanceValue:namespaceValue=1 local copyValue:typeof(instanceValue)=instanceValue return namespaceValue,copyValue";
    let analysis = scope::analyze(source, Target::Luau).unwrap();
    let namespace = bindings(&analysis, "namespaceValue")[0];
    assert_eq!(
        references(&analysis, "namespaceValue"),
        [Some(namespace), Some(namespace)]
    );
    assert!(!analysis
        .references
        .iter()
        .any(|reference| reference.name == "Member"));
    assert_eq!(references(&analysis, "instanceValue").len(), 2);
    let output = minify(source, Target::Luau).unwrap();
    assert!(output.contains("type namespaceValue=number"));
    assert!(output.contains(".Member"));
    assert!(!output.contains("namespaceValue.Member"));
}

#[test]
fn exports_host_names_and_type_functions_are_conservatively_preserved() {
    let source = "export const exportedValue=1 export function exportedFunction(longParameter) return longParameter end local game=1 type function IdentityType(typeParameter) local typeLocal=typeParameter return typeLocal end local ordinaryValue=game print(ordinaryValue)";
    let analysis = scope::analyze(source, Target::Luau).unwrap();
    for name in ["exportedValue", "exportedFunction"] {
        assert_eq!(
            analysis.bindings[bindings(&analysis, name)[0]].preserve,
            Some(PreserveReason::Exported)
        );
    }
    for name in ["typeParameter", "typeLocal"] {
        assert_eq!(
            analysis.bindings[bindings(&analysis, name)[0]].preserve,
            Some(PreserveReason::TypeFunction)
        );
    }
    assert_eq!(
        analysis.bindings[bindings(&analysis, "game")[0]].preserve,
        Some(PreserveReason::Reserved)
    );
    let output = minify(source, Target::Luau).unwrap();
    for name in [
        "exportedValue",
        "exportedFunction",
        "IdentityType",
        "typeParameter",
        "typeLocal",
        "game",
    ] {
        assert!(output.contains(name), "{output} lost {name}");
    }
    assert!(!output.contains("ordinaryValue"));
    assert!(!output.contains("longParameter"));
}

#[test]
fn original_short_names_and_globals_cannot_be_captured() {
    for target in [Target::Lua51, Target::Luau] {
        let source = "a=10 local b=2 local longerName=1 return a,b,longerName,longerName";
        let output = minify(source, target).unwrap();
        assert_eq!(output, "a=10 local b=2 local c=1 return a,b,c,c");
        assert_eq!(output, minify(source, target).unwrap());
        let lexical = minify_with_options(
            source,
            target,
            MinifyOptions {
                rename_locals: false,
            },
        )
        .unwrap();
        assert!(lexical.contains("longerName"));
        assert!(output.len() < lexical.len());
    }
}

#[test]
fn shorter_names_go_to_more_frequent_bindings_and_never_lengthen_locals() {
    let mut source = String::new();
    for index in 0..40 {
        source.push_str(&format!("local lengthyVariable{index}={index} "));
    }
    source.push_str("local frequentlyUsed=99 print(frequentlyUsed,frequentlyUsed,frequentlyUsed)");
    let output = minify(&source, Target::Lua51).unwrap();
    assert!(output.contains("local a=99"), "{output}");
    let before = scope::analyze(&source, Target::Lua51).unwrap();
    let after = scope::analyze(&output, Target::Lua51).unwrap();
    for (before, after) in before.bindings.iter().zip(&after.bindings) {
        assert!(after.name.len() <= before.name.len());
    }
}

#[test]
fn allocator_skips_keywords_and_remains_deterministic_beyond_one_letter() {
    let mut source = String::new();
    for index in 0..750 {
        source.push_str(&format!(
            "do local lengthyVariable{index}={index} print(lengthyVariable{index}) end "
        ));
    }
    for target in [Target::Lua51, Target::Luau] {
        let output = minify(&source, target).unwrap();
        assert_eq!(output, minify(&source, target).unwrap());
        assert!(!output.contains("lengthyVariable"));
        let analysis = scope::analyze(&output, target).unwrap();
        let names: std::collections::BTreeSet<_> = analysis
            .bindings
            .iter()
            .map(|binding| &binding.name)
            .collect();
        assert_eq!(names.len(), 750);
        for name in ["do", "if", "in", "or", "and", "end", "for", "nil", "not"] {
            assert!(!names.iter().any(|candidate| candidate.as_str() == name));
        }
    }
}

#[test]
fn reflection_aliases_escaped_fields_and_environment_access_disable_renaming() {
    let tails = [
        "return debug",
        "return getfenv",
        "return setfenv",
        "return _G",
        "return _ENV",
        "return getgenv",
        "return loadstring",
        "return string.dump",
        "return probe.getlocal",
        r#"return probe["get" .. "local"]"#,
        r#"return probe['\103etupvalue']"#,
        "return probe[ [=[getlocal]=] ]",
    ];
    for target in [Target::Lua51, Target::Luau] {
        for tail in tails {
            let source = format!("local retainedLongName=42 {tail}");
            let analysis = scope::analyze(&source, target).unwrap();
            assert!(!analysis.rename_barriers.is_empty(), "{source}");
            assert_eq!(
                minify(&source, target).unwrap(),
                minify_with_options(
                    &source,
                    target,
                    MinifyOptions {
                        rename_locals: false
                    }
                )
                .unwrap()
            );
        }
    }
    let source = "local retainedLongName=42 return probe[`getlocal`]";
    assert!(!scope::analyze(source, Target::Luau)
        .unwrap()
        .rename_barriers
        .is_empty());
}

#[test]
fn fields_methods_and_string_contents_are_not_textually_renamed() {
    let source = "local longerName=1 local objectName={longerName=longerName} function objectName:longerName(argumentName) return argumentName+self.longerName end return objectName:longerName(longerName),\"longerName\"";
    for target in [Target::Lua51, Target::Luau] {
        let output = minify(source, target).unwrap();
        assert!(!output.contains("local longerName="));
        assert!(output.contains("{longerName="));
        assert!(output.contains(":longerName("));
        assert!(output.contains("self.longerName"));
        assert!(output.contains("\"longerName\""));
    }
}

#[test]
fn nested_interpolations_rewrite_only_expression_bindings_and_remove_trivia() {
    let source = "local outsideValue=3 return `literal outsideValue={\n(function(insideValue) -- ignored } `\nlocal temporaryValue=outsideValue+insideValue return `nested={temporaryValue}` end)(2)}`";
    let output = minify(source, Target::Luau).unwrap();
    assert!(output.contains("literal outsideValue="));
    assert!(!output.contains("insideValue"));
    assert!(!output.contains("temporaryValue"));
    assert!(!output.contains("ignored"));
    assert!(!output.contains(['\n', '\r']));
    let table = minify(
        "local longValue=1 return `{ {field=longValue} }`",
        Target::Luau,
    )
    .unwrap();
    assert!(table.contains("{ {field="));
}

#[test]
fn malformed_token_arrays_fail_with_diagnostics_instead_of_panicking() {
    use obf::lexer::{Token, TokenKind};
    for span in [0..100, 2..1, 1..2] {
        let tokens = [Token {
            kind: TokenKind::Identifier,
            span,
            line: 1,
            column: 1,
        }];
        let result =
            std::panic::catch_unwind(|| obf::minify::minify("\u{4e2d}", &tokens, Target::Luau));
        assert!(result.is_ok());
        assert!(result.unwrap().is_err());
    }
    let source = format!("return {}1{}", "(".repeat(300), ")".repeat(300));
    assert!(scope::analyze(&source, Target::Lua51).is_err());
    assert!(minify(&source, Target::Luau).is_err());
}

#[test]
fn long_iterative_chains_are_rejected_before_recursive_ast_drop_can_overflow() {
    let expressions = [
        format!("return {}", vec!["value"; 100_000].join("+")),
        format!("return value{}", ".field".repeat(100_000)),
        format!("return value{}", "()".repeat(100_000)),
    ];
    for target in [Target::Lua51, Target::Luau] {
        for source in &expressions {
            let result = minify(source, target);
            assert!(result.is_err());
            assert!(result.unwrap_err().message.contains("chain"));
        }
    }
    for source in [
        format!("type Value=number{}", "?".repeat(100_000)),
        format!("return value{}", "::number".repeat(100_000)),
    ] {
        assert!(minify(&source, Target::Luau)
            .unwrap_err()
            .message
            .contains("chain"));
    }
}

#[test]
fn bounded_nested_chains_use_iterative_binding_analysis() {
    let mut expression = "longValue".to_owned();
    for _ in 0..40 {
        expression = format!("({expression}{})", "+longValue".repeat(60));
    }
    let source = format!("local longValue=1 return {expression}");
    for target in [Target::Lua51, Target::Luau] {
        let output = minify(&source, target).unwrap();
        assert!(!output.contains("longValue"));
    }
}
