/// The payload table's fields, accepting either shape a shipped script can have:
/// the table passed straight to `setmetatable`, or handed over by a function of
/// the script's own -- `setmetatable((function() local <pool> return {..}
/// end)(),x)`. The second is how the numeric pool keeps repeated literals inside
/// the shell rather than in front of it, so its shape is pinned here as well: the
/// producer takes nothing and is called with nothing, exactly one statement
/// precedes the returned table, and that statement is a `local` whose every value
/// is a number -- the pool declaration, one binding per slot. A script with
/// nothing worth a local (a two-line fixture, say) keeps the first shape.
fn shell_payload<'a>(
    argument: &'a crate::ast::Expression,
    target: Target,
    output: &str,
) -> &'a Vec<crate::ast::TableField> {
    use crate::ast::{ExpressionKind, StatementKind};
    /// Parentheses around a subexpression are a node of their own in this AST.
    fn peel<'b>(expression: &'b crate::ast::Expression) -> &'b ExpressionKind {
        let mut kind = &expression.kind;
        while let ExpressionKind::Group(inner) = kind {
            kind = &inner.kind;
        }
        kind
    }
    if let ExpressionKind::Table(fields) = peel(argument) {
        return fields;
    }
    let ExpressionKind::Call {
        function,
        method: None,
        type_arguments,
        arguments,
    } = peel(argument)
    else {
        panic!("{target}: {output}");
    };
    assert!(
        type_arguments.is_empty() && arguments.is_empty(),
        "{target}: the payload's producer is called with nothing: {output}"
    );
    let ExpressionKind::Function(producer) = peel(function) else {
        panic!("{target}: {output}");
    };
    assert!(
        producer.parameters.is_empty() && !producer.has_vararg,
        "{target}: the payload's producer takes nothing: {output}"
    );
    let (last, head) = producer.body.statements.split_last().unwrap();
    assert_eq!(
        head.len(),
        1,
        "{target}: only the numeric pool precedes the table: {output}"
    );
    let StatementKind::Local {
        bindings, values, ..
    } = &head[0].kind
    else {
        panic!("{target}: {output}");
    };
    assert!(
        !bindings.is_empty()
            && bindings.len() <= crate::vm::custom::numeric_pool::MAX_SLOTS
            && bindings.len() == values.len()
            && values
                .iter()
                .all(|value| matches!(value.kind, ExpressionKind::Number(_))),
        "{target}: the shell opens with the numeric pool: {output}"
    );
    let StatementKind::Return(returned) = &last.kind else {
        panic!("{target}: {output}");
    };
    assert_eq!(returned.len(), 1);
    let ExpressionKind::Table(fields) = &returned[0].kind else {
        panic!("{target}: {output}");
    };
    fields
}
