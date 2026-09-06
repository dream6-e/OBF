//! Seeded short-name reuse with bounded lexical interference constraints.
//!
//! Same naming scope: all declarations conflict, including unused/shadowed
//! ones. This clique is represented by color ownership, never all-pairs edges.
//! Different scopes: A and B conflict if an A reference can see an active B
//! in a scope between that reference and A's declaration. All active bindings
//! matter, not just the currently visible spelling: renaming can un-shadow an
//! earlier declaration. Declaration activation uses resolver reference order,
//! so initializers, signatures, repeat conditions and closures follow exactly
//! the same visibility rules as binding analysis.
//!
//! Globals/preserved names are excluded from the entire palette. Thus any
//! changed resolution must be a local/local capture covered above. Final
//! reparsing independently checks binding identities AND naming-scope clashes.

use super::{Analysis, BindingId, RenamePlan, ScopeId, MAX_WORK};
use crate::random::Prng;
use crate::{Diagnostic, Target};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

const MAX_EDGES: usize = 1_000_000;
const MAX_COLORS: usize = 26 + 26 * 26;

struct Budget {
    remaining: usize,
}

impl Budget {
    fn spend(&mut self, count: usize) -> Result<(), Diagnostic> {
        self.remaining = self.remaining.checked_sub(count).ok_or_else(|| {
            Diagnostic::new(
                "scope name reuse exceeds work safety limit; use --no-rename or split the source",
            )
        })?;
        Ok(())
    }
}

struct Constraints {
    groups: Vec<Vec<BindingId>>,
    neighbors: Vec<Vec<BindingId>>,
}

fn name_scope(analysis: &Analysis, binding: BindingId) -> ScopeId {
    analysis.scopes[analysis.bindings[binding].scope].name_scope
}

impl Constraints {
    fn build(
        analysis: &Analysis,
        palette_size: usize,
        work: &mut Budget,
    ) -> Result<Self, Diagnostic> {
        let mut groups = vec![Vec::new(); analysis.scopes.len()];
        for (id, binding) in analysis.bindings.iter().enumerate() {
            work.spend(1)?;
            if binding.preserve.is_none() {
                let group = name_scope(analysis, id);
                groups[group].push(id);
                if groups[group].len() > palette_size {
                    return Err(exhausted(group, palette_size));
                }
            }
        }
        let mut edges = BTreeSet::new();
        for (ordinal, reference) in analysis.references.iter().enumerate() {
            work.spend(1)?;
            let Some(outer) = reference.binding else {
                continue;
            };
            if analysis.bindings[outer].preserve.is_some() {
                continue;
            }
            let owner = analysis.bindings[outer].scope;
            let mut current = reference.scope;
            while current != owner {
                work.spend(1)?;
                for &inner in &analysis.scopes[current].bindings {
                    work.spend(1)?;
                    // Binding lists are in semantic declaration order.
                    if analysis.activations[inner] > ordinal {
                        break;
                    }
                    if analysis.bindings[inner].preserve.is_none()
                        && name_scope(analysis, outer) != name_scope(analysis, inner)
                    {
                        edges.insert((outer.min(inner), outer.max(inner)));
                        if edges.len() > MAX_EDGES {
                            return Err(Diagnostic::new("scope name reuse conflict count exceeds safety limit; use --no-rename or split the source"));
                        }
                    }
                }
                current = analysis.scopes[current].parent.ok_or_else(|| {
                    Diagnostic::new("local reference is outside its declaration's scope")
                })?;
            }
        }
        let mut neighbors = vec![Vec::new(); analysis.bindings.len()];
        for (left, right) in edges {
            neighbors[left].push(right);
            neighbors[right].push(left);
        }
        Ok(Self { groups, neighbors })
    }

    fn blocked(
        &self,
        id: BindingId,
        colors: &[Option<usize>],
        work: &mut Budget,
    ) -> Result<[bool; MAX_COLORS], Diagnostic> {
        work.spend(self.neighbors[id].len())?;
        let mut blocked = [false; MAX_COLORS];
        for &neighbor in &self.neighbors[id] {
            if let Some(color) = colors[neighbor] {
                blocked[color] = true;
            }
        }
        Ok(blocked)
    }
}

pub(super) fn plan(
    analysis: &Analysis,
    target: Target,
    seed: u64,
) -> Result<RenamePlan, Diagnostic> {
    let mut reserved = analysis.reserved.clone();
    // Old names of simultaneously rewritten locals are available, but never
    // use names of globals, types, exports, implicit or opaque bindings.
    reserved.extend(
        analysis
            .bindings
            .iter()
            .filter(|binding| binding.preserve.is_some())
            .map(|binding| binding.name.clone()),
    );
    let mut single = Vec::new();
    let mut double = Vec::new();
    for first in b'a'..=b'z' {
        single.push(char::from(first).to_string());
        for second in b'a'..=b'z' {
            double.push(format!("{}{}", char::from(first), char::from(second)));
        }
    }
    for pool in [&mut single, &mut double] {
        pool.retain(|name| !reserved.contains(name) && !target.is_reserved_name(name));
    }
    let domain = if target.is_luau() {
        0x6e61_6d65_0000_0735
    } else {
        0x6e61_6d65_0000_0051
    };
    let mut random = Prng::new(seed ^ domain);
    random.shuffle(&mut single);
    random.shuffle(&mut double);
    single.extend(double);
    let palette = single;
    let mut order: Vec<_> = (0..analysis.bindings.len())
        .filter(|&id| analysis.bindings[id].preserve.is_none())
        .collect();
    order.sort_by_key(|&id| {
        let binding = &analysis.bindings[id];
        (
            std::cmp::Reverse(binding.references),
            binding.declaration.map_or(usize::MAX, |span| span.start),
            id,
        )
    });
    let mut work = Budget {
        remaining: MAX_WORK,
    };
    let constraints = Constraints::build(analysis, palette.len(), &mut work)?;
    let colors = allocate(analysis, &palette, &order, &constraints, &mut work)?;
    Ok(RenamePlan {
        names: colors
            .into_iter()
            .map(|color| color.map(|color| palette[color].clone()))
            .collect(),
    })
}

fn allocate(
    analysis: &Analysis,
    palette: &[String],
    order: &[BindingId],
    constraints: &Constraints,
    work: &mut Budget,
) -> Result<Vec<Option<usize>>, Diagnostic> {
    let mut colors = vec![None; analysis.bindings.len()];
    let mut owners = vec![BTreeMap::new(); constraints.groups.len()];
    for &id in order {
        work.spend(1)?;
        let group = name_scope(analysis, id);
        let blocked = constraints.blocked(id, &colors, work)?;
        let mut available = None;
        for (color, name) in palette.iter().enumerate() {
            work.spend(1)?;
            if name != &analysis.bindings[id].name
                && !blocked[color]
                && !owners[group].contains_key(&color)
            {
                available = Some(color);
                break;
            }
        }
        if let Some(color) = available {
            colors[id] = Some(color);
            owners[group].insert(color, id);
        } else {
            repair(
                analysis,
                palette,
                id,
                constraints,
                &mut colors,
                &mut owners[group],
                work,
            )?;
        }
    }
    Ok(colors)
}

// Find an augmenting path in this naming scope's binding/color matching.
// Other scopes stay fixed; never perform an unchecked cross-scope swap.
// Iterative BFS, <= palette_size bindings, bounded candidate/edge scans.
// This repairs own-spelling dead ends and multi-step swaps. It is deliberately
// not an unbounded search for an optimal coloring of the entire program.
fn repair(
    analysis: &Analysis,
    palette: &[String],
    root: BindingId,
    constraints: &Constraints,
    colors: &mut [Option<usize>],
    owners: &mut BTreeMap<usize, BindingId>,
    work: &mut Budget,
) -> Result<(), Diagnostic> {
    let mut queue = VecDeque::from([root]);
    let mut parents: BTreeMap<BindingId, Option<(BindingId, usize)>> =
        BTreeMap::from([(root, None)]);
    while let Some(id) = queue.pop_front() {
        let blocked = constraints.blocked(id, colors, work)?;
        for (color, name) in palette.iter().enumerate() {
            work.spend(1)?;
            if blocked[color] || name == &analysis.bindings[id].name {
                continue;
            }
            if let Some(&owner) = owners.get(&color) {
                if let std::collections::btree_map::Entry::Vacant(entry) = parents.entry(owner) {
                    entry.insert(Some((id, color)));
                    queue.push_back(owner);
                }
            } else {
                let (mut mover, mut new_color) = (id, color);
                loop {
                    colors[mover] = Some(new_color);
                    owners.insert(new_color, mover);
                    if let Some((previous, previous_color)) = parents[&mover] {
                        mover = previous;
                        new_color = previous_color;
                    } else {
                        return Ok(());
                    }
                }
            }
        }
    }
    Err(exhausted(name_scope(analysis, root), palette.len()))
}

fn exhausted(scope: ScopeId, palette_size: usize) -> Diagnostic {
    Diagnostic::new(format!(
        "1-2 letter variable name pool exhausted in scope {scope}: cannot rename every binding with {palette_size} safe candidates under scope/capture constraints; use --no-rename or split the source"
    ))
}

pub(super) fn verify_names(analysis: &Analysis, plan: &RenamePlan) -> Result<(), Diagnostic> {
    let mut seen = BTreeMap::new();
    for (id, binding) in analysis.bindings.iter().enumerate() {
        let key = (name_scope(analysis, id), binding.name.as_str());
        if let Some(previous) = seen.insert(key, id) {
            // Don't reject intentional pre-existing duplicates when neither
            // is renamed (e.g. protected self/arg or reflection opt-out).
            if plan.names[id].is_some() || plan.names[previous].is_some() {
                return Err(Diagnostic::new(
                    "safe minification introduced duplicate names in a scope; refusing output",
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn analyze(source: &str) -> Analysis {
        super::super::analyze(source, Target::Luau).unwrap()
    }

    #[test]
    fn unused_same_scope_and_parameter_body_collisions_are_rejected() {
        for source in [
            "local first=1 local second=2",
            "function f(first) local second=2 end",
            "for first=1,2 do local second=2 end",
        ] {
            let before = analyze(source);
            assert_eq!(before.bindings.len(), 2);
            let plan = RenamePlan {
                names: vec![Some("a".into()), Some("a".into())],
            };
            let output = plan.apply(source, &before).unwrap().unwrap();
            let after = analyze(&output);
            assert_eq!(before.references.len(), after.references.len());
            assert!(before
                .verify_renamed(&after, &plan)
                .unwrap_err()
                .message
                .contains("duplicate names"));
        }
        let source = "local print=1 local print=2 return print";
        assert_eq!(
            crate::minify_with_options(source, Target::Luau, crate::MinifyOptions::seeded(0))
                .unwrap(),
            "local print=1;local print=2;return print"
        );
    }

    #[test]
    fn originally_shadowed_bindings_still_interfere_after_renaming() {
        let before =
            analyze("local outer=1 do local duplicate=2 local duplicate=3 return outer end");
        let constraints = Constraints::build(
            &before,
            26,
            &mut Budget {
                remaining: MAX_WORK,
            },
        )
        .unwrap();
        assert_eq!(constraints.neighbors[0], [1, 2]);
        assert_eq!(constraints.groups[name_scope(&before, 1)], [1, 2]);
    }

    #[test]
    fn iterative_matching_repairs_multi_step_paths_without_cross_scope_capture() {
        let source = "do local c=1 local a=2 local c=3 do local a=4 print(c,a) end end";
        let before = analyze(source);
        let palette: Vec<String> = ["a", "b", "c"].into_iter().map(String::from).collect();
        let mut work = Budget {
            remaining: MAX_WORK,
        };
        let constraints = Constraints::build(&before, palette.len(), &mut work).unwrap();
        // Greedy: child=b; group a,b,unassigned. Last old c can only use a
        // (b would capture the child). Repair must move a->b->c, not just swap.
        let colors = allocate(&before, &palette, &[3, 0, 1, 2], &constraints, &mut work).unwrap();
        assert_eq!(colors, [Some(1), Some(2), Some(0), Some(1)]);
        let plan = RenamePlan {
            names: colors
                .into_iter()
                .map(|color| color.map(|color| palette[color].clone()))
                .collect(),
        };
        let output = plan.apply(source, &before).unwrap().unwrap();
        before.verify_renamed(&analyze(&output), &plan).unwrap();
    }

    #[test]
    fn interference_and_coloring_work_limits_fail_closed() {
        let before = analyze("local outer=1 do local inner=2 print(outer,inner) end");
        assert!(
            Constraints::build(&before, 26, &mut Budget { remaining: 1 })
                .err()
                .unwrap()
                .message
                .contains("safety limit")
        );
        let constraints = Constraints::build(
            &before,
            26,
            &mut Budget {
                remaining: MAX_WORK,
            },
        )
        .unwrap();
        let palette = vec!["a".into(), "b".into()];
        assert!(allocate(
            &before,
            &palette,
            &[0, 1],
            &constraints,
            &mut Budget { remaining: 0 }
        )
        .unwrap_err()
        .message
        .contains("safety limit"));
    }
}

#[cfg(test)]
mod constraint_oracle_tests {
    use super::*;

    #[test]
    fn small_constraint_graphs_match_exhaustive_reparse_oracle() {
        let cases = [
            "local outside=1 do local inside=2 print(outside,inside) end",
            "local outside=1 do local inside=outside print(inside) end",
            "local outside=1 do local inside=function()return outside end end",
            "local outside=1 do local function inside()return outside end end",
            "local outside=1 do local shadow=2 local shadow=3 print(outside) end",
            "local function fun(parameter) local inside=parameter return inside end",
            "local outside=1 repeat local inside=outside until inside>0",
            "local outside=1 for inside=outside,outside do local copied=inside print(copied) end",
            "local module={} do local blocker=1 type Alias=module.Member end",
            "local outside=1 do local inside=`{outside}` print(inside) end",
            "local outside=1 do local function outside(parameter:typeof(outside)):typeof(outside) return parameter end end",
        ];
        for source in cases {
            let before = super::super::analyze(source, Target::Luau).unwrap();
            assert!(before
                .bindings
                .iter()
                .all(|binding| binding.preserve.is_none()));
            let constraints = Constraints::build(
                &before,
                3,
                &mut Budget {
                    remaining: MAX_WORK,
                },
            )
            .unwrap();
            // Every 3-color assignment, including deliberately bad captures
            // and unused/shadowed same-scope collisions. This oracle reparses
            // text; it does not consult the interference builder's traversal.
            for mut encoding in 0..3usize.pow(before.bindings.len() as u32) {
                let colors: Vec<_> = (0..before.bindings.len())
                    .map(|_| {
                        let color = encoding % 3;
                        encoding /= 3;
                        color
                    })
                    .collect();
                let allowed = constraints.groups.iter().all(|group| {
                    let distinct: BTreeSet<_> = group.iter().map(|&id| colors[id]).collect();
                    distinct.len() == group.len()
                }) && constraints.neighbors.iter().enumerate().all(
                    |(id, neighbors)| neighbors.iter().all(|&other| colors[id] != colors[other]),
                );
                let plan = RenamePlan {
                    names: colors
                        .iter()
                        .map(|&color| Some(char::from(b'a' + color as u8).to_string()))
                        .collect(),
                };
                let output = plan.apply(source, &before).unwrap().unwrap();
                let after = super::super::analyze(&output, Target::Luau).unwrap();
                assert_eq!(
                    allowed,
                    before.verify_renamed(&after, &plan).is_ok(),
                    "{source} -> {output}"
                );
            }
        }
    }
}
