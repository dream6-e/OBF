// K4 — 生成脚本的函数级布局（inlining / outlining / reorder）的门。
//
// 这个文件只做两件事：证明 pass 确实在动（0 命中=藏在 no-op 后面，不是"安全"），
// 以及证明它动完语义一模一样。等价性不靠"看着像"：同一份镜像分别过/不过布局，
// 两份成品都在真机 Lua 5.1 / Luau 上跑，stdout 与退出码必须逐字节相同；准入判据
// 则用一批手写的坏例子从反面钉住（每种被禁止的改写，任何种子都不许动）。

fn laid_script(source: &str, target: Target, seed: u64, laid_out: bool) -> String {
    let bytecode = compile(source, target).expect("fixture compiles");
    let program = custom::decode(&bytecode, target).expect("image decodes");
    let raw = generate(&bytecode, &program, seed).expect("script generates");
    let text = if laid_out {
        super::layout::restructure(&raw, target, seed).expect("layout accepts the script")
    } else {
        raw
    };
    finalize(&text, target, seed).expect("finalize accepts the script")
}

/// Run a chunk of plain Lua on the real interpreter for `target`, and hand back
/// stdout plus whether it exited zero. The runner knows nothing about the
/// obfuscator: the differential gate feeds it finished artifacts, the refusal
/// gates feed it hand-written chunks.
fn run_chunk(target: Target, text: &str, label: &str) -> (String, bool) {
    let (stdout, _stderr, ok) = run_chunk_full(target, text, label);
    (stdout, ok)
}

/// The same, keeping stderr: the fail-closed gates need to read the message the
/// script raised.
fn run_chunk_full(target: Target, text: &str, label: &str) -> (String, String, bool) {
    let work = native::Workspace::new();
    let path = work.0.join(format!("{label}.lua"));
    fs::write(&path, text).unwrap();
    assert!(
        native::compile(target, &path).status.success(),
        "{target}: {label} does not compile"
    );
    let runner = if target.is_luau() { "luau" } else { "lua5.1" };
    let output = std::process::Command::new(native::root().join("toolchains/bin").join(runner))
        .arg(&path)
        .output()
        .unwrap();
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        output.status.success(),
    )
}

/// `true` when the layout pass left this text byte-for-byte alone.
fn untouched(source: &str, target: Target, bucket: usize) -> bool {
    for seed in [1u64, 7, 7001, 4242, 65535] {
        let (text, counts) = super::layout::restructure_probe(source, target, seed, bucket)
            .unwrap_or_else(|error| panic!("{target} bucket {bucket} seed {seed}: {error}"));
        if counts != [0, 0, 0] || text != source {
            return false;
        }
    }
    true
}

fn rewrite(source: &str, target: Target, seed: u64, bucket: usize) -> (String, [usize; 3]) {
    super::layout::restructure_probe(source, target, seed, bucket)
        .unwrap_or_else(|error| panic!("{target} bucket {bucket} seed {seed}: {error}"))
}

/// The pass must be doing real work on the shipped script, per target and per
/// seed, and the totals are pinned so a regression to "nobody was rewritten"
/// cannot be read as "nothing to do".
#[test]
fn layout_actually_rewrites_the_generated_script() {
    for target in [Target::Lua51, Target::Luau] {
        let label = if target.is_luau() { "luau" } else { "lua51" };
        let source = fs::read_to_string(format!(
            "{}/tests/fixtures/vm_{label}.lua",
            native::root().display()
        ))
        .unwrap();
        let mut totals = [0usize; 3];
        let mut growth = (0i64, 0i64);
        // 重排是三条 pass 里最受依赖关系约束的一条：Goal 6 (part 3) 的不透明字面量
        // 让每个站点多读一枚运行期局部量，可重排的相邻声明随之变少。这里改成按六个
        // 种子求和，测到 lua51 6 次 / luau 4 次，下限 3 仍能把「pass 完全不动」
        // 变成红（旧口径是单种子最大值 ≥ 2，luau 现在单种子最多只到 1）。
        let mut reordered_total = 0usize;
        for seed in [7001u64, 7002, 7351, 7352, 42424, 90210] {
            let bytecode = compile(&source, target).unwrap();
            let program = custom::decode(&bytecode, target).unwrap();
            let raw = generate(&bytecode, &program, seed).unwrap();
            let text =
                super::layout::restructure(&raw, target, seed).expect("layout accepts the script");
            let (counts, before, after) = super::layout::tally(&raw, target, seed).unwrap();
            println!(
                "{label} {seed}: inlined={} outlined={} reordered={} bytes {before} -> {after}",
                counts[0], counts[1], counts[2]
            );
            // `tally` runs the same passes as `restructure`, so the two must
            // agree byte for byte or one of them is lying.
            assert_eq!((before, after), (raw.len(), text.len()));
            for (slot, value) in totals.iter_mut().zip(&counts) {
                *slot = (*slot).max(*value);
            }
            reordered_total += counts[2];
            growth = (
                growth.0.min(after as i64 - before as i64),
                growth.1.max(after as i64 - before as i64),
            );
            assert!(
                counts[1] >= 1,
                "{target} seed {seed}: every seed must hoist the shared guard chain"
            );
        }
        println!("{label} size delta range: {} .. {} bytes", growth.0, growth.1);
        // Floors, pinned just under what the six seeds actually reach
        // (lua51 26/1/2, luau 43/1/3 at the time of writing). They exist to turn
        // "the pass quietly stopped matching anything" into a failure: a no-op
        // layout looks exactly like a safe one if nobody measures it.
        assert!(
            totals[0] >= 10,
            "{target}: inline pass only ever hit {} sites",
            totals[0]
        );
        assert!(
            totals[1] >= 1,
            "{target}: outline pass never hoisted anything"
        );
        assert!(
            reordered_total >= 3,
            "{target}: reorder pass only moved {reordered_total} statements over six seeds"
        );
    }
}

/// The load-bearing gate: laid out or not, the shipped script must behave
/// identically on the real interpreters.
#[test]
fn laid_out_script_behaves_exactly_like_the_unlaid_one() {
    for target in [Target::Lua51, Target::Luau] {
        let label = if target.is_luau() { "luau" } else { "lua51" };
        let source = fs::read_to_string(format!(
            "{}/tests/fixtures/vm_{label}.lua",
            native::root().display()
        ))
        .unwrap();
        for seed in [7001u64, 7351, 42424, 90210] {
            let plain = laid_script(&source, target, seed, false);
            let laid = laid_script(&source, target, seed, true);
            assert_ne!(plain, laid, "{target} seed {seed}: nothing was laid out");
            let (plain_out, plain_ok) = run_chunk(target, &plain, &format!("plain{seed}"));
            let (laid_out, laid_ok) = run_chunk(target, &laid, &format!("laid{seed}"));
            assert_eq!(plain_out, laid_out, "{target} seed {seed} stdout drifted");
            assert_eq!(plain_ok, laid_ok, "{target} seed {seed} exit status drifted");
            assert!(plain_ok, "{target} seed {seed} fixture must pass");
        }
    }
}

/// The admission criteria, from the wrong side. Each hostile snippet *looks*
/// inlinable and is exactly the shape that would change behaviour, so no seed
/// and no probability bucket may touch it. Each one is paired with the same
/// snippet minus the hazard, which has to be rewritten — without that control a
/// refusal gate is satisfied by a pass that never fires at all, and that is how
/// this batch nearly shipped.
#[test]
fn a_refused_rewrite_is_refused_for_every_seed() {
    // Two call sites minimum, on both sides of each pair: the inline pass
    // deliberately leaves a single-use helper alone, so a one-site refusal would
    // be a refusal of nothing.
    let pairs = [
        (
            "body reads a name the site resolves elsewhere",
            "local v=1\nlocal f=function() return v+1 end\ndo local v=9;print(f());print(f())end\nprint(v)\n",
            "local v=1\nlocal f=function() return v+1 end\nprint(f())\nprint(f())\nprint(v)\n",
        ),
        (
            "body writes a name the site resolves elsewhere",
            "local acc=0\nlocal bump=function() acc=acc+1 end\ndo local acc=100;bump();bump();print(acc)end\nprint(acc)\n",
            "local acc=0\nlocal bump=function() acc=acc+1 end\nbump();bump();print(acc)\n",
        ),
        (
            "varargs: the count lives in the frame, not in a value",
            "local f=function(a,...) return a+select('#',...)end\nprint(f(2,3,4))\nprint(f(5,6))\n",
            "local f=function(a) return a+1 end\nprint(f(2))\nprint(f(3))\n",
        ),
        (
            "argument count mismatch",
            "local g=function(a,b) return a+(b or 0)end\nprint(g(1))\nprint(g(2))\n",
            "local g=function(a,b) return a+(b or 0)end\nprint(g(1,2))\nprint(g(3,4))\n",
        ),
        (
            "a raise with a frame-relative level",
            "local d=function(m) if m then error(m,2)end end\nd('boom')\nd('bang')\nprint('after')\n",
            "local d=function(m) if m then error(m)end end\nd('boom')\nd('bang')\nprint('after')\n",
        ),
    ];
    for target in [Target::Lua51, Target::Luau] {
        for (label, hostile, control) in pairs {
            for bucket in 0..4 {
                assert!(
                    untouched(hostile, target, bucket),
                    "{target} bucket {bucket} ({label}): the layout pass rewrote a forbidden shape:\n{hostile}"
                );
            }
            let mut best = 0usize;
            for seed in [1u64, 7, 7001, 4242, 65535] {
                for bucket in 1..4 {
                    let (text, counts) = rewrite(control, target, seed, bucket);
                    best = best.max(counts[0]);
                    let (plain, plain_ok) = run_chunk(target, control, "before");
                    let (after, after_ok) = run_chunk(target, &text, "after");
                    assert_eq!(plain, after, "{target} {label}: inline changed stdout");
                    assert_eq!(plain_ok, after_ok, "{target} {label}: inline changed status");
                }
            }
            assert!(
                best >= 1,
                "{target} {label}: the control was never inlined, so the refusal gate proves nothing"
            );
        }
    }
}

/// Outlining may only hoist a fragment whose free locals nobody ever assigns.
/// The fragment below calls a function *and* reads a local that the call
/// assigns, so a hoisted copy would read the value from before the call; the
/// control is the same fragment with a call that assigns nothing, and it has to
/// be hoisted, or the refusal above is proving nothing.
#[test]
fn outlining_refuses_a_fragment_whose_inputs_a_call_can_assign() {
    let frag = "f(v)+f(v)+f(v)+f(v)+f(v)+f(v)+f(v)+f(v)+f(v)+f(v)";
    let sites = format!(
        "local aa={frag}\nlocal bb={frag}\nlocal cc={frag}\nprint(aa,bb,cc,v)\n"
    );
    let unsafe_hoist = format!("local v=0\nlocal f=function(x) v=v+x return x*3 end\n{sites}");
    let safe_hoist = format!("local v=0\nlocal f=function(x) return x*3 end\n{sites}");
    for target in [Target::Lua51, Target::Luau] {
        let mut hoists = [0usize; 2];
        for (index, snippet) in [unsafe_hoist.as_str(), safe_hoist.as_str()]
            .iter()
            .enumerate()
        {
            for seed in [1u64, 7, 7001, 4242, 65535] {
                for bucket in 0..4 {
                    let (text, counts) = rewrite(snippet, target, seed, bucket);
                    hoists[index] = hoists[index].max(counts[1]);
                    assert!(
                        counts[1] <= if index == 0 { 0 } else { 2 },
                        "{target}: hoisted {counts:?} copies of the {} fragment",
                        if index == 0 { "unsafe" } else { "safe" }
                    );
                    let (plain, plain_ok) = run_chunk(target, snippet, "before");
                    let (after, after_ok) = run_chunk(target, &text, "after");
                    assert_eq!(plain, after, "{target}: hoisting changed stdout");
                    assert_eq!(plain_ok, after_ok, "{target}: hoisting changed status");
                }
            }
        }
        assert_eq!(
            hoists,
            [0, 1],
            "{target}: the outline control stopped firing, so the refusal proves nothing"
        );
    }
}

/// Re-ordering may only permute declarations that cannot see each other, and
/// even a legal permutation has to keep the chunk's behaviour.
#[test]
fn reordering_only_moves_independent_declarations() {
    for target in [Target::Lua51, Target::Luau] {
        // Four helpers that reference each other in a chain: no permutation may
        // put a reader ahead of the declaration it reads.
        let dependent = "local a=function() return 1 end\nlocal b=function() return a()+1 end\nlocal c=function() return b()+1 end\nlocal d=function() return c()+1 end\nprint(d())\n";
        let independent = "local a=function() return 1 end\nlocal b=function() return 2 end\nlocal c=function() return 3 end\nlocal d=function() return 4 end\nprint(a()+b()+c()+d())\n";
        for (label, snippet, floor) in [("dependent", dependent, false), ("independent", independent, true)] {
            let mut moved = 0usize;
            for seed in [1u64, 7, 7001, 4242, 65535] {
                for bucket in 0..4 {
                    let (text, counts) = rewrite(snippet, target, seed, bucket);
                    moved = moved.max(counts[2]);
                    assert!(
                        counts[2] <= 1,
                        "{target} {label}: moved {counts:?} statements in a run of four"
                    );
                    let (plain, plain_ok) = run_chunk(target, snippet, "before");
                    let (after, after_ok) = run_chunk(target, &text, "after");
                    assert_eq!(plain, after, "{target} {label}: reordering changed stdout");
                    assert_eq!(plain_ok, after_ok);
                }
            }
            assert_eq!(moved > 0, floor, "{target} {label}: reorder fire/no-fire is wrong");
        }
    }
}

/// The documented boundary of "provably safe". A guard that aborts has to keep
/// aborting with the same code and the same exit status after the layout pass,
/// on both interpreters. What the pass is allowed to move is the `file:line:`
/// prefix the interpreter puts on an `error(msg)` message with no level — the
/// raising statement has changed lines, and no rewrite can claim otherwise — so
/// this gate compares stdout, the status, and the message itself, not the prefix.
#[test]
fn a_guard_still_aborts_with_the_same_code_after_layout() {
    let source = "local E=error\nlocal code=0\nlocal fail=function(c) code=c;E(\"seedfail:\"..c)end\nlocal chk=function(x) if x<0 then fail(36)end return x end\nlocal chk2=function(y) if y>0 then fail(32)end return y end\nprint(chk(1));print(chk2(-1));fail(7)\n";
    for target in [Target::Lua51, Target::Luau] {
        let (plain, plain_err, plain_ok) = run_chunk_full(target, source, "plain");
        assert!(!plain_ok, "{target}: the control must abort");
        assert!(plain_err.contains("seedfail:7"), "{target}: {plain_err}");
        assert_eq!(plain, "1\n-1\n", "{target}: unexpected control stdout");
        let mut hits = 0usize;
        for seed in [1u64, 4242, 7001, 90210] {
            for bucket in 1..4 {
                let (text, counts) = rewrite(source, target, seed, bucket);
                hits = hits.max(counts.iter().sum::<usize>());
                let (laid, laid_err, laid_ok) = run_chunk_full(target, &text, "laid");
                assert!(!laid_ok, "{target} seed {seed} bucket {bucket}: the abort was lost");
                assert_eq!(plain, laid, "{target} seed {seed}: stdout drifted");
                assert!(
                    laid_err.contains("seedfail:7"),
                    "{target} seed {seed} bucket {bucket}: the raised code changed:\n{laid_err}"
                );
            }
        }
        assert!(
            hits >= 1,
            "{target}: nothing was rewritten here, so this gate would pass on a no-op pass"
        );
    }
}
