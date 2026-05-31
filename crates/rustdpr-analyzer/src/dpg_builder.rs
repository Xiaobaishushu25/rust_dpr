use rustdpr_core::{
    normalize_symbol, DangerousKind, DangerousPathGraph, DpgEdge, DpgEdgeKind, DpgNode,
    DpgNodeKind, FunctionIndex, SiteMap,
};
use std::collections::BTreeSet;

pub fn build_dpg(site_map: &SiteMap, function_index: &FunctionIndex) -> DangerousPathGraph {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let mut seen_nodes = BTreeSet::new();
    let mut seen_edges = BTreeSet::new();

    for f in &function_index.functions {
        insert_node(
            &mut nodes,
            &mut seen_nodes,
            DpgNode {
                id: f.function_id.clone(),
                label: f.function_id.clone(),
                kind: DpgNodeKind::Function,
                normalized_id: normalize_symbol(&f.function_id),
            },
        );

        if f.is_public {
            let public_api_id = format!("api::{}", f.function_id);
            insert_node(
                &mut nodes,
                &mut seen_nodes,
                DpgNode {
                    id: public_api_id.clone(),
                    label: f.function_id.clone(),
                    kind: DpgNodeKind::PublicApi,
                    normalized_id: normalize_symbol(&public_api_id),
                },
            );
            insert_edge(
                &mut edges,
                &mut seen_edges,
                public_api_id,
                f.function_id.clone(),
                DpgEdgeKind::Exposes,
                1.0,
                "static",
            );
        }
    }

    let known_functions: Vec<String> = function_index
        .functions
        .iter()
        .map(|f| f.function_id.clone())
        .collect();

    for edge in &function_index.call_edges {
        let caller = resolve_function_id(&edge.caller, &known_functions);
        let callee = resolve_function_id(&edge.callee, &known_functions);

        insert_node(
            &mut nodes,
            &mut seen_nodes,
            DpgNode {
                id: caller.clone(),
                label: caller.clone(),
                kind: DpgNodeKind::Function,
                normalized_id: normalize_symbol(&caller),
            },
        );
        insert_node(
            &mut nodes,
            &mut seen_nodes,
            DpgNode {
                id: callee.clone(),
                label: callee.clone(),
                kind: DpgNodeKind::Function,
                normalized_id: normalize_symbol(&callee),
            },
        );
        insert_edge(
            &mut edges,
            &mut seen_edges,
            caller,
            callee,
            DpgEdgeKind::Calls,
            0.7,
            "static",
        );
    }

    for ds in &site_map.dangerous_sites {
        let node_kind = if matches!(
            ds.kind,
            DangerousKind::FfiBoundary | DangerousKind::FfiUnwindBoundary | DangerousKind::FfiDeclaration
        ) {
            DpgNodeKind::FfiBoundary
        } else {
            DpgNodeKind::DangerousSite
        };
        insert_node(
            &mut nodes,
            &mut seen_nodes,
            DpgNode {
                id: ds.site_id.clone(),
                label: format!("{:?}:{:?}", ds.category, ds.kind),
                kind: node_kind,
                normalized_id: normalize_symbol(&ds.site_id),
            },
        );
        insert_node(
            &mut nodes,
            &mut seen_nodes,
            DpgNode {
                id: ds.enclosing_fn.clone(),
                label: ds.enclosing_fn.clone(),
                kind: DpgNodeKind::Function,
                normalized_id: normalize_symbol(&ds.enclosing_fn),
            },
        );
        insert_edge(
            &mut edges,
            &mut seen_edges,
            ds.enclosing_fn.clone(),
            ds.site_id.clone(),
            DpgEdgeKind::ContainsDangerous,
            1.0,
            "static",
        );
    }

    for ps in &site_map.panic_sites {
        insert_node(
            &mut nodes,
            &mut seen_nodes,
            DpgNode {
                id: ps.panic_id.clone(),
                label: format!("{:?}", ps.kind),
                kind: DpgNodeKind::PanicSite,
                normalized_id: normalize_symbol(&ps.panic_id),
            },
        );
        insert_node(
            &mut nodes,
            &mut seen_nodes,
            DpgNode {
                id: ps.enclosing_fn.clone(),
                label: ps.enclosing_fn.clone(),
                kind: DpgNodeKind::Function,
                normalized_id: normalize_symbol(&ps.enclosing_fn),
            },
        );
        insert_edge(
            &mut edges,
            &mut seen_edges,
            ps.enclosing_fn.clone(),
            ps.panic_id.clone(),
            DpgEdgeKind::ContainsPanic,
            1.0,
            "static",
        );

        for ds in site_map.dangerous_sites.iter().filter(|s| s.enclosing_fn == ps.enclosing_fn) {
            let (from, to, kind) = if ps.span.line_end < ds.span.line_start {
                (ps.panic_id.clone(), ds.site_id.clone(), DpgEdgeKind::BlockedByPanic)
            } else if ds.span.line_end < ps.span.line_start {
                (ds.site_id.clone(), ps.panic_id.clone(), DpgEdgeKind::ObservedAfter)
            } else {
                (ds.site_id.clone(), ps.panic_id.clone(), DpgEdgeKind::InsideSameUnsafeRegion)
            };
            insert_edge(&mut edges, &mut seen_edges, from, to, kind, 0.8, "static-locality");
        }
    }

    let mut graph = DangerousPathGraph {
        nodes,
        edges,
        reachability: vec![],
        normalization_notes: vec![
            "symbol ids are normalized by lower-casing, stripping api:: prefix, and normalizing path separators".to_string(),
        ],
    };
    graph.normalize_all();
    graph.compute_reachability();
    graph
}

fn insert_node(nodes: &mut Vec<DpgNode>, seen: &mut BTreeSet<String>, mut node: DpgNode) {
    if node.normalized_id.is_empty() {
        node.normalized_id = normalize_symbol(&node.id);
    }
    if seen.insert(node.id.clone()) {
        nodes.push(node);
    }
}

fn insert_edge(
    edges: &mut Vec<DpgEdge>,
    seen: &mut BTreeSet<String>,
    from: String,
    to: String,
    kind: DpgEdgeKind,
    confidence: f32,
    static_or_dynamic: &str,
) {
    let key = format!("{}->{:?}->{}", from, kind, to);
    if seen.insert(key) {
        edges.push(DpgEdge {
            normalized_from: normalize_symbol(&from),
            normalized_to: normalize_symbol(&to),
            from,
            to,
            kind,
            confidence,
            static_or_dynamic: static_or_dynamic.to_string(),
            support_count: 1,
        });
    }
}
fn resolve_function_id(raw: &str, known_functions: &[String]) -> String {
    let raw_norm = normalize_symbol(raw);

    if let Some(exact) = known_functions
        .iter()
        .find(|id| normalize_symbol(id) == raw_norm)
    {
        return exact.clone();
    }

    let local = raw.rsplit("::").next().unwrap_or(raw);
    let local_norm = normalize_symbol(local);
    let suffix = format!("::{local_norm}");

    let matches: Vec<&String> = known_functions
        .iter()
        .filter(|id| {
            let id_norm = normalize_symbol(id);
            id_norm == local_norm || id_norm.ends_with(&suffix)
        })
        .collect();

    if matches.len() == 1 {
        return matches[0].clone();
    }

    raw.to_string()
}