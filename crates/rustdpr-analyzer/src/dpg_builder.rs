use rustdpr_core::{
    DangerousPathGraph, DpgEdge, DpgEdgeKind, DpgNode, DpgNodeKind, FunctionIndex, SiteMap,
};
use std::collections::BTreeSet;

pub fn build_dpg(site_map: &SiteMap, function_index: &FunctionIndex) -> DangerousPathGraph {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let mut seen_nodes = BTreeSet::new();

    for f in &function_index.functions {
        if f.is_public {
            let public_api_id = format!("api::{}", f.function_id);
            insert_node(
                &mut nodes,
                &mut seen_nodes,
                DpgNode {
                    id: public_api_id.clone(),
                    label: f.function_id.clone(),
                    kind: DpgNodeKind::PublicApi,
                },
            );
            insert_node(
                &mut nodes,
                &mut seen_nodes,
                DpgNode {
                    id: f.function_id.clone(),
                    label: f.function_id.clone(),
                    kind: DpgNodeKind::Function,
                },
            );
            edges.push(DpgEdge {
                from: public_api_id,
                to: f.function_id.clone(),
                kind: DpgEdgeKind::Exposes,
            });
        } else {
            insert_node(
                &mut nodes,
                &mut seen_nodes,
                DpgNode {
                    id: f.function_id.clone(),
                    label: f.function_id.clone(),
                    kind: DpgNodeKind::Function,
                },
            );
        }
    }

    for edge in &function_index.call_edges {
        insert_node(
            &mut nodes,
            &mut seen_nodes,
            DpgNode {
                id: edge.caller.clone(),
                label: edge.caller.clone(),
                kind: DpgNodeKind::Function,
            },
        );
        insert_node(
            &mut nodes,
            &mut seen_nodes,
            DpgNode {
                id: edge.callee.clone(),
                label: edge.callee.clone(),
                kind: DpgNodeKind::Function,
            },
        );
        edges.push(DpgEdge {
            from: edge.caller.clone(),
            to: edge.callee.clone(),
            kind: DpgEdgeKind::Calls,
        });
    }

    for ds in &site_map.dangerous_sites {
        insert_node(
            &mut nodes,
            &mut seen_nodes,
            DpgNode {
                id: ds.site_id.clone(),
                label: format!("{:?}", ds.kind),
                kind: DpgNodeKind::DangerousSite,
            },
        );
        insert_node(
            &mut nodes,
            &mut seen_nodes,
            DpgNode {
                id: ds.enclosing_fn.clone(),
                label: ds.enclosing_fn.clone(),
                kind: DpgNodeKind::Function,
            },
        );
        edges.push(DpgEdge {
            from: ds.enclosing_fn.clone(),
            to: ds.site_id.clone(),
            kind: DpgEdgeKind::ContainsDangerous,
        });
    }

    for ps in &site_map.panic_sites {
        insert_node(
            &mut nodes,
            &mut seen_nodes,
            DpgNode {
                id: ps.panic_id.clone(),
                label: format!("{:?}", ps.kind),
                kind: DpgNodeKind::PanicSite,
            },
        );
        insert_node(
            &mut nodes,
            &mut seen_nodes,
            DpgNode {
                id: ps.enclosing_fn.clone(),
                label: ps.enclosing_fn.clone(),
                kind: DpgNodeKind::Function,
            },
        );
        edges.push(DpgEdge {
            from: ps.enclosing_fn.clone(),
            to: ps.panic_id.clone(),
            kind: DpgEdgeKind::ContainsPanic,
        });
    }

    DangerousPathGraph { nodes, edges }
}

fn insert_node(nodes: &mut Vec<DpgNode>, seen: &mut BTreeSet<String>, node: DpgNode) {
    if seen.insert(node.id.clone()) {
        nodes.push(node);
    }
}