use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet, VecDeque};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DpgNodeKind {
    PublicApi,
    Function,
    DangerousSite,
    PanicSite,
    HarnessSite,
    OracleEvent,
    FfiBoundary,
    TraceWaypoint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpgNode {
    pub id: String,
    pub label: String,
    pub kind: DpgNodeKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DpgEdgeKind {
    Exposes,
    Calls,
    ContainsDangerous,
    ContainsPanic,
    MayReach,
    ObservedBefore,
    ObservedAfter,
    InsideSameUnsafeRegion,
    ValidatedByOracle,
    BlockedByPanic,
    TriggeredByHarness,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpgEdge {
    pub from: String,
    pub to: String,
    pub kind: DpgEdgeKind,
    pub confidence: f32,
    pub static_or_dynamic: String,
    pub support_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DangerousPathGraph {
    pub nodes: Vec<DpgNode>,
    pub edges: Vec<DpgEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UnsafeDistanceResult {
    pub from_node: String,
    pub nearest_site: Option<String>,
    pub distance: Option<u32>,
}

impl DangerousPathGraph {
    pub fn node_exists(&self, node_id: &str) -> bool {
        self.nodes.iter().any(|n| n.id == node_id)
    }

    pub fn outgoing<'a>(&'a self, node_id: &'a str) -> impl Iterator<Item = &'a DpgEdge> {
        self.edges.iter().filter(move |e| e.from == node_id)
    }

    pub fn dangerous_site_ids(&self) -> Vec<&str> {
        self.nodes
            .iter()
            .filter(|n| n.kind == DpgNodeKind::DangerousSite)
            .map(|n| n.id.as_str())
            .collect()
    }

    pub fn shortest_distance_to_any_dangerous_site(&self, from_node: &str) -> UnsafeDistanceResult {
        if !self.node_exists(from_node) {
            return UnsafeDistanceResult {
                from_node: from_node.to_string(),
                nearest_site: None,
                distance: None,
            };
        }

        let dangerous: HashSet<&str> = self.dangerous_site_ids().into_iter().collect();
        if dangerous.contains(from_node) {
            return UnsafeDistanceResult {
                from_node: from_node.to_string(),
                nearest_site: Some(from_node.to_string()),
                distance: Some(0),
            };
        }

        let mut q = VecDeque::new();
        let mut visited = HashSet::new();
        let mut dist: BTreeMap<String, u32> = BTreeMap::new();

        q.push_back(from_node.to_string());
        visited.insert(from_node.to_string());
        dist.insert(from_node.to_string(), 0);

        while let Some(cur) = q.pop_front() {
            let cur_dist = *dist.get(&cur).unwrap_or(&0);

            for edge in self.outgoing(&cur) {
                if visited.contains(&edge.to) {
                    continue;
                }
                let next = edge.to.clone();
                let next_dist = cur_dist + 1;
                if dangerous.contains(next.as_str()) {
                    return UnsafeDistanceResult {
                        from_node: from_node.to_string(),
                        nearest_site: Some(next),
                        distance: Some(next_dist),
                    };
                }
                visited.insert(next.clone());
                dist.insert(next.clone(), next_dist);
                q.push_back(next);
            }
        }

        UnsafeDistanceResult {
            from_node: from_node.to_string(),
            nearest_site: None,
            distance: None,
        }
    }
}