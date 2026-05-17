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

    #[serde(default)]
    pub normalized_id: String,
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

    #[serde(default)]
    pub normalized_from: String,

    #[serde(default)]
    pub normalized_to: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DangerousPathGraph {
    pub nodes: Vec<DpgNode>,
    pub edges: Vec<DpgEdge>,

    #[serde(default)]
    pub reachability: Vec<ReachabilityFact>,

    #[serde(default)]
    pub normalization_notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReachabilityFact {
    pub from: String,
    pub to: String,
    pub distance: u32,
    pub via: Vec<String>,
    pub relation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UnsafeDistanceResult {
    pub from_node: String,
    pub nearest_site: Option<String>,
    pub distance: Option<u32>,
}

impl DangerousPathGraph {
    pub fn normalize_all(&mut self) {
        for node in &mut self.nodes {
            node.normalized_id = normalize_symbol(&node.id);
        }
        for edge in &mut self.edges {
            edge.normalized_from = normalize_symbol(&edge.from);
            edge.normalized_to = normalize_symbol(&edge.to);
        }
    }

    pub fn node_exists(&self, node_id: &str) -> bool {
        let key = normalize_symbol(node_id);
        self.nodes.iter().any(|n| n.id == node_id || n.normalized_id == key)
    }

    pub fn outgoing<'a>(&'a self, node_id: &'a str) -> impl Iterator<Item = &'a DpgEdge> {
        let key = normalize_symbol(node_id);
        self.edges.iter().filter(move |e| {
            e.from == node_id || e.normalized_from == key || normalize_symbol(&e.from) == key
        })
    }

    pub fn dangerous_site_ids(&self) -> Vec<&str> {
        self.nodes
            .iter()
            .filter(|n| matches!(n.kind, DpgNodeKind::DangerousSite | DpgNodeKind::FfiBoundary))
            .map(|n| n.id.as_str())
            .collect()
    }

    pub fn public_api_ids(&self) -> Vec<&str> {
        self.nodes
            .iter()
            .filter(|n| n.kind == DpgNodeKind::PublicApi)
            .map(|n| n.id.as_str())
            .collect()
    }

    pub fn shortest_distance_to_any_dangerous_site(&self, from_node: &str) -> UnsafeDistanceResult {
        let key = normalize_symbol(from_node);
        let start = self
            .nodes
            .iter()
            .find(|n| n.id == from_node || n.normalized_id == key)
            .map(|n| n.id.clone());
        let Some(start) = start else {
            return UnsafeDistanceResult { from_node: from_node.to_string(), nearest_site: None, distance: None };
        };

        let dangerous: HashSet<String> = self.dangerous_site_ids().into_iter().map(normalize_symbol).collect();
        if dangerous.contains(&normalize_symbol(&start)) {
            return UnsafeDistanceResult { from_node: from_node.to_string(), nearest_site: Some(start), distance: Some(0) };
        }

        let mut q = VecDeque::new();
        let mut visited = HashSet::new();
        let mut dist: BTreeMap<String, u32> = BTreeMap::new();

        q.push_back(start.clone());
        visited.insert(normalize_symbol(&start));
        dist.insert(normalize_symbol(&start), 0);

        while let Some(node) = q.pop_front() {
            let nd = *dist.get(&normalize_symbol(&node)).unwrap_or(&0);
            for edge in self.outgoing(&node) {
                let next = edge.to.clone();
                let next_norm = normalize_symbol(&next);
                if !visited.insert(next_norm.clone()) {
                    continue;
                }
                let next_dist = nd + 1;
                if dangerous.contains(&next_norm) {
                    return UnsafeDistanceResult {
                        from_node: from_node.to_string(),
                        nearest_site: Some(next),
                        distance: Some(next_dist),
                    };
                }
                dist.insert(next_norm, next_dist);
                q.push_back(next);
            }
        }

        UnsafeDistanceResult { from_node: from_node.to_string(), nearest_site: None, distance: None }
    }

    pub fn compute_reachability(&mut self) {
        let sources: Vec<String> = self
            .nodes
            .iter()
            .filter(|n| matches!(n.kind, DpgNodeKind::PublicApi | DpgNodeKind::Function | DpgNodeKind::PanicSite))
            .map(|n| n.id.clone())
            .collect();

        let dangerous: HashSet<String> = self
            .dangerous_site_ids()
            .into_iter()
            .map(normalize_symbol)
            .collect();

        let mut reachability = Vec::new();

        for source in sources {
            let mut q = VecDeque::new();
            let mut visited = HashSet::new();
            let mut parent: BTreeMap<String, String> = BTreeMap::new();
            let mut distance: BTreeMap<String, u32> = BTreeMap::new();

            q.push_back(source.clone());
            visited.insert(normalize_symbol(&source));
            distance.insert(normalize_symbol(&source), 0);

            while let Some(node) = q.pop_front() {
                let nd = *distance.get(&normalize_symbol(&node)).unwrap_or(&0);
                let outgoing_edges: Vec<DpgEdge> = self.outgoing(&node).cloned().collect();

                for edge in outgoing_edges {
                    let next = edge.to.clone();
                    let next_norm = normalize_symbol(&next);

                    if !visited.insert(next_norm.clone()) {
                        continue;
                    }

                    parent.insert(next.clone(), node.clone());
                    let d = nd + 1;
                    distance.insert(next_norm.clone(), d);

                    if dangerous.contains(&next_norm) {
                        reachability.push(ReachabilityFact {
                            from: source.clone(),
                            to: next.clone(),
                            distance: d,
                            via: reconstruct_path(&source, &next, &parent),
                            relation: "may_reach_dangerous_site".to_string(),
                        });
                    }

                    q.push_back(next);
                }
            }
        }

        self.reachability = reachability;
    }
}

pub fn normalize_symbol(s: &str) -> String {
    let mut out = s.trim().replace('\\', "/").replace(" ", "");
    while out.contains("::::") {
        out = out.replace("::::", "::");
    }
    if let Some(stripped) = out.strip_prefix("api::") {
        out = stripped.to_string();
    }
    out.to_lowercase()
}

fn reconstruct_path(source: &str, target: &str, parent: &BTreeMap<String, String>) -> Vec<String> {
    let mut path = vec![target.to_string()];
    let mut cur = target.to_string();
    while cur != source {
        let Some(prev) = parent.get(&cur) else { break };
        path.push(prev.clone());
        cur = prev.clone();
    }
    path.reverse();
    path
}
