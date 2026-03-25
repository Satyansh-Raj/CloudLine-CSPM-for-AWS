/** Types for the security resource graph endpoint. */

export interface GraphNode {
  id: string;
  label: string;
  resource_type: string;
  service: string;
  region: string;
  violation_count: number;
  max_severity: string;
  risk_score: number;
}

export interface GraphEdge {
  source: string;
  target: string;
  relationship: string;
  attack_path: boolean;
}

export interface SecurityGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  attack_paths: number;
  total_nodes: number;
  total_edges: number;
}
