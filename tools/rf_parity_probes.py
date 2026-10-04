#!/usr/bin/env python3
"""Ancestor-aware numeric probes for RF-to-P4 parity, not training data.

Every witness is inside the frozen per-feature integer domain and follows all
ancestor split predicates. The Cartesian feature domain includes combinations
that no physical flow can produce; coverage here is classifier-code coverage,
not traffic coverage or an accuracy measurement.
"""

import copy

import prepare_rf_deployment as reference


def _reachable_boxes(export):
    """Yield (tree ID, native node ID, ancestor box) for feasible nodes."""
    initial = tuple((export['domains'][name]['min'],
                     export['domains'][name]['max'])
                    for name in export['feature_order'])
    for tree_id, tree in enumerate(export['trees']):
        stack = [(0, initial)]
        while stack:
            node_id, box = stack.pop()
            yield tree_id, node_id, box
            node = tree['nodes'][node_id]
            if node['kind'] == 'leaf':
                continue
            # Push right first so the traversal and generated witnesses are
            # deterministic in left-to-right tree order.
            for side in ('right', 'left'):
                child_box = _child_box(box, node, side)
                if child_box is not None:
                    stack.append((node[side], child_box))


def _child_box(box, node, side):
    """Intersect one branch predicate with all existing ancestor constraints."""
    index, cut = node['feature_index'], node['cut']
    lo, hi = box[index]
    if side == 'left':
        hi = min(hi, cut)
    else:
        lo = max(lo, cut + 1)
    if lo > hi:
        return None
    result = list(box)
    result[index] = (lo, hi)
    return tuple(result)


def branch_probes(export):
    """Return witnesses for all numerically reachable nodes and branches.

    For a left branch, prefer the cut itself; for a right branch, prefer cut+1.
    If an ancestor constraint moves the branch away from that boundary, choose
    the nearest feasible value instead. Other coordinates use the lower bound
    of their ancestor-constrained interval. Leaf witnesses cover constant trees
    as well. Deduplication is across trees but preserves deterministic order.
    """
    reference.validate_export(export)
    probes, seen = [], set()

    def add(row):
        key = tuple(row)
        if key not in seen:
            seen.add(key)
            probes.append(row)

    for tree_id, node_id, box in _reachable_boxes(export):
        node = export['trees'][tree_id]['nodes'][node_id]
        if node['kind'] == 'leaf':
            add([lo for lo, _ in box])
            continue
        for side in ('left', 'right'):
            child_box = _child_box(box, node, side)
            if child_box is None:
                continue
            row = [lo for lo, _ in child_box]
            index = node['feature_index']
            # Left interval's upper bound is min(parent_hi, cut); right
            # interval's lower bound is max(parent_lo, cut+1).
            row[index] = child_box[index][1 if side == 'left' else 0]
            add(row)
    reference.validate_vectors(export, probes)
    return probes


def coverage(export, vectors):
    """Count reachable/covered native tree nodes, leaves and branch edges.

    Empty inputs are rejected rather than silently reported as a completed
    parity check. Infeasible nodes are structurally connected to the tree root
    but cannot be reached inside the frozen integer feature domain.
    """
    reference.validate_export(export)
    values = reference.validate_vectors(export, vectors)
    total = {'nodes': set(), 'leaves': set(), 'branches': set()}
    reachable = {name: set() for name in total}
    covered = {name: set() for name in total}

    for tree_id, tree in enumerate(export['trees']):
        for node_id, node in enumerate(tree['nodes']):
            total['nodes'].add((tree_id, node_id))
            if node['kind'] == 'leaf':
                total['leaves'].add((tree_id, node_id))
            else:
                total['branches'].update((tree_id, node_id, side)
                                         for side in ('left', 'right'))

    for tree_id, node_id, box in _reachable_boxes(export):
        reachable['nodes'].add((tree_id, node_id))
        node = export['trees'][tree_id]['nodes'][node_id]
        if node['kind'] == 'leaf':
            reachable['leaves'].add((tree_id, node_id))
        else:
            for side in ('left', 'right'):
                if _child_box(box, node, side) is not None:
                    reachable['branches'].add((tree_id, node_id, side))

    for row in values:
        for tree_id, tree in enumerate(export['trees']):
            node_id = 0
            while True:
                covered['nodes'].add((tree_id, node_id))
                node = tree['nodes'][node_id]
                if node['kind'] == 'leaf':
                    covered['leaves'].add((tree_id, node_id))
                    break
                side = 'left' if row[node['feature_index']] <= node['cut'] else 'right'
                covered['branches'].add((tree_id, node_id, side))
                node_id = node[side]

    result = {'vectors': len(values),
              'scope': 'frozen integer Cartesian feature domain; not physical-flow coverage'}
    for name in total:
        reference.require(covered[name] <= reachable[name],
                          'Internal probe coverage/reachability inconsistency')
        result[name] = {'total': len(total[name]),
                        'reachable': len(reachable[name]),
                        'covered': len(covered[name])}
        result['uncovered_' + name] = [list(item) for item in sorted(reachable[name] - covered[name])]
        result['infeasible_' + name] = [list(item) for item in sorted(total[name] - reachable[name])]
    return result


def synthetic_export():
    """Return a valid diagnostic-only forest that stresses aggregation rules.

    Four input regions exercise lowest-index ties (classes 0/1 and 2/4), a
    maximum score accumulator (all trees assign class 5 probability 1), and a
    soft-vote result of class 1 despite six hard tree votes for class 0.
    This forest is never a replacement for either fitted research model.
    """
    feature_set = 'B'

    def leaf(probabilities):
        return {'kind': 'leaf', 'probabilities': probabilities,
                'scores': [int(round(p * reference.SCALE)) for p in probabilities]}

    def split(threshold, left, right):
        return {'kind': 'split', 'feature_index': 0,
                'threshold_float64': float(threshold),
                'cut': reference.integer_cut(threshold, reference.DOMAINS['size_min']['max']),
                'left': left, 'right': right}

    result = {
        'schema_version': reference.VERSION,
        'feature_set': feature_set,
        'feature_order': list(reference.FEATURES[feature_set]),
        'classes': list(reference.baseline.CLASSES),
        'domains': copy.deepcopy({name: reference.DOMAINS[name]
                                  for name in reference.FEATURES[feature_set]}),
        'score_scale': reference.SCALE,
        'parameters': dict(reference.PARAMETERS),
        'trees': [],
    }
    for tree_id in range(10):
        disagreement = ([0.51, 0.49, 0, 0, 0, 0] if tree_id < 6
                        else [0, 1, 0, 0, 0, 0])
        result['trees'].append({'nodes': [
            split(100, 1, 2),
            leaf([0.5, 0.5, 0, 0, 0, 0]),
            split(200, 3, 4),
            leaf([0, 0, 0.5, 0, 0.5, 0]),
            split(300, 5, 6),
            leaf([0, 0, 0, 0, 0, 1]),
            leaf(disagreement),
        ]})
    reference.validate_export(result)
    return result


def synthetic_vectors():
    """Four numeric-only witnesses; do not interpret these as real flows."""
    width = len(reference.FEATURES['B'])
    return [[value] + [0] * (width - 1) for value in (100, 101, 201, 301)]
