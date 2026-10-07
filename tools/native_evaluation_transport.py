#!/usr/bin/env python3
"""Paced isolated-prefix batches, using persistent Linux AF_PACKET sockets.

Each case has its own unique Ethernet-address tag. Inter-case reports may
interleave; exact IP bytes, occurrences and order are checked within each case.
Userspace socket-read timestamps are diagnostics, NOT performance benchmarks.
This module never manages interfaces, switches, files, credentials or models.
"""
import heapq
import math
import selectors
import socket
import sys
import time

from native_pilot_transport import CaptureMatcher


ETH_P_ALL = 0x0003
MAX_CASES = 32
MAX_TIMEOUT_SECONDS = 600


def validate_batch(plans, timeout_seconds, drain_seconds):
    """Validate the entire batch before opening any socket or sending bytes."""
    if not isinstance(plans, list) or not 1 <= len(plans) <= MAX_CASES:
        raise ValueError('Batch needs 1..32 isolated eight-packet cases')
    if (not isinstance(timeout_seconds, (int, float)) or not math.isfinite(timeout_seconds)
            or not 0 < timeout_seconds <= MAX_TIMEOUT_SECONDS):
        raise ValueError('Whole-batch timeout must be finite and in (0, 600] seconds')
    if (not isinstance(drain_seconds, (int, float)) or not math.isfinite(drain_seconds)
            or not 0 <= drain_seconds <= 2):
        raise ValueError('Duplicate-capture drain must be finite and in [0, 2] seconds')
    ids, tags, latest = set(), set(), 0
    for plan in plans:
        if not isinstance(plan, dict):
            raise ValueError('Case plan must be a dictionary')
        case_id, frames = plan.get('case_id'), plan.get('frames')
        offsets, start = plan.get('relative_us'), plan.get('start_offset_us')
        if not isinstance(case_id, str) or not case_id or case_id in ids:
            raise ValueError('Each case needs a nonempty unique original record ID')
        ids.add(case_id)
        if not isinstance(frames, list) or len(frames) != 8:
            raise ValueError(f'{case_id}: exactly eight ordinary Ethernet/IPv4 frames required')
        if any(type(frame) is not bytes or len(frame) < 34 or frame[12:14] != b'\x08\x00'
               or frame[14] >> 4 != 4 for frame in frames):
            raise ValueError(f'{case_id}: incomplete/non-IPv4 input frame')
        tag = frames[0][:12]
        if any(frame[:12] != tag for frame in frames) or tag in tags:
            raise ValueError(f'{case_id}: use one unique Ethernet-address tag per case')
        tags.add(tag)
        if (not isinstance(offsets, list) or len(offsets) != 8
                or any(type(offset) is not int or offset < 0 for offset in offsets)
                or offsets[0] != 0 or offsets != sorted(offsets)):
            raise ValueError(f'{case_id}: eight nondecreasing integer offsets must start at zero')
        if type(start) is not int or start < 0:
            raise ValueError(f'{case_id}: nonnegative integer batch start offset required')
        latest = max(latest, start + offsets[-1])
    if latest / 1e6 + drain_seconds >= timeout_seconds:
        raise ValueError('Whole-batch timeout must exceed final scheduled send plus capture drain')
    return latest


def build_schedule(plans):
    """Heap keys preserve each case's packet order even for equal timestamps."""
    entries = [(plan['start_offset_us'] + offset, case_index, packet_index)
               for case_index, plan in enumerate(plans)
               for packet_index, offset in enumerate(plan['relative_us'])]
    heapq.heapify(entries)
    return entries


def _strict_output_decoder(callback):
    def decode(frame):
        key = callback(frame)
        # The caller already filtered this invocation's exact MAC-address tag.
        # A nonreport with that tag is not unrelated traffic: do not ignore it.
        if key is None:
            raise ValueError('Known-case tagged output is not a valid native debug report')
        return key
    return decode


def replay_batch(plans, input_iface, output_iface, timeout_seconds, *,
                 key_from_output, drain_seconds=0.3):
    """Replay <=32 independent prefixes with unchanged per-prefix timing gaps.

    This requires Linux raw-socket permission. Capture sockets are ready before
    sending, and scheduled sends never wait for previous reports. Packet IDs
    are not used for matching. Deadline/send/read failures return every case's
    diagnostics; setup/validation failures and Ctrl+C raise after cleanup.
    """
    latest = validate_batch(plans, timeout_seconds, drain_seconds)
    if sys.platform != 'linux' or not hasattr(socket, 'AF_PACKET'):
        raise ValueError('Native live batches require Linux AF_PACKET support')
    if not input_iface or not output_iface or input_iface == output_iface:
        raise ValueError('Use two distinct isolated host endpoints')
    decoder = _strict_output_decoder(key_from_output)
    matchers = {plan['case_id']: CaptureMatcher(plan['frames'], decoder) for plan in plans}
    by_tag = {plan['frames'][0][:12]: plan['case_id'] for plan in plans}
    sent_logs = {plan['case_id']: [] for plan in plans}
    schedule, global_errors = build_schedule(plans), []
    ignored = {'input_untagged': 0, 'output_untagged': 0}
    opened, selector = [], selectors.DefaultSelector()
    started_ns = None
    try:
        for role, interface in (('input', input_iface), ('output', output_iface)):
            capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
            opened.append(capture)
            capture.bind((interface, 0))
            capture.setblocking(False)
            selector.register(capture, selectors.EVENT_READ, role)
        sender = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        opened.append(sender)
        sender.bind((input_iface, 0))
        sender.settimeout(2.0)
        # All capture sockets are bound before the batch clock begins.
        started_ns = time.monotonic_ns()
        deadline_ns = started_ns + int(timeout_seconds * 1e9)
        completed_ns = None
        fatal_ns = None
        while True:
            now_ns = time.monotonic_ns()
            if now_ns >= deadline_ns:
                global_errors.append('Whole-batch deadline expired; inspect each case missing indices')
                break
            if fatal_ns is not None and now_ns - fatal_ns >= drain_seconds * 1e9:
                break
            if fatal_ns is None and schedule and started_ns + schedule[0][0] * 1000 <= now_ns:
                due_us, case_index, packet_index = heapq.heappop(schedule)
                plan, send_started_ns = plans[case_index], time.monotonic_ns()
                try:
                    length = sender.send(plan['frames'][packet_index])
                    send_finished_ns = time.monotonic_ns()
                    if length != len(plan['frames'][packet_index]):
                        raise OSError(f'Partial raw send: {length}/{len(plan["frames"][packet_index])}')
                except OSError as error:
                    global_errors.append(f'Send failed for {plan["case_id"]} packet {packet_index + 1}: {error}')
                    fatal_ns = time.monotonic_ns()
                else:
                    sent_logs[plan['case_id']].append({
                        'case_id': plan['case_id'], 'packet_index': packet_index,
                        'scheduled_offset_us': plan['relative_us'][packet_index],
                        'batch_scheduled_offset_us': due_us,
                        'scheduled_monotonic_ns': started_ns + due_us * 1000,
                        'actual_send_monotonic_ns': send_started_ns,
                        'send_finished_monotonic_ns': send_finished_ns,
                        'actual_batch_offset_us': (send_started_ns - started_ns) / 1000,
                        'send_lateness_ns': send_started_ns - started_ns - due_us * 1000})
            all_received = all(not matcher.input.missing() and not matcher.output.missing()
                               for matcher in matchers.values())
            if not schedule and all_received:
                completed_ns = completed_ns or time.monotonic_ns()
                if time.monotonic_ns() - completed_ns >= drain_seconds * 1e9:
                    break
            next_due_ns = (started_ns + schedule[0][0] * 1000
                           if schedule and fatal_ns is None else deadline_ns)
            stop_ns = min(deadline_ns,
                          fatal_ns + int(drain_seconds * 1e9) if fatal_ns is not None else deadline_ns,
                          completed_ns + int(drain_seconds * 1e9) if completed_ns is not None else deadline_ns)
            # Once another packet is due, capture select is nonblocking: sending
            # does not wait for BMv2 reports. Max 64 reads prevents noise starvation.
            wait_seconds = max(0.0, min(.02, (next_due_ns - time.monotonic_ns()) / 1e9,
                                       (stop_ns - time.monotonic_ns()) / 1e9))
            try:
                ready = selector.select(wait_seconds)
                for key, _ in ready:
                    for _ in range(64):
                        try:
                            frame, address = key.fileobj.recvfrom(65535)
                        except BlockingIOError:
                            break
                        observed_ns, wall_ns = time.monotonic_ns(), time.time_ns()
                        case_id = by_tag.get(frame[:12])
                        if case_id is None:
                            ignored[key.data + '_untagged'] += 1
                            continue
                        matchers[case_id].observe(key.data, frame, address[2], observed_ns, wall_ns)
            except OSError as error:
                global_errors.append(f'Capture socket failed: {error}')
                # A broken capture cannot be meaningfully drained. Return all
                # partial case reports promptly rather than waiting minutes.
                break
        cases = {}
        for plan in plans:
            case_id = plan['case_id']
            row = matchers[case_id].report(sent_logs[case_id])
            if len(sent_logs[case_id]) != 8:
                row['transport_passed'] = False
                row['errors'].append('Not all eight scheduled sends completed successfully')
            row.update({'case_id': case_id, 'start_offset_us': plan['start_offset_us'],
                        'sent_packets': len(sent_logs[case_id]),
                        'status': 'complete' if row['transport_passed'] else 'incomplete_or_invalid'})
            cases[case_id] = row
        logs = [row for rows in sent_logs.values() for row in rows]
        return {'transport_passed': not global_errors and all(row['transport_passed'] for row in cases.values()),
                'cases': cases, 'global_errors': global_errors, 'ignored': ignored,
                'scheduling': {'policy': 'Global heap of unscaled original within-prefix offsets; no report-gated sends',
                               'planned_cases': len(plans), 'planned_packets': len(plans) * 8,
                               'sent_packets': len(logs), 'latest_scheduled_offset_us': latest,
                               'started_monotonic_ns': started_ns, 'finished_monotonic_ns': time.monotonic_ns(),
                               'timeout_seconds': timeout_seconds, 'drain_seconds': drain_seconds,
                               'maximum_send_lateness_us': max((row['send_lateness_ns'] / 1000 for row in logs), default=None)},
                'input_iface': input_iface, 'output_iface': output_iface,
                'capture_time_meaning': 'Userspace socket-read diagnostics, not forwarding/inference latency measurement'}
    finally:
        selector.close()
        for handle in opened:
            handle.close()
