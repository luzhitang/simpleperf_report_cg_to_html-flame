#!/usr/bin/env python3
"""
Collapse simpleperf report into folded stacks / HTML tree / FlameGraph.
- Parse full callgraph trees by multiplying root Children% with any explicit inline percentages on the path; frames without percentage inherit 100%.
- Parse brief mode by grouping contiguous rows with same Command and near-equal Children%,
  reconstructing the full call chain (in original order) as one stack.
- Counts are computed directly as Event count × (root Children% and path percentages). No normalization or remainder fill like "[other]".
"""

import argparse
import os
import re
import subprocess
import sys
import urllib.request
import tempfile
import stat
import shutil
import json

from collections import defaultdict


def read_text_file_auto(path):
    with open(path, 'rb') as f:
        data = f.read()
    try:
        return data.decode('utf-8-sig')
    except Exception:
        pass
    try:
        return data.decode('utf-16')
    except Exception:
        pass
    for enc in ('utf-16-le', 'utf-16-be', 'utf-8', 'latin-1'):
        try:
            return data.decode(enc)
        except Exception:
            continue
    return data.decode('utf-8', errors='replace')


def run_simpleperf_report(data_path):
    # Prepare report output path: report_<basename>.txt in the same directory as data
    base_dir = os.path.dirname(data_path) or os.getcwd()
    base_name = os.path.splitext(os.path.basename(data_path))[0]
    report_txt = os.path.join(base_dir, f"report_{base_name}.txt")
    report_sg_txt = os.path.join(base_dir, f"report_{base_name}_sg.txt")

    # Try to let simpleperf write to the report file directly (if supported)
    cmd_with_simple = ["simpleperf", "report", "-i", data_path, "-o", report_txt]
    cmd_with_sg = ["simpleperf", "report", "-i", data_path, "-g", "-o", report_sg_txt]
    try:
        p0 = subprocess.run(cmd_with_simple, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, text=True)
        p = subprocess.run(cmd_with_sg, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, text=True)
        # Read back the generated report file (stdout may be empty when using -o)
        try:
            with open(report_sg_txt, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception:
            # Fallback to stdout if reading file fails for any reason
            return p.stdout
    except Exception:
        # Fallback: run without -o, capture stdout, and write it to report_sg_txt
        cmd = ["simpleperf", "report", "-i", data_path, "-g"]
        try:
            p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, text=True)
            try:
                with open(report_sg_txt, 'w', encoding='utf-8') as f:
                    f.write(p.stdout)
            except Exception:
                pass
            return p.stdout
        except Exception:
            return None


def parse_report_text(text, reverse=False, dedug_first_start=False, equalize_root_sum=False):
    lines = text.splitlines()
    stacks = {}

    # Basic info
    basic_info = {}
    event_count = None
    total_samples = None
    for line in lines[:40]:
        s = line.strip()
        if s.startswith('Cmdline:'):
            basic_info['cmdline'] = s.replace('Cmdline:', '').strip()
        elif s.startswith('Arch:'):
            basic_info['arch'] = s.replace('Arch:', '').strip()
        elif s.startswith('Event:'):
            basic_info['event'] = s.replace('Event:', '').strip()
        elif s.startswith('Samples:'):
            basic_info['samples'] = s.replace('Samples:', '').strip()
            try:
                total_samples = int(basic_info['samples'])
            except Exception:
                pass
        elif s.startswith('Error Callchains:'):
            basic_info['error_callchains'] = s.replace('Error Callchains:', '').strip()
        elif s.startswith('Event count:'):
            basic_info['event_count'] = s.replace('Event count:', '').strip()
            try:
                event_count = int(basic_info['event_count'])
            except Exception:
                pass

    if event_count is None or total_samples is None:
        sys.exit(1)

    events_per_sample = event_count / total_samples if total_samples > 0 else 1
    event_total = events_per_sample * total_samples

    has_tree = any(l.strip().startswith('-- ') or ('|--' in l) for l in lines)
    is_brief = (not has_tree) and any('skipped in brief callgraph mode' in l for l in lines)

    # Brief mode: aggregate contiguous rows by thread, use the first row's Children% for the whole block
    current = None  # {'thread_key': (command,pid,tid), 'command': str, 'symbols': [...], 'block_pct': float}
    emitted_threads = set()  # threads already emitted when dedug_first_start is enabled

    def flush_current_block():
        nonlocal current
        if not current or not current.get('symbols'):
            return
        # If marked as skipped, do not emit this block
        if current.get('skip'):
            return
        should_emit = True
        if dedug_first_start:
            if current['thread_key'] in emitted_threads:
                should_emit = False
            else:
                first_sym = current['symbols'][0] if current['symbols'] else ''
                if '__start_thread' not in first_sym:
                    should_emit = False
        if should_emit:
            elems = [current['command']] + current['symbols']
            if reverse:
                elems.reverse()
            key = ';'.join(elems)
            cnt_float = event_total * (current['block_pct'] / 100.0)
            if cnt_float > 0.0:
                stacks[key] = stacks.get(key, 0.0) + cnt_float
            if dedug_first_start:
                emitted_threads.add(current['thread_key'])

    i = 0
    while i < len(lines):
        line = lines[i].rstrip()
        if not line:
            i += 1
            continue
        if line.startswith('Cmdline:') or line.startswith('Arch:') or line.startswith('Event:') \
           or line.startswith('Samples:') or line.startswith('Error Callchains:') or line.startswith('Event count:'):
            i += 1
            continue
        if 'Children' in line and 'Self' in line and 'Command' in line:
            i += 1
            continue
        if 'skipped in brief callgraph mode' in line:
            # Mark current brief block as skipped to avoid double counting
            if not has_tree and current is not None:
                current['skip'] = True
            i += 1
            continue

        if re.match(r'^\d+\.\d+%', line):
            parts = re.split(r'\s{2,}', line)
            if len(parts) < 6:
                i += 1
                continue
            command = parts[2].strip()
            pid = parts[3].strip() if len(parts) > 3 else ''
            tid = parts[4].strip() if len(parts) > 4 else ''
            symbol = parts[-1].strip()
            try:
                children_pct_val = float(parts[0].strip().rstrip('%'))
            except Exception:
                children_pct_val = 100.0

            if has_tree:
                # Tree mode: only keep first main entry per thread starting from __start_thread if dedug_first_start
                key_thread = (command, pid, tid)
                if dedug_first_start:
                    if key_thread in emitted_threads:
                        i = skip_to_next_main_entry(lines, i + 1)
                        continue
                    if '__start_thread' not in symbol:
                        i = skip_to_next_main_entry(lines, i + 1)
                        continue
                i += 1
                tree_stacks = parse_entry_callstack(lines, i, command, children_pct_val, events_per_sample, total_samples, equalize_root_sum)
                for stack_str, count in tree_stacks.items():
                    stk = ';'.join(reversed(stack_str.split(';'))) if reverse else stack_str
                    # Skip zero-count stacks
                    if float(count) <= 0.0:
                        continue
                    stacks[stk] = stacks.get(stk, 0.0) + float(count)
                if dedug_first_start:
                    emitted_threads.add(key_thread)
                i = skip_to_next_main_entry(lines, i)
                continue
            else:
                # Brief mode
                key_thread = (command, pid, tid)
                if current is None:
                    current = {
                        'thread_key': key_thread,
                        'command': command,
                        'symbols': [symbol] if symbol else [],
                        'block_pct': children_pct_val,
                        'skip': False,
                    }
                else:
                    if key_thread == current['thread_key']:
                        if symbol and (not current['symbols'] or current['symbols'][-1] != symbol):
                            current['symbols'].append(symbol)
                    else:
                        # flush previous contiguous block for the prior thread (with optional dedug/skip)
                        flush_current_block()
                        # start new block for new thread
                        current = {
                            'thread_key': key_thread,
                            'command': command,
                            'symbols': [symbol] if symbol else [],
                            'block_pct': children_pct_val,
                            'skip': False,
                        }
                i += 1
                continue
        else:
            i += 1

    # finalize remaining active block (brief mode)
    if not has_tree and current is not None and current.get('symbols'):
        flush_current_block()

    raw_stacks = dict(stacks)
    final_stacks = {k: int(round(v)) for k, v in stacks.items() if v > 0}
    return final_stacks, event_count, total_samples, basic_info, raw_stacks


def find_thread_head_pct(report_text, thread_name):
    """Find the first Children% row for a given thread in the table (prefer __start_thread if present)."""
    best_pct = None
    first_pct = None
    for line in report_text.splitlines():
        if not re.match(r'^\d+\.\d+%', line.strip()):
            continue
        parts = re.split(r'\s{2,}', line.rstrip())
        if len(parts) < 6:
            continue
        command = parts[2].strip()
        if command != thread_name:
            continue
        try:
            pct = float(parts[0].strip().rstrip('%'))
        except Exception:
            continue
        symbol = parts[-1].strip()
        if first_pct is None:
            first_pct = pct
        if '__start_thread' in symbol:
            best_pct = pct
            break
    return best_pct if best_pct is not None else first_pct


def parse_entry_callstack(lines, start_idx, command, children_pct, events_per_sample, total_samples, equalize_root_sum=False):
    stacks = {}
    i = start_idx

    while i < len(lines):
        line = lines[i]
        if not line.strip():
            i += 1
            continue
        if re.match(r'^\d+\.\d+%', line):
            break
        if line.strip() == '|' or 'skipped in brief callgraph mode' in line:
            i += 1
            continue
        if line.strip().startswith('-- '):
            root_func = line.strip()[3:].strip()
            if root_func and len(root_func) > 1:
                tree_stacks = parse_callstack_tree_new(lines, i, command, children_pct, events_per_sample, total_samples)
                # Equalize: scale this root's stacks so their sum equals EventCount * Children%
                if equalize_root_sum and '__start_thread' in root_func:
                    event_total = events_per_sample * total_samples
                    block_total = event_total * (children_pct / 100.0)
                    ssum = sum(tree_stacks.values())
                    if ssum > 0 and block_total > 0:
                        factor = block_total / ssum
                        for k in list(tree_stacks.keys()):
                            tree_stacks[k] *= factor
                for stack_str, count in tree_stacks.items():
                    stacks[stack_str] = stacks.get(stack_str, 0.0) + count
            i = skip_to_next_tree_or_main_entry(lines, i)
            continue
        i += 1

    return stacks


def parse_callstack_tree_new(lines, start_idx, command, children_pct, events_per_sample, total_samples):
    stacks = {}

    root_line = lines[start_idx].strip()
    if not root_line.startswith('-- '):
        return stacks
    root_func = root_line[3:].strip()

    base_path = [command, root_func] if (command and command != 'Unknown') else [root_func]
    event_total = events_per_sample * total_samples

    frames = []
    context_stack = []
    pending_context = []
    emitted = set()
    pipe_base_depth = None  # 基准深度：首次遇到管道形式的节点时，固定为当前帧栈深度

    def flatten_context(upto_level):
        res = []
        for idx in range(min(upto_level, len(context_stack))):
            res.extend(context_stack[idx])
        return res

    def emit_leaf(frames_prefix):
        if not frames_prefix:
            return
        frac = (children_pct / 100.0) if children_pct is not None else 1.0
        for fr in frames_prefix:
            pct = fr.get('pct')
            if pct is not None:
                frac *= (pct / 100.0)
        count_float = event_total * frac
        ctx = flatten_context(len(frames_prefix))
        stack_path = base_path + ctx + [fr['name'] for fr in frames_prefix]
        key = ';'.join(stack_path)
        if key in emitted:
            return
        emitted.add(key)
        stacks[key] = stacks.get(key, 0.0) + count_float

    i = start_idx + 1
    while i < len(lines):
        line = lines[i]
        if not line.strip():
            i += 1
            continue
        # stop only on main-entry row or a new root at column 0
        if re.match(r'^\d+\.\d+%', line) or line.startswith('-- '):
            break
        if line.strip() == '|' or 'skipped in brief callgraph mode' in line:
            i += 1
            continue

        stripped_full = line.strip()
        stripped_l = line.lstrip()

        # implicit child frame without markers: treat as a child of previous level (100% weight)
        if stripped_full and not stripped_full.startswith('|') and not stripped_full.startswith('--') and not re.search(r'\d+\.\d+%', stripped_full):
            if frames:
                frames[-1]['child'] = True
            frames.append({'name': stripped_full, 'pct': None, 'child': False})
            i += 1
            continue

        # child node without percentage like "   -- func" => treat as frame with 100%
        if stripped_l.startswith('-- '):
            func_name = stripped_l[3:].strip()
            if pending_context:
                depth = len(frames)
                while len(context_stack) < depth:
                    context_stack.append([])
                if len(context_stack) == depth:
                    context_stack.append(pending_context[:])
                else:
                    context_stack[depth].extend(pending_context)
                pending_context.clear()
            if any(fr['name'] == func_name for fr in frames):
                if frames:
                    frames[-1]['child'] = True
                i += 1
                continue
            if frames:
                frames[-1]['child'] = True
            frames.append({'name': func_name, 'pct': None, 'child': False})
            i += 1
            continue

        m = re.search(r'\|--(\d+\.\d+%)--\s*(.+)', line)
        if m:
            pct_str = m.group(1)
            func_name = m.group(2).strip()
            try:
                pct_val = float(pct_str.rstrip('%'))
            except Exception:
                pct_val = 0.0

            pipe_count = 0
            for ch in line:
                if ch == '|':
                    pipe_count += 1
                elif ch not in (' ', '\t'):
                    break
            rel_depth = max(0, pipe_count - 1)
            if pipe_base_depth is None:
                pipe_base_depth = len(frames)
            depth = pipe_base_depth + rel_depth

            while len(frames) > depth:
                last = frames.pop()
                if not last.get('child'):
                    emit_leaf(frames + [last])
            while len(context_stack) > depth:
                context_stack.pop()

            if pending_context:
                while len(context_stack) < depth:
                    context_stack.append([])
                if len(context_stack) == depth:
                    context_stack.append(pending_context[:])
                else:
                    context_stack[depth].extend(pending_context)
                pending_context.clear()

            if any(fr['name'] == func_name for fr in frames):
                if frames:
                    frames[-1]['child'] = True
                i += 1
                continue

            if frames:
                frames[-1]['child'] = True
            frames.append({'name': func_name, 'pct': pct_val, 'child': False})

            if len(frames) > 512:
                emit_leaf(frames)
                break

        i += 1

    if pending_context:
        depth = len(frames)
        while len(context_stack) < depth:
            context_stack.append([])
        if len(context_stack) == depth:
            context_stack.append(pending_context[:])
        else:
            context_stack[depth].extend(pending_context)
        pending_context.clear()

    while frames:
        last = frames.pop()
        if not last.get('child'):
            emit_leaf(frames + [last])

    return stacks


def skip_to_next_tree_or_main_entry(lines, start_idx):
    i = start_idx + 1
    while i < len(lines):
        line = lines[i]
        if not line.strip():
            i += 1
            continue
        # next table entry or next root at column 0
        if re.match(r'^\d+\.\d+%', line) or line.startswith('-- '):
            return i
        i += 1
    return i


def skip_to_next_main_entry(lines, start_idx):
    i = start_idx
    while i < len(lines):
        line = lines[i]
        if re.match(r'^\d+\.\d+%', line):
            return i
        i += 1
    return i


def validate_folded_file(folded_path):
    if not os.path.isfile(folded_path):
        return False, "File does not exist"
    if os.path.getsize(folded_path) == 0:
        return False, "File is empty"
    try:
        line_count = 0
        valid_lines = 0
        with open(folded_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line_count += 1
                line = line.strip()
                if not line:
                    continue
                parts = line.rsplit(' ', 1)
                if len(parts) == 2:
                    try:
                        count = int(parts[1])
                        if count > 0:
                            valid_lines += 1
                    except ValueError:
                        pass
                if line_num >= 1000:
                    break
        if valid_lines == 0:
            return False, f"No valid stack traces found (checked {line_count} lines)"
        validity_ratio = valid_lines / min(line_count, 1000)
        if validity_ratio < 0.5:
            return False, f"Too many invalid lines: {valid_lines}/{min(line_count, 1000)} valid"
        return True, f"Valid folded file: {valid_lines} valid lines out of {line_count} total"
    except Exception as e:
        return False, f"Error reading file: {e}"


def write_folded(stacks, out_path):
    with open(out_path, 'w', encoding='utf-8') as f:
        for stack, count in stacks.items():
            try:
                c = int(count)
            except Exception:
                try:
                    c = int(round(float(count)))
                except Exception:
                    c = 0
            if c <= 0:
                continue
            f.write(f"{stack} {c}\n")


def write_folded_ordered_for_flamegraph(stacks, out_path, total_event_count):
    # Write counts as parsed, without any scaling/normalization. Skip zero or negative counts.
    written = 0
    with open(out_path, 'w', encoding='utf-8') as f:
        for stack, count in stacks.items():
            c = int(round(count)) if isinstance(count, (int, float)) else int(count)
            if c <= 0:
                continue
            f.write(f"{stack} {c}\n")
            written += c
    return written


def download_flamegraph(dest_dir=None):
    url = 'https://raw.githubusercontent.com/brendangregg/FlameGraph/master/flamegraph.pl'
    if dest_dir is None:
        dest_dir = os.getcwd()
    dest = os.path.join(dest_dir, 'flamegraph.pl')
    if os.path.isfile(dest):
        return dest
    fd, tmp_path = tempfile.mkstemp(prefix='flamegraph_', suffix='.pl')
    os.close(fd)
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            if resp.status != 200:
                raise RuntimeError(f"HTTP {resp.status}: Failed to download flamegraph.pl")
            with open(tmp_path, 'wb') as out:
                out.write(resp.read())
        try:
            st = os.stat(tmp_path)
            os.chmod(tmp_path, st.st_mode | stat.S_IEXEC)
        except Exception:
            pass
        shutil.move(tmp_path, dest)
        return dest
    except Exception as e:
        try:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
        except Exception:
            pass
        raise RuntimeError(f"Failed to download flamegraph.pl: {e}")


def call_flamegraph(flamegraph_path, folded_path, svg_out, perl_path=None, basic_info=None, event_count=None, total_samples=None, events_per_sample=None):
    if not os.path.isfile(flamegraph_path):
        raise FileNotFoundError(f"flamegraph.pl not found at {flamegraph_path}")
    if not os.path.isfile(folded_path):
        raise FileNotFoundError(f"Folded file not found at {folded_path}")
    if os.path.getsize(folded_path) == 0:
        raise RuntimeError("Folded file is empty - no data to generate flamegraph")

    # Build dynamic title from event type name (strip parentheses suffix)
    event_field = (basic_info or {}).get('event', '')
    event_name = event_field.split('(')[0].strip() if event_field else 'Performance'
    graph_title = f"{event_name} Flamegraph"

    use_perl = False
    if os.name == 'nt' or flamegraph_path.lower().endswith('.pl'):
        use_perl = True
    else:
        try:
            st = os.stat(flamegraph_path)
            if not (st.st_mode & stat.S_IXUSR):
                use_perl = True
        except Exception:
            use_perl = True

    if use_perl:
        perl = None
        if perl_path:
            if os.path.isfile(perl_path):
                perl = perl_path
            else:
                found_perl = shutil.which(perl_path)
                if found_perl:
                    perl = found_perl
        if not perl:
            perl = shutil.which('perl')
        if not perl and os.name == 'nt':
            for path in [
                r"C:\\Strawberry\\perl\\bin\\perl.exe",
                r"C:\\Perl64\\bin\\perl.exe",
                r"C:\\Perl\\bin\\perl.exe",
                r"C:\\ActivePerl\\bin\\perl.exe",
                r"C:\\msys64\\usr\\bin\\perl.exe",
            ]:
                if os.path.isfile(path):
                    perl = path
                    break
        if not perl:
            raise FileNotFoundError(
                'Perl interpreter not found. Please install Perl or provide --perl path.'
            )
        cmd = [perl, flamegraph_path,
               '--width', '1800',
               '--height', '16',
               '--title', graph_title,
               '--fontsize', '12',
               '--countname', 'events',
               folded_path]
    else:
        cmd = [flamegraph_path,
               '--width', '1800',
               '--height', '16',
               '--title', graph_title,
               '--fontsize', '12',
               '--countname', 'events',
               folded_path]

    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
    if proc.returncode != 0:
        stderr = proc.stderr.decode('utf-8', errors='replace') if proc.stderr else "Unknown error"
        raise RuntimeError(f"flamegraph.pl failed (exit code {proc.returncode}): {stderr}")
    if not proc.stdout:
        raise RuntimeError("flamegraph.pl produced no output")

    raw_svg_path = svg_out
    if not raw_svg_path:
        raise RuntimeError("--svg output path is required")
    with open(raw_svg_path, 'wb') as outfh:
        outfh.write(proc.stdout)

    base, _ = os.path.splitext(raw_svg_path)
    html_out = f"{base}_svg.html"
    create_responsive_flamegraph_html(raw_svg_path, html_out,
                                      basic_info=basic_info,
                                      event_count=event_count,
                                      total_samples=total_samples,
                                      events_per_sample=events_per_sample)
    if os.path.getsize(html_out) == 0:
        raise RuntimeError("Generated HTML file is empty")
    return html_out


def create_responsive_flamegraph_html(svg_path, html_out, basic_info=None, event_count=None, total_samples=None, events_per_sample=None):
    if not os.path.isfile(svg_path):
        raise FileNotFoundError(f"SVG file not found: {svg_path}")
    if os.path.getsize(svg_path) == 0:
        raise RuntimeError("SVG file is empty")
    svg_filename = os.path.basename(svg_path)

    cmdline = (basic_info or {}).get('cmdline', 'N/A')
    arch = (basic_info or {}).get('arch', 'N/A')
    event = (basic_info or {}).get('event', 'N/A')
    err = (basic_info or {}).get('error_callchains', 'N/A')
    evt_cnt = f"{event_count:,}" if isinstance(event_count, int) else 'N/A'
    tot_samp = f"{total_samples:,}" if isinstance(total_samples, int) else 'N/A'
    eps = f"{events_per_sample:.2f}" if isinstance(events_per_sample, (int, float)) else 'N/A'

    # Build page title as "<event> Flamegraph" using the event name before parenthesis
    event_field = (basic_info or {}).get('event', '')
    event_name = event_field.split('(')[0].strip() if event_field else 'Performance'
    event_title = f"{event_name} Flamegraph"

    html_content = '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>EVENT_TITLE_PLACEHOLDER</title>
<style>
body { margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f5f5f5; }
.header { background-color: #2c3e50; color: white; padding: 15px; text-align: center; }
.header h1 { margin: 0; font-size: 20px; }
.header p { margin: 5px 0 0 0; opacity: 0.8; font-size: 12px; }
.controls { background-color: #34495e; color: white; padding: 10px; text-align: center; }
.controls button { background-color: #3498db; color: white; border: none; padding: 6px 12px; margin: 0 5px; border-radius: 3px; cursor: pointer; font-size: 12px; }
.controls button:hover { background-color: #2980b9; }
.info { background: #ffffff; margin: 10px; padding: 12px; border-radius: 6px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
.info h3 { margin: 0 0 8px 0; font-size: 14px; }
.info ul { margin: 0; padding-left: 18px; }
.info li { margin: 2px 0; font-size: 12px; }
.info code { background:#e8e8e8; padding:1px 4px; border-radius:3px; }
.flamegraph-container { width: 100%; height: calc(100vh - 220px); background-color: white; }
.flamegraph-iframe { width: 100%; height: 100%; border: none; background-color: white; }
</style>
</head>
<body>
<div class="header">
<h1>🔥 EVENT_TITLE_PLACEHOLDER</h1>
<p>Interactive CPU performance visualization</p>
</div>
<div class="controls">
<button onclick="window.open('SVG_FILENAME_PLACEHOLDER', '_blank')">🔗 Open SVG</button>
<button onclick="toggleFullscreen()">📱 Fullscreen</button>
</div>
<div class="info">
<h3>Simpleperf Report Information</h3>
<ul>
<li><strong>Command Line:</strong> <code>CMDLINE_PLACEHOLDER</code></li>
<li><strong>Architecture:</strong> ARCH_PLACEHOLDER</li>
<li><strong>Event Type:</strong> EVENT_PLACEHOLDER</li>
<li><strong>Total Samples:</strong> TOTAL_SAMPLES_PLACEHOLDER</li>
<li><strong>Error Callchains:</strong> ERROR_CALLCHAINS_PLACEHOLDER</li>
<li><strong>Total Event Count:</strong> EVENT_COUNT_PLACEHOLDER</li>
<li><strong>Events per Sample:</strong> EPS_PLACEHOLDER</li>
</ul>
</div>
<div class="flamegraph-container">
<iframe class="flamegraph-iframe" src="SVG_FILENAME_PLACEHOLDER" title="Flamegraph"></iframe>
</div>
<script>
function toggleFullscreen() {
    if (!document.fullscreenElement) {
        document.documentElement.requestFullscreen().catch(function(err) {
            alert('Fullscreen not supported');
        });
    } else {
        document.exitFullscreen();
    }
}
</script>
</body>
</html>'''
    html_content = html_content.replace('SVG_FILENAME_PLACEHOLDER', svg_filename)
    html_content = html_content.replace('CMDLINE_PLACEHOLDER', cmdline)
    html_content = html_content.replace('ARCH_PLACEHOLDER', arch)
    html_content = html_content.replace('EVENT_PLACEHOLDER', event)
    html_content = html_content.replace('ERROR_CALLCHAINS_PLACEHOLDER', err)
    html_content = html_content.replace('EVENT_COUNT_PLACEHOLDER', evt_cnt)
    html_content = html_content.replace('TOTAL_SAMPLES_PLACEHOLDER', tot_samp)
    html_content = html_content.replace('EPS_PLACEHOLDER', eps)
    html_content = html_content.replace('EVENT_TITLE_PLACEHOLDER', event_title)

    with open(html_out, 'w', encoding='utf-8', newline='') as f:
        f.write(html_content)


def stacks_to_tree(stacks, event_count):
    root = {'name': 'root', 'count': 0, 'children': {}}
    for stack, cnt in stacks.items():
        parts = stack.split(';')
        node = root
        for p in parts:
            children = node['children']
            if p not in children:
                children[p] = {'name': p, 'count': 0, 'children': {}}
            node = children[p]
            node['count'] += cnt
    root['count'] = sum(child['count'] for child in root['children'].values())

    insertion_order = {}
    order_counter = 0

    def record_order(stacks_dict, node_dict):
        nonlocal order_counter
        for stack in stacks_dict.keys():
            parts = stack.split(';')
            current = node_dict
            for part in parts:
                if part in current['children']:
                    if part not in insertion_order:
                        insertion_order[part] = order_counter
                        order_counter += 1
                    current = current['children'][part]

    record_order(stacks, root)

    def clean_and_convert(node):
        result = {'name': node['name'], 'count': node['count'], 'children': []}
        children_list = [clean_and_convert(child) for child in node['children'].values()]
        children_list.sort(key=lambda x: (-x['count'], insertion_order.get(x['name'], 999999)))
        result['children'] = children_list
        return result

    return clean_and_convert(root)


def write_html(tree, out_path, title='Stack Tree', event_count=None, total_samples=None, events_per_sample=None, basic_info=None):
    data_json = json.dumps(tree, ensure_ascii=True)
    html = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>TITLE_PLACEHOLDER</title>
<style>
body { font-family: Arial, sans-serif; font-size:14px; }
ul { list-style-type: none; margin-left: 20px; padding-left: 10px; }
li > span { cursor: pointer; user-select: none; }
.count { color: #666; margin-left:6px; font-size: 0.9em; }
.truncated { color: #999; font-style: italic; }
.toggle { margin-right: 5px; font-family: monospace; }
</style>
</head>
<body>
<h2>TITLE_PLACEHOLDER</h2>
<div style="background-color: #f0f0f0; padding: 15px; margin: 10px 0; border-radius: 5px;">
<h3>Simpleperf Report Information</h3>
<ul style="list-style-type: disc; margin-left: 20px;">
<li><strong>Command Line:</strong> <code style="background-color: #e8e8e8; padding: 2px 4px; border-radius: 3px;">CMDLINE_PLACEHOLDER</code></li>
<li><strong>Architecture:</strong> ARCH_PLACEHOLDER</li>
<li><strong>Event Type:</strong> EVENT_PLACEHOLDER</li>
<li><strong>Total Samples:</strong> TOTAL_SAMPLES_PLACEHOLDER</li>
<li><strong>Error Callchains:</strong> ERROR_CALLCHAINS_PLACEHOLDER</li>
<li><strong>Total Event Count:</strong> EVENT_COUNT_PLACEHOLDER</li>
<li><strong>Events per Sample:</strong> EVENTS_PER_SAMPLE_PLACEHOLDER</li>
</ul>
</div>
<p><button onclick="expandAll()">Expand All</button> <button onclick="collapseAll()">Collapse All</button></p>
<div id="tree"></div>
<script>
const data = DATA_PLACEHOLDER;
function createNode(node) {
  const li = document.createElement('li');
  const label = document.createElement('span');
  if (node.children && node.children.length) {
    const toggle = document.createElement('span');
    toggle.textContent = '▼ ';
    toggle.className = 'toggle';
    label.appendChild(toggle);
  }
  const nameSpan = document.createElement('span');
  nameSpan.textContent = node.name + (node.name !== 'root' ? '' : '');
  label.appendChild(nameSpan);
  const cnt = document.createElement('span');
  if (node.name === 'root') {
    cnt.textContent = ' (' + node.count + ', 100.00%)';
  } else {
    const percentage = ((node.count / data.count) * 100).toFixed(2);
    cnt.textContent = ' (' + node.count + ', ' + percentage + '%)';
  }
  cnt.className = 'count';
  label.appendChild(cnt);
  li.appendChild(label);
  if (node.children && node.children.length) {
    const ul = document.createElement('ul');
    ul.style.display = 'block';
    for (const c of node.children) {
      ul.appendChild(createNode(c));
    }
    li.appendChild(ul);
    label.onclick = function(e) {
      const toggle = label.querySelector('.toggle');
      if (ul.style.display === 'none') {
        ul.style.display = 'block';
        toggle.textContent = '▼ ';
      } else {
        ul.style.display = 'none';
        toggle.textContent = '▶ ';
      }
      e.stopPropagation();
    };
  }
  return li;
}
function expandAll() { document.querySelectorAll('#tree ul').forEach(ul => { ul.style.display = 'block'; }); document.querySelectorAll('.toggle').forEach(toggle => { toggle.textContent = '▼ '; }); }
function collapseAll() { document.querySelectorAll('#tree ul').forEach(ul => { ul.style.display = 'none'; }); document.querySelectorAll('.toggle').forEach(toggle => { toggle.textContent = '▶ '; }); }
(function(){ const root = createNode(data); const container = document.getElementById('tree'); const ul = document.createElement('ul'); ul.appendChild(root); container.appendChild(ul); })();
</script>
</body>
</html>
"""
    html = html.replace('TITLE_PLACEHOLDER', title).replace('DATA_PLACEHOLDER', data_json)
    if basic_info:
        html = html.replace('CMDLINE_PLACEHOLDER', basic_info.get('cmdline', 'N/A'))
        html = html.replace('ARCH_PLACEHOLDER', basic_info.get('arch', 'N/A'))
        html = html.replace('EVENT_PLACEHOLDER', basic_info.get('event', 'N/A'))
        html = html.replace('ERROR_CALLCHAINS_PLACEHOLDER', basic_info.get('error_callchains', 'N/A'))
    else:
        html = html.replace('CMDLINE_PLACEHOLDER', 'N/A')
        html = html.replace('ARCH_PLACEHOLDER', 'N/A')
        html = html.replace('EVENT_PLACEHOLDER', 'N/A')
        html = html.replace('ERROR_CALLCHAINS_PLACEHOLDER', 'N/A')
    if event_count is not None:
        html = html.replace('EVENT_COUNT_PLACEHOLDER', f"{event_count:,}")
    else:
        html = html.replace('EVENT_COUNT_PLACEHOLDER', "N/A")
    if total_samples is not None:
        html = html.replace('TOTAL_SAMPLES_PLACEHOLDER', f"{total_samples:,}")
    else:
        html = html.replace('TOTAL_SAMPLES_PLACEHOLDER', "N/A")
    if events_per_sample is not None:
        html = html.replace('EVENTS_PER_SAMPLE_PLACEHOLDER', f"{events_per_sample:.2f}")
    else:
        html = html.replace('EVENTS_PER_SAMPLE_PLACEHOLDER', "N/A")
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(html)


def main():
    parser = argparse.ArgumentParser(description='Collapse simpleperf report into folded stacks for FlameGraph')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--report', help='simpleperf text report file produced by: simpleperf report -g > report.txt')
    group.add_argument('--data', help='raw simpleperf data file (perf.data). The script will run simpleperf report -g on it')
    parser.add_argument('--folded', help='output folded stacks file (default: <report_or_data_basename>.folded)')
    parser.add_argument('--svg', help='optional output svg path (default: <report_or_data_basename>.svg)')
    parser.add_argument('--html', help='optional output interactive HTML tree (default: <report_or_data_basename>.html)')
    parser.add_argument('--flamegraph', help='path to flamegraph.pl script')
    parser.add_argument('--perl', help='path to perl interpreter (optional)')
    parser.add_argument('--reverse', action='store_true', help='reverse frame order when building stacks')
    parser.add_argument('--explain-thread', help='thread name to explain, e.g., GameThread')
    parser.add_argument('--dedug-first-start-thread', dest='dedug_first_start', action='store_true',
                        help='Only keep the first contiguous block per thread that starts with __start_thread; skip others')
    parser.add_argument('--equalize-root-sum', action='store_true',
                        help='Rescale each __start_thread tree so its leaf sum equals EventCount * Children% for that row')
    args = parser.parse_args()

    # If using --report, derive default output paths from its basename
    if args.report:
        base_dir = os.path.dirname(args.report)
        base_name = os.path.splitext(os.path.basename(args.report))[0]
        if not args.folded:
            args.folded = os.path.join(base_dir, f"{base_name}.folded")
        if args.svg is None:
            args.svg = os.path.join(base_dir, f"{base_name}.svg")
        if args.html is None:
            args.html = os.path.join(base_dir, f"{base_name}.html")
    # If using --data (no --report), derive defaults from data basename
    elif args.data:
        base_dir = os.path.dirname(args.data)
        base_name = os.path.splitext(os.path.basename(args.data))[0]
        if not args.folded:
            args.folded = os.path.join(base_dir, f"{base_name}.folded")
        if args.svg is None:
            args.svg = os.path.join(base_dir, f"{base_name}.svg")
        if args.html is None:
            args.html = os.path.join(base_dir, f"{base_name}.html")

    if args.data:
        report_text = run_simpleperf_report(args.data)
        if report_text is None:
            sys.exit(1)
    else:
        if not os.path.isfile(args.report):
            sys.exit(1)
        report_text = read_text_file_auto(args.report)

    stacks, event_count, total_samples, basic_info, raw_stacks = parse_report_text(report_text, reverse=args.reverse, dedug_first_start=args.dedug_first_start, equalize_root_sum=args.equalize_root_sum)
    if not stacks:
        sys.exit(1)

    events_per_sample = event_count / total_samples if total_samples > 0 else 1

    write_folded(stacks, args.folded)
    is_valid, _ = validate_folded_file(args.folded)
    if not is_valid:
        sys.exit(1)

    # Explain mode: compare expected vs actual for "<Thread>;__start_thread"
    if args.explain_thread:
        thread = args.explain_thread
        head_pct = find_thread_head_pct(report_text, thread)
        expected_events = int(round((head_pct or 0.0) / 100.0 * event_count))
        actual_events = sum(c for k, c in stacks.items() if k.startswith(f"{thread};__start_thread"))
        folded_sum = sum(stacks.values())
        # Print concise diagnostics
        print(f"[Explain] Thread={thread}")
        print(f"  Event count (total): {event_count}")
        print(f"  First-row Children%: {head_pct if head_pct is not None else 'N/A'}%")
        print(f"  Expected events (EventCount * Children%): {expected_events}")
        print(f"  Actual folded events (keys starting with '{thread};__start_thread'): {actual_events}")
        if event_count > 0:
            print(f"  Actual as % of EventCount: {actual_events / event_count * 100:.2f}%")
        if folded_sum > 0:
            print(f"  Actual as % of FoldedSum: {actual_events / folded_sum * 100:.2f}% (FoldedSum={folded_sum})")

    if args.html:
        tree = stacks_to_tree(stacks, event_count)
        write_html(tree, args.html, title=os.path.basename(args.folded),
                   event_count=event_count, total_samples=total_samples,
                   events_per_sample=events_per_sample, basic_info=basic_info)

    if args.svg:
        # Use the primary folded file directly for flamegraph to avoid duplicate .folded files
        flamegraph_path = args.flamegraph
        if not flamegraph_path:
            flamegraph_path = download_flamegraph()
        html_path = call_flamegraph(flamegraph_path, args.folded, args.svg, perl_path=args.perl,
                                    basic_info=basic_info,
                                    event_count=event_count,
                                    total_samples=total_samples,
                                    events_per_sample=events_per_sample)
        if not os.path.isfile(html_path) or os.path.getsize(html_path) == 0:
            sys.exit(1)


if __name__ == '__main__':
    main()
