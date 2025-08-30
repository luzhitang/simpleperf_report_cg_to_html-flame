#!/usr/bin/env python3
"""
stackcollapse_simpleperf.py

Usage examples:
  python stackcollapse_simpleperf.py --report perf_report_icache_sg.txt --folded out.folded
  python stackcollapse_simpleperf.py --data perf_icache.data --folded out.folded --svg out.svg --perl "C:\\Strawberry\\perl\\bin\\perl.exe"

This script:
 - Parses a simpleperf text report (produced by `simpleperf report -g`) or runs simpleperf on a .data file
 - Collapses callstacks into folded format for FlameGraph
 - Optionally downloads flamegraph.pl and runs it (uses perl; supports --perl)
"""

import argparse
import os
import re
import subprocess
import sys
from collections import defaultdict
import urllib.request
import tempfile
import stat
import shutil
import json
import traceback


def read_text_file_auto(path):
    # Read raw bytes and attempt to decode using common encodings, including UTF-16 with BOM
    with open(path, 'rb') as f:
        data = f.read()
    # Try utf-8 with BOM first
    try:
        return data.decode('utf-8-sig')
    except Exception:
        pass
    # Try utf-16 (will handle BOM)
    try:
        return data.decode('utf-16')
    except Exception:
        pass
    # Try common alternatives
    for enc in ('utf-16-le', 'utf-16-be', 'utf-8', 'latin-1'):
        try:
            return data.decode(enc)
        except Exception:
            continue
    # As a last resort, replace errors
    return data.decode('utf-8', errors='replace')


def run_simpleperf_report(data_path):
    cmd = ["simpleperf", "report", "-i", data_path, "-g"]
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, text=True)
        return p.stdout
    except Exception as e:
        sys.stderr.write(f"Failed to run simpleperf: {e}\n")
        return None


def parse_report_text(text, reverse=False):
    """Parse simpleperf report text with hierarchical callstack structure based on indentation."""
    lines = text.splitlines()
    stacks = {}  # 使用普通字典保持插入顺序
    
    # 提取Event count和Samples
    event_count = None
    total_samples = None
    
    for line in lines[:20]:  # 在前20行中查找
        if line.startswith('Event count:'):
            try:
                event_count = int(line.split(':')[1].strip())
                print(f"Found Event count: {event_count}")
            except:
                pass
        elif line.startswith('Samples:'):
            try:
                total_samples = int(line.split(':')[1].strip())
                print(f"Found Samples: {total_samples}")
            except:
                pass
    
    if event_count is None:
        event_count = 2614742680  # 默认值
        print(f"Using default Event count: {event_count}")
    
    if total_samples is None:
        total_samples = 262226  # 默认值
        print(f"Using default Samples: {total_samples}")
    
    # 计算平均每个样本代表的事件数
    events_per_sample = event_count / total_samples if total_samples > 0 else 1
    print(f"Events per sample: {events_per_sample:.2f}")
    
    process_order = 0
    
    i = 0
    while i < len(lines):
        line = lines[i].rstrip()
        if not line:
            i += 1
            continue
            
        # Skip headers and metadata
        if line.startswith('Cmdline:') or line.startswith('Arch:') or line.startswith('Event:') or line.startswith('Samples:') or line.startswith('Error Callchains:') or line.startswith('Event count:'):
            i += 1
            continue
        if 'Children' in line and 'Self' in line and 'Command' in line:
            i += 1
            continue
        if 'skipped in brief callgraph mode' in line:
            i += 1
            continue
            
        # Parse main entry lines with percentage data (no leading spaces)
        if re.match(r'^\d+\.\d+%', line):
            # Extract process info from main line
            parts = re.split(r'\s{2,}', line)
            if len(parts) < 6:
                i += 1
                continue
                
            command = parts[2].strip()
            children_pct = parts[0].strip()  # Children percentage
            
            try:
                children_pct_val = float(children_pct.rstrip('%'))
            except:
                children_pct_val = 0.0
            
            process_order += 1
            if process_order <= 20:  # 只打印前20条
                print(f"Debug: Processing main entry {process_order}: {command} ({children_pct})")
            
            # Look for callstack starting from next lines
            i += 1
            
            # Parse the callstack tree that follows this entry
            tree_stacks = parse_entry_callstack(lines, i, command, children_pct_val, events_per_sample, total_samples)
            for stack_str, count in tree_stacks.items():
                if reverse:
                    stack_parts = stack_str.split(';')
                    stack_str = ';'.join(reversed(stack_parts))
                if stack_str in stacks:
                    stacks[stack_str] += count
                else:
                    stacks[stack_str] = count
            
            # Skip to next main entry
            i = skip_to_next_main_entry(lines, i)
        else:
            i += 1
    
    print(f"Debug: Processed {process_order} main entries")
    print(f"Debug: Generated {len(stacks)} unique call stacks")
    
    # 计算所有stacks的总事件数
    total_stack_events = sum(stacks.values())
    print(f"Debug: Total events in all stacks: {total_stack_events}")
    
    return stacks, event_count, total_samples


def parse_entry_callstack(lines, start_idx, command, children_pct, events_per_sample, total_samples):
    """解析一个主条目下的完整调用栈树"""
    stacks = {}  # 使用普通字典保持插入顺序
    i = start_idx
    
    while i < len(lines):
        line = lines[i]
        if not line.strip():
            i += 1
            continue
            
        # 如果遇到下一个主条目，停止
        if re.match(r'^\d+\.\d+%', line):
            break
            
        # 跳过分隔线和无关行
        if line.strip() == '|' or 'skipped in brief callgraph mode' in line:
            i += 1
            continue
            
        # 查找调用栈根节点（以 "-- " 开始的行）
        if line.strip().startswith('-- '):
            root_func = line.strip()[3:].strip()
            if root_func and len(root_func) > 1:
                # 解析从这个根开始的调用栈树
                tree_stacks = parse_callstack_tree_new(lines, i, command, children_pct, events_per_sample, total_samples)
                for stack_str, count in tree_stacks.items():
                    if stack_str in stacks:
                        stacks[stack_str] += count
                    else:
                        stacks[stack_str] = count
            
            # 跳过这个树的其余部分
            i = skip_to_next_tree_or_main_entry(lines, i)
            continue
        
        i += 1
    
    return stacks


def parse_callstack_tree_new(lines, start_idx, command, children_pct, events_per_sample, total_samples):
    """解析单个调用栈树，基于实际的simpleperf报告格式"""
    stacks = {}  # 使用普通字典保持插入顺序
    
    # 获取根函数
    root_line = lines[start_idx].strip()
    if not root_line.startswith('-- '):
        return stacks
    
    root_func = root_line[3:].strip()
    
    # 初始化基础调用栈路径
    if command and command != 'Unknown':
        base_path = [command, root_func]
    else:
        base_path = [root_func]
    
    # 当前栈路径，用于跟踪层级关系
    current_stack = []
    
    # 累积百分比：从根节点开始的累乘百分比
    cumulative_percentages = []  # 记录到达每一层的累积百分比
    
    i = start_idx + 1
    
    while i < len(lines):
        line = lines[i]
        if not line.strip():
            i += 1
            continue
            
        # 如果遇到下一个主条目或下一个调用栈根，停止
        if re.match(r'^\d+\.\d+%', line) or line.strip().startswith('-- '):
            break
            
        # 跳过分隔线和无关行
        if line.strip() == '|' or 'skipped in brief callgraph mode' in line:
            i += 1
            continue
            
        stripped_line = line.strip()
        
        # 处理无百分比的中间函数（它们属于基础路径的一部分）
        if (not stripped_line.startswith('|') and 
            not stripped_line.startswith('--') and 
            stripped_line and 
            len(stripped_line) > 2 and
            not re.search(r'\d+\.\d+%', stripped_line)):
            
            func_name = stripped_line
            # 这些中间函数是基础路径的一部分
            base_path.append(func_name)
            i += 1
            continue
            
        # 解析带百分比的函数调用行：|--xx.xx%-- function_name
        match = re.search(r'\|--(\d+\.\d+%)--\s*(.+)', line)
        if match:
            func_pct = match.group(1)
            func_name = match.group(2).strip()
            
            # 只跳过完全无效的函数名
            if not func_name:
                i += 1
                continue
            
            try:
                pct_val = float(func_pct.rstrip('%'))
            except:
                pct_val = 0.0
            
            # 计算当前管道符的层级
            pipe_count = 0
            for char in line:
                if char == '|':
                    pipe_count += 1
                elif char != ' ' and char != '\t':
                    break
            
            # 调整current_stack到正确的层级
            # pipe_count 就是当前函数在树中的深度
            target_depth = pipe_count - 1  # 减1因为这是父级数量
            
            # 截断栈和百分比数组到正确的深度
            if target_depth < len(current_stack):
                current_stack = current_stack[:target_depth]
                cumulative_percentages = cumulative_percentages[:target_depth]
            
            # 添加当前函数到栈
            current_stack.append(func_name)
            cumulative_percentages.append(pct_val)
            
            # 构建完整路径：基础路径 + 当前栈路径
            complete_path = base_path + current_stack
            
            # 计算累积百分比：children% × 所有层级百分比的乘积
            cumulative_pct = children_pct / 100.0  # 从children%开始
            for pct in cumulative_percentages:
                cumulative_pct *= (pct / 100.0)
            
            # 计算最终事件数：events_per_sample × total_samples × 累积百分比
            count = max(1, int(events_per_sample * total_samples * cumulative_pct))
            
            # 调试：显示计算过程
            if len(complete_path) <= 5 and 'AndroidMain' in func_name:  # 只显示AndroidMain相关的计算
                pct_chain = " × ".join([f"{p:.2f}%" for p in cumulative_percentages])
                print(f"  计算: {func_name} = {events_per_sample:.2f} × {total_samples} × {children_pct:.2f}% × ({pct_chain}) = {count}")
            
            # 添加到结果
            stack_str = ';'.join(complete_path)
            if stack_str in stacks:
                stacks[stack_str] += count
            else:
                stacks[stack_str] = count
        
        i += 1
    
    return stacks


def get_indent_level_new(line):
    """计算缩进级别，基于实际的simpleperf报告格式"""
    # 计算 | 字符的数量来确定层级
    pipe_count = 0
    i = 0
    while i < len(line):
        if line[i] == '|':
            pipe_count += 1
        elif line[i] != ' ' and line[i] != '\t':
            break
        i += 1
    
    # 如果是 "-- " 开头的根节点
    if line.strip().startswith('-- '):
        return 0
    
    # 对于带 |-- 的节点，pipe_count 就是层级
    if '|--' in line:
        return pipe_count
    
    # 对于中间的函数名行（没有百分比），根据前面的管道符数量
    return pipe_count


def skip_to_next_tree_or_main_entry(lines, start_idx):
    """跳到下一个调用栈树或主条目"""
    i = start_idx + 1
    while i < len(lines):
        line = lines[i]
        if not line.strip():
            i += 1
            continue
        # 停在下一个主条目或下一个调用栈根
        if re.match(r'^\d+\.\d+%', line) or line.strip().startswith('-- '):
            return i
        i += 1
    return i


def skip_to_next_main_entry(lines, start_idx):
    """跳到下一个主条目"""
    i = start_idx
    while i < len(lines):
        line = lines[i]
        if re.match(r'^\d+\.\d+%', line):
            return i
        i += 1
    return i





def write_folded(stacks, out_path):
    with open(out_path, 'w', encoding='utf-8') as f:
        # 保持原始顺序：按照遇到的顺序写入，而不是按计数排序
        for stack, count in stacks.items():
            f.write(f"{stack} {count}\n")


def download_flamegraph(dest_dir=None):
    url = 'https://raw.githubusercontent.com/brendangregg/FlameGraph/master/flamegraph.pl'
    if dest_dir is None:
        dest_dir = os.getcwd()
    dest = os.path.join(dest_dir, 'flamegraph.pl')
    if os.path.isfile(dest):
        return dest
    try:
        fd, tmp_path = tempfile.mkstemp(prefix='flamegraph_', suffix='.pl')
        os.close(fd)
        # download raw bytes
        with urllib.request.urlopen(url) as resp, open(tmp_path, 'wb') as out:
            out.write(resp.read())
        try:
            st = os.stat(tmp_path)
            os.chmod(tmp_path, st.st_mode | stat.S_IEXEC)
        except Exception:
            pass
        return tmp_path
    except Exception as e:
        raise RuntimeError(f"Failed to download flamegraph.pl: {e}")


def call_flamegraph(flamegraph_path, folded_path, svg_out, perl_path=None):
    if not os.path.isfile(flamegraph_path):
        raise FileNotFoundError(f"flamegraph.pl not found at {flamegraph_path}")

    # Decide whether to run via perl
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
            perl = perl_path if os.path.isfile(perl_path) else shutil.which(perl_path) or None
        if not perl:
            perl = shutil.which('perl')
        if not perl and os.name == 'nt':
            common = [
                r"C:\\Strawberry\\perl\\bin\\perl.exe",
                r"C:\\Perl64\\bin\\perl.exe",
                r"C:\\Perl\\bin\\perl.exe",
            ]
            for p in common:
                if os.path.isfile(p):
                    perl = p
                    break
        if not perl:
            raise FileNotFoundError('Perl interpreter not found. Ensure perl is installed and in PATH or provide --perl')
        cmd = [perl, flamegraph_path, folded_path]
    else:
        cmd = [flamegraph_path, folded_path]

    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode != 0:
        stderr = proc.stderr.decode('utf-8', errors='replace') if isinstance(proc.stderr, (bytes, bytearray)) else str(proc.stderr)
        raise RuntimeError(f"flamegraph.pl failed: {stderr}")
    with open(svg_out, 'wb') as outfh:
        outfh.write(proc.stdout)


def stacks_to_tree(stacks, event_count):
    """Convert Counter of folded stacks into a nested tree with event counts."""
    root = {'name': 'root', 'count': event_count, 'children': {}}  # 直接设置root = event_count
    
    # 简单构建树结构，只在叶子节点放置调用栈的计数
    for stack, cnt in stacks.items():
        parts = stack.split(';')
        node = root
        
        # 构建树结构
        for p in parts:
            children = node['children']
            if p not in children:
                children[p] = {'name': p, 'count': 0, 'children': {}}
            node = children[p]
        
        # 只在叶子节点累加计数
        node['count'] += cnt

    # 转换为排序的列表结构
    def clean_and_convert(node):
        result = {
            'name': node['name'], 
            'count': node['count'], 
            'children': []
        }
        
        # 递归处理子节点并排序
        for child in node['children'].values():
            result['children'].append(clean_and_convert(child))
        
        result['children'].sort(key=lambda x: -x['count'])
        return result

    final_tree = clean_and_convert(root)
    return final_tree


def write_html(tree, out_path, title='Stack Tree', event_count=None, total_samples=None, events_per_sample=None):
    """Write a simple collapsible HTML page visualizing the tree."""
    print('Starting JSON serialization...')
    sys.stdout.flush()
    
    try:
        data_json = json.dumps(tree, ensure_ascii=True)  # Use ensure_ascii=True to avoid Unicode issues
        print('JSON serialization completed')
        sys.stdout.flush()
    except Exception as e:
        print(f'JSON serialization failed: {e}')
        sys.stdout.flush()
        raise
    
    print('Building HTML template...')
    sys.stdout.flush()
    
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
<div style="background-color: #f0f0f0; padding: 10px; margin: 10px 0; border-radius: 5px;">
<h3>Performance Summary</h3>
<ul style="list-style-type: disc; margin-left: 20px;">
<li><strong>Total Samples:</strong> TOTAL_SAMPLES_PLACEHOLDER</li>
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
    ul.style.display = 'block';  // Default to expanded
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

function expandAll() {
  document.querySelectorAll('#tree ul').forEach(ul => {
    ul.style.display = 'block';
  });
  document.querySelectorAll('.toggle').forEach(toggle => {
    toggle.textContent = '▼ ';
  });
}

function collapseAll() {
  document.querySelectorAll('#tree ul').forEach(ul => {
    ul.style.display = 'none';
  });
  document.querySelectorAll('.toggle').forEach(toggle => {
    toggle.textContent = '▶ ';
  });
}

(function(){
  const root = createNode(data);
  const container = document.getElementById('tree');
  const ul = document.createElement('ul');
  ul.appendChild(root);
  container.appendChild(ul);
})();
</script>
</body>
</html>
"""
    
    print('Replacing placeholders and writing file...')
    sys.stdout.flush()
    
    html = html.replace('TITLE_PLACEHOLDER', title).replace('DATA_PLACEHOLDER', data_json)
    
    # 替换统计信息占位符
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
    
    try:
        with open(out_path, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f'Successfully wrote HTML to {out_path}')
        sys.stdout.flush()
    except Exception as e:
        print(f'Failed to write HTML file: {e}')
        sys.stdout.flush()
        raise


def main():
    parser = argparse.ArgumentParser(description='Collapse simpleperf report into folded stacks for FlameGraph')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--report', help='simpleperf text report file produced by: simpleperf report -g > report.txt')
    group.add_argument('--data', help='raw simpleperf data file (perf.data). The script will run simpleperf report -g on it')
    parser.add_argument('--folded', required=True, help='output folded stacks file')
    parser.add_argument('--svg', help='optional output svg path (requires flamegraph.pl)')
    parser.add_argument('--html', help='optional output interactive HTML tree')
    parser.add_argument('--flamegraph', help='path to flamegraph.pl script')
    parser.add_argument('--perl', help='path to perl interpreter (optional)')
    parser.add_argument('--reverse', action='store_true', help='reverse frame order when building stacks')
    args = parser.parse_args()

    report_text = None
    if args.data:
        report_text = run_simpleperf_report(args.data)
        if report_text is None:
            sys.exit(1)
    else:
        if not os.path.isfile(args.report):
            sys.stderr.write(f"Report file not found: {args.report}\n")
            sys.exit(1)
        # Read report with automatic encoding detection (handles UTF-16 reports)
        report_text = read_text_file_auto(args.report)

    stacks, event_count, total_samples = parse_report_text(report_text, reverse=args.reverse)
    if not stacks:
        sys.stderr.write('No stacks extracted. Try --reverse or provide raw .data file.\n')
        sys.exit(1)

    # 计算统计信息用于HTML显示
    events_per_sample = event_count / total_samples if total_samples > 0 else 1

    write_folded(stacks, args.folded)
    print(f'Wrote folded stacks to {args.folded}')
    
    # Debug: Print first 5 stacks to see the structure (including deep ones)
    print("\nDebug: First 5 generated stacks (showing hierarchy):")
    count = 0
    for stack, stack_count in stacks.items():  # 保持原始顺序
        if count >= 5:
            break
        levels = len(stack.split(';'))
        if levels >= 3:  # Only show stacks with 3+ levels
            print(f"{count+1}: levels={levels} count={stack_count}")
            print(f"   {stack}")
            count += 1
    print()

    if args.html:
        print('Starting HTML generation...')
        sys.stdout.flush()
        
        print(f'Converting {len(stacks)} stacks to tree...')
        sys.stdout.flush()
        
        try:
            tree = stacks_to_tree(stacks, event_count)
            print('Tree conversion completed, writing HTML...')
            sys.stdout.flush()
            
            write_html(tree, args.html, title=os.path.basename(args.folded), 
                      event_count=event_count, total_samples=total_samples, events_per_sample=events_per_sample)
            print(f'Wrote interactive HTML tree to {args.html}')
        except Exception as e:
            print(f'HTML generation failed at step: {e}')
            sys.stdout.flush()
            
            tb = traceback.format_exc()
            err_file = os.path.join(os.getcwd(), 'out_html_error.txt')
            
            # Always write a minimal debug HTML even if main HTML fails
            debug_html = f'''<!DOCTYPE html>
<html><head><title>Debug Error</title></head>
<body>
<h1>HTML Generation Failed</h1>
<pre>{tb}</pre>
</body></html>'''
            
            try:
                with open(err_file, 'w', encoding='utf-8') as ef:
                    ef.write(tb)
                with open('debug_error.html', 'w', encoding='utf-8') as df:
                    df.write(debug_html)
                print(f'Error details written to {err_file} and debug_error.html')
            except Exception as write_err:
                print(f'Even error file writing failed: {write_err}')
            
            sys.stderr.write(f'Failed to write HTML tree: {e}. Full traceback written to {err_file}\n')
            sys.exit(1)

    if args.svg:
        flamegraph_path = args.flamegraph
        if not flamegraph_path:
            try:
                print('No --flamegraph provided: downloading flamegraph.pl...')
                flamegraph_path = download_flamegraph()
                print(f'Downloaded flamegraph.pl to {flamegraph_path}')
            except Exception as e:
                sys.stderr.write(str(e) + '\n')
                sys.exit(1)
        try:
            call_flamegraph(flamegraph_path, args.folded, args.svg, perl_path=args.perl)
            print(f'Wrote flamegraph SVG to {args.svg}')
        except Exception as e:
            sys.stderr.write(str(e) + '\n')
            sys.exit(1)


if __name__ == '__main__':
    main()
