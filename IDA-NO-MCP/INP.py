# ida_export_for_ai.py
# IDA Plugin to export decompiled functions with disassembly fallback, strings, memory, imports and exports for AI analysis

import os
import sys
import ida_hexrays
import ida_funcs
import ida_nalt
import ida_xref
import ida_segment
import ida_bytes
import ida_entry
import idautils
import idc
import ida_lines
import ida_auto
import ida_kernwin
import ida_idaapi
import ida_undo
import ida_idp
import ida_ida
import gc
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import multiprocessing as mp

WORKER_COUNT = max(1, mp.cpu_count() - 1)
TASK_BATCH_SIZE = 50


def get_worker_count():
    """获取用户配置的并行工作线程数"""
    return WORKER_COUNT


def get_idb_directory():
    """获取 IDB 文件所在目录"""
    idb_path = ida_nalt.get_input_file_path()
    if not idb_path:
        import ida_loader
        idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
    return os.path.dirname(idb_path) if idb_path else os.getcwd()


def ensure_dir(path):
    """确保目录存在"""
    if not os.path.exists(path):
        os.makedirs(path)


def clear_undo_buffer():
    """清理 IDA 撤销缓冲区，防止内存溢出"""
    try:
        ida_undo.clear_undo_buffer()
        gc.collect()
    except:
        pass


def disable_undo():
    """禁用撤销功能（IDA 7.0+）"""
    try:
        ida_idp.disable_undo(True)
    except:
        pass


def enable_undo():
    """启用撤销功能"""
    try:
        ida_idp.disable_undo(False)
    except:
        pass


def get_callers(func_ea):
    """获取调用当前函数的地址列表"""
    callers = []
    for ref in idautils.XrefsTo(func_ea, 0):
        if idc.is_code(idc.get_full_flags(ref.frm)):
            caller_func = ida_funcs.get_func(ref.frm)
            if caller_func:
                callers.append(caller_func.start_ea)
    return sorted(list(set(callers)))


def get_callees(func_ea):
    """获取当前函数调用的函数地址列表"""
    callees = []
    func = ida_funcs.get_func(func_ea)
    if not func:
        return callees

    for head in idautils.Heads(func.start_ea, func.end_ea):
        if idc.is_code(idc.get_full_flags(head)):
            for ref in idautils.XrefsFrom(head, 0):
                if ref.type in [ida_xref.fl_CF, ida_xref.fl_CN]:
                    callee_func = ida_funcs.get_func(ref.to)
                    if callee_func:
                        callees.append(callee_func.start_ea)
    return sorted(list(set(callees)))


def format_address_list(addr_list):
    """格式化地址列表为逗号分隔的十六进制字符串"""
    return ", ".join([hex(addr) for addr in addr_list])


def sanitize_filename(name):
    """清理函数名，使其适合作为文件名"""
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        name = name.replace(char, '_')
    name = name.replace('.', '_')
    if len(name) > 200:
        name = name[:200]
    return name


def get_function_output_filename(func_ea, export_type):
    """根据导出类型生成函数输出文件名"""
    if export_type == "disassembly-fallback":
        return "{:X}.asm".format(func_ea)
    return "{:X}.c".format(func_ea)


def get_function_output_subdir(export_type):
    """根据导出类型返回函数输出子目录"""
    if export_type == "disassembly-fallback":
        return "disassembly"
    return "decompile"


def get_function_output_relative_path(func_ea, export_type):
    """获取函数导出文件的相对路径"""
    return "{}/{}".format(
        get_function_output_subdir(export_type),
        get_function_output_filename(func_ea, export_type)
    )


def get_function_output_path(export_dir, func_ea, export_type):
    """获取函数导出文件的绝对路径"""
    output_dir = os.path.join(export_dir, get_function_output_subdir(export_type))
    output_filename = get_function_output_filename(func_ea, export_type)
    return os.path.join(output_dir, output_filename)


def find_existing_function_output(export_dir, func_ea):
    """查找函数已有的导出文件"""
    for export_type in ("decompile", "disassembly-fallback"):
        output_filename = get_function_output_relative_path(func_ea, export_type)
        output_path = get_function_output_path(export_dir, func_ea, export_type)
        if os.path.exists(output_path):
            return output_filename, output_path
    return None, None


def build_function_output_lines(func_ea, func_name, source_type, callers, callees, body, fallback_reason=None):
    """构建函数导出文件内容"""
    output_lines = []
    output_lines.append("/*")
    output_lines.append(" * func-name: {}".format(func_name))
    output_lines.append(" * func-address: {}".format(hex(func_ea)))
    output_lines.append(" * export-type: {}".format(source_type))
    output_lines.append(" * callers: {}".format(format_address_list(callers) if callers else "none"))
    output_lines.append(" * callees: {}".format(format_address_list(callees) if callees else "none"))
    if fallback_reason:
        output_lines.append(" * fallback-reason: {}".format(fallback_reason))
    output_lines.append(" */")
    output_lines.append("")
    output_lines.append(body)
    return output_lines


def generate_function_disassembly(func_ea):
    """生成函数的反汇编文本，用于反编译失败时回退"""
    func = ida_funcs.get_func(func_ea)
    if not func:
        return None, "not a valid function"

    disasm_lines = []
    for item_ea in idautils.FuncItems(func_ea):
        disasm_line = ida_lines.generate_disasm_line(
            item_ea,
            ida_lines.GENDSM_FORCE_CODE | ida_lines.GENDSM_REMOVE_TAGS
        )
        if disasm_line is None:
            disasm_line = ""
        else:
            disasm_line = ida_lines.tag_remove(disasm_line).rstrip()
        if not disasm_line:
            disasm_line = "<unable to render disassembly>"
        disasm_lines.append("{:X}: {}".format(item_ea, disasm_line))

    if not disasm_lines:
        return None, "function has no items"

    return "\n".join(disasm_lines), None


def save_progress(export_dir, processed_addrs, fallback_funcs, failed_funcs, skipped_funcs):
    """保存当前进度到文件"""
    progress_file = os.path.join(export_dir, ".export_progress")
    try:
        with open(progress_file, 'w', encoding='utf-8') as f:
            f.write("# Export Progress\n")
            f.write("# Format: address | status (done/fallback/failed/skipped)\n")
            for addr in processed_addrs:
                f.write("{:X}|done\n".format(addr))
            for addr, name, reason, output_filename in fallback_funcs:
                f.write("{:X}|fallback|{}|{}|{}\n".format(addr, name, reason, output_filename))
            for addr, name, reason in failed_funcs:
                f.write("{:X}|failed|{}|{}\n".format(addr, name, reason))
            for addr, name, reason in skipped_funcs:
                f.write("{:X}|skipped|{}|{}\n".format(addr, name, reason))
    except Exception as e:
        print("[!] Failed to save progress: {}".format(str(e)))


def load_progress(export_dir):
    """从文件加载进度"""
    progress_file = os.path.join(export_dir, ".export_progress")
    processed = set()
    fallback = []
    failed = []
    skipped = []

    if not os.path.exists(progress_file):
        return processed, fallback, failed, skipped

    try:
        with open(progress_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split('|')
                if len(parts) >= 2:
                    addr = int(parts[0], 16)
                    status = parts[1]
                    if status == 'done':
                        processed.add(addr)
                    elif status == 'fallback' and len(parts) >= 5:
                        fallback.append((addr, parts[2], parts[3], parts[4]))
                    elif status == 'failed' and len(parts) >= 4:
                        failed.append((addr, parts[2], parts[3]))
                    elif status == 'skipped' and len(parts) >= 4:
                        skipped.append((addr, parts[2], parts[3]))
        print("[+] Loaded progress: {} functions already processed".format(len(processed)))
    except Exception as e:
        print("[!] Failed to load progress: {}".format(str(e)))

    return processed, fallback, failed, skipped


def export_decompiled_functions(export_dir, skip_existing=True):
    """导出所有函数的反编译代码（内存优化版 - 流式处理）

    Args:
        export_dir: 导出目录
        skip_existing: 是否跳过已存在的文件
    """
    decompile_dir = os.path.join(export_dir, "decompile")
    disassembly_dir = os.path.join(export_dir, "disassembly")
    ensure_dir(decompile_dir)
    ensure_dir(disassembly_dir)

    total_funcs = 0
    exported_funcs = 0
    fallback_funcs = []
    failed_funcs = []
    skipped_funcs = []
    function_index = []
    addr_to_info = {}

    # 使用单线程I/O避免内存累积
    io_executor = ThreadPoolExecutor(max_workers=1)

    # 加载之前的进度
    processed_addrs, prev_fallback, prev_failed, prev_skipped = load_progress(export_dir)
    fallback_funcs.extend(prev_fallback)
    failed_funcs.extend(prev_failed)
    skipped_funcs.extend(prev_skipped)

    # 收集所有函数地址
    all_funcs = list(idautils.Functions())
    total_funcs = len(all_funcs)

    # 过滤掉已处理的函数
    remaining_funcs = [ea for ea in all_funcs if ea not in processed_addrs]

    print("[*] Found {} functions total, {} remaining to process".format(total_funcs, len(remaining_funcs)))
    print("[*] Memory-optimized mode: processing one function at a time")

    if len(remaining_funcs) == 0:
        print("[+] All functions already exported!")
        io_executor.shutdown(wait=False)
        return

    # 流式处理 - 不预加载所有调用关系
    BATCH_SIZE = 10  # 减小批量大小
    MEMORY_CLEAN_INTERVAL = 5  # 更频繁地清理内存
    pending_writes = []

    def write_function_file(args):
        """线程安全的文件写入"""
        func_ea, func_name, body, callers, callees, export_type, fallback_reason = args
        output_lines = build_function_output_lines(
            func_ea,
            func_name,
            export_type,
            callers,
            callees,
            body,
            fallback_reason=fallback_reason
        )

        output_filename = get_function_output_relative_path(func_ea, export_type)
        output_path = get_function_output_path(export_dir, func_ea, export_type)

        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(output_lines))
            return func_ea, func_name, True, output_filename, callers, callees, export_type, fallback_reason, None
        except IOError as e:
            return func_ea, func_name, False, output_filename, callers, callees, export_type, fallback_reason, str(e)

    def aggressive_memory_cleanup():
        """激进的内存清理"""
        # 强制删除大对象引用
        import sys
        # 清理IDA内部缓存
        try:
            ida_hexrays.clear_cached_cfuncs()
        except:
            pass
        # 强制垃圾回收
        gc.collect()
        gc.collect()  # 两次收集确保清理

    for idx, func_ea in enumerate(remaining_funcs):
        # 实时获取函数信息（不缓存）
        func_name = idc.get_func_name(func_ea)

        # 跳过外部函数和导入函数
        func = ida_funcs.get_func(func_ea)
        if func is None:
            skipped_funcs.append((func_ea, func_name, "not a valid function"))
            processed_addrs.add(func_ea)
            continue

        if func.flags & ida_funcs.FUNC_LIB:
            skipped_funcs.append((func_ea, func_name, "library function"))
            processed_addrs.add(func_ea)
            continue

        dec_str = None
        dec_obj = None
        output_body = None
        export_type = None
        fallback_reason = None

        try:
            # 尝试反编译
            dec_obj = ida_hexrays.decompile(func_ea)
            if dec_obj is None:
                fallback_reason = "decompile returned None"
            else:
                dec_str = str(dec_obj)
                # 立即释放反编译对象
                dec_obj = None

                if dec_str and len(dec_str.strip()) > 0:
                    output_body = dec_str
                    export_type = "decompile"
                else:
                    fallback_reason = "empty decompilation result"

        except ida_hexrays.DecompilationFailure as e:
            fallback_reason = "decompilation failure: {}".format(str(e))
        except Exception as e:
            fallback_reason = "unexpected error: {}".format(str(e))
            print("[!] Error decompiling {} at {}: {}".format(func_name, hex(func_ea), str(e)))
        finally:
            # 确保反编译对象被释放
            dec_obj = None
            dec_str = None

        if output_body is None:
            output_body, disasm_error = generate_function_disassembly(func_ea)
            if output_body is None:
                combined_reason = fallback_reason or "unknown decompilation error"
                if disasm_error:
                    combined_reason = "{}; disassembly fallback failed: {}".format(combined_reason, disasm_error)
                failed_funcs.append((func_ea, func_name, combined_reason))
                processed_addrs.add(func_ea)
                continue
            export_type = "disassembly-fallback"

        callers = get_callers(func_ea)
        callees = get_callees(func_ea)

        existing_output_filename, _ = find_existing_function_output(export_dir, func_ea)
        if skip_existing and existing_output_filename:
            exported_funcs += 1
            processed_addrs.add(func_ea)
            if (exported_funcs + len(prev_fallback) + len(prev_failed) + len(prev_skipped)) % 100 == 0:
                print("[+] Exported {} / {} functions...".format(
                    exported_funcs + len(prev_fallback) + len(prev_failed) + len(prev_skipped),
                    total_funcs
                ))
            continue

        output_filename = get_function_output_relative_path(func_ea, export_type)
        write_args = (
            func_ea,
            func_name,
            output_body,
            callers,
            callees,
            export_type,
            fallback_reason
        )
        future = io_executor.submit(write_function_file, write_args)
        pending_writes.append((
            future,
            func_ea,
            func_name,
            output_filename,
            callers,
            callees,
            export_type,
            fallback_reason
        ))

        output_body = None

        # 定期清理撤销缓冲区
        if (idx + 1) % MEMORY_CLEAN_INTERVAL == 0:
            clear_undo_buffer()
            aggressive_memory_cleanup()

        # 批量等待写入完成并收集结果
        if len(pending_writes) >= BATCH_SIZE:
            for future, func_ea, func_name, output_filename, callers, callees, export_type, fallback_reason in pending_writes:
                try:
                    result = future.result()
                    func_ea, func_name, success, output_filename, callers, callees, export_type, fallback_reason, error = result

                    if success:
                        func_info = {
                            'address': func_ea,
                            'name': func_name,
                            'filename': output_filename,
                            'export_type': export_type,
                            'callers': callers,
                            'callees': callees
                        }
                        if fallback_reason:
                            func_info['fallback_reason'] = fallback_reason
                        function_index.append(func_info)
                        addr_to_info[func_ea] = func_info
                        if export_type == "disassembly-fallback":
                            fallback_funcs.append((func_ea, func_name, fallback_reason or "decompilation failed", output_filename))
                        exported_funcs += 1
                        processed_addrs.add(func_ea)
                    else:
                        failed_funcs.append((func_ea, func_name, "IO error: {}".format(error)))
                        processed_addrs.add(func_ea)

                except Exception as e:
                    print("[!] Write error: {}".format(str(e)))

            # 保存进度并清理
            save_progress(export_dir, processed_addrs, fallback_funcs, failed_funcs, skipped_funcs)
            if exported_funcs % 100 == 0:
                print("[+] Exported {} / {} functions...".format(
                    exported_funcs + len(prev_fallback) + len(prev_failed) + len(prev_skipped),
                    total_funcs
                ))

            pending_writes = []
            aggressive_memory_cleanup()

    # 处理剩余的写入任务
    if pending_writes:
        for future, func_ea, func_name, output_filename, callers, callees, export_type, fallback_reason in pending_writes:
            try:
                result = future.result()
                func_ea, func_name, success, output_filename, callers, callees, export_type, fallback_reason, error = result

                if success:
                    func_info = {
                        'address': func_ea,
                        'name': func_name,
                        'filename': output_filename,
                        'export_type': export_type,
                        'callers': callers,
                        'callees': callees
                    }
                    if fallback_reason:
                        func_info['fallback_reason'] = fallback_reason
                    function_index.append(func_info)
                    addr_to_info[func_ea] = func_info
                    if export_type == "disassembly-fallback":
                        fallback_funcs.append((func_ea, func_name, fallback_reason or "decompilation failed", output_filename))
                    exported_funcs += 1
                    processed_addrs.add(func_ea)
                else:
                    failed_funcs.append((func_ea, func_name, "IO error: {}".format(error)))
                    processed_addrs.add(func_ea)

            except Exception as e:
                print("[!] Write error: {}".format(str(e)))

    # 关闭线程池
    io_executor.shutdown(wait=True)

    # 最终保存进度
    save_progress(export_dir, processed_addrs, fallback_funcs, failed_funcs, skipped_funcs)

    print("\n[*] Decompilation Summary:")
    print("    Total functions: {}".format(total_funcs))
    print("    Exported: {}".format(exported_funcs))
    print("    Fallback to disassembly: {}".format(len(fallback_funcs)))
    print("    Skipped: {} (library/invalid functions)".format(len(skipped_funcs)))
    print("    Failed: {}".format(len(failed_funcs)))

    if fallback_funcs:
        fallback_log_path = os.path.join(export_dir, "disassembly_fallback.txt")
        with open(fallback_log_path, 'w', encoding='utf-8') as f:
            f.write("# Fallback to disassembly for {} functions\n".format(len(fallback_funcs)))
            f.write("# Format: address | function_name | reason | output_file\n")
            f.write("#" + "=" * 80 + "\n\n")
            for addr, name, reason, output_filename in fallback_funcs:
                f.write("{} | {} | {} | {}\n".format(hex(addr), name, reason, output_filename))
        print("    Fallback list saved to: disassembly_fallback.txt")

    # 保存失败列表
    if failed_funcs:
        failed_log_path = os.path.join(export_dir, "decompile_failed.txt")
        with open(failed_log_path, 'w', encoding='utf-8') as f:
            f.write("# Failed to decompile {} functions\n".format(len(failed_funcs)))
            f.write("# Format: address | function_name | reason\n")
            f.write("#" + "=" * 80 + "\n\n")
            for addr, name, reason in failed_funcs:
                f.write("{} | {} | {}\n".format(hex(addr), name, reason))
        print("    Failed list saved to: decompile_failed.txt")

    # 保存跳过列表
    if skipped_funcs:
        skipped_log_path = os.path.join(export_dir, "decompile_skipped.txt")
        with open(skipped_log_path, 'w', encoding='utf-8') as f:
            f.write("# Skipped {} functions\n".format(len(skipped_funcs)))
            f.write("# Format: address | function_name | reason\n")
            f.write("#" + "=" * 80 + "\n\n")
            for addr, name, reason in skipped_funcs:
                f.write("{} | {} | {}\n".format(hex(addr), name, reason))
        print("    Skipped list saved to: decompile_skipped.txt")

    # 生成函数索引文件
    if function_index:
        index_path = os.path.join(export_dir, "function_index.txt")
        with open(index_path, 'w', encoding='utf-8') as f:
            f.write("# Function Index\n")
            f.write("# Total exported functions: {}\n".format(len(function_index)))
            f.write("#" + "=" * 80 + "\n\n")

            for func_info in function_index:
                f.write("=" * 80 + "\n")
                f.write("Function: {}\n".format(func_info['name']))
                f.write("Address: {}\n".format(hex(func_info['address'])))
                f.write("File: {}\n".format(func_info['filename']))
                f.write("Type: {}\n".format(func_info['export_type']))
                if 'fallback_reason' in func_info:
                    f.write("Fallback reason: {}\n".format(func_info['fallback_reason']))
                f.write("\n")

                if func_info['callers']:
                    f.write("Called by ({} callers):\n".format(len(func_info['callers'])))
                    for caller_addr in func_info['callers']:
                        if caller_addr in addr_to_info:
                            caller_info = addr_to_info[caller_addr]
                            f.write("  - {} ({}) -> {}\n".format(
                                hex(caller_addr),
                                caller_info['name'],
                                caller_info['filename']
                            ))
                        else:
                            caller_name = idc.get_func_name(caller_addr)
                            f.write("  - {} ({})\n".format(hex(caller_addr), caller_name))
                else:
                    f.write("Called by: none\n")

                f.write("\n")

                if func_info['callees']:
                    f.write("Calls ({} callees):\n".format(len(func_info['callees'])))
                    for callee_addr in func_info['callees']:
                        if callee_addr in addr_to_info:
                            callee_info = addr_to_info[callee_addr]
                            f.write("  - {} ({}) -> {}\n".format(
                                hex(callee_addr),
                                callee_info['name'],
                                callee_info['filename']
                            ))
                        else:
                            callee_name = idc.get_func_name(callee_addr)
                            f.write("  - {} ({})\n".format(hex(callee_addr), callee_name))
                else:
                    f.write("Calls: none\n")

                f.write("\n")

        print("    Function index saved to: function_index.txt")


def export_strings(export_dir):
    """导出所有字符串"""
    strings_path = os.path.join(export_dir, "strings.txt")

    string_count = 0
    BATCH_SIZE = 500  # 每500个字符串清理一次

    with open(strings_path, 'w', encoding='utf-8') as f:
        f.write("# Strings exported from IDA\n")
        f.write("# Format: address | length | type | string\n")
        f.write("#" + "=" * 80 + "\n\n")

        for idx, s in enumerate(idautils.Strings()):
            try:
                string_content = str(s)
                str_type = "ASCII"
                if s.strtype == ida_nalt.STRTYPE_C_16:
                    str_type = "UTF-16"
                elif s.strtype == ida_nalt.STRTYPE_C_32:
                    str_type = "UTF-32"

                f.write("{} | {} | {} | {}\n".format(
                    hex(s.ea),
                    s.length,
                    str_type,
                    string_content.replace('\n', '\\n').replace('\r', '\\r')
                ))
                string_count += 1

                # 定期清理撤销缓冲区
                if (idx + 1) % BATCH_SIZE == 0:
                    clear_undo_buffer()

            except Exception as e:
                continue

    print("[*] Strings Summary:")
    print("    Total strings exported: {}".format(string_count))


def export_imports(export_dir):
    """导出导入表"""
    imports_path = os.path.join(export_dir, "imports.txt")

    import_count = 0
    with open(imports_path, 'w', encoding='utf-8') as f:
        f.write("# Imports\n")
        f.write("# Format: func-addr:func-name\n")
        f.write("#" + "=" * 60 + "\n\n")

        nimps = ida_nalt.get_import_module_qty()
        for i in range(nimps):
            module_name = ida_nalt.get_import_module_name(i)

            def imp_cb(ea, name, ordinal):
                nonlocal import_count
                if name:
                    f.write("{}:{}\n".format(hex(ea), name))
                else:
                    f.write("{}:ordinal_{}\n".format(hex(ea), ordinal))
                import_count += 1
                return True

            ida_nalt.enum_import_names(i, imp_cb)

    print("[*] Imports Summary:")
    print("    Total imports exported: {}".format(import_count))


def export_exports(export_dir):
    """导出导出表"""
    exports_path = os.path.join(export_dir, "exports.txt")

    export_count = 0
    with open(exports_path, 'w', encoding='utf-8') as f:
        f.write("# Exports\n")
        f.write("# Format: func-addr:func-name\n")
        f.write("#" + "=" * 60 + "\n\n")

        for i in range(ida_entry.get_entry_qty()):
            ordinal = ida_entry.get_entry_ordinal(i)
            ea = ida_entry.get_entry(ordinal)
            name = ida_entry.get_entry_name(ordinal)

            if name:
                f.write("{}:{}\n".format(hex(ea), name))
            else:
                f.write("{}:ordinal_{}\n".format(hex(ea), ordinal))
            export_count += 1

    print("[*] Exports Summary:")
    print("    Total exports exported: {}".format(export_count))


def export_memory(export_dir):
    """导出内存数据，按 1MB 分割，hexdump 格式"""
    memory_dir = os.path.join(export_dir, "memory")
    ensure_dir(memory_dir)

    CHUNK_SIZE = 1 * 1024 * 1024  # 1MB
    BYTES_PER_LINE = 16

    total_bytes = 0
    file_count = 0

    for seg_idx in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(seg_idx)
        if seg is None:
            continue

        seg_start = seg.start_ea
        seg_end = seg.end_ea
        seg_name = ida_segment.get_segm_name(seg)

        print("[*] Processing segment: {} ({} - {})".format(
            seg_name, hex(seg_start), hex(seg_end)))

        current_addr = seg_start
        while current_addr < seg_end:
            chunk_end = min(current_addr + CHUNK_SIZE, seg_end)

            filename = "{:08X}--{:08X}.txt".format(current_addr, chunk_end)
            filepath = os.path.join(memory_dir, filename)

            # 跳过已存在的文件
            if os.path.exists(filepath):
                file_count += 1
                current_addr = chunk_end
                total_bytes += (chunk_end - current_addr)
                continue

            with open(filepath, 'w', encoding='utf-8') as f:
                f.write("# Memory dump: {} - {}\n".format(hex(current_addr), hex(chunk_end)))
                f.write("# Segment: {}\n".format(seg_name))
                f.write("#" + "=" * 76 + "\n\n")
                f.write("# Address        | Hex Bytes                                       | ASCII\n")
                f.write("#" + "-" * 76 + "\n")

                addr = current_addr
                while addr < chunk_end:
                    line_bytes = []
                    for i in range(BYTES_PER_LINE):
                        if addr + i < chunk_end:
                            byte_val = ida_bytes.get_byte(addr + i)
                            if byte_val is not None:
                                line_bytes.append(byte_val)
                            else:
                                line_bytes.append(0)
                        else:
                            break

                    if not line_bytes:
                        addr += BYTES_PER_LINE
                        continue

                    hex_part = ""
                    for i, b in enumerate(line_bytes):
                        hex_part += "{:02X} ".format(b)
                        if i == 7:
                            hex_part += " "
                    remaining = BYTES_PER_LINE - len(line_bytes)
                    if remaining > 0:
                        if len(line_bytes) <= 8:
                            hex_part += " "
                        hex_part += "   " * remaining

                    ascii_part = ""
                    for b in line_bytes:
                        if 0x20 <= b <= 0x7E:
                            ascii_part += chr(b)
                        else:
                            ascii_part += "."

                    f.write("{:016X} | {} | {}\n".format(addr, hex_part.ljust(49), ascii_part))

                    addr += BYTES_PER_LINE
                    total_bytes += len(line_bytes)

            file_count += 1
            current_addr = chunk_end

            # 每处理完一个chunk清理一次撤销缓冲区
            clear_undo_buffer()

    print("\n[*] Memory Export Summary:")
    print("    Total bytes exported: {} ({:.2f} MB)".format(total_bytes, total_bytes / (1024 * 1024)))
    print("    Files created: {}".format(file_count))


def _ptr_export_get_ptr_size():
    """获取当前数据库的指针大小"""
    return 8 if ida_ida.inf_is_64bit() else 4


def _ptr_export_read_pointer(ea, ptr_size):
    """读取指针值"""
    return ida_bytes.get_qword(ea) if ptr_size == 8 else ida_bytes.get_dword(ea)


def _ptr_export_get_segment_name(ea):
    """获取地址所在段名"""
    seg = ida_segment.getseg(ea)
    if not seg:
        return "unknown"
    name = ida_segment.get_segm_name(seg)
    return name if name else "unknown"


def _ptr_export_is_valid_target(target_ea):
    """判断目标地址是否落在有效段内"""
    if target_ea in (0, ida_idaapi.BADADDR):
        return False
    return ida_segment.getseg(target_ea) is not None


def _ptr_export_safe_text(value):
    """将文本压成单行，便于写入导出文件"""
    if value is None:
        return ""
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8", errors="replace")
        except Exception:
            value = repr(value)
    else:
        value = str(value)

    value = value.replace("\r", " ").replace("\n", " ").replace("|", "/").strip()
    if len(value) > 80:
        value = value[:77] + "..."
    return value


def _ptr_export_get_target_name(target_ea):
    """获取目标符号名"""
    name = idc.get_name(target_ea, idc.GN_VISIBLE)
    if not name:
        func = ida_funcs.get_func(target_ea)
        if func:
            name = idc.get_func_name(func.start_ea)
    if not name:
        name = "unknown"
    return _ptr_export_safe_text(name)


def _ptr_export_try_get_string_preview(target_ea):
    """尝试提取字符串预览"""
    try:
        flags = ida_bytes.get_full_flags(target_ea)
        if not ida_bytes.is_strlit(flags):
            return ""
    except Exception:
        return ""

    try:
        strtype = idc.get_str_type(target_ea)
    except Exception:
        strtype = -1

    try:
        raw = ida_bytes.get_strlit_contents(target_ea, -1, strtype)
    except Exception:
        raw = None

    preview = _ptr_export_safe_text(raw)
    if preview:
        return '"{}"'.format(preview)
    return "string_literal"


def _ptr_export_is_import_target(target_ea, target_name):
    """启发式判断是否为导入项/IAT"""
    seg_name = _ptr_export_get_segment_name(target_ea).lower()
    name_l = (target_name or "").lower()

    if name_l.startswith("__imp_") or name_l.startswith("imp_"):
        return True

    import_like_segments = {
        "extern", ".idata", "idata", ".idata$2", ".idata$4", ".idata$5", ".idata$6",
        ".got", "got", ".got.plt", "got.plt", "__la_symbol_ptr", "__nl_symbol_ptr"
    }
    return seg_name in import_like_segments


def _ptr_export_classify_target(target_ea):
    """返回 (target_name, target_type, target_detail)"""
    target_name = _ptr_export_get_target_name(target_ea)

    try:
        flags = ida_bytes.get_full_flags(target_ea)
    except Exception:
        flags = 0

    if _ptr_export_is_import_target(target_ea, target_name):
        return target_name, "import_pointer", "import_entry"

    try:
        if ida_bytes.is_strlit(flags):
            return target_name, "string_pointer", _ptr_export_try_get_string_preview(target_ea)
    except Exception:
        pass

    try:
        func = ida_funcs.get_func(target_ea)
    except Exception:
        func = None

    if func:
        if func.start_ea == target_ea:
            return target_name, "function_pointer", "function_start"
        func_name = _ptr_export_get_target_name(func.start_ea)
        return target_name, "code_pointer", "inside_{}".format(func_name)

    try:
        if ida_bytes.is_code(flags):
            return target_name, "code_pointer", "instruction"
    except Exception:
        pass

    try:
        if ida_bytes.is_struct(flags):
            return target_name, "struct_pointer", "struct_data"
    except Exception:
        pass

    try:
        if ida_bytes.is_data(flags):
            return target_name, "data_pointer", "data_item_size={}".format(ida_bytes.get_item_size(target_ea))
    except Exception:
        pass

    return target_name, "unknown_pointer", ""


def _ptr_export_add_record(records, seen, source_ea, target_ea):
    """去重后加入一条记录"""
    key = (source_ea, target_ea)
    if key in seen:
        return
    seen.add(key)

    target_name, target_type, target_detail = _ptr_export_classify_target(target_ea)
    records.append({
        "source_addr": source_ea,
        "source_seg": _ptr_export_get_segment_name(source_ea),
        "points_to": target_ea,
        "target_name": target_name,
        "target_type": target_type,
        "target_detail": target_detail,
    })


def _ptr_export_collect_data_xrefs(records, seen):
    """收集所有代码头/数据头上的 data xref"""
    total = 0

    for seg_idx in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(seg_idx)
        if not seg:
            continue

        for head in idautils.Heads(seg.start_ea, seg.end_ea):
            try:
                flags = ida_bytes.get_full_flags(head)
            except Exception:
                continue

            if not ida_bytes.is_head(flags):
                continue
            if not (ida_bytes.is_code(flags) or ida_bytes.is_data(flags)):
                continue

            try:
                target = ida_xref.get_first_dref_from(head)
            except Exception:
                target = ida_idaapi.BADADDR

            while target != ida_idaapi.BADADDR:
                if _ptr_export_is_valid_target(target):
                    _ptr_export_add_record(records, seen, head, target)
                    total += 1
                try:
                    target = ida_xref.get_next_dref_from(head, target)
                except Exception:
                    break

    return total


def _ptr_export_collect_raw_pointers(records, seen, ptr_size):
    """扫描常见数据段中的裸指针，补齐未建立 xref 的项"""
    total = 0

    for seg_ea in idautils.Segments():
        seg_name = idc.get_segm_name(seg_ea)
        seg_start = idc.get_segm_start(seg_ea)
        seg_end = idc.get_segm_end(seg_ea)

        if not seg_name or not (
                seg_name.startswith(".data") or seg_name.startswith(".rdata") or seg_name.startswith("data")):
            continue

        print("[*] Scanning segment: {} ({:X} - {:X})".format(seg_name, seg_start, seg_end))

        for head in idautils.Heads(seg_start, seg_end):
            try:
                flags = ida_bytes.get_full_flags(head)
            except Exception:
                continue

            if not ida_bytes.is_head(flags):
                continue
            if not ida_bytes.is_data(flags):
                continue

            try:
                item_size = ida_bytes.get_item_size(head)
            except Exception:
                item_size = 0

            if item_size < ptr_size:
                continue

            slot_count = item_size // ptr_size
            if slot_count <= 0:
                continue

            for i in range(slot_count):
                slot_ea = head + i * ptr_size
                try:
                    target = _ptr_export_read_pointer(slot_ea, ptr_size)
                except Exception:
                    continue

                if _ptr_export_is_valid_target(target):
                    _ptr_export_add_record(records, seen, slot_ea, target)
                    total += 1

    return total


def export_pointers(export_dir):
    """导出指针引用，保留原有导出目录模式"""
    output_path = os.path.join(export_dir, "pointers.txt")
    ptr_size = _ptr_export_get_ptr_size()
    records = []
    seen = set()

    print("[*] Starting pointer scan. Pointer size: {} bytes".format(ptr_size))

    dref_hits = _ptr_export_collect_data_xrefs(records, seen)
    raw_hits = _ptr_export_collect_raw_pointers(records, seen, ptr_size)

    records.sort(key=lambda item: (
        item["source_addr"],
        item["points_to"],
        item["source_seg"],
        item["target_name"],
        item["target_type"],
        item["target_detail"],
    ))

    if records:
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write("# Total Pointers Found: {}\n".format(len(records)))
                f.write(
                    "# Format: Source_Address | Segment | Points_To_Address | Target_Name | Target_Type | Target_Detail\n")
                f.write("# Pointer size: {}\n".format(ptr_size))
                f.write("# Data xref hits: {}\n".format(dref_hits))
                f.write("# Raw pointer hits: {}\n".format(raw_hits))
                f.write("-" * 120 + "\n")
                for p in records:
                    f.write("{:X} | {} | {:X} | {} | {} | {}\n".format(
                        p["source_addr"],
                        p["source_seg"],
                        p["points_to"],
                        p["target_name"],
                        p["target_type"],
                        p["target_detail"]
                    ))
            print("[+] Pointers exported to: {}".format(output_path))
            print("[*] Pointers Summary:")
            print("    Data xref hits: {}".format(dref_hits))
            print("    Raw pointer hits: {}".format(raw_hits))
            print("    Unique pointer references exported: {}".format(len(records)))
        except Exception as e:
            print("[!] Failed to write pointers: {}".format(str(e)))
    else:
        print("[*] No pointers found or no data segments scanned.")


def do_export(export_dir=None, ask_user=True, skip_auto_analysis=False, worker_count=None):
    """执行导出操作

    Args:
        export_dir: 导出目录路径，如果为None则使用默认或询问用户
        ask_user: 是否询问用户选择目录
        skip_auto_analysis: 是否跳过等待自动分析（如果已经分析完成）
        worker_count: 并行工作线程数，默认为CPU核心数-1
    """
    global WORKER_COUNT

    if worker_count is not None:
        WORKER_COUNT = max(1, worker_count)

    print("=" * 60)
    print("IDA Export for AI Analysis")
    print("=" * 60)
    print("[*] Using {} worker threads for parallel I/O".format(WORKER_COUNT))

    # 初始清理
    clear_undo_buffer()

    # 尝试禁用撤销功能以减少内存使用
    disable_undo()

    if not ida_hexrays.init_hexrays_plugin():
        print("[!] Hex-Rays decompiler is not available!")
        print("[!] Strings will still be exported, but no decompilation.")
        has_hexrays = False
    else:
        has_hexrays = True
        print("[+] Hex-Rays decompiler initialized")

    if not skip_auto_analysis:
        print("[*] Waiting for auto-analysis to complete...")
        print("[*] Tip: This may take a while for large files. Press Ctrl+Break to cancel.")

        # 在auto_wait之前清理一次
        clear_undo_buffer()

        ida_auto.auto_wait()

        # auto_wait之后立即清理
        clear_undo_buffer()
    else:
        print("[*] Skipping auto-analysis wait (assuming already complete)")

    if export_dir is None:
        idb_dir = get_idb_directory()
        default_export_dir = os.path.join(idb_dir, "export-for-ai")

        if ask_user:
            choice = ida_kernwin.ask_yn(ida_kernwin.ASKBTN_YES,
                                        "Export to default directory?\n\n{}\n\nYes: Use default directory\nNo: Choose custom directory\nCancel: Abort export".format(
                                            default_export_dir))

            if choice == ida_kernwin.ASKBTN_CANCEL:
                print("[*] Export cancelled by user")
                enable_undo()
                return
            elif choice == ida_kernwin.ASKBTN_NO:
                selected_dir = ida_kernwin.ask_str(default_export_dir, 0, "Enter export directory path:")
                if selected_dir:
                    export_dir = selected_dir
                    print("[*] Using custom directory: {}".format(export_dir))
                else:
                    print("[*] Export cancelled by user")
                    enable_undo()
                    return
            else:
                export_dir = default_export_dir
        else:
            export_dir = default_export_dir

    ensure_dir(export_dir)

    print("[+] Export directory: {}".format(export_dir))
    print("")

    print("[*] Exporting strings...")
    export_strings(export_dir)
    clear_undo_buffer()
    print("")

    print("[*] Exporting imports...")
    export_imports(export_dir)
    clear_undo_buffer()
    print("")

    print("[*] Exporting exports...")
    export_exports(export_dir)
    clear_undo_buffer()
    print("")

    # [新增] 导出指针引用
    print("[*] Exporting pointers...")
    export_pointers(export_dir)
    clear_undo_buffer()
    print("")

    print("[*] Exporting memory...")
    export_memory(export_dir)
    clear_undo_buffer()
    print("")



    if has_hexrays:
        print("[*] Exporting decompiled functions with disassembly fallback...")
        print("[*] Tip: If IDA crashes, you can restart and the export will resume from where it left off")
        export_decompiled_functions(export_dir, skip_existing=True)

    # 恢复撤销功能
    enable_undo()

    print("")
    print("=" * 60)
    print("[+] Export completed!")
    print("    Output directory: {}".format(export_dir))
    print("=" * 60)

    ida_kernwin.info("Export completed!\n\nOutput directory:\n{}".format(export_dir))


# ============================================================================
# Plugin Class
# ============================================================================

class ExportForAIPlugin(ida_idaapi.plugin_t):
    """IDA Plugin for exporting data for AI analysis"""

    flags = ida_idaapi.PLUGIN_KEEP
    comment = "Export IDA data for AI analysis"
    help = "Export decompiled functions with disassembly fallback, strings, memory, imports and exports"
    wanted_name = "Export for AI"
    wanted_hotkey = "Ctrl-Shift-E"

    def init(self):
        """插件初始化"""
        print("[+] Export for AI plugin loaded")
        print("    Hotkey: {}".format(self.wanted_hotkey))
        print("    Menu: Edit -> Plugins -> Export for AI")
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        """插件运行"""
        try:
            # 询问是否跳过自动分析（如果用户已经分析完成）
            choice = ida_kernwin.ask_yn(ida_kernwin.ASKBTN_YES,
                                        "Has the auto-analysis already completed?\n\n"
                                        "Yes: Skip waiting for auto-analysis (faster)\n"
                                        "No: Wait for auto-analysis to complete\n"
                                        "Cancel: Abort export")

            if choice == ida_kernwin.ASKBTN_CANCEL:
                print("[*] Export cancelled by user")
                return

            skip_analysis = (choice == ida_kernwin.ASKBTN_YES)
            do_export(skip_auto_analysis=skip_analysis)
        except Exception as e:
            print("[!] Export failed: {}".format(str(e)))
            import traceback
            traceback.print_exc()
            ida_kernwin.warning("Export failed!\n\n{}".format(str(e)))

    def term(self):
        """插件卸载"""
        print("[-] Export for AI plugin unloaded")


def PLUGIN_ENTRY():
    """IDA插件入口点"""
    return ExportForAIPlugin()


# ============================================================================
# Standalone Script Support
# ============================================================================

if __name__ == "__main__":
    # 支持作为独立脚本运行（用于批处理模式）
    argc = int(idc.eval_idc("ARGV.count"))
    if argc < 2:
        export_dir = None
        skip_analysis = False
    elif argc < 3:
        export_dir = idc.eval_idc("ARGV[1]")
        skip_analysis = False
    else:
        export_dir = idc.eval_idc("ARGV[1]")
        skip_analysis = (idc.eval_idc("ARGV[2]") == "1")

    # 批处理模式不询问用户
    do_export(export_dir, ask_user=False, skip_auto_analysis=skip_analysis)

    # 只在批处理模式下退出
    if argc >= 2:
        idc.qexit(0)
