import json
import os
import posixpath
from urllib.parse import parse_qs, urlsplit

from androidemu.const import emu_const
from androidemu.emulator import Emulator
from androidemu.java.classes.activity_thread import ActivityThread
from androidemu.java.classes.array import ByteArray
from androidemu.java.classes.list import List
from androidemu.java.classes.object import Object
from androidemu.java.classes.string import String
from androidemu.java.classes.types import Boolean, Long
from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_method_def import java_method_def
from androidemu.native_hook_utils import FuncHooker
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X30


LICENSE_STR = (
    "bo95dJizD1WFcV03zOuLzN5Pn1sFtVa3szqiVQmflMJTNW0p0Kpqfw8D4i0zUlfrou4kuYt/"
    "i0521YRygM83dwv/wn3DD+TMJF+QFzW9wb8Qq2/1B4jPMbObrDNdyMMukpAYqy1fLWtbLGVIP"
    "xsFsZegwQy5lsRX9h49PH/Qx8MwgYvWvH7ZTFLV28LwTWZiljQyBPaBE+TsyumEu0Y+JRkeidH"
    "FEYcVs0yRoa+xC004hugQhdPupIt6dBiWA4phsB3fNJZjFTAKGE1lPB4gzt6Qf+FmlgZBbRvT8"
    "zekxTV2HZ5dUvSutB2/0QpbHKAvWL4DRA=="
)
SDK_VERSION_KEY = "dfc345"
SDK_VERSION_BYTES = [
    0x63, 0x34, 0x44, 0x09, 0x5A, 0x72, 0x29, 0x17, 0x62, 0x2D,
    0x25, 0x36, 0x5D, 0x45, 0x1E, 0x25, 0x61, 0x4E, 0x2A,
]
FRAME_SIGN_CANDIDATES = (0, 1, 2, 3, 4)
FINAL_SIGN_OPCODE = 33554438
RAW_FRAME_SIGN_OPCODE = 33554442
SIGN_HEADER_ORDER = (
    "X-Argus",
    "X-Gorgon",
    "X-Helios",
    "X-Khronos",
    "X-Ladon",
    "X-Medusa",
)
RAW_SIGN_FIELD_ORDER = (
    "frametype",
    "lid",
    "signinfo",
    "signvalue",
    "signversion",
)


def _ms_callback_stub(i1):
    if i1 == 65539:
        return String("/data/user/0/com.ss.android.ugc.aweme/files/.msdata")
    if i1 == 268435470:
        return False
    if i1 == 16777233:
        return String("38.8.0")
    if i1 == 33554433:
        return True
    if i1 == 33554434:
        return True
    return None


class ms_bd_c_k(Object, metaclass=JavaClassDef, jvm_name="ms/bd/c/k", jvm_super=Object):
    @staticmethod
    @java_method_def(
        name="a",
        args_list=["jint", "jint", "jlong", "jstring", "jobject"],
        signature="(IIJLjava/lang/String;Ljava/lang/Object;)Ljava/lang/Object;",
        native=True,
    )
    def a(emu, i1, i2, l, s, obj):
        pass


class ms_bd_c_a0(metaclass=JavaClassDef, jvm_name="ms/bd/c/a0", jvm_super=ms_bd_c_k):
    pass


class ms_bd_c_f3(Object, metaclass=JavaClassDef, jvm_name="ms/bd/c/f3", jvm_super=Object):
    @staticmethod
    @java_method_def(
        name="a",
        args_list=["jint", "jint", "jlong", "jstring", "jobject"],
        signature="(IIJLjava/lang/String;Ljava/lang/Object;)Ljava/lang/Object;",
        native=True,
    )
    def a(emu, i1, i2, l, s, obj):
        pass

    @staticmethod
    @java_method_def(
        name="b",
        args_list=["jint", "jint", "jlong", "jstring", "jobject"],
        signature="(IIJLjava/lang/String;Ljava/lang/Object;)Ljava/lang/Object;",
        native=False,
    )
    def b(emu, i1, i2, l, s, obj):
        return _ms_callback_stub(i1)


class MS(metaclass=JavaClassDef, jvm_name="com/bytedance/mobsec/metasec/ml/MS", jvm_super=ms_bd_c_a0):
    @staticmethod
    @java_method_def(name="a", signature="()V", native=False)
    def a(emu):
        return None

    @staticmethod
    @java_method_def(
        name="b",
        args_list=["jint", "jint", "jlong", "jstring", "jobject"],
        signature="(IIJLjava/lang/String;Ljava/lang/Object;)Ljava/lang/Object;",
        native=False,
    )
    def b(emu, i1, i2, l, s, obj):
        return _ms_callback_stub(i1)


class java_lang_Thread(Object, metaclass=JavaClassDef, jvm_name="java/lang/Thread", jvm_super=Object):
    @java_method_def(name="currentThread", signature="()Ljava/lang/Thread;", native=False)
    def currentThread(self):
        return java_lang_Thread()

    @java_method_def(name="getStackTrace", signature="()[Ljava/lang/StackTraceElement;", native=False)
    def getStackTrace(self, s):
        return List([])


def _normalize_string(value):
    if value is None:
        return ""
    if isinstance(value, String):
        return value.get_py_string()
    if hasattr(value, "get_py_string"):
        return value.get_py_string()
    return str(value)


def _normalize_bool(value):
    if isinstance(value, Boolean):
        return bool(value.booleanValue(None))
    return bool(value)


def _normalize_long(value):
    if isinstance(value, Long):
        return value.get_py_value()
    if hasattr(value, "get_py_value"):
        return value.get_py_value()
    return int(value)


def _headers_from_s2(s2):
    headers = {}
    if not s2:
        return headers

    parts = [item for item in s2.split("\r\n") if item != ""]
    for idx in range(0, len(parts) - 1, 2):
        headers[parts[idx]] = parts[idx + 1]
    return headers


def _cookie_value(cookie_text, key):
    if not cookie_text:
        return ""

    for item in cookie_text.split(";"):
        chunk = item.strip()
        if not chunk or "=" not in chunk:
            continue
        name, value = chunk.split("=", 1)
        if name.strip() == key:
            return value.strip()
    return ""


def _query_value(url, key, default=""):
    value_list = parse_qs(urlsplit(url).query).get(key)
    if not value_list:
        return default
    return value_list[0]


def _flatten_map(map_data):
    flat = []
    for key, value in map_data.items():
        if key is None or value is None:
            continue
        flat.append(_normalize_string(key))
        flat.append(_normalize_string(value))
    return flat


def _build_ms_config(app_id, sdk_version, channel):
    payload = [
        app_id,
        "",
        "",
        LICENSE_STR,
        sdk_version,
        channel,
        "",
        "",
        "",
        "",
        "0",
        "-1",
        "99999",
        "",
        "0",
        [],
        ["tk_key", "douyin"],
    ]
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def _result_to_map(result):
    if result is None:
        return {}

    if isinstance(result, dict):
        return result

    if hasattr(result, "get_py_items"):
        items = list(result.get_py_items())
    elif isinstance(result, (list, tuple)):
        items = list(result)
    else:
        return {}

    if len(items) < 2 or len(items) % 2 != 0:
        return {}

    result_map = {}
    for idx in range(0, len(items), 2):
        key = _normalize_string(items[idx])
        value = _normalize_string(items[idx + 1])
        if key and value:
            result_map[key] = value
    return result_map


def _format_sign_result(result_map):
    lines = []
    for key in SIGN_HEADER_ORDER:
        value = result_map.get(key)
        if value:
            lines.append(key)
            lines.append(value)
    if lines:
        return "\r\n".join(lines)

    for key in RAW_SIGN_FIELD_ORDER:
        value = result_map.get(key)
        if value:
            lines.append(key)
            lines.append(value)

    if not lines:
        for key, value in result_map.items():
            if key and value:
                lines.append(key)
                lines.append(value)

    return "\r\n".join(lines)


def _read_table_func_addr(emulator, table_addr, index):
    ptr_sz = emulator.get_ptr_size()
    data = emulator.mu.mem_read(table_addr + index * ptr_sz, ptr_sz)
    return int.from_bytes(data, byteorder="little", signed=False)


def _resolve_ms_entry():
    if ms_bd_c_k.a.jvm_method.native_addr:
        return ms_bd_c_k.a, "ms.bd.c.k.a"
    if ms_bd_c_f3.a.jvm_method.native_addr:
        return ms_bd_c_f3.a, "ms.bd.c.f3.a"
    return None, None


def _call_ms(emulator, opcode, i2=0, handle=0, text=None, obj=0):
    str_arg = String(text) if text is not None else 0
    obj_arg = 0 if obj is None else obj
    entry, entry_name = _resolve_ms_entry()
    if entry is None:
        raise RuntimeError(
            "public native entry is unresolved; "
            "expected ms.bd.c.k.a or ms.bd.c.f3.a after JNI_OnLoad"
        )
    return entry(emulator, opcode, i2, handle, str_arg, obj_arg)


def _build_emulator(repo_root):
    emulator = Emulator(
        vfs_root=posixpath.join(repo_root, "vfs"),
        arch=emu_const.ARCH_ARM64,
        muti_task=True,
    )
    emulator.java_classloader.add_class(ms_bd_c_k)
    emulator.java_classloader.add_class(ms_bd_c_a0)
    emulator.java_classloader.add_class(ms_bd_c_f3)
    emulator.java_classloader.add_class(MS)
    emulator.java_classloader.add_class(java_lang_Thread)
    return emulator


def _load_runtime(emulator, repo_root):
    libc_path = os.path.join(repo_root, "vfs", "system", "lib64", "libc.so")
    so_path = os.path.join(repo_root, "_tmp_new_libmetasec_ml.so")
    emulator.load_library(libc_path)
    libml = emulator.modules.load_module(so_path, True)

    hooker = FuncHooker(emulator)

    def _sub_291324_before(emu):
        emu.mu.reg_write(UC_ARM64_REG_X0, 0)
        return True

    hooker.fun_hook(libml.base + 0x291324, 0, _sub_291324_before, None)

    emulator.call_symbol(libml, "JNI_OnLoad", emulator.java_vm.address_ptr, 0)
    _, entry_name = _resolve_ms_entry()
    if entry_name is None:
        raise RuntimeError(
            "JNI_OnLoad completed but did not resolve public native entry "
            "ms.bd.c.k.a / ms.bd.c.f3.a"
        )
    return libml


def _init_ms_handle(emulator, url, header_text):
    headers = _headers_from_s2(header_text)
    cookie_text = headers.get("Cookie", "")

    app_id = _query_value(url, "aid", "1128")
    channel = _query_value(url, "channel", "")
    device_id = _query_value(url, "device_id", "")
    install_id = _query_value(url, "iid", "") or _cookie_value(cookie_text, "install_id")
    session_id = _cookie_value(cookie_text, "sessionid") or _cookie_value(cookie_text, "sid_tt")

    app_ctx = ActivityThread.currentApplication(emulator)
    _call_ms(emulator, 16777219, 0, 0, None, app_ctx)

    sdk_version = _normalize_string(
        _call_ms(
            emulator,
            16777217,
            0,
            0,
            SDK_VERSION_KEY,
            ByteArray(SDK_VERSION_BYTES),
        )
    )
    if not sdk_version:
        raise RuntimeError("failed to resolve native sdk version")

    config_payload = _build_ms_config(app_id, sdk_version, channel)
    init_result = _call_ms(emulator, 67108865, 0, 0, config_payload, 0)
    if not _normalize_bool(init_result):
        raise RuntimeError("native metasec init failed")

    handle_result = _call_ms(emulator, 67108866, 0, 0, app_id, 0)
    handle = _normalize_long(handle_result)
    if handle <= 0:
        raise RuntimeError("native metasec handle is invalid")

    if device_id:
        _call_ms(emulator, 33554434, 0, handle, device_id, app_ctx)
    if install_id:
        _call_ms(emulator, 33554435, 0, handle, install_id, app_ctx)
    if session_id:
        _call_ms(emulator, 33554436, 0, handle, session_id, app_ctx)

    return handle


def _try_frame_sign(emulator, handle, url):
    best_result = {}
    for candidate in FRAME_SIGN_CANDIDATES:
        result_map = _result_to_map(_call_ms(emulator, FINAL_SIGN_OPCODE, candidate, handle, url, 0))
        if not result_map:
            continue

        if "X-Argus" in result_map or "X-Gorgon" in result_map:
            return result_map

        if not best_result:
            best_result = result_map

    for candidate in FRAME_SIGN_CANDIDATES:
        result_map = _result_to_map(_call_ms(emulator, RAW_FRAME_SIGN_OPCODE, candidate, handle, url, 0))
        if result_map and not best_result:
            best_result = result_map

    return best_result


def get_sign_map(s1, s2):
    repo_root = os.path.dirname(os.path.abspath(__file__))
    emulator = _build_emulator(repo_root)

    try:
        _load_runtime(emulator, repo_root)
        handle = _init_ms_handle(emulator, s1, s2)
        sign_map = _try_frame_sign(emulator, handle, s1)
        if not sign_map:
            raise RuntimeError("frameSign returned empty result for all candidate modes")
        return sign_map
    finally:
        del emulator


def get_sign(s1, s2):
    return _format_sign_result(get_sign_map(s1, s2))
