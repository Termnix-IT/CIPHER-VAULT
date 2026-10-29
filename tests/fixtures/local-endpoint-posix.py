"""Development-only native socket probe; never opens a vault or handles secrets."""
import ctypes
import errno
import json
import os
import socket
import stat
import struct
import sys


def directory(endpoint):
    root = os.path.dirname(endpoint)
    info = os.lstat(root)
    if (not os.path.isabs(endpoint) or not os.path.basename(root).startswith("cv-ep-") or
            os.path.basename(endpoint) != "probe.sock" or os.path.realpath(root) != root or
            not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError("UNSAFE_DIRECTORY")


def endpoint_info(endpoint):
    directory(endpoint)
    info = os.lstat(endpoint)
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise ValueError("UNSAFE_ENDPOINT")
    return info


def peer(connection):
    if sys.platform.startswith("linux"):
        pid, uid, _gid = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
    elif sys.platform == "darwin":
        library = ctypes.CDLL(None, use_errno=True)
        getpeereid = library.getpeereid
        getpeereid.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(ctypes.c_uint)]
        getpeereid.restype = ctypes.c_int
        uid_value, gid = ctypes.c_uint(), ctypes.c_uint()
        if getpeereid(connection.fileno(), ctypes.byref(uid_value), ctypes.byref(gid)) != 0:
            raise OSError(ctypes.get_errno(), "PEER_QUERY_FAILED")
        uid = uid_value.value
        # Darwin sys/un.h: SOL_LOCAL=0, LOCAL_PEERPID=2; no caller-supplied PID fallback.
        pid = struct.unpack("i", connection.getsockopt(0, 2, struct.calcsize("i")))[0]
    else:
        raise ValueError("UNSUPPORTED_PLATFORM")
    return pid, uid


def inspect(endpoint, expected):
    original = endpoint_info(endpoint)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(5)
        connection.connect(endpoint)
        current = endpoint_info(endpoint)
        if (original.st_dev, original.st_ino) != (current.st_dev, current.st_ino):
            raise ValueError("ENDPOINT_CHANGED")
        pid, uid = peer(connection)
        return {"accepted": pid == expected and uid == os.geteuid(), "peerMatches": pid == expected, "userMatches": uid == os.geteuid()}


def serve(endpoint, expected, count):
    directory(endpoint)
    if os.path.lexists(endpoint):
        raise ValueError("ENDPOINT_EXISTS")
    original = None
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.settimeout(10)
            server.bind(endpoint)
            os.chmod(endpoint, 0o600)
            original = endpoint_info(endpoint)
            server.listen(1)
            print(json.dumps({"ready": True}), flush=True)
            for _ in range(count):
                connection, _ = server.accept()
                with connection:
                    connection.settimeout(5)
                    try:
                        pid, uid = peer(connection)
                    except OSError as error:
                        # The inspection-only client may close before accept/query on Darwin.
                        if error.errno not in (errno.ENOTCONN, errno.ECONNRESET, errno.EPIPE):
                            raise
                        continue
                    request = b""
                    while len(request) < 4:
                        chunk = connection.recv(4 - len(request))
                        if not chunk:
                            break
                        request += chunk
                    if len(request) != 4:
                        continue
                    claimed, = struct.unpack("!I", request)
                    result = {"accepted": pid == expected and uid == os.geteuid(), "peerMatches": pid == expected,
                              "userMatches": uid == os.geteuid(), "claimedMatches": claimed == expected}
                    try:
                        connection.sendall((json.dumps(result) + "\n").encode("utf-8"))
                        connection.recv(1)  # Wait for the reader's close, matching the Windows probe.
                    except (BrokenPipeError, ConnectionResetError):
                        pass
    finally:
        if original is not None and os.path.lexists(endpoint):
            current = os.lstat(endpoint)
            if stat.S_ISSOCK(current.st_mode) and (current.st_dev, current.st_ino) == (original.st_dev, original.st_ino):
                os.unlink(endpoint)


try:
    mode, endpoint, expected_text, *remaining = sys.argv[1:]
    expected = int(expected_text)
    if expected <= 0 or mode not in ("inspect", "serve"):
        raise ValueError("INVALID_ARGUMENTS")
    if mode == "inspect":
        if remaining:
            raise ValueError("INVALID_ARGUMENTS")
        print(json.dumps(inspect(endpoint, expected)), flush=True)
    else:
        count = int(remaining[0])
        if len(remaining) != 1 or not 1 <= count <= 8:
            raise ValueError("INVALID_ARGUMENTS")
        serve(endpoint, expected, count)
except Exception as error:
    print("LOCAL_ENDPOINT_PROBE_FAILED: " + type(error).__name__, file=sys.stderr)
    sys.exit(1)
