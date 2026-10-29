"""
Compatibility layer for FastAPI and Pydantic.
Uses native FastAPI + Pydantic when installed (e.g., in Docker or virtualenv),
and provides a strict stdlib fallback in restricted containers without pip
so unit/security tests and the HTTP server run deterministically everywhere.
"""
from __future__ import annotations

import inspect
import json
import os
import re
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional, Tuple, Type, get_type_hints

try:
    from pydantic import BaseModel as _PydanticBaseModel, Field as _PydanticField, ValidationError as _PydanticValidationError
    HAS_PYDANTIC = True
except ImportError:
    HAS_PYDANTIC = False


class ValidationError(ValueError):
    def __init__(self, errors: List[Dict[str, Any]]):
        self.errors_list = errors
        super().__init__(json.dumps(errors))

    def errors(self) -> List[Dict[str, Any]]:
        return self.errors_list


class _FieldInfo:
    def __init__(
        self,
        default: Any = ...,
        min_length: Optional[int] = None,
        max_length: Optional[int] = None,
        description: Optional[str] = None,
    ):
        self.default = default
        self.min_length = min_length
        self.max_length = max_length
        self.description = description


def Field(
    default: Any = ...,
    *,
    min_length: Optional[int] = None,
    max_length: Optional[int] = None,
    description: Optional[str] = None,
) -> Any:
    if HAS_PYDANTIC:
        return _PydanticField(
            default=default,
            min_length=min_length,
            max_length=max_length,
            description=description,
        )
    return _FieldInfo(
        default=default,
        min_length=min_length,
        max_length=max_length,
        description=description,
    )


if HAS_PYDANTIC:
    BaseModel = _PydanticBaseModel  # type: ignore
else:
    class BaseModel:
        """Strict server-side schema validation model compatible with Pydantic v2."""

        def __init__(self, **data: Any):
            hints = get_type_hints(self.__class__)
            errors: List[Dict[str, Any]] = []

            for field_name, field_type in hints.items():
                if field_name.startswith("_"):
                    continue
                class_attr = getattr(self.__class__, field_name, ...)
                field_info = class_attr if isinstance(class_attr, _FieldInfo) else None
                default_val = field_info.default if field_info is not None else class_attr

                if field_name in data and data[field_name] is not None:
                    val = data[field_name]
                elif default_val is not ...:
                    val = default_val() if callable(default_val) else default_val
                else:
                    errors.append({"loc": [field_name], "msg": "Field required", "type": "missing"})
                    continue

                if val is not None and (
                    (field_type is str and not isinstance(val, str))
                    or (field_type is int and (isinstance(val, bool) or not isinstance(val, int)))
                ):
                    errors.append({"loc": [field_name], "msg": "Invalid type", "type": "type_error"})
                    continue

                if val is not None and field_info is not None:
                    if isinstance(val, str):
                        if field_info.min_length is not None and len(val.strip()) < field_info.min_length:
                            errors.append({
                                "loc": [field_name],
                                "msg": f"String should have at least {field_info.min_length} characters",
                                "type": "string_too_short",
                            })
                        if field_info.max_length is not None and len(val) > field_info.max_length:
                            errors.append({
                                "loc": [field_name],
                                "msg": f"String should have at most {field_info.max_length} characters",
                                "type": "string_too_long",
                            })

                setattr(self, field_name, val)

            if errors:
                raise ValidationError(errors)

        def model_dump(self) -> Dict[str, Any]:
            result: Dict[str, Any] = {}
            hints = get_type_hints(self.__class__)
            for k in hints:
                if not k.startswith("_"):
                    val = getattr(self, k, None)
                    if hasattr(val, "value"):
                        result[k] = val.value
                    elif isinstance(val, BaseModel):
                        result[k] = val.model_dump()
                    else:
                        result[k] = val
            return result


class HTTPException(Exception):
    def __init__(self, status_code: int, detail: Any):
        self.status_code = status_code
        self.detail = detail
        super().__init__(str(detail))


class RequestContext:
    def __init__(
        self,
        method: str,
        path: str,
        headers: Dict[str, str],
        query_params: Dict[str, str],
        body_bytes: bytes = b"",
    ):
        self.method = method.upper()
        self.path = path
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        self.query_params = query_params or {}
        self._body_bytes = body_bytes

    def header(self, name: str, default: Optional[str] = None) -> Optional[str]:
        return self.headers.get(name.lower(), default)

    def json(self) -> Dict[str, Any]:
        if not self._body_bytes:
            return {}
        return json.loads(self._body_bytes.decode("utf-8"))


class ResponseData:
    def __init__(self, status_code: int, body: Any):
        self.status_code = status_code
        self._body = body

    def json(self) -> Any:
        return self._body

    @property
    def text(self) -> str:
        return json.dumps(self._body)


class BayoraRouterApp:
    """Lightweight FastAPI-compatible application router with TestClient and HTTP server support."""

    def __init__(self, title: str = "Bayora Control Plane API", version: str = "1.0.0"):
        self.title = title
        self.version = version
        self.routes: List[Tuple[str, re.Pattern, List[str], Callable]] = []

    def _register(self, method: str, path_template: str, func: Callable) -> Callable:
        param_names = re.findall(r"\{([a-zA-Z0-9_]+)\}", path_template)
        regex_str = "^" + re.sub(r"\{[a-zA-Z0-9_]+\}", r"([^/]+)", path_template) + "$"
        self.routes.append((method.upper(), re.compile(regex_str), param_names, func))
        return func

    def get(self, path: str) -> Callable:
        def decorator(func: Callable) -> Callable:
            return self._register("GET", path, func)
        return decorator

    def post(self, path: str) -> Callable:
        def decorator(func: Callable) -> Callable:
            return self._register("POST", path, func)
        return decorator

    def dispatch(
        self,
        method: str,
        raw_url: str,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[Any] = None,
    ) -> ResponseData:
        parsed = urllib.parse.urlparse(raw_url)
        path = parsed.path
        qs = dict(urllib.parse.parse_qsl(parsed.query))

        if body is None:
            body_bytes = b""
        elif isinstance(body, bytes):
            body_bytes = body
        elif isinstance(body, str):
            body_bytes = body.encode("utf-8")
        else:
            body_bytes = json.dumps(body).encode("utf-8")

        req = RequestContext(
            method=method,
            path=path,
            headers=headers or {},
            query_params=qs,
            body_bytes=body_bytes,
        )

        matched_path = False
        for route_method, pattern, param_names, handler in self.routes:
            m = pattern.match(path)
            if m:
                matched_path = True
                if route_method != method.upper():
                    continue
                path_params = dict(zip(param_names, m.groups()))
                try:
                    sig = inspect.signature(handler)
                    type_hints = get_type_hints(handler)
                    kwargs: Dict[str, Any] = {}
                    for pname, param in sig.parameters.items():
                        resolved_type = type_hints.get(pname, param.annotation)
                        if pname == "request":
                            kwargs["request"] = req
                        elif pname in path_params:
                            kwargs[pname] = path_params[pname]
                        elif pname in qs:
                            kwargs[pname] = qs[pname]
                        elif isinstance(resolved_type, type) and issubclass(resolved_type, BaseModel):
                            payload_dict = req.json()
                            kwargs[pname] = resolved_type(**payload_dict)
                        elif param.default is not inspect.Parameter.empty:
                            kwargs[pname] = param.default
                    result = handler(**kwargs)
                    if isinstance(result, tuple) and len(result) == 2 and isinstance(result[1], int):
                        payload, status = result
                    else:
                        payload, status = result, 200
                    if isinstance(payload, BaseModel):
                        payload = payload.model_dump()
                    return ResponseData(status_code=status, body=payload)
                except HTTPException as exc:
                    err_body = exc.detail if isinstance(exc.detail, dict) else {"detail": exc.detail}
                    return ResponseData(status_code=exc.status_code, body=err_body)
                except (ValidationError, ValueError, json.JSONDecodeError) as exc:
                    return ResponseData(
                        status_code=422,
                        body={"error": "VALIDATION_ERROR", "detail": str(exc)},
                    )
                except Exception as exc:
                    return ResponseData(
                        status_code=500,
                        body={"error": "INTERNAL_SERVER_ERROR", "detail": "An unexpected control plane error occurred."},
                    )

        if matched_path:
            return ResponseData(status_code=405, body={"error": "METHOD_NOT_ALLOWED", "detail": "Method not allowed"})
        return ResponseData(status_code=404, body={"error": "NOT_FOUND", "detail": f"Route {path} not found"})


class TestClient:
    """Synchronous test client matching FastAPI/Starlette TestClient interface."""

    def __init__(self, app: BayoraRouterApp):
        self.app = app

    def get(self, url: str, headers: Optional[Dict[str, str]] = None) -> ResponseData:
        return self.app.dispatch("GET", url, headers=headers)

    def post(
        self,
        url: str,
        json: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> ResponseData:
        return self.app.dispatch("POST", url, headers=headers, body=json)


MAX_BODY_BYTES = 1024 * 1024


def run_http_server(app: BayoraRouterApp, host: str = "127.0.0.1", port: int = 8000) -> None:
    class Handler(BaseHTTPRequestHandler):
        timeout = 15  # drop slow/stalled clients (slowloris)

        def _handle(self, method: str) -> None:
            try:
                content_len = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                content_len = -1
            if content_len < 0 or content_len > MAX_BODY_BYTES:
                msg = json.dumps({"error": "BAD_OR_OVERSIZED_BODY"}).encode()
                self.send_response(413)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(msg)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(msg)
                return
            body_bytes = self.rfile.read(content_len) if content_len > 0 else b""
            headers_dict = {k: v for k, v in self.headers.items()}
            resp = app.dispatch(method, self.path, headers=headers_dict, body=body_bytes)
            out_bytes = json.dumps(resp.json()).encode("utf-8")
            self.send_response(resp.status_code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out_bytes)))
            self._security_headers()
            self.end_headers()
            self.wfile.write(out_bytes)

        def _security_headers(self) -> None:
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            origin = os.environ.get("BAYORA_CORS_ORIGIN", "")  # unset = same-origin only (no CORS)
            if origin and origin != "*":
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
                self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

        def do_GET(self) -> None:
            self._handle("GET")

        def do_POST(self) -> None:
            self._handle("POST")

        def do_OPTIONS(self) -> None:
            self.send_response(204)
            self._security_headers()
            self.end_headers()

        def log_message(self, format: str, *args: Any) -> None:
            return

    server = ThreadingHTTPServer((host, port), Handler)
    server.serve_forever()
