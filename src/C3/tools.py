import inspect
import typing
from typing import Any, Callable

from src.zeek.queries import (
    query_conn,
    query_dce_rpc,
    query_dns,
    query_kerberos,
    query_smb_files,
    query_smb_mapping,
)

TOOL_FUNCTIONS: dict[str, Callable[..., dict]] = {
    "query_conn": query_conn,
    "query_dns": query_dns,
    "query_dce_rpc": query_dce_rpc,
    "query_smb_files": query_smb_files,
    "query_smb_mapping": query_smb_mapping,
    "query_kerberos": query_kerberos,
}

# Types we actually check. Anything else (e.g. Path/Union[str,Path] on
# log_path, which is excluded anyway) is left unchecked rather than
# guessing at a validation rule for it.
_CHECKABLE_TYPES = (str, int, float, bool)


class ToolDispatchError(Exception):
    """Raised when a tool call from the LLM cannot be safely dispatched."""


def _allowed_params(fn: Callable) -> set[str]:
    sig = inspect.signature(fn)
    return {p for p in sig.parameters if p != "log_path"}


def _unwrap_optional(annotation):
    """Optional[X] is Union[X, None] -- return X; pass through anything else."""
    origin = typing.get_origin(annotation)
    if origin is typing.Union:
        non_none = [a for a in typing.get_args(annotation) if a is not type(None)]
        if len(non_none) == 1:
            return non_none[0]
    return annotation


def _validate_arg_types(fn: Callable, args: dict) -> None:
    """
    Check each supplied argument's runtime type against the function's
    real type hint, for the small set of scalar types every filter
    parameter actually uses. None is always accepted (every parameter
    is Optional). No coercion is performed -- a value either matches or
    it's rejected with a clear, specific message; this keeps behavior
    deterministic for a reproducible research baseline.
    """
    hints = typing.get_type_hints(fn)
    for name, value in args.items():
        if value is None:
            continue
        expected = _unwrap_optional(hints.get(name))
        if expected not in _CHECKABLE_TYPES:
            continue  # no scalar type hint to check against -- skip

        if expected is bool:
            ok = isinstance(value, bool)
        elif expected is int:
            ok = isinstance(value, int) and not isinstance(value, bool)
        elif expected is float:
            ok = isinstance(value, (int, float)) and not isinstance(value, bool)
        else:  # str
            ok = isinstance(value, str)

        if not ok:
            raise ToolDispatchError(
                f"Argument '{name}' has wrong type: expected {expected.__name__}, "
                f"got {type(value).__name__} ({value!r})"
            )


def dispatch_tool_call(
    tool_name: Any,
    args: Any,
    log_paths: dict[str, str],
) -> dict:
    """
    Safely call one of the six Zeek query functions on behalf of the LLM.

    Args:
        tool_name: the tool the LLM requested. Expected to be a string
            key of TOOL_FUNCTIONS; anything else is a controlled error.
        args: the arguments object the LLM requested. Expected to be a
            JSON object (dict); anything else is a controlled error.
        log_paths: mapping of tool_name -> real log file path for the
            current case, resolved by the investigation harness (never
            the model).

    Returns:
        The query_* function's normal return dict, unmodified.

    Raises:
        ToolDispatchError: for every validation failure described in
            the module docstring. This is the ONLY exception type this
            function raises -- callers only need to catch one type to
            treat any bad tool call as recoverable, not fatal.
    """
    if not isinstance(tool_name, str):
        raise ToolDispatchError(
            f"'tool' must be a string naming one of {sorted(TOOL_FUNCTIONS)}, "
            f"got {type(tool_name).__name__}"
        )

    if tool_name not in TOOL_FUNCTIONS:
        raise ToolDispatchError(
            f"Unknown tool '{tool_name}'. Available tools: {sorted(TOOL_FUNCTIONS)}"
        )

    if not isinstance(args, dict):
        raise ToolDispatchError(
            f"'args' must be a JSON object, got {type(args).__name__}"
        )

    if "log_path" in args:
        raise ToolDispatchError(
            "'log_path' may not be supplied by the model; it is resolved "
            "server-side per case."
        )

    fn = TOOL_FUNCTIONS[tool_name]

    if tool_name not in log_paths:
        raise ToolDispatchError(
            f"No log path configured for tool '{tool_name}' in this case. "
            f"Tools available for this case: {sorted(log_paths)}"
        )

    allowed = _allowed_params(fn)
    unknown = set(args) - allowed
    if unknown:
        raise ToolDispatchError(
            f"Unknown argument(s) {sorted(unknown)} for tool '{tool_name}'. "
            f"Allowed: {sorted(allowed)}"
        )

    _validate_arg_types(fn, args)

    try:
        return fn(log_path=log_paths[tool_name], **args)
    except (ValueError, FileNotFoundError) as exc:
        raise ToolDispatchError(f"{tool_name} rejected arguments: {exc}") from exc


def tool_schemas_for_prompt() -> list[dict]:
    """
    Build a JSON-serializable description of all six tools and their
    parameters, derived directly from the real function signatures (not
    hand-duplicated), for inclusion in the system prompt so the model
    knows exactly what it can call and with what arguments.
    """
    schemas = []
    for name, fn in TOOL_FUNCTIONS.items():
        sig = inspect.signature(fn)
        params = {}
        for pname, p in sig.parameters.items():
            if pname == "log_path":
                continue
            default = None if p.default is inspect.Parameter.empty else p.default
            params[pname] = {"default": default}
        first_doc_line = (fn.__doc__ or "").strip().split("\n")[0]
        schemas.append(
            {
                "tool": name,
                "description": first_doc_line,
                "parameters": params,
            }
        )
    return schemas