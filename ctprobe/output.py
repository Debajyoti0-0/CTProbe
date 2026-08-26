"""Output and export functionality."""

import json
import re
import tempfile
from typing import List, Optional, Sequence, Union
from pathlib import Path

from .models import LiveTestResult


def safe_filename(name: Optional[str]) -> str:
    """
    Make a filename safe by removing special characters.
    
    Keeps alphanumerics, dots, underscores, hyphens.
    """
    return re.sub(r"[^\w.-]", "_", name or "", flags=re.UNICODE)


def save_txt(domains: List[str], filepath: str) -> None:
    """
    Save subdomains to TXT file (one per line).
    """
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)
    
    # Write to temp file then atomically replace
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=str(path.parent),
        delete=False,
    ) as tmp:
        for domain in domains:
            tmp.write(domain + "\n")
        tmp_path = tmp.name
    
    try:
        Path(tmp_path).replace(path)
    except Exception:
        Path(tmp_path).unlink(missing_ok=True)
        raise


def save_json(data: Union[dict, list], filepath: str) -> None:
    """
    Save data to JSON file.
    """
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)
    
    # Write to temp file then atomically replace
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=str(path.parent),
        delete=False,
    ) as tmp:
        json.dump(data, tmp, indent=2, ensure_ascii=False)
        tmp_path = tmp.name
    
    try:
        Path(tmp_path).replace(path)
    except Exception:
        Path(tmp_path).unlink(missing_ok=True)
        raise


def save_xlsx(data: Sequence[Union[dict, str]], filepath: str) -> bool:
    """
    Save data to XLSX file.
    
    Returns True on success, False if openpyxl not available.
    """
    try:
        from openpyxl import Workbook
    except ImportError:
        print("[-] XLSX output requires openpyxl.")
        print("[+] Install with: pip install openpyxl")
        return False
    
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)
    
    workbook = Workbook()
    sheet = workbook.active
    if sheet is None:
        raise RuntimeError("Unable to create an XLSX worksheet")
    sheet.title = "Results"
    
    if not data:
        workbook.save(path)
        return True
    
    # Determine if data contains strings or dicts
    if isinstance(data[0], str):
        # List of subdomain strings
        sheet.append(["Subdomain"])
        for item in data:
            sheet.append([item])
    else:
        # List of dicts (results)
        all_keys = []
        dict_items = [item for item in data if isinstance(item, dict)]
        for item in dict_items:
            for key in item.keys():
                if key not in all_keys:
                    all_keys.append(key)
        
        sheet.append(all_keys)
        
        for item in dict_items:
            row = [item.get(key) for key in all_keys]
            sheet.append(row)
    
    workbook.save(path)
    return True


def get_output_extension(output_format: str) -> str:
    """Get file extension for output format."""
    mapping = {
        "txt": ".txt",
        "json": ".json",
        "xls": ".xlsx",
        "xlsx": ".xlsx",
    }
    return mapping.get(output_format, ".txt")


def make_output_path(
    output_dir: str,
    filename: Optional[str] = None,
    domain: Optional[str] = None,
    suffix: str = "ALL",
    output_format: str = "txt",
) -> str:
    """
    Create output file path.

    Examples:
        example.com.ALL-output.txt
        example.com.LIVE-output.txt
        custom.ALL-output.txt

    ``domain`` is the target domain; the files hold the discovered
    subdomains associated with it.
    """
    # Pure path builder: the directory is created by the save_* writers at
    # write time (each mkdir(parents=True) their parent), so computing a path
    # never touches the filesystem.
    output_path = Path(output_dir)

    extension = get_output_extension(output_format)

    if filename:
        base = safe_filename(filename)
        # Remove existing extension if any
        base = Path(base).stem
    else:
        base = safe_filename(domain)
    
    return str(output_path / f"{base}.{suffix}-output{extension}")


def make_simple_output_path(
    output_dir: str,
    filename: Optional[str] = None,
    domain: Optional[str] = None,
    output_format: str = "txt",
) -> str:
    """
    Create simple output file path (for non-live-test mode).

    Examples:
        example.com.output.txt
        custom.txt
    """
    # Pure path builder (see make_output_path): no filesystem side effects; the
    # save_* writers create the directory when the file is actually written.
    output_path = Path(output_dir)

    extension = get_output_extension(output_format)
    
    if filename:
        safe_name = safe_filename(filename)
        safe_path = Path(safe_name)
        base = safe_path.stem
        existing_ext = safe_path.suffix
        
        if existing_ext:
            # Keep existing extension if provided
            return str(output_path / safe_name)
        else:
            return str(output_path / (base + extension))
    else:
        return str(output_path / f"{safe_filename(domain)}.output{extension}")


def results_to_dicts(results: List[LiveTestResult]) -> List[dict]:
    """Convert LiveTestResult objects to dictionaries."""
    return [r.to_dict() for r in results]


def _result_dict(result: Union[LiveTestResult, dict]) -> dict:
    """Return a serializable result dictionary without changing its meaning."""
    return result.to_dict() if isinstance(result, LiveTestResult) else dict(result)


def _result_text(result: Union[LiveTestResult, dict]) -> str:
    """Format one result for human-readable TXT output."""
    data = _result_dict(result)
    domain = data.get("domain", "")
    status = data.get("status_code")
    protocol = data.get("http_version") or ""
    if data.get("live"):
        label = "LIVE"
    elif data.get("status_filtered"):
        label = "FILTERED"
    elif data.get("http_response_received"):
        label = "NOT_MATCHED"
    else:
        label = data.get("error_type") or "FAILED"
    status_text = str(status) if status is not None else label
    suffix = f" {protocol}" if protocol else ""
    return f"{domain} [{status_text}] {label}{suffix}"


def save_live_test_output(
    all_domains: List[str],
    results: Sequence[Union[LiveTestResult, dict]],
    output_dir: str = "Outputs",
    domain: str = "unknown",
    filename: Optional[str] = None,
    output_format: str = "txt",
) -> tuple:
    """
    Save output for live testing (ALL and LIVE files).
    
    Returns: (all_path, live_path)
    """
    all_path = make_output_path(
        output_dir=output_dir,
        filename=filename,
        domain=domain,
        suffix="ALL",
        output_format=output_format,
    )
    
    live_path = make_output_path(
        output_dir=output_dir,
        filename=filename,
        domain=domain,
        suffix="LIVE",
        output_format=output_format,
    )
    
    result_dicts = [_result_dict(result) for result in results]
    if not result_dicts:
        result_dicts = [{"domain": domain} for domain in all_domains]
    live_results = [result for result in result_dicts if result.get("live")]
    
    if output_format == "txt":
        all_lines = [_result_text(result) for result in results]
        live_lines = [_result_text(result) for result in results if _result_dict(result).get("live")]
        save_txt(sorted(all_lines), all_path)
        save_txt(sorted(live_lines), live_path)
    
    elif output_format == "json":
        save_json(result_dicts, all_path)
        save_json(live_results, live_path)
    
    elif output_format in ("xls", "xlsx"):
        save_xlsx(result_dicts, all_path)
        save_xlsx(live_results, live_path)
    
    return all_path, live_path


def save_discovery_output(
    domains: List[str],
    output_dir: str = "Outputs",
    domain: str = "unknown",
    filename: Optional[str] = None,
    output_format: str = "txt",
    threat_results: Optional[List[dict]] = None,
) -> str:
    """
    Save output for discovery-only mode (no live testing).
    
    Returns: output_path
    """
    output_path = make_simple_output_path(
        output_dir=output_dir,
        filename=filename,
        domain=domain,
        output_format=output_format,
    )
    
    if output_format == "txt":
        save_txt(domains, output_path)
    
    elif output_format == "json":
        if threat_results:
            save_json(threat_results, output_path)
        else:
            data = [{"domain": d} for d in domains]
            save_json(data, output_path)
    
    elif output_format in ("xls", "xlsx"):
        if threat_results:
            save_xlsx(threat_results, output_path)
        else:
            save_xlsx(domains, output_path)
    
    return output_path
