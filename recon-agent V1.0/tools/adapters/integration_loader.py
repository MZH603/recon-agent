"""Load only tool extension settings; connector files cannot relax scan guards."""
from pathlib import Path
import yaml
from utils.config import Settings

EXTENSION_KEYS = {'custom_tools', 'mcp_servers', 'extension_tools', 'TOOL_EVIDENCE_DIR',
                  'API_RECON_MAX_REQUESTS', 'API_RECON_MAX_ASSET_BYTES', 'API_RECON_TIMEOUT_SECONDS'}


def load_tools_config(settings: Settings, path: Path, *, max_bytes: int | None = None) -> Settings:
    if max_bytes is None:
        source = path.read_text(encoding='utf-8')
    else:
        with path.open('rb') as stream:
            raw = stream.read(max_bytes + 1)
        if len(raw) > max_bytes:
            raise ValueError('Tool configuration exceeds byte limit')
        source = raw.decode('utf-8')
    try:
        data = yaml.safe_load(source) or {}
    except yaml.YAMLError:
        # Do not expose parser excerpts that may contain operator secrets.
        raise ValueError('Invalid tool configuration YAML') from None
    if not isinstance(data, dict):
        raise ValueError('Tool configuration must be a YAML mapping')
    unknown = set(data) - EXTENSION_KEYS
    if unknown:
        raise ValueError('Unsupported tool configuration keys: ' + ', '.join(sorted(map(str, unknown))))
    merged = {**settings.model_dump(), **data}
    if isinstance(data.get('extension_tools'), dict):
        merged['extension_tools'] = {**settings.extension_tools.model_dump(), **data['extension_tools']}
    # Preserve in-memory credentials excluded by model serialization.
    merged['model'] = settings.model.model_copy(deep=True)
    return Settings.model_validate(merged)
