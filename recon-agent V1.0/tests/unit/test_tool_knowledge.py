import asyncio
from importlib.resources import files
from types import SimpleNamespace

import pytest
from pydantic import ValidationError


def test_catalog_and_load_are_bounded_package_resources(tmp_path):
    from tools.runtime.knowledge import LoadSkillTool, SkillCatalogTool
    settings = SimpleNamespace(TOOL_EVIDENCE_DIR=str(tmp_path / 'evidence'))
    catalog = SkillCatalogTool(settings)
    result = asyncio.run(catalog.run(catalog.params_model(target='example.com')))
    assert result.success and 'api_recon' in [item['name'] for item in result.data['skills']]
    tool = LoadSkillTool(settings)
    loaded = asyncio.run(tool.run(tool.params_model(target='example.com', skills=['api_recon', 'coverage'])))
    assert loaded.success and loaded.source_hash and loaded.evidence
    assert len(loaded.data['skills']) == 2
    assert files('tools').joinpath('data/skills/api_recon.md').is_file()
    rejected = asyncio.run(tool.run(tool.params_model(target='example.com', skills=['unknown'])))
    assert not rejected.success
    with pytest.raises(ValidationError):
        tool.params_model(target='example.com', skills=['../../config'])
    with pytest.raises(ValidationError):
        tool.params_model(target='example.com', skills=['api_recon'] * 6)
