"""Model-visible controls. Controls never authorize a scan or change its scope."""
from pydantic import BaseModel, ConfigDict, Field


class AskUser(BaseModel):
    model_config = ConfigDict(extra='forbid')
    question: str = Field(min_length=1)
    options: list[str] = Field(default_factory=list)


class UpdatePlan(BaseModel):
    model_config = ConfigDict(extra='forbid')
    plan: str = Field(min_length=1)


CONTROLS = {'ask_user': AskUser, 'update_plan': UpdatePlan}


def control_specs() -> list[dict]:
    descriptions = {
        'ask_user': 'Pause and ask the operator for missing information or a next-step choice.',
        'update_plan': 'Record a concise task plan without changing target, safety limits or grants.',
    }
    return [{'type': 'function', 'function': {'name': name, 'description': descriptions[name],
                                             'parameters': schema.model_json_schema()}}
            for name, schema in CONTROLS.items()]
