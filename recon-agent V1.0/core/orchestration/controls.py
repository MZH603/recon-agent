"""Model-visible controls. Controls never authorize a scan or change its scope."""
from pydantic import BaseModel, ConfigDict, Field


class AskUser(BaseModel):
    model_config = ConfigDict(extra='forbid')
    question: str = Field(min_length=1)
    options: list[str] = Field(default_factory=list)


class UpdatePlan(BaseModel):
    model_config = ConfigDict(extra='forbid')
    plan: str = Field(min_length=1)


class FinishTask(BaseModel):
    model_config = ConfigDict(extra='forbid')
    answer: str = Field(min_length=1)
    evidence: list[str] = Field(default_factory=list)
    clarification_only: bool = False


CONTROLS = {'ask_user': AskUser, 'update_plan': UpdatePlan, 'finish_task': FinishTask}


def control_specs() -> list[dict]:
    descriptions = {
        'ask_user': 'Pause and ask the operator for missing information or a next-step choice.',
        'update_plan': 'Record a concise task plan without changing target, safety limits or grants.',
        'finish_task': 'Explicitly finish using evidence sources from successful tools. Use clarification_only only for a task that makes no findings.',
    }
    return [{'type': 'function', 'function': {'name': name, 'description': descriptions[name],
                                             'parameters': schema.model_json_schema()}}
            for name, schema in CONTROLS.items()]
