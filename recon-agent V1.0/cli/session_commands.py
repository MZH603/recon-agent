"""Operator-only commands shared by CLI and TUI; cost additions never alter context."""
import math


def operator_command(text):
    parts=text.strip().split()
    if not parts: return None
    if parts[0].lower() in ('/new','new') and len(parts)==1:
        return ('new',None)
    if parts[0].lower()=='/budget':
        if len(parts) != 3 or parts[1].lower() != 'cost':
            raise ValueError('token 预算已取消；追加费用用 /budget cost USD，例如 /budget cost 1')
        try:
            cost=float(parts[2])
        except ValueError:
            raise ValueError('追加费用必须为有限正数（USD）') from None
        if not math.isfinite(cost) or cost <= 0:
            raise ValueError('追加费用必须为有限正数（USD）')
        return ('budget',(0,cost))
    return None


async def apply_command(runtime, command):
    kind,value=command
    if kind=='new': return await runtime.new_task()
    state=await runtime.add_budget(tokens=value[0],cost=value[1])
    if state.get('pending',{} ) and state['pending'].get('kind')=='budget':
        if runtime.guard.allows(0):
            return await runtime.resume('Continue')
    return state
