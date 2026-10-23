"""Validate monetary usage without assuming that missing prices are zero."""
import math


def valid_cost(value):
    if isinstance(value, bool):
        return None
    try:
        cost = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return cost if math.isfinite(cost) and cost >= 0 else None


def response_cost(response, sdk):
    hidden = getattr(response, '_hidden_params', None) or {}
    cost = valid_cost(hidden.get('response_cost'))
    if cost is None:
        pricing = getattr(sdk, 'completion_cost', None)
        if callable(pricing):
            try:
                cost = valid_cost(pricing(completion_response=response))
            except Exception:
                pass  # A successful paid completion must never be retried for pricing.
    return cost
