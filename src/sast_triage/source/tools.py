"""Read-only tool dispatch and policy, separated from the LLM transport."""

def execute(explorer, action, arguments):
    if action not in ('read','find'):
        raise ValueError('Only read and find are permitted')
    if not isinstance(arguments,dict):
        raise ValueError('Tool arguments must be an object')
    return explorer.tool(action,arguments)
