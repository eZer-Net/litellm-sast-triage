"""Change HTTP response envelope extraction here (not command syntax)."""

def extract_message(response):
    if not isinstance(response,dict):raise ValueError('Provider response is not an object')
    choices=response.get('choices') or []
    if not choices or not isinstance(choices[0],dict):raise ValueError('Missing choices')
    msg=choices[0].get('message')
    if not isinstance(msg,dict):raise ValueError('Missing assistant message')
    return msg
