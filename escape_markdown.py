def escape_markdown(msg: str):
    m = str(msg)
    m = m.replace('[', '\\[')
    m = m.replace('_', '\\_')
    m = m.replace('*', '\\*')
    m = m.replace('`', '\\`')
    return m

