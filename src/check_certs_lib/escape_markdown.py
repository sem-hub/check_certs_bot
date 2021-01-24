# Fix odd markdown characters in text by adding '\' before the first

MARKDOWN_CHARS = '[_*`'
def escape_markdown(msg: str) -> str:
    text = msg.split('\n')
    output = list()
    d = dict()
    for l in text:
        for c in l:
            for m in MARKDOWN_CHARS:
                if c == m:
                    d[c] = d.get(c, 0) + 1
        for k in d.keys():
            if d[k] % 2 != 0:
                l = l[:l.index(k)] + '\\' + l[l.index(k):]
        output.append(l)
        d.clear()
    return '\n'.join(output)
