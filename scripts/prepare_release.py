"""Create an obfuscated release copy; preserve reviewed source and wire/JSON names."""
from pathlib import Path
import re
import secrets

ROOT = Path(__file__).resolve().parents[1]

def tokens(source):
    # Keep comments and complete string literals unchanged. Only app type names
    # are renamed, so property/Codable keys, selectors and framework APIs survive.
    pattern = re.compile(r'//[^\n]*|/\*[\s\S]*?\*/|"""[\s\S]*?"""|"(?:\\.|[^"\\])*"|\b[A-Za-z_][A-Za-z_0-9]*\b')
    return pattern

def rewrite(source, mapping):
    return tokens(source).sub(lambda m: mapping.get(m.group(), m.group()), source)

def prepare():
    sources = list((ROOT / 'iphone/Sources').glob('*.swift'))
    names = set()
    for file in sources:
        lexical = tokens(file.read_text(encoding='utf-8')).sub(lambda m: ' ' if m.group().startswith(('"', '//', '/*')) else m.group(), file.read_text(encoding='utf-8'))
        names.update(re.findall(r'\b(?:struct|enum|class)\s+([A-Za-z_]\w*)', lexical))
    names.discard('func')
    mapping = {name: 'Q' + secrets.token_hex(12) for name in sorted(names)}
    relative = Path('Generated') / ('Release-' + secrets.token_hex(6))
    output = ROOT / 'iphone' / relative
    output.mkdir(parents=True)
    for file in sources:
        (output / file.name).write_text(rewrite(file.read_text(encoding='utf-8'), mapping), encoding='utf-8')
    project = (ROOT / 'iphone/project.yml').read_text(encoding='utf-8')
    needle = 'sources: [Sources, Resources]'
    if project.count(needle) != 1:
        raise RuntimeError('Unexpected project source layout')
    project = project.replace(needle, f'sources: [{relative.as_posix()}, Resources]')
    (ROOT / 'iphone/project-release.yml').write_text(project, encoding='utf-8')
    print(f'Prepared release sources with {len(mapping)} randomized app type names. JSON fields and cryptographic APIs unchanged.')

if __name__ == '__main__':
    prepare()
