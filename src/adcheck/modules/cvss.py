"""Minimal, self-contained CVSS v3.1 Base score calculator.

Implements the official scoring formula from the CVSS v3.1 specification
(https://www.first.org/cvss/v3.1/specification-document) so that every score
shown in the reports is derived from — and justified by — its vector string,
rather than being a hardcoded number.
"""
import math

# Metric value weights (CVSS v3.1 Base, section 7.4).
_WEIGHTS = {
    'AV': {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2},
    'AC': {'L': 0.77, 'H': 0.44},
    # Privileges Required is Scope-dependent; the 'C' (Changed) values are used
    # only when Scope == Changed.
    'PR': {
        'U': {'N': 0.85, 'L': 0.62, 'H': 0.27},
        'C': {'N': 0.85, 'L': 0.68, 'H': 0.5},
    },
    'UI': {'N': 0.85, 'R': 0.62},
    'C': {'H': 0.56, 'L': 0.22, 'N': 0.0},
    'I': {'H': 0.56, 'L': 0.22, 'N': 0.0},
    'A': {'H': 0.56, 'L': 0.22, 'N': 0.0},
}

_SEVERITY_BANDS = (
    (9.0, 'Critical'),
    (7.0, 'High'),
    (4.0, 'Medium'),
    (0.1, 'Low'),
    (0.0, 'None'),
)


def _roundup(value):
    """CVSS v3.1 'Roundup' function: round up to one decimal place."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def parse_vector(vector):
    """Parse a CVSS:3.x base vector string into a dict of metric -> value."""
    metrics = {}
    parts = vector.strip().split('/')
    for part in parts:
        if ':' not in part:
            continue
        key, _, val = part.partition(':')
        key = key.strip().upper()
        if key in ('CVSS',):
            continue
        metrics[key] = val.strip().upper()
    return metrics


def base_score(vector):
    """Compute the CVSS v3.1 Base score (0.0 - 10.0) from a vector string."""
    m = parse_vector(vector)
    try:
        scope_changed = m['S'] == 'C'
        scope_key = 'C' if scope_changed else 'U'

        iss = 1 - (
            (1 - _WEIGHTS['C'][m['C']])
            * (1 - _WEIGHTS['I'][m['I']])
            * (1 - _WEIGHTS['A'][m['A']])
        )

        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss * 0.9731 - 0.02) ** 13
        else:
            impact = 6.42 * iss

        exploitability = (
            8.22
            * _WEIGHTS['AV'][m['AV']]
            * _WEIGHTS['AC'][m['AC']]
            * _WEIGHTS['PR'][scope_key][m['PR']]
            * _WEIGHTS['UI'][m['UI']]
        )
    except KeyError:
        return 0.0

    if impact <= 0:
        return 0.0

    if scope_changed:
        score = min(1.08 * (impact + exploitability), 10)
    else:
        score = min(impact + exploitability, 10)

    return _roundup(score)


def severity(score):
    """Return the qualitative severity rating for a numeric base score."""
    for threshold, label in _SEVERITY_BANDS:
        if score >= threshold:
            return label
    return 'None'
