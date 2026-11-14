"""Require an explicit positive numeric UID in the built image configuration."""
import argparse
import json
from pathlib import Path
import re
import subprocess


def assess_image(image):
    config = image.get('Config')
    if not isinstance(config, dict):
        raise ValueError('Docker inspect response has no image Config object')
    user = config.get('User')
    report = {'schema': 1, 'policy': 'explicit-nonroot-numeric-uid',
              'image_id': image.get('Id'), 'configured_user': user}
    if user is None or user == '':
        return {**report, 'decision': 'blocked', 'reason': 'Image has no explicit USER'}
    if not isinstance(user, str):
        raise ValueError('Docker Config.User must be a string or null')
    if not re.fullmatch(r'[0-9]+(?::[0-9]+)?', user):
        return {**report, 'decision': 'blocked', 'reason': 'Policy requires a numeric UID, optionally followed by numeric GID'}
    parts = user.split(':')
    uid = int(parts[0])
    if not 1 <= uid <= 4294967294:
        return {**report, 'decision': 'blocked', 'reason': 'UID must be positive and within the supported range'}
    if len(parts) == 2 and not 0 <= int(parts[1]) <= 4294967294:
        return {**report, 'decision': 'blocked', 'reason': 'GID is outside the supported range'}
    return {**report, 'decision': 'passed', 'uid': uid, 'reason': 'Explicit non-root numeric UID'}


def check_image(reference):
    if not reference or reference.startswith('-'):
        raise ValueError('Invalid image reference')
    completed = subprocess.run(['docker', 'image', 'inspect', reference],
                               check=True, capture_output=True, text=True, timeout=60)
    data = json.loads(completed.stdout)
    if not isinstance(data, list) or len(data) != 1 or not isinstance(data[0], dict):
        raise ValueError('Expected exactly one inspected image')
    return assess_image(data[0])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', default='vulntrack:ci')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = check_image(args.image)
        code = 0 if report['decision'] == 'passed' else 1
    except (OSError, ValueError, subprocess.SubprocessError):
        # Do not expose Config.Env or other image contents from inspect output.
        report = {'schema': 1, 'policy': 'explicit-nonroot-numeric-uid',
                  'decision': 'error', 'reason': 'Image inspection failed or returned malformed data'}
        code = 2
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, indent=2))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
