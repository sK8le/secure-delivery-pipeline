"""Record a built image and publish exactly that image after the security gates."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

if __package__:
    from .delivery_common import digest, require, validate_identity
else:
    from delivery_common import digest, require, validate_identity


def command(args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=600).stdout


def sha256_file(path):
    result = hashlib.sha256()
    with Path(path).open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            result.update(block)
    return 'sha256:' + result.hexdigest()


def inspect_image(reference):
    return json.loads(command(['docker', 'image', 'inspect', reference]))[0]


def identity_from_environment():
    data = {'repository': os.environ['GITHUB_REPOSITORY'], 'revision': os.environ['GITHUB_SHA'],
            'run_id': int(os.environ['GITHUB_RUN_ID']), 'run_attempt': int(os.environ['GITHUB_RUN_ATTEMPT'])}
    validate_identity(**data)
    return data


def record_build(archive, identity):
    image = inspect_image('vulntrack:ci')
    labels = image['Config']['Labels']
    require(labels.get('org.opencontainers.image.source') == 'https://github.com/' + identity['repository'], 'Image source label mismatch')
    require(labels.get('org.opencontainers.image.revision') == identity['revision'], 'Image revision label mismatch')
    return {'schema': 1, **identity, 'image_config_digest': digest(image['Id']), 'archive_sha256': sha256_file(archive)}


def publish(archive, receipt, identity):
    require(receipt.get('schema') == 1, 'Unsupported build receipt')
    for name in ['repository', 'revision', 'run_id']:
        expected = identity[name]
        require(receipt.get(name) == expected, 'Build receipt identity mismatch: ' + name)
    build_attempt = receipt.get('run_attempt')
    require(type(build_attempt) is int and 1 <= build_attempt <= identity['run_attempt'], 'Invalid original build attempt')
    require(sha256_file(archive) == digest(receipt.get('archive_sha256')), 'Image archive changed after the build')
    expected_id = digest(receipt.get('image_config_digest'))
    command(['docker', 'load', '--input', str(archive)])
    require(inspect_image('vulntrack:ci')['Id'] == expected_id, 'Loaded image differs from the tested build')
    repository = 'ghcr.io/' + identity['repository'].lower()
    tag = repository + f":verified-{identity['run_id']}-{identity['run_attempt']}"
    command(['docker', 'tag', 'vulntrack:ci', tag])
    command(['docker', 'push', tag])
    published = inspect_image(tag)
    references = [ref for ref in published.get('RepoDigests', []) if ref.startswith(repository + '@')]
    require(len(references) == 1, 'Registry did not return a unique published digest')
    reference = repository + '@' + digest(references[0].split('@', 1)[1])
    # The VM uses anonymous pulls. Never mistake the publisher's cached login for
    # public access; a private package must be made public before delivery.
    with tempfile.TemporaryDirectory(prefix='delivery-public-pull-') as configuration:
        command(['docker', '--config', configuration, 'pull', reference])
    require(inspect_image(reference)['Id'] == expected_id, 'Published image differs from the tested build')
    return {**receipt, 'run_attempt': identity['run_attempt'], 'build_run_attempt': build_attempt, 'image': reference}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=['build', 'publish'])
    parser.add_argument('--archive', type=Path, default=Path('vulntrack-image.tar'))
    parser.add_argument('--receipt', type=Path, default=Path('image-build.json'))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    identity = identity_from_environment()
    if args.phase == 'build':
        result = record_build(args.archive, identity)
    else:
        require(os.environ.get('GITHUB_EVENT_NAME') == 'push' and os.environ.get('GITHUB_REF') == 'refs/heads/main', 'Only a push to main may publish a delivery')
        result = publish(args.archive, json.loads(args.receipt.read_text(encoding='utf-8')), identity)
    args.output.write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
