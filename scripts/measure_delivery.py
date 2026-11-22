"""Deliver a successful CI build into the dedicated VulnTrack measurement cluster."""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import time

if __package__:
    from .delivery_common import DeliveryError, digest, require, validate_identity
    from .image_receipt import sha256_file
else:
    from delivery_common import DeliveryError, digest, require, validate_identity
    from image_receipt import sha256_file


PROFILE = 'vkr-delivery-exp'
NAMESPACE = 'vulntrack'
REPOSITORY = 'sK8le/secure-delivery-pipeline'
REGISTRY_CONTAINER = 'vkr-measurement-registry'
IMAGE_REPOSITORY = 'localhost:5000/vulntrack'
ROOT = Path(__file__).resolve().parents[1]
VARIANTS = {
    'baseline': ('.github/workflows/baseline.yml', 'baseline-image'),
    'secured': ('.github/workflows/security.yml', 'vulntrack-image'),
}


def command(*args, input_text=None, timeout=180):
    result = subprocess.run(
        args, input=input_text, text=True, capture_output=True, timeout=timeout,
    )
    require(result.returncode == 0, f'{args[0]} {args[1]}: {result.stderr.strip()[-2000:]}')
    return result.stdout


def kubectl(*args, input_text=None, timeout=180):
    return command(
        'minikube', '-p', PROFILE, 'kubectl', '--', '--context', PROFILE,
        '-n', NAMESPACE, *args, input_text=input_text, timeout=timeout,
    )


def docker(*args, timeout=180):
    return command('minikube', '-p', PROFILE, 'ssh', '--', 'docker', *args, timeout=timeout)


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec='milliseconds')


def assert_cluster():
    nodes = json.loads(kubectl('get', 'nodes', '-o', 'json'))['items']
    require(len(nodes) == 1, 'Expected one node in the measurement cluster')
    node = nodes[0]
    require(node['metadata']['name'] == PROFILE, 'Unexpected measurement node name')
    runtime = node['status']['nodeInfo']['containerRuntimeVersion']
    require(runtime.startswith('docker://'), 'The measurement profile requires the Docker runtime')
    return node['status']['nodeInfo']


def registry_info():
    registry = json.loads(docker('container', 'inspect', REGISTRY_CONTAINER))[0]
    require(registry['State']['Running'], 'The isolated image registry is stopped')
    require(
        registry['HostConfig']['PortBindings'] == {'5000/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '5000'}]},
        'Unexpected bind address for the image registry',
    )
    command('minikube', '-p', PROFILE, 'ssh', '--', 'curl', '-fsS', '--retry', '5',
            '--retry-connrefused', '--max-time', '5', 'http://127.0.0.1:5000/v2/')
    return digest(registry['Image'])


def bootstrap():
    cluster = assert_cluster()
    names = docker('container', 'ls', '-a', '--filter', f'name=^/{REGISTRY_CONTAINER}$', '--format', '{{.Names}}')
    if names.strip() == REGISTRY_CONTAINER:
        docker('container', 'start', REGISTRY_CONTAINER)
    else:
        docker('run', '-d', '--name', REGISTRY_CONTAINER, '--restart=unless-stopped',
               '-p', '127.0.0.1:5000:5000', 'registry:2')
    registry_id = registry_info()

    kubectl('apply', '-f', str(ROOT / 'k8s' / '00-namespace.yaml'))
    for name, key, size in (
        ('vulntrack-secret', 'POSTGRES_PASSWORD', 16),
        ('vulntrack-app-secret', 'VULNTRACK_SECRET_KEY', 32),
    ):
        if not kubectl('get', 'secret', name, '--ignore-not-found', '-o', 'name').strip():
            secret = {'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'name': name},
                      'stringData': {key: secrets.token_hex(size)}}
            kubectl('create', '-f', '-', input_text=json.dumps(secret))
    kubectl('apply', '-f', str(ROOT / 'k8s' / '01-config.yaml'), '-f', str(ROOT / 'k8s' / '02-postgres.yaml'))
    kubectl('rollout', 'status', 'statefulset/db', '--timeout=240s', timeout=260)
    print(json.dumps({'profile': PROFILE, 'node': cluster, 'registry_image_id': registry_id}, indent=2))


def read_run(run_id):
    return json.loads(command('gh', 'api', '--hostname', 'github.com', f'repos/{REPOSITORY}/actions/runs/{run_id}'))


def validate_run(run, args, workflow):
    require(run['id'] == args.run_id and run['run_attempt'] == 1, 'Use a fresh workflow run on its first attempt')
    require(run['repository']['full_name'].lower() == REPOSITORY.lower(), 'Unexpected workflow repository')
    head_repository = run.get('head_repository') or {}
    require(head_repository.get('full_name', '').lower() == REPOSITORY.lower(), 'Use a branch in the project repository')
    require(run['head_sha'] == args.head, 'Workflow head commit does not match the chosen commit')
    require(run['path'].split('@', 1)[0] == workflow, 'Unexpected workflow file')
    require(run['event'] in {'pull_request', 'workflow_dispatch'}, 'Use an experiment PR or a manually started workflow')
    if run['event'] == 'workflow_dispatch':
        require(args.revision == args.head, 'The checkout of a manual run must match the head commit')


def wait_for_run(args, workflow, report):
    deadline = time.monotonic() + 3600
    report['observer_started_at'] = utc_now()
    run = read_run(args.run_id)
    validate_run(run, args, workflow)
    report.update(ci_created_at=run['created_at'], ci_started_at=run.get('run_started_at'),
                  workflow_url=run['html_url'], event=run['event'])
    require(args.pilot or run['status'] != 'completed', 'A timed run must be observed before CI completes. Use --pilot for past runs')
    while run['status'] != 'completed':
        require(time.monotonic() < deadline, 'Timeout waiting for the CI run')
        time.sleep(5)
        run = read_run(args.run_id)
        validate_run(run, args, workflow)
    report.update(ci_started_at=run.get('run_started_at'), ci_last_updated_at=run['updated_at'],
                  ci_observed_complete_at=utc_now(), ci_conclusion=run['conclusion'])
    require(run['conclusion'] == 'success', 'CI did not conclude successfully')


def verified_artifact(args, artifact, directory, report):
    command('gh', 'run', 'download', str(args.run_id), '--repo', 'github.com/' + REPOSITORY,
            '--name', artifact, '--dir', str(directory), timeout=600)
    report['artifact_downloaded_at'] = utc_now()
    receipt = json.loads((directory / 'image-build.json').read_text(encoding='utf-8'))
    require(type(receipt.get('schema')) is int and receipt['schema'] == 1, 'Unsupported image build receipt')
    identity = {name: receipt.get(name) for name in ('repository', 'revision', 'run_id', 'run_attempt')}
    validate_identity(**identity)
    require(identity == dict(repository=REPOSITORY, revision=args.revision, run_id=args.run_id, run_attempt=1),
            'Artifact receipt does not match the selected run and checkout')
    archive = directory / 'vulntrack-image.tar'
    require(sha256_file(archive) == digest(receipt.get('archive_sha256')), 'Image archive checksum mismatch')
    report['archive_sha256'] = receipt['archive_sha256']
    report['image_config_digest'] = digest(receipt.get('image_config_digest'))
    return archive


def publish_in_cluster(archive, run_id, expected_id):
    command('minikube', '-p', PROFILE, 'image', 'load', str(archive), '--overwrite', timeout=600)
    image = json.loads(docker('image', 'inspect', 'vulntrack:ci'))[0]
    require(image['Id'] == expected_id, 'Loaded image does not match the CI image ID')
    tag = f'{IMAGE_REPOSITORY}:run-{run_id}'
    docker('image', 'tag', expected_id, tag)
    docker('image', 'push', tag, timeout=600)
    published = json.loads(docker('image', 'inspect', tag))[0]
    require(published['Id'] == expected_id, 'The registry tag points to another image')
    prefix = IMAGE_REPOSITORY + '@'
    digests = [ref[len(prefix):] for ref in published.get('RepoDigests', []) if ref.startswith(prefix)]
    require(len(digests) == 1, 'Expected a unique manifest digest in the isolated registry')
    return prefix + digest(digests[0])


def rollout(directory, reference, run_id):
    shutil.copyfile(ROOT / 'k8s' / '03-web.yaml', directory / 'web.yaml')
    repository, manifest_digest = reference.rsplit('@', 1)
    patch = '\n'.join([
        'apiVersion: apps/v1', 'kind: Deployment', 'metadata:', '  name: vulntrack-web',
        'spec:', '  template:', '    metadata:', '      annotations:',
        f'        vkr.example/measurement-run: "{run_id}"',
        '    spec:', '      containers:', '        - name: web', '          imagePullPolicy: Always',
    ])
    configuration = {
        'apiVersion': 'kustomize.config.k8s.io/v1beta1', 'kind': 'Kustomization',
        'resources': ['web.yaml'],
        'images': [{'name': 'vulntrack', 'newName': repository, 'digest': manifest_digest}],
        'patches': [{'path': 'rollout.yaml', 'target': {'kind': 'Deployment', 'name': 'vulntrack-web'}}],
    }
    (directory / 'kustomization.yaml').write_text(json.dumps(configuration), encoding='utf-8')
    (directory / 'rollout.yaml').write_text(patch, encoding='utf-8')
    raw = kubectl('get', 'deployment', 'vulntrack-web', '--ignore-not-found', '-o', 'json')
    if raw.strip():
        previous = json.loads(raw)['spec']['template']['metadata'].get('annotations', {})
        require(previous.get('vkr.example/measurement-run') != str(run_id),
                'This run already changed the pod template. Use a fresh CI run')
    kubectl('apply', '-k', str(directory))
    kubectl('rollout', 'status', 'deployment/vulntrack-web', '--timeout=240s', timeout=260)


def verify_pods(reference, config_digest, run_id):
    data = json.loads(kubectl('get', 'pods', '-l', 'app=vulntrack-web', '-o', 'json'))
    pods = [pod for pod in data['items'] if not pod['metadata'].get('deletionTimestamp')]
    require(len(pods) == 2, 'Expected two non-terminating web pods after rollout')
    manifest_digest = reference.rsplit('@', 1)[1]
    evidence = []
    for pod in pods:
        metadata, spec, status = pod['metadata'], pod['spec'], pod['status']
        require(metadata.get('annotations', {}).get('vkr.example/measurement-run') == str(run_id),
                'Pod does not belong to the measured rollout')
        web = next(container for container in spec['containers'] if container['name'] == 'web')
        observed = next(container for container in status['containerStatuses'] if container['name'] == 'web')
        require(web['image'] == reference and observed['ready'], 'Pod is unready or points to another image')
        image_id = observed['imageID']
        runtime_digest = image_id.rsplit('@', 1)[-1].rsplit('://', 1)[-1]
        require(runtime_digest in {manifest_digest, config_digest}, 'Runtime image ID does not match the measured image')
        name = metadata['name']
        probe = (
            'import json; from urllib.request import urlopen; '
            'base = "http://127.0.0.1:8000"; '
            'ready = json.load(urlopen(base + "/readyz", timeout=5)); '
            'login = urlopen(base + "/login", timeout=5).read(); '
            'print(json.dumps({"database_ready": ready == {"status": "ok"}, '
            '"login_form": b\'type="password"\' in login}))'
        )
        checks = json.loads(kubectl('exec', name, '-c', 'web', '--', 'python', '-c', probe, timeout=25))
        require(checks == {'database_ready': True, 'login_form': True}, 'Database readiness or login form check failed')
        evidence.append({'pod': name, 'image_id': image_id, **checks})
    return evidence


def measure(args, report):
    validate_identity(REPOSITORY, args.head, args.run_id, 1)
    validate_identity(REPOSITORY, args.revision, args.run_id, 1)
    report['node'] = assert_cluster()
    report['registry_image_id'] = registry_info()
    workflow, artifact = VARIANTS[args.variant]
    wait_for_run(args, workflow, report)
    with tempfile.TemporaryDirectory(prefix='vkr-delivery-') as work:
        directory = Path(work)
        archive = verified_artifact(args, artifact, directory, report)
        report['image'] = publish_in_cluster(archive, args.run_id, report['image_config_digest'])
        report['published_at'] = utc_now()
        report['rollout_started_at'] = utc_now()
        rollout(directory, report['image'], args.run_id)
        report['pods'] = verify_pods(report['image'], report['image_config_digest'], args.run_id)
        report['ready_at'] = utc_now()
    start = datetime.fromisoformat(report['ci_created_at'].replace('Z', '+00:00'))
    duration = (datetime.fromisoformat(report['ready_at']) - start).total_seconds()
    require(duration >= 0, 'VM clock or CI timestamp is incorrect')
    if not args.pilot:
        report['delivery_seconds'] = round(duration, 3)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    tasks = parser.add_subparsers(dest='task', required=True)
    tasks.add_parser('bootstrap', help='Prepare PostgreSQL and a loopback-only registry')
    run = tasks.add_parser('run', help='Observe one run and deliver its verified build')
    run.add_argument('--variant', choices=VARIANTS, required=True)
    run.add_argument('--run-id', type=int, required=True)
    run.add_argument('--head', required=True, help='Full commit SHA expected from the workflow API')
    run.add_argument('--revision', required=True, help='Full checkout SHA expected in the build receipt')
    run.add_argument('--pilot', action='store_true', help='Allow a past run and omit delivery duration')
    run.add_argument('--output', type=Path, required=True, help='New JSON report to write')
    args = parser.parse_args()

    import fcntl  # The measurement cluster runs on the Linux VM.

    lock_path = Path.home() / '.minikube' / 'profiles' / PROFILE / 'measurement.lock'
    try:
        with lock_path.open('a') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise DeliveryError('Another delivery is using the measurement profile') from None
            if args.task == 'bootstrap':
                bootstrap()
                return
            report = dict(schema=1, variant=args.variant, run_id=args.run_id, head=args.head,
                          revision=args.revision, pilot=args.pilot, profile=PROFILE)
            with args.output.open('x', encoding='utf-8') as output:
                try:
                    measure(args, report)
                    report['result'] = 'success'
                except (OSError, ValueError, KeyError, StopIteration, subprocess.SubprocessError, KeyboardInterrupt) as error:
                    report.update(result='failed', reason=str(error) or type(error).__name__)
                    raise
                finally:
                    json.dump(report, output, indent=2)
                    output.write('\n')
            print(args.output)
    except (OSError, ValueError, KeyError, StopIteration, subprocess.SubprocessError, KeyboardInterrupt) as error:
        parser.exit(1, f'{str(error) or type(error).__name__}\n')


if __name__ == '__main__':
    main()
