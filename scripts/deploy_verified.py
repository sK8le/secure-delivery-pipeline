"""Pull-based deployment: no GitHub runner, repository checkout or GitHub token on the VM."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

if __package__:
    from .delivery_common import DeliveryError, digest, release_tag, require, validate_identity, validate_manifest
else:
    from delivery_common import DeliveryError, digest, release_tag, require, validate_identity, validate_manifest

MAX_JSON_BYTES = 1024 * 1024
DOWNLOAD_HOSTS = {'api.github.com', 'github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com'}


def validate_download_url(url):
    parsed = urlsplit(url)
    require(parsed.scheme == 'https' and parsed.hostname in DOWNLOAD_HOSTS
            and parsed.port in (None, 443) and not parsed.username and not parsed.password,
            'Only HTTPS downloads from the expected GitHub hosts are allowed')


class GitHubRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_download_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(url):
    validate_download_url(url)
    message = Request(url, headers={'Accept': 'application/vnd.github+json', 'User-Agent': 'vulntrack-delivery'})
    with build_opener(GitHubRedirects()).open(message, timeout=30) as response:
        body = response.read(MAX_JSON_BYTES + 1)
    require(len(body) <= MAX_JSON_BYTES, 'Delivery response too large')
    return body


def api(repository, path):
    return json.loads(download(f'https://api.github.com/repos/{repository}/{path}'))


def validate_run(run, repository, revision):
    validate_identity(repository, revision, run['id'], run['run_attempt'])
    require(run.get('repository', {}).get('full_name', '').lower() == repository.lower(), 'Workflow repository mismatch')
    require(run.get('head_repository', {}).get('full_name', '').lower() == repository.lower(), 'Fork workflow cannot deploy')
    require(run.get('event') == 'push' and run.get('head_branch') == 'main', 'Only a push to main may deploy')
    require(run.get('path') == '.github/workflows/security.yml', 'Unexpected workflow')
    require(run.get('status') == 'completed' and run.get('conclusion') == 'success', 'Workflow has not passed')
    require(run.get('head_sha') == revision, 'Successful workflow is not the current main')


def candidate(repository, previous):
    validate_identity(repository, '0' * 40, 1, 1)
    head = api(repository, 'git/ref/heads/main')['object']['sha']
    runs = api(repository, 'actions/workflows/security.yml/runs?branch=main&event=push&status=success&per_page=1')['workflow_runs']
    if not runs or runs[0]['head_sha'] != head:
        return None
    run = runs[0]
    validate_run(run, repository, head)
    if (previous.get('revision'), previous.get('run_id'), previous.get('run_attempt')) == (head, run['id'], run['run_attempt']):
        return None
    tag = release_tag(run['id'], run['run_attempt'])
    try:
        release = api(repository, 'releases/tags/' + tag)
    except HTTPError as error:
        if error.code == 404:
            return None
        raise
    require(release.get('draft') is False and release.get('published_at'), 'Delivery release is not published')
    require(release.get('tag_name') == tag and release.get('target_commitish') == head, 'Delivery release target mismatch')
    require(release.get('author', {}).get('login') == 'github-actions[bot]', 'Delivery release was not published by GitHub Actions')
    ref = api(repository, 'git/ref/tags/' + tag)['object']
    require(ref.get('type') == 'commit' and ref.get('sha') == head, 'Delivery tag target mismatch')
    assets = [asset for asset in release['assets'] if asset['name'] == 'deployment.json' and asset.get('state') == 'uploaded']
    require(len(assets) == 1, 'Delivery release must contain one deployment manifest')
    asset = assets[0]
    expected_url = f'https://github.com/{repository}/releases/download/{tag}/deployment.json'
    require(asset.get('browser_download_url') == expected_url, 'Unexpected delivery download URL')
    body = download(expected_url)
    require('sha256:' + hashlib.sha256(body).hexdigest() == digest(asset.get('digest')), 'Delivery manifest download checksum mismatch')
    return validate_manifest(json.loads(body), repository, run)


class Cluster:
    def __init__(self, state_directory):
        self.prefix = ['kubectl', '--context', 'minikube', '--namespace', 'vulntrack', '--cache-dir', str(state_directory / 'kube-cache')]

    def command(self, *args, timeout=360):
        return subprocess.run(self.prefix + list(args), check=True, capture_output=True, text=True, timeout=timeout).stdout

    def deployment(self):
        return json.loads(self.command('get', 'deployment', 'vulntrack-web', '-o', 'json'))

    @staticmethod
    def web(deployment):
        matches = [(index, container) for index, container in enumerate(deployment['spec']['template']['spec']['containers']) if container['name'] == 'web']
        require(len(matches) == 1, 'Expected exactly one web container')
        return matches[0]

    def replace_image(self, before, image):
        index, container = self.web(before)
        patch = [{'op': 'test', 'path': '/metadata/resourceVersion', 'value': before['metadata']['resourceVersion']},
                 {'op': 'test', 'path': f'/spec/template/spec/containers/{index}/image', 'value': container['image']},
                 {'op': 'replace', 'path': f'/spec/template/spec/containers/{index}/image', 'value': image}]
        return json.loads(self.command('patch', 'deployment', 'vulntrack-web', '--type=json', '--patch', json.dumps(patch), '-o', 'json'))

    def ready(self, manifest):
        self.command('rollout', 'status', 'deployment/vulntrack-web', '--timeout=300s', timeout=330)
        deployment = self.deployment()
        require(self.web(deployment)[1]['image'] == manifest['image'], 'Deployment image changed during rollout')
        desired, status = deployment['spec']['replicas'], deployment['status']
        require(desired > 0 and status.get('observedGeneration', 0) >= deployment['metadata']['generation'], 'Deployment generation not observed')
        require(all(status.get(key) == desired for key in ['updatedReplicas', 'availableReplicas', 'readyReplicas']), 'Deployment replicas are not ready')
        pods = json.loads(self.command('get', 'pods', '-l', 'app=vulntrack-web', '-o', 'json'))['items']
        pods = [pod for pod in pods if not pod['metadata'].get('deletionTimestamp')]
        require(len(pods) == desired, 'Unexpected active pod count')
        identities = []
        for pod in pods:
            containers = [container for container in pod['spec']['containers'] if container['name'] == 'web']
            require(len(containers) == 1 and containers[0]['image'] == manifest['image'], 'Pod image reference mismatch')
            states = [container for container in pod['status'].get('containerStatuses', []) if container['name'] == 'web']
            require(len(states) == 1 and states[0].get('ready') is True, 'Pod container is not ready')
            image_id = states[0].get('imageID', '')
            match = re.search(r'(sha256:[0-9a-f]{64})$', image_id)
            allowed = {manifest['image'].split('@', 1)[1], manifest['image_config_digest']}
            require(match and match.group(1) in allowed, 'Running image digest mismatch')
            identities.append({'pod': pod['metadata']['name'], 'image_id': image_id})
        code = "import json,urllib.request; print(json.dumps(json.load(urllib.request.urlopen('http://127.0.0.1:8000/healthz',timeout=10))))"
        health = json.loads(self.command('exec', 'deployment/vulntrack-web', '--', 'python', '-c', code, timeout=30))
        require(health.get('status') == 'ok', 'Application health check failed')
        return identities


def deploy(cluster, manifest):
    before = cluster.deployment()
    previous_image = cluster.web(before)[1]['image']
    changed = cluster.replace_image(before, manifest['image'])
    try:
        identities = cluster.ready(manifest)
    except (DeliveryError, subprocess.SubprocessError, KeyError, ValueError) as error:
        current = cluster.deployment()
        if (cluster.web(current)[1]['image'] == manifest['image']
                and current['metadata']['generation'] == changed['metadata']['generation']):
            cluster.replace_image(current, previous_image)
            cluster.command('rollout', 'status', 'deployment/vulntrack-web', '--timeout=180s', timeout=210)
            raise DeliveryError('Deployment failed; previous image restored: ' + type(error).__name__) from error
        raise DeliveryError('Deployment failed; concurrent change detected, no rollback performed') from error
    return {**manifest, 'event': 'deployment_succeeded', 'deployed_at': datetime.now(timezone.utc).isoformat(),
            'previous_image': previous_image, 'pods': identities}


def save(path, result):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(result, indent=2), encoding='utf-8')
    temporary.replace(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', default='sK8le/secure-delivery-pipeline')
    parser.add_argument('--state-directory', type=Path, default=Path.home() / '.local/state/vulntrack-delivery')
    parser.add_argument('--check-only', action='store_true', help='Validate candidate without changing Kubernetes')
    args = parser.parse_args()
    args.state_directory.mkdir(parents=True, exist_ok=True)
    import fcntl  # Linux only; the service runs on the deployment VM.
    with (args.state_directory / 'lock').open('a', encoding='utf-8') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        state_path = args.state_directory / 'last-success.json'
        previous = json.loads(state_path.read_text(encoding='utf-8')) if state_path.exists() else {}
        manifest = candidate(args.repository, previous)
        if manifest is None:
            print(json.dumps({'event': 'no_new_verified_delivery'}))
            return
        if args.check_only:
            print(json.dumps({'event': 'candidate_validated', **manifest}, indent=2))
            return
        # Recheck main just before the first cluster mutation.
        require(api(args.repository, 'git/ref/heads/main')['object']['sha'] == manifest['revision'], 'Main changed while validating delivery')
        result = deploy(Cluster(args.state_directory), manifest)
        save(state_path, result)
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (DeliveryError, OSError, subprocess.SubprocessError, KeyError, TypeError, ValueError) as error:
        print(json.dumps({'event': 'delivery_refused_or_failed', 'reason': str(error)}))
        raise SystemExit(1) from error
