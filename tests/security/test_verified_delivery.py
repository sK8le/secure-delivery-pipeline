"""Trust boundaries and failure handling of pull-based delivery."""
import copy
import hashlib
import json
from urllib.error import HTTPError

import pytest

from scripts import deploy_verified as agent, image_receipt as publisher
from scripts.delivery_common import DeliveryError, validate_manifest

REPO = 'sK8le/secure-delivery-pipeline'
REVISION = 'a' * 40
CONFIG = 'sha256:' + 'b' * 64
REGISTRY_DIGEST = 'sha256:' + 'c' * 64
IMAGE = 'ghcr.io/sk8le/secure-delivery-pipeline@' + REGISTRY_DIGEST


@pytest.mark.parametrize('url', ['file:///etc/passwd', 'http://api.github.com/',
                              'https://attacker.invalid/', 'https://api.github.com.attacker.invalid/',
                              'https://user:password@api.github.com/', 'https://api.github.com:444/'])
def test_download_rejects_unexpected_origins_before_network_access(url):
    with pytest.raises(DeliveryError, match='Only HTTPS'):
        agent.download(url)


def test_redirect_cannot_escape_the_github_allowlist():
    with pytest.raises(DeliveryError, match='Only HTTPS'):
        agent.GitHubRedirects().redirect_request(None, None, 302, '', {}, 'http://169.254.169.254/')


@pytest.fixture
def run():
    return {'id': 123, 'run_attempt': 2, 'head_sha': REVISION, 'repository': {'full_name': REPO},
            'head_repository': {'full_name': REPO}, 'event': 'push', 'head_branch': 'main',
            'path': '.github/workflows/security.yml', 'status': 'completed', 'conclusion': 'success'}


@pytest.fixture
def manifest():
    return {'schema': 1, 'repository': REPO, 'revision': REVISION, 'run_id': 123, 'run_attempt': 2,
            'build_run_attempt': 1, 'image': IMAGE, 'image_config_digest': CONFIG,
            'archive_sha256': 'sha256:' + 'd' * 64}


@pytest.mark.parametrize('field,value', [
    ('event', 'pull_request'), ('head_branch', 'experiment'), ('conclusion', 'failure'),
    ('status', 'in_progress'), ('head_sha', 'f' * 40), ('path', '.github/workflows/baseline.yml'),
    ('head_repository', {'full_name': 'stranger/fork'}), ('repository', {'full_name': 'stranger/project'}),
])
def test_untrusted_workflow_is_rejected(run, field, value):
    run[field] = value
    with pytest.raises(DeliveryError):
        agent.validate_run(run, REPO, REVISION)


@pytest.mark.parametrize('field,value', [
    ('repository', 'stranger/fork'), ('revision', 'f' * 40), ('run_id', 456), ('run_attempt', 1),
    ('run_attempt', True), ('schema', True), ('image_config_digest', 'latest'),
    ('image', 'ghcr.io/stranger/other@' + REGISTRY_DIGEST), ('image', 'ghcr.io/sk8le/secure-delivery-pipeline:latest'),
    ('archive_sha256', 'broken'),
])
def test_manifest_cannot_select_another_build(run, manifest, field, value):
    manifest[field] = value
    with pytest.raises(DeliveryError):
        validate_manifest(manifest, REPO, run)


@pytest.fixture
def github(monkeypatch, run, manifest):
    body = json.dumps(manifest).encode()
    release = {'draft': False, 'published_at': '2026-11-11T00:00:00Z', 'tag_name': 'delivery-123-2',
               'target_commitish': REVISION, 'author': {'login': 'github-actions[bot]'},
               'assets': [{'name': 'deployment.json', 'state': 'uploaded',
                           'browser_download_url': f'https://github.com/{REPO}/releases/download/delivery-123-2/deployment.json',
                           'digest': 'sha256:' + hashlib.sha256(body).hexdigest()}]}
    responses = {'git/ref/heads/main': {'object': {'sha': REVISION}},
                 'actions/workflows/security.yml/runs?branch=main&event=push&status=success&per_page=1': {'workflow_runs': [run]},
                 'releases/tags/delivery-123-2': release,
                 'git/ref/tags/delivery-123-2': {'object': {'type': 'commit', 'sha': REVISION}}}
    calls = []
    def fake_api(repository, path):
        assert repository == REPO
        calls.append(path)
        return responses[path]
    monkeypatch.setattr(agent, 'api', fake_api)
    monkeypatch.setattr(agent, 'download', lambda url: body)
    return responses, release, calls


def test_valid_main_release_becomes_a_candidate(github, manifest):
    assert agent.candidate(REPO, {}) == manifest


def test_new_unverified_main_is_not_replaced_by_an_older_success(github):
    responses, _, _ = github
    responses['git/ref/heads/main']['object']['sha'] = 'e' * 40
    assert agent.candidate(REPO, {}) is None


def test_same_deployed_run_is_not_redeployed(github, manifest):
    assert agent.candidate(REPO, manifest) is None
    assert not any(path.startswith('releases/') for path in github[2])


@pytest.mark.parametrize('defect', ['draft', 'author', 'target', 'tag', 'url', 'checksum'])
def test_release_validation_precedes_any_cluster_action(github, defect):
    responses, release, _ = github
    if defect == 'draft':
        release['draft'] = True
    elif defect == 'author':
        release['author']['login'] = 'some-user'
    elif defect == 'target':
        release['target_commitish'] = 'main'
    elif defect == 'tag':
        responses['git/ref/tags/delivery-123-2']['object']['sha'] = 'e' * 40
    elif defect == 'url':
        release['assets'][0]['browser_download_url'] = 'http://169.254.169.254/metadata'
    else:
        release['assets'][0]['digest'] = 'sha256:' + '0' * 64
    with pytest.raises(DeliveryError):
        agent.candidate(REPO, {})


def test_absent_delivery_release_is_idle(monkeypatch, github):
    original = agent.api
    def missing(repository, path):
        if path.startswith('releases/'):
            raise HTTPError('https://api.github.com/', 404, 'not found', {}, None)
        return original(repository, path)
    monkeypatch.setattr(agent, 'api', missing)
    assert agent.candidate(REPO, {}) is None


def deployment(image='vulntrack:previous', generation=1):
    return {'metadata': {'resourceVersion': '10', 'generation': generation},
            'spec': {'replicas': 2, 'template': {'spec': {'containers': [{'name': 'web', 'image': image}]}}},
            'status': {'observedGeneration': generation, 'updatedReplicas': 2, 'availableReplicas': 2, 'readyReplicas': 2}}


class FakeCluster:
    web = staticmethod(agent.Cluster.web)
    def __init__(self, failure=None):
        self.current = deployment()
        self.changes = []
        self.failure = failure
    def deployment(self):
        return copy.deepcopy(self.current)
    def replace_image(self, before, image):
        assert before['metadata']['resourceVersion'] == self.current['metadata']['resourceVersion']
        self.changes.append(image)
        self.current = deployment(image, before['metadata']['generation'] + 1)
        self.current['metadata']['resourceVersion'] = str(int(before['metadata']['resourceVersion']) + 1)
        return self.deployment()
    def ready(self, manifest):
        if self.failure == 'concurrent':
            self.current = deployment('vulntrack:human-change', self.current['metadata']['generation'] + 1)
        if self.failure:
            raise DeliveryError('health failed')
        return [{'pod': 'pod-1', 'image_id': CONFIG}]
    def command(self, *args, **kwargs):
        return ''


def test_success_is_recorded_only_after_rollout_and_health(manifest):
    cluster = FakeCluster()
    result = agent.deploy(cluster, manifest)
    assert result['event'] == 'deployment_succeeded'
    assert result['previous_image'] == 'vulntrack:previous'
    assert cluster.changes == [IMAGE]
    assert result['pods']


def test_failed_rollout_restores_previous_image(manifest):
    cluster = FakeCluster('health')
    with pytest.raises(DeliveryError, match='previous image restored'):
        agent.deploy(cluster, manifest)
    assert cluster.changes == [IMAGE, 'vulntrack:previous']


def test_rollback_does_not_overwrite_a_concurrent_manual_deployment(manifest):
    cluster = FakeCluster('concurrent')
    with pytest.raises(DeliveryError, match='concurrent change'):
        agent.deploy(cluster, manifest)
    assert cluster.changes == [IMAGE]
    assert cluster.web(cluster.current)[1]['image'] == 'vulntrack:human-change'


@pytest.mark.parametrize('image_id,accepted', [(CONFIG, True), (REGISTRY_DIGEST, True), ('sha256:' + 'e' * 64, False)])
def test_running_container_identity_must_match_the_approved_image(tmp_path, monkeypatch, manifest, image_id, accepted):
    cluster = agent.Cluster(tmp_path)
    pod = {'metadata': {'name': 'pod'}, 'spec': {'containers': [{'name': 'web', 'image': IMAGE}]},
           'status': {'containerStatuses': [{'name': 'web', 'ready': True, 'imageID': image_id}]}}
    responses = {'rollout': '', 'get:deployment': json.dumps(deployment(IMAGE)),
                 'get:pods': json.dumps({'items': [pod, copy.deepcopy(pod)]}), 'exec': '{"status":"ok"}'}
    monkeypatch.setattr(cluster, 'command', lambda *args, **kwargs: responses[args[0] + ':' + args[1]] if args[0] == 'get' else responses[args[0]])
    if accepted:
        assert len(cluster.ready(manifest)) == 2
    else:
        with pytest.raises(DeliveryError, match='digest mismatch'):
            cluster.ready(manifest)


@pytest.fixture
def build(tmp_path, monkeypatch):
    archive = tmp_path / 'image.tar'
    archive.write_bytes(b'tested image archive')
    identity = {'repository': REPO, 'revision': REVISION, 'run_id': 123, 'run_attempt': 2}
    receipt = {'schema': 1, **identity, 'run_attempt': 1, 'image_config_digest': CONFIG,
               'archive_sha256': publisher.sha256_file(archive)}
    commands = []
    monkeypatch.setattr(publisher, 'command', lambda args: commands.append(args) or '')
    monkeypatch.setattr(publisher, 'inspect_image', lambda reference: {'Id': CONFIG, 'RepoDigests': [IMAGE]})
    return archive, receipt, identity, commands


def test_publisher_reuses_tested_archive_even_after_a_publish_retry(build):
    archive, receipt, identity, commands = build
    result = publisher.publish(archive, receipt, identity)
    assert result['image'] == IMAGE
    assert result['build_run_attempt'] == 1 and result['run_attempt'] == 2
    assert ['docker', 'load', '--input', str(archive)] in commands
    assert not any('build' in args for args in commands)
    assert any(args[:2] == ['docker', '--config'] and args[-2:] == ['pull', IMAGE] for args in commands)


def test_modified_archive_is_rejected_before_docker_load(build):
    archive, receipt, identity, commands = build
    archive.write_bytes(b'different archive')
    with pytest.raises(DeliveryError, match='archive changed'):
        publisher.publish(archive, receipt, identity)
    assert commands == []


def test_loaded_image_identity_mismatch_is_not_published(build, monkeypatch):
    archive, receipt, identity, commands = build
    monkeypatch.setattr(publisher, 'inspect_image', lambda reference: {'Id': 'sha256:' + '0' * 64})
    with pytest.raises(DeliveryError, match='Loaded image differs'):
        publisher.publish(archive, receipt, identity)
    assert not any('push' in args for args in commands)
