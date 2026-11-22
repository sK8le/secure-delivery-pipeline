import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from scripts import measure_delivery as measurement


HEAD = 'a' * 40
REVISION = 'b' * 40
CONFIG = 'sha256:' + 'c' * 64
MANIFEST = 'sha256:' + 'd' * 64
REFERENCE = measurement.IMAGE_REPOSITORY + '@' + MANIFEST


def arguments(variant='secured', pilot=False):
    return SimpleNamespace(variant=variant, pilot=pilot, run_id=17, head=HEAD, revision=REVISION)


def workflow_run(variant, status='completed', conclusion='success'):
    repository = {'full_name': measurement.REPOSITORY}
    return {
        'id': 17, 'run_attempt': 1, 'repository': repository, 'head_repository': repository,
        'head_sha': HEAD, 'path': measurement.VARIANTS[variant][0], 'event': 'pull_request',
        'created_at': '2026-11-20T10:00:00Z', 'run_started_at': '2026-11-20T10:00:01Z',
        'updated_at': '2026-11-20T10:05:00Z', 'html_url': 'https://github.com/run/17',
        'status': status, 'conclusion': conclusion,
    }


def download_fixture(*args, **kwargs):
    directory = Path(args[-1])
    archive = directory / 'vulntrack-image.tar'
    archive.write_bytes(b'fixture')
    receipt = {
        'schema': 1, 'repository': measurement.REPOSITORY, 'revision': REVISION,
        'run_id': 17, 'run_attempt': 1, 'image_config_digest': CONFIG,
        'archive_sha256': measurement.sha256_file(archive),
    }
    (directory / 'image-build.json').write_text(json.dumps(receipt), encoding='utf-8')


def pod(name, image_id):
    return {
        'metadata': {'name': name, 'annotations': {'vkr.example/measurement-run': '17'}},
        'spec': {'containers': [{'name': 'web', 'image': REFERENCE}]},
        'status': {'containerStatuses': [{'name': 'web', 'ready': True, 'imageID': image_id}]},
    }


class MeasurementTests(unittest.TestCase):
    def test_variants_use_the_same_delivery_path_after_success(self):
        for variant, (_, artifact) in measurement.VARIANTS.items():
            with self.subTest(variant=variant):
                pods = [{'pod': 'web'}]
                with (
                    patch.object(measurement, 'assert_cluster', return_value={}),
                    patch.object(measurement, 'registry_info', return_value=CONFIG),
                    patch.object(measurement, 'read_run', side_effect=[
                        workflow_run(variant, 'in_progress', None), workflow_run(variant),
                    ]),
                    patch.object(measurement.time, 'sleep'),
                    patch.object(measurement, 'command', side_effect=download_fixture) as download,
                    patch.object(measurement, 'publish_in_cluster', return_value=REFERENCE) as publish,
                    patch.object(measurement, 'rollout') as rollout,
                    patch.object(measurement, 'verify_pods', return_value=pods) as verify,
                    patch.object(measurement, 'utc_now', return_value='2026-11-20T10:06:00+00:00'),
                ):
                    report = {}
                    measurement.measure(arguments(variant), report)
                self.assertEqual(report['delivery_seconds'], 360.0)
                self.assertEqual(report['pods'], pods)
                self.assertIn(artifact, download.call_args.args)
                self.assertEqual(publish.call_args.args[1:], (17, CONFIG))
                self.assertEqual(rollout.call_args.args[1:], (REFERENCE, 17))
                verify.assert_called_once_with(REFERENCE, CONFIG, 17)

    def test_wrong_workflow_source_fails_before_download(self):
        workflow = measurement.VARIANTS['secured'][0]
        for field, value in (
            ('head_repository', {'full_name': 'example/fork'}),
            ('path', '.github/workflows/baseline.yml'),
            ('head_sha', REVISION),
            ('run_attempt', 2),
        ):
            with self.subTest(field=field), self.assertRaises(measurement.DeliveryError):
                measurement.validate_run({**workflow_run('secured'), field: value}, arguments(), workflow)

    def test_failed_ci_and_late_observation_are_rejected(self):
        workflow = measurement.VARIANTS['secured'][0]
        for pilot, conclusion, message in (
            (True, 'failure', 'CI did not conclude successfully'),
            (False, 'success', 'timed run must be observed'),
        ):
            with self.subTest(pilot=pilot), patch.object(
                measurement, 'read_run', return_value=workflow_run('secured', conclusion=conclusion),
            ), self.assertRaisesRegex(measurement.DeliveryError, message):
                measurement.wait_for_run(arguments(pilot=pilot), workflow, {})

    def test_altered_archive_is_rejected(self):
        def download_then_alter(*args, **kwargs):
            download_fixture(*args, **kwargs)
            (Path(args[-1]) / 'vulntrack-image.tar').write_bytes(b'changed')

        with tempfile.TemporaryDirectory() as directory, patch.object(
            measurement, 'command', side_effect=download_then_alter,
        ), self.assertRaisesRegex(measurement.DeliveryError, 'checksum mismatch'):
            measurement.verified_artifact(arguments(), 'vulntrack-image', Path(directory), {})

    def test_rollout_uses_registry_digest_and_unique_pod_annotation(self):
        def kube(*args, **kwargs):
            if args[:2] == ('apply', '-k'):
                directory = Path(args[2])
                kustomization = json.loads((directory / 'kustomization.yaml').read_text(encoding='utf-8'))
                self.assertEqual(kustomization['images'][0]['digest'], MANIFEST)
                patch_text = (directory / 'rollout.yaml').read_text(encoding='utf-8')
                self.assertIn('measurement-run: "17"', patch_text)
                self.assertIn('imagePullPolicy: Always', patch_text)
            return ''

        with tempfile.TemporaryDirectory() as directory, patch.object(measurement, 'kubectl', side_effect=kube):
            measurement.rollout(Path(directory), REFERENCE, 17)

    def test_pod_identity_and_application_check_gate_ready_timestamp(self):
        checks = json.dumps({'database_ready': True, 'login_form': True})
        first = pod('web-1', 'docker-pullable://' + REFERENCE)
        second = pod('web-2', 'docker://' + CONFIG)
        with patch.object(measurement, 'kubectl', side_effect=[
            json.dumps({'items': [first, second]}), checks, checks,
        ]):
            self.assertEqual(len(measurement.verify_pods(REFERENCE, CONFIG, 17)), 2)
        wrong = pod('web-2', 'docker://' + 'sha256:' + 'e' * 64)
        with patch.object(measurement, 'kubectl', side_effect=[
            json.dumps({'items': [first, wrong]}), checks,
        ]), self.assertRaisesRegex(measurement.DeliveryError, 'Runtime image ID'):
            measurement.verify_pods(REFERENCE, CONFIG, 17)
        with patch.object(measurement, 'kubectl', side_effect=[
            json.dumps({'items': [first, second]}), json.dumps({'database_ready': True, 'login_form': False}),
        ]), self.assertRaisesRegex(measurement.DeliveryError, 'login form check failed'):
            measurement.verify_pods(REFERENCE, CONFIG, 17)

    def test_kubectl_is_only_invoked_in_the_measurement_profile(self):
        command = Mock()
        with patch.object(measurement, 'command', command):
            measurement.kubectl('get', 'nodes')
        self.assertEqual(command.call_args.args[:9], (
            'minikube', '-p', 'vkr-delivery-exp', 'kubectl', '--',
            '--context', 'vkr-delivery-exp', '-n', 'vulntrack',
        ))


if __name__ == '__main__':
    unittest.main()
