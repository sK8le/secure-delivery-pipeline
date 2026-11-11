"""Validation shared by the image publisher and the local deployment service."""
import re


class DeliveryError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise DeliveryError(message)


def validate_identity(repository, revision, run_id, run_attempt):
    require(isinstance(repository, str) and re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository), "Invalid repository")
    require(isinstance(revision, str) and re.fullmatch(r"[0-9a-f]{40}", revision), "Invalid revision")
    require(type(run_id) is int and run_id > 0, "Invalid run ID")
    require(type(run_attempt) is int and run_attempt > 0, "Invalid run attempt")


def digest(value):
    require(isinstance(value, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", value), "Invalid SHA-256 digest")
    return value


def release_tag(run_id, attempt):
    return f"delivery-{run_id}-{attempt}"


def validate_manifest(manifest, repository, run):
    revision, run_id, attempt = run['head_sha'], run['id'], run['run_attempt']
    validate_identity(repository, revision, run_id, attempt)
    require(type(manifest.get('schema')) is int and manifest['schema'] == 1, "Unsupported delivery manifest")
    validate_identity(manifest.get('repository'), manifest.get('revision'), manifest.get('run_id'), manifest.get('run_attempt'))
    require(manifest.get('repository', '').lower() == repository.lower(), "Manifest repository mismatch")
    require(manifest.get('revision') == revision, "Manifest revision mismatch")
    require(manifest.get('run_id') == run_id and manifest.get('run_attempt') == attempt, "Manifest workflow run mismatch")
    digest(manifest.get('image_config_digest'))
    digest(manifest.get('archive_sha256'))
    image = manifest.get('image', '')
    prefix = 'ghcr.io/' + repository.lower() + '@'
    require(isinstance(image, str) and image.startswith(prefix), "Unexpected image registry or repository")
    digest(image[len(prefix):])
    return manifest
