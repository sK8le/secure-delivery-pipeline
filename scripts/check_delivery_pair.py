"""Validate two measured deliveries and summarize the timing difference."""

import argparse
from datetime import datetime
import json
from pathlib import Path
import re


def require(condition, message):
    if not condition:
        raise ValueError(message)


def utc_time(report, field):
    time = datetime.fromisoformat(report[field].replace('Z', '+00:00'))
    require(time.utcoffset() is not None, f'{field}: expected a time zone')
    return time


def checked(report):
    variant = report['variant']
    require(report['schema'] == 1 and report['pilot'] is False and report['result'] == 'success',
            f'{variant}: expected a successful timed delivery')
    require(report['profile'] == 'vkr-delivery-exp' and report['ci_conclusion'] == 'success',
            f'{variant}: expected the experiment profile and successful CI')
    for field in ('head', 'revision'):
        require(re.fullmatch(r'[0-9a-f]{40}', report[field]), f'{variant}: malformed {field}')
    image = report['image']
    require(re.fullmatch(r'localhost:5000/vulntrack@sha256:[a-f0-9]{64}', image),
            f'{variant}: expected an image from the experiment registry')
    manifest = image.rsplit('@', 1)[1]
    config = report['image_config_digest']
    require(re.fullmatch(r'sha256:[a-f0-9]{64}', config), f'{variant}: invalid config digest')
    pods = report['pods']
    require(len(pods) == 2 and len({pod['pod'] for pod in pods}) == 2,
            f'{variant}: expected two distinct pods')
    for pod in pods:
        observed = pod['image_id'].rsplit('@', 1)[-1].rsplit('://', 1)[-1]
        require(observed in {manifest, config} and pod['database_ready'] is True and pod['login_form'] is True,
                f'{variant}: pod failed the digest, database or login form check')
    stamps = [utc_time(report, field) for field in (
        'ci_created_at', 'observer_started_at', 'ci_observed_complete_at',
        'artifact_downloaded_at', 'published_at', 'rollout_started_at', 'ready_at',
    )]
    require(stamps == sorted(stamps), f'{variant}: out-of-order timestamps')
    duration = (stamps[-1] - stamps[0]).total_seconds()
    require(duration > 0 and report['delivery_seconds'] == round(duration, 3),
            f'{variant}: duration disagrees with timestamps')
    return stamps[0], stamps[-1], duration


def compare(first, second):
    order = [first['variant'], second['variant']]
    require(set(order) == {'baseline', 'secured'}, 'Expected one report of each variant')
    first_start, first_ready, first_seconds = checked(first)
    second_start, _, second_seconds = checked(second)
    require(first['run_id'] != second['run_id'], 'Expected distinct CI runs')
    require(first_start < second_start and first_ready <= second_start,
            'The second run started before the first delivery finished')
    for field in ('head', 'revision', 'event', 'node', 'registry_image_id'):
        require(first[field] == second[field], f'The reports disagree on {field}')
    require({pod['pod'] for pod in first['pods']}.isdisjoint(pod['pod'] for pod in second['pods']),
            'The two deliveries must have distinct pods')
    seconds = dict(zip(order, (first_seconds, second_seconds)))
    delta = seconds['secured'] - seconds['baseline']
    return dict(order=order, run_ids=[first['run_id'], second['run_id']], revision=first['revision'],
                baseline_seconds=round(seconds['baseline'], 3),
                secured_seconds=round(seconds['secured'], 3),
                delta_seconds=round(delta, 3),
                overhead_percent=round(100 * delta / seconds['baseline'], 2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('first', type=Path, help='Report of the first delivery in the pair')
    parser.add_argument('second', type=Path, help='Report of the second delivery in the pair')
    args = parser.parse_args()
    try:
        first, second = (json.loads(path.read_text(encoding='utf-8')) for path in (args.first, args.second))
        print(json.dumps(compare(first, second), indent=2))
    except (KeyError, OSError, TypeError, ValueError) as error:
        parser.exit(1, f'Pair rejected: {error}\n')


if __name__ == '__main__':
    main()
