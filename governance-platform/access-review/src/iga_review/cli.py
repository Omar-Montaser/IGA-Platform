"""Initialize and run the local Module 4 prototype."""
import argparse
from dataclasses import asdict
import hashlib
import json
import logging
import os
from pathlib import Path
import secrets
import sys
import uvicorn
from .api import create_app
from .connector import FixtureConnector, HTTPConnector
from .demo import build_demo
from .domain import User, strict_json, utcnow
from .ai import configured_reviewer, check_connection
from .service import ReviewService
from .worker import WorkerConfig, run_worker


def initialize(directory, demo=False):
    directory.mkdir(parents=True, exist_ok=True)
    directory.chmod(0o700)
    config_path = directory / 'config.json'
    if config_path.exists():
        raise ValueError('State already exists; use serve to preserve the existing review history.')
    token = secrets.token_urlsafe(32)
    user = User('reviewer:admin', 'Demo reviewer' if demo else 'Review administrator', 'admin', None, hashlib.sha256(token.encode()).hexdigest())
    config = {'version': 1, 'demo': demo, 'fallback_reviewer_id': user.id, 'users': [asdict(user)], 'connectors': []}
    for name, content in (('config.json', json.dumps(config, indent=2) + '\n'), ('reviewer-token.txt', token + '\n')):
        path = directory / name
        with path.open('x', encoding='utf-8') as stream:
            stream.write(content)
        path.chmod(0o600)
    return config


def load_service(directory):
    config = strict_json((directory / 'config.json').read_text())
    if config.get('version') != 1:
        raise ValueError('Unsupported configuration version')
    users = [User(**u) for u in config['users']]
    connectors = {}
    if config['demo']:
        connectors['prototype-system'] = FixtureConnector(directory / 'simulated-source.sqlite3')
    else:
        for item in config.get('connectors', []):
            if item['source'] in connectors:
                raise ValueError('Duplicate connector source')
            connectors[item['source']] = HTTPConnector(item['base_url'], os.environ.get(item['token_env'], ''))
    explainer = configured_reviewer()
    if not config['demo'] and explainer.provider != 'rules' and os.environ.get('IGA_AI_ALLOW_REAL_DATA') != '1':
        raise ValueError('External AI sends identity evidence to the provider. Obtain data-owner approval, '
                         'then explicitly set IGA_AI_ALLOW_REAL_DATA=1, or use IGA_AI_PROVIDER=rules.')
    return ReviewService(directory / 'reviews.sqlite3', users, fallback_reviewer_id=config['fallback_reviewer_id'],
                         connectors=connectors, explainer=explainer, demo=config['demo'],
                         allow_external_ai_data=os.environ.get('IGA_AI_ALLOW_REAL_DATA') == '1')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('ai-check', help='Verify one structured AI generation using synthetic evidence only')
    for command in ('init', 'serve', 'demo', 'work', 'worker'):
        cmd = sub.add_parser(command)
        cmd.add_argument('--state-dir', type=Path, default=Path('.iga-review'))
        if command in ('serve', 'demo'):
            cmd.add_argument('--host', choices=['127.0.0.1', '::1'], default='127.0.0.1')
            cmd.add_argument('--port', type=int, default=8040)
        if command == 'demo':
            cmd.add_argument('--identities', type=Path, default=Path('../hr-policy/data/identities.json'))
            cmd.add_argument('--policies', type=Path, default=Path('../hr-policy/data/policies.json'))
        if command == 'worker':
            cmd.add_argument('--poll-interval', type=int, default=10, help='Polling interval in seconds (default: 10)')
            cmd.add_argument('--max-poll-interval', type=int, default=60, help='Maximum polling interval when idle (default: 60)')
            cmd.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], default='INFO', help='Logging level (default: INFO)')
    args = parser.parse_args(argv)
    if args.command == 'ai-check':
        try:
            result = check_connection(configured_reviewer())
            print(json.dumps(result))
            return 0 if result['status'] == 'ready' else 1
        except ValueError as exc:
            print(f'AI configuration error: {exc}', file=sys.stderr)
            return 1
    directory = args.state_dir.resolve()
    
    # Configure logging for worker
    if args.command == 'worker':
        logging.basicConfig(
            level=getattr(logging, args.log_level),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            stream=sys.stdout
        )
    
    try:
        if args.command == 'init':
            initialize(directory)
            print(f'Initialized. Reviewer credential: {directory / "reviewer-token.txt"}')
            return 0
        if args.command == 'demo' and not (directory / 'config.json').exists():
            configured_reviewer()  # Fail bad AI configuration before creating state.
            # Validate all input and generate the fixture before creating credentials.
            payload = build_demo(strict_json(args.identities.read_text()), strict_json(args.policies.read_text()), utcnow())
            initialize(directory, demo=True)
            FixtureConnector(directory / 'simulated-source.sqlite3', payload['scan'])
            (directory / 'demo-import.json').write_text(json.dumps(payload, indent=2, ensure_ascii=False) + '\n')
            service = load_service(directory)
            service.create_campaign(payload, service.users['reviewer:admin'])
        else:
            service = load_service(directory)
        if args.command == 'demo' and not service.demo:
            raise ValueError('This state directory is not a demo. Use serve or a new demo directory.')
        if args.command == 'work':
            # One-shot work command (backward compatible)
            admin = next(u for u in service.users.values() if u.role == 'admin')
            results = [service.process(c['id'], admin) for c in service.list_campaigns(admin)['campaigns']]
            print(json.dumps(results, indent=2))
            return 0
        if args.command == 'worker':
            # Supervised worker mode
            config = WorkerConfig(
                poll_interval_seconds=args.poll_interval,
                max_poll_interval_seconds=args.max_poll_interval
            )
            logger = logging.getLogger('iga_review.worker')
            logger.info('Starting remediation worker', extra={
                'state_dir': str(directory),
                'demo': service.demo,
                'poll_interval': config.poll_interval_seconds,
                'max_poll_interval': config.max_poll_interval_seconds
            })
            run_worker(service, config)
            return 0
        print(f'Reviewer credential: {directory / "reviewer-token.txt"}')
        print(f'Configured reviewer: {service.reviewer.provider} '
              f'{getattr(service.reviewer, "model", "(no AI)")}. Existing assessments are preserved.')
        print(f'Open http://{args.host}:{args.port} — ' + ('SIMULATED SOURCE, no real target changes.' if service.demo else 'Configured connectors only.'))
        uvicorn.run(create_app(service), host=args.host, port=args.port, log_level='info')
        return 0
    except (OSError, ValueError, StopIteration) as exc:
        print(f'Unable to start Module 4: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
