"""Background remediation worker with graceful shutdown and lease recovery."""
import json
import logging
import signal
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class WorkerConfig:
    """Worker polling and timing configuration."""
    poll_interval_seconds: int = 10
    max_poll_interval_seconds: int = 60
    lease_duration_minutes: int = 2
    shutdown_grace_seconds: int = 30
    
    def __post_init__(self):
        if not 1 <= self.poll_interval_seconds <= self.max_poll_interval_seconds:
            raise ValueError('poll_interval_seconds must be between 1 and max_poll_interval_seconds')
        if not 1 <= self.max_poll_interval_seconds <= 300:
            raise ValueError('max_poll_interval_seconds must be between 1 and 300')
        if not 1 <= self.lease_duration_minutes <= 60:
            raise ValueError('lease_duration_minutes must be between 1 and 60')
        if not 1 <= self.shutdown_grace_seconds <= 120:
            raise ValueError('shutdown_grace_seconds must be between 1 and 120')


class RemediationWorker:
    """Supervised background worker for processing remediation requests.
    
    Polls for queued, dispatching, and verification_pending requests using
    the existing service lease model. Supports graceful shutdown and lease
    recovery. Never repeats successful revocations.
    """
    
    def __init__(self, service, config=WorkerConfig()):
        self.service = service
        self.config = config
        self.running = False
        self.shutdown_requested = False
        self.current_request_id: Optional[str] = None
        
    def start(self):
        """Start the worker loop with signal handlers for graceful shutdown."""
        self.running = True
        self.shutdown_requested = False
        
        # Register signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        logger.info('Remediation worker starting', extra={
            'poll_interval': self.config.poll_interval_seconds,
            'lease_duration': self.config.lease_duration_minutes
        })
        
        try:
            self._run_loop()
        except Exception as error:
            logger.error('Worker loop failed', extra={
                'error': str(error),
                'error_type': type(error).__name__
            })
            raise
        finally:
            self.running = False
            logger.info('Remediation worker stopped')
    
    def _signal_handler(self, signum, frame):
        """Handle SIGINT/SIGTERM for graceful shutdown."""
        sig_name = 'SIGINT' if signum == signal.SIGINT else 'SIGTERM'
        if self.shutdown_requested:
            logger.warning('Shutdown already requested, forcing exit', extra={
                'signal': sig_name
            })
            sys.exit(1)
        
        logger.info('Shutdown signal received, finishing current work', extra={
            'signal': sig_name,
            'current_request': self.current_request_id,
            'grace_seconds': self.config.shutdown_grace_seconds
        })
        self.shutdown_requested = True
    
    def _run_loop(self):
        """Main worker loop: poll for work, process, sleep, repeat."""
        idle_count = 0
        
        while not self.shutdown_requested:
            try:
                # Get all campaigns and process their requests
                admin = next((u for u in self.service.users.values() if u.role == 'admin'), None)
                if not admin:
                    logger.error('No admin user configured, cannot process requests')
                    time.sleep(self.config.poll_interval_seconds)
                    continue
                
                campaigns_data = self.service.list_campaigns(admin)
                campaigns = campaigns_data.get('campaigns', [])
                
                if not campaigns:
                    logger.debug('No campaigns found')
                    time.sleep(self.config.poll_interval_seconds)
                    continue
                
                # Process requests from all campaigns
                work_done = False
                for campaign in campaigns:
                    if self.shutdown_requested:
                        logger.info('Shutdown requested, stopping campaign processing')
                        break
                    
                    campaign_work = self._process_campaign(campaign['id'], admin)
                    work_done = work_done or campaign_work
                
                if work_done:
                    idle_count = 0
                    # Short sleep after doing work
                    self._interruptible_sleep(self.config.poll_interval_seconds)
                else:
                    # Backoff when idle
                    idle_count += 1
                    sleep_time = min(
                        self.config.poll_interval_seconds * (1 + idle_count // 3),
                        self.config.max_poll_interval_seconds
                    )
                    logger.debug('No work found, sleeping', extra={'sleep_seconds': sleep_time})
                    self._interruptible_sleep(sleep_time)
                    
            except KeyboardInterrupt:
                logger.info('Keyboard interrupt, initiating shutdown')
                self.shutdown_requested = True
            except Exception as error:
                # Log and continue - don't crash the worker loop
                logger.error('Error processing work', extra={
                    'error': str(error),
                    'error_type': type(error).__name__
                })
                self._interruptible_sleep(self.config.poll_interval_seconds)
    
    def _process_campaign(self, campaign_id: str, admin) -> bool:
        """Process all pending requests for a campaign. Returns True if work was done."""
        try:
            # Get pending requests for this campaign
            with self.service.store.read() as conn:
                rows = conn.execute(
                    'SELECT r.id FROM requests r '
                    'JOIN findings f ON f.id=r.finding_id '
                    'WHERE f.campaign_id=? AND r.state IN (?,?,?) '
                    'ORDER BY rowid ASC',
                    (campaign_id, 'queued', 'dispatching', 'verification_pending')
                ).fetchall()
            
            if not rows:
                return False
            
            request_ids = [row[0] for row in rows]
            logger.info('Processing campaign requests', extra={
                'campaign_id': campaign_id,
                'request_count': len(request_ids)
            })
            
            work_done = False
            for request_id in request_ids:
                if self.shutdown_requested:
                    logger.info('Shutdown requested during campaign processing')
                    break
                
                result = self._process_request(request_id, admin)
                if result:
                    work_done = True
            
            return work_done
            
        except Exception as error:
            logger.error('Campaign processing error', extra={
                'campaign_id': campaign_id,
                'error': str(error),
                'error_type': type(error).__name__
            })
            return False
    
    def _process_request(self, request_id: str, admin) -> bool:
        """Process a single request. Returns True if state changed."""
        self.current_request_id = request_id
        
        try:
            # Use the existing service._work method which handles:
            # - Lease acquisition
            # - Authorization checks
            # - Connector calls
            # - Verification
            # - State transitions
            result = self.service._work(request_id)
            
            # Log result without sensitive data
            state = result.get('state')
            busy = result.get('busy', False)
            error_msg = result.get('error')
            
            if busy:
                logger.debug('Request busy (leased by another worker)', extra={
                    'request_id': request_id
                })
                return False
            
            if state in ('verified', 'failed', 'verification_failed'):
                log_level = logging.INFO if state == 'verified' else logging.WARNING
                logger.log(log_level, 'Request processed', extra={
                    'request_id': request_id,
                    'final_state': state,
                    'has_error': error_msg is not None
                })
                return True
            elif state in ('queued', 'dispatching', 'verification_pending'):
                # State didn't change (lease was held)
                logger.debug('Request state unchanged', extra={
                    'request_id': request_id,
                    'state': state
                })
                return False
            else:
                logger.warning('Unexpected request state', extra={
                    'request_id': request_id,
                    'state': state
                })
                return False
                
        except Exception as error:
            # Service._work should catch and handle errors,
            # but log here for worker visibility
            logger.error('Request processing error', extra={
                'request_id': request_id,
                'error': str(error),
                'error_type': type(error).__name__
            })
            return False
        finally:
            self.current_request_id = None
    
    def _interruptible_sleep(self, seconds: int):
        """Sleep in small increments to allow shutdown checks."""
        end_time = time.time() + seconds
        while time.time() < end_time and not self.shutdown_requested:
            time.sleep(min(1, end_time - time.time()))
    
    def stop(self):
        """Request graceful shutdown."""
        logger.info('Stop requested')
        self.shutdown_requested = True


def run_worker(service, config=WorkerConfig()):
    """Run the remediation worker.
    
    This is the main entry point for the background worker. It creates
    a worker instance and starts the supervised loop.
    
    Args:
        service: ReviewService instance with configured connectors
        config: WorkerConfig with polling and timing parameters
    
    Raises:
        Exception: If worker initialization or loop fails
    """
    worker = RemediationWorker(service, config)
    worker.start()
