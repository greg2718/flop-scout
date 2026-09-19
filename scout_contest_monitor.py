"""Read-only preservation of configured sonnet-2 contest observations."""
from __future__ import annotations
import json

PENDING_OR_UNKNOWN = 'PENDING_OR_UNKNOWN'
SAFE_RETRY_SAME_REQUEST_ID_AVAILABLE = 'SAFE_RETRY_SAME_REQUEST_ID_AVAILABLE'

class ReadOnlyBoundaryError(PermissionError): pass

class ContestMonitor:
    def __init__(self, did, request_id, referee_did):
        if not all(isinstance(v, str) and v for v in (did, request_id, referee_did)):
            raise ValueError('Contest monitor requires explicit existing DID, request_id, and pinned referee DID')
        self.did, self.request_id, self.referee_did = did, request_id, referee_did

    def write(self, *args, **kwargs):
        raise ReadOnlyBoundaryError('Contest monitor is read-only; registration, voting, submission and posting are forbidden')

    def observe(self, raw_record):
        """Return a non-authoritative routing hint; Bench verifies all signatures."""
        raw = raw_record if isinstance(raw_record, dict) else json.loads(raw_record)
        text = raw.get('text', '')
        pinned = raw.get('did', raw.get('from')) == self.referee_did
        matches = self.request_id in text and self.did in text
        kind = 'UNRELATED'
        if matches and 'rejection' in text.lower(): kind = 'SIGNED_REJECTION_CANDIDATE'
        elif matches and 'ballot' in text.lower(): kind = 'BALLOT_RECEIPT_CANDIDATE'
        elif matches and 'registration' in text.lower(): kind = 'REGISTRATION_RECEIPT_CANDIDATE'
        return dict(raw_signed_record=raw_record, pinned_referee_candidate=pinned, kind=kind,
                    authoritative=False, verification_authority='Bench', request_id=self.request_id)

    def missing_receipt_state(self):
        return dict(state=PENDING_OR_UNKNOWN, retry=SAFE_RETRY_SAME_REQUEST_ID_AVAILABLE,
                    action='Scout does not retry')
