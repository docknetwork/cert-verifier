import hashlib
import json
import logging
from datetime import datetime
from threading import Lock

import bitcoin
import pytz
from bitcoin.signmessage import BitcoinMessage, VerifyMessage
from cert_core import BlockcertVersion, Chain
from cert_core import chain_to_bitcoin_network
from cert_core.cert_model.model import SignatureType
from cert_schema import BlockcertValidationError
from cert_schema import normalize_jsonld
from cert_verifier import StepStatus
from cert_verifier.errors import InvalidCertificateError
from chainpoint.chainpoint import Chainpoint

lock = Lock()


def hash_normalized(normalized):
    encoded = normalized.encode('utf-8')
    return hashlib.sha256(encoded).hexdigest()


def hashes_match(actual_hash, expected_hash):
    return actual_hash in expected_hash or actual_hash == expected_hash


class VerificationCheck(object):
    """Individual task involved in verification"""

    def __init__(self, certificate, transaction_info=None, issuer_info=None):
        self.certificate = certificate
        self.transaction_info = transaction_info
        self.issuer_info = issuer_info

    def execute(self):
        return self.do_execute()

    def do_execute(self):
        """Steps should override this"""
        return False


class VerificationGroup(VerificationCheck):
    """
    Wraps steps in a phase of validation. Generally you should be able to instantiate this directly instead of subclass
    """

    def __init__(self, steps, name, success_status=StepStatus.passed):
        self.steps = steps
        self.name = name
        self.success_status = success_status
        self.status = StepStatus.not_started

    def name(self):
        return self.name

    def do_execute(self):

        for step in self.steps:
            try:
                passed = step.do_execute()
                if passed:
                    self.status = self.success_status
                    logging.debug('Verification step %s passed', self.__class__.__name__)
                else:
                    self.status = StepStatus.failed
                    logging.error('Verification step %s failed!', self.__class__.__name__)
                    break
            except Exception:
                logging.exception('caught exception executing step %s', self.__class__.__name__)
                self.status = StepStatus.failed
                break
        return self.status == StepStatus.done or self.status == StepStatus.passed

    def add_detailed_status(self, messages):
        # first add any child detailed results
        for step in self.steps:
            if isinstance(step, VerificationGroup):
                step.add_detailed_status(messages)

        # add own results
        my_results = {'name': self.name, 'status': self.status.name}
        messages.append(my_results)


class BinaryFileIntegrityChecker(VerificationCheck):
    def __init__(self, content_to_verify, transaction_info):
        self.content_to_verify = content_to_verify
        self.transaction_info = transaction_info

    def do_execute(self):
        blockchain_hash = self.transaction_info.op_return
        local_hash = hashlib.sha256(self.content_to_verify).hexdigest()
        match = hashes_match(blockchain_hash, local_hash)
        if not match:
            logging.error(
                f"BinaryFileIntegrityChecker failed - Blockchain hash: '{blockchain_hash}'' | Local hash: '{local_hash}'"
            )
        return match


class NormalizedJsonLdIntegrityChecker(VerificationCheck):
    def __init__(self, content_to_verify, expected_hash, detect_unmapped_fields=False):
        self.content_to_verify = content_to_verify
        self.expected_hash = expected_hash
        self.detect_unmapped_fields = detect_unmapped_fields

    def do_execute(self):
        try:
            normalized_f = normalize_jsonld(self.content_to_verify, detect_unmapped_fields=False)
            local_hash = hash_normalized(normalized_f)
            cert_hashes_match = hashes_match(local_hash, self.expected_hash)
            if not cert_hashes_match:
                logging.error(
                    f"NormalizedJsonLdIntegrityChecker failed - Expected hash: '{self.expected_hash}'' | Local hash: '{local_hash}'"
                )
            return cert_hashes_match
        except BlockcertValidationError:
            logging.error('Certificate has been modified', exc_info=True)
            return False


class MerkleRootIntegrityChecker(VerificationCheck):
    def __init__(self, expected_merkle_root, actual_merkle_root):
        self.expected_merkle_root = expected_merkle_root
        self.actual_merkle_root = actual_merkle_root

    def do_execute(self):
        merkle_root_matches = hashes_match(self.expected_merkle_root, self.actual_merkle_root)
        if not merkle_root_matches:
            logging.error(f"MerkleRootIntegrityChecker failed - Actual: '{self.actual_merkle_root}' | "
                          f"Expected: '{self.expected_merkle_root}'")
        return merkle_root_matches


class ReceiptIntegrityChecker(VerificationCheck):
    def __init__(self, merkle_proof):
        self.merkle_proof = merkle_proof

    def do_execute(self):
        cp = Chainpoint()
        # overwrite with Chainpoint type before passing to validator
        self.merkle_proof['type'] = 'ChainpointSHA256v2'
        dumped_proof = json.dumps(self.merkle_proof)
        valid_receipt = cp.valid_receipt(dumped_proof)
        if not valid_receipt:
            logging.error(f"ReceiptIntegrityChecker failed - Dumped proof: '{dumped_proof}'")
        return valid_receipt


class NoopChecker(VerificationCheck):
    def __init__(self):
        pass

    def do_execute(self):
        return True


class RevocationChecker(VerificationCheck):
    def __init__(self, values_to_check, revoked_values):
        self.values_to_check = values_to_check
        self.revoked_values = revoked_values

    def do_execute(self):
        revoked = any(k in self.revoked_values for k in self.values_to_check)
        if revoked:
            logging.error('RevocationChecker failed - This certificate has been revoked by the issuer')
        return not revoked


class ExpiredChecker(VerificationCheck):
    def __init__(self, expires):
        self.expires = expires

    def do_execute(self):
        if not self.expires:
            return True
        # compare to current time. If expires_date is timezone naive, we assume UTC
        now_tz = pytz.UTC.localize(datetime.utcnow())
        current = now_tz < self.expires
        if not current:
            logging.error(f"ExpiredChecker failed - Now: '{now_tz}' | Expires: '{self.expires}'")
        return current


class EmbeddedSignatureChecker(VerificationCheck):
    def __init__(self, signing_key, content_to_verify, signature_value, chain=Chain.bitcoin_mainnet):
        self.signing_key = signing_key
        self.content_to_verify = content_to_verify
        self.signature_value = signature_value
        self.chain = chain

    def do_execute(self):

        if self.signing_key is None:
            logging.error('EmbeddedSignatureChecker failed - signing key is none')
            return False
        if self.content_to_verify is None:
            logging.error('EmbeddedSignatureChecker failed - content to verify is none')
            return False
        if self.signature_value is None:
            logging.error('EmbeddedSignatureChecker failed - signature value is none')
            return False
        message = BitcoinMessage(self.content_to_verify)
        try:
            lock.acquire()
            # obtain lock while modifying global state
            bitcoin.SelectParams(chain_to_bitcoin_network(self.chain))
            return VerifyMessage(self.signing_key, message, self.signature_value)
        finally:
            lock.release()


class AuthenticityChecker(VerificationCheck):
    """
    Was transaction signing key valid at transaction signing date?
      - valid means: signing key claimed by issuer + date range (revocation info, etc)
    """

    def __init__(self, transaction_signing_key, transaction_signing_date, issuer_key_map):
        self.transaction_signing_key = transaction_signing_key
        self.transaction_signing_date = transaction_signing_date
        self.issuer_key_map = issuer_key_map

    def do_execute(self):
        signing_key = self.transaction_signing_key.casefold()
        issuer_keys = {k.casefold(): v for k, v in self.issuer_key_map.items()}
        if signing_key in issuer_keys:
            key = issuer_keys[signing_key]
            res = True
            if key.created:
                created_ok = self.transaction_signing_date >= key.created
                if not created_ok:
                    logging.error('AuthenticityChecker failed - transaction_signing_date >= key.created.')
                res &= created_ok
            if key.revoked:
                revoked_ok = self.transaction_signing_date <= key.revoked
                if not revoked_ok:
                    logging.error('AuthenticityChecker failed - transaction_signing_date >= key.revoked.')
                res &= revoked_ok
            if key.expires:
                expired_ok = self.transaction_signing_date <= key.expires
                if not expired_ok:
                    logging.error('AuthenticityChecker failed - transaction_signing_date <= key.expires')
                res &= expired_ok
            return res
        else:
            logging.error(
                f'Transaction signing key "{signing_key}" can\'t be found among the keys in the '
                f'issuer profile: "{issuer_keys}".'
            )
            return False


# Verification group creators

def create_embedded_signature_verification_group(signatures, transaction_info, chain):
    signature_check = None
    for s in signatures:
        if s.signature_type == SignatureType.signed_content:
            signature_check = EmbeddedSignatureChecker(transaction_info.signing_key, s.content_to_verify,
                                                       s.signature_value, chain)
            break

    return VerificationGroup(steps=[signature_check], name='Checking issuer signature')


def create_anchored_data_verification_group(signatures, chain, transaction_info, detect_unmapped_fields=False):
    anchored_data_verification = None
    for s in signatures:
        if s.signature_type == SignatureType.signed_transaction:
            if s.merkle_proof:
                steps = [ReceiptIntegrityChecker(s.merkle_proof.proof_json),
                         NormalizedJsonLdIntegrityChecker(s.content_to_verify, s.merkle_proof.target_hash,
                                                          detect_unmapped_fields=detect_unmapped_fields)]
                if chain != Chain.mockchain and chain != Chain.bitcoin_regtest:
                    steps.append(MerkleRootIntegrityChecker(s.merkle_proof.merkle_root, transaction_info.op_return))

                anchored_data_verification = VerificationGroup(
                    steps=steps,
                    name='Checking certificate has not been tampered with')
            else:
                anchored_data_verification = VerificationGroup(
                    steps=[BinaryFileIntegrityChecker(s.content_to_verify, transaction_info)],
                    name='Checking certificate has not been tampered with')

            break
    return anchored_data_verification


def create_revocation_verification_group(certificate_model, issuer_info, transaction_info):
    if issuer_info.revocation_keys:
        revocation_check = RevocationChecker(certificate_model.revocation_addresses,
                                             transaction_info.revoked_addresses)
    elif issuer_info.revoked_assertions:
        revocation_check = RevocationChecker([certificate_model.uid], issuer_info.revoked_assertions)
    else:
        revocation_check = NoopChecker()

    return VerificationGroup(steps=[revocation_check], name='Checking not revoked by issuer')


def create_verification_steps(certificate_model, transaction_info, issuer_info, chain):
    steps = []

    v2ish = certificate_model.version == BlockcertVersion.V2 or certificate_model.version == BlockcertVersion.V2_ALPHA

    # embedded signature: V1.1. and V1.2 must have this
    if not v2ish:
        embedded_signature_group = create_embedded_signature_verification_group(certificate_model.signatures,
                                                                                transaction_info, chain)
        if not embedded_signature_group:
            raise InvalidCertificateError('Did not find signature verification info in certificate')
        steps.append(embedded_signature_group)

    # transaction-anchored data. All versions must have this. In V2 we add an extra check for unmapped fields
    detect_unmapped_fields = v2ish
    transaction_signature_group = create_anchored_data_verification_group(certificate_model.signatures,
                                                                          chain,
                                                                          transaction_info,
                                                                          detect_unmapped_fields)
    if not transaction_signature_group:
        raise InvalidCertificateError('Did not find transaction verification info in certificate')
    steps.append(transaction_signature_group)

    # expiration check. All versions have this as an option.
    expired_group = ExpiredChecker(certificate_model.expires)
    steps.append(VerificationGroup(steps=[expired_group],
                                   name='Checking certificate has not expired'))

    # revocation check. All versions have this
    revocation_group = create_revocation_verification_group(certificate_model, issuer_info, transaction_info)
    steps.append(revocation_group)

    # authenticity check
    if chain != Chain.mockchain and chain != Chain.bitcoin_regtest:
        key_map = {k.public_key: k for k in issuer_info.issuer_keys}
        authenticity_checker = AuthenticityChecker(transaction_info.signing_key, transaction_info.date_time_utc,
                                                   key_map)
        steps.append(VerificationGroup(steps=[authenticity_checker],
                                       name='Checking authenticity'))

    if chain == Chain.mockchain or chain == Chain.bitcoin_regtest:
        return VerificationGroup(steps=steps, name='Validation', success_status=StepStatus.mock_passed)
    return VerificationGroup(steps=steps, name='Validation')
