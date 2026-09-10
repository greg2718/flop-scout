"""Frozen pure Router evidence rules for router-evidence-classes/2.

Copied from Router for exact complete-group semantics; no Router runtime import,
network, identity, filesystem or database operations. Changes require policy review.
"""
from __future__ import annotations
from dataclasses import dataclass, field, replace
from collections import Counter
from typing import Iterable
import re
import unicodedata

ROUTER_SOURCE_SHA256 = '30ac18aa715ea7a905f8c4a76e9a35def2fe432a3e96cba863536d5f7d10d71d'

UNKNOWN_GENERATION = "UNKNOWN_LEGACY"

@dataclass(frozen=True)
class AgentIdentity:
    did: str
    network: str = "technocore"

@dataclass(frozen=True)
class AgentObservation:
    identity: AgentIdentity
    room: str
    sequence_id: int
    timestamp: str | None
    text: str
    normalized_text: str
    template_hash: str
    is_signed: bool
    template_dids: int = 1
    generation: str = UNKNOWN_GENERATION
    server_timestamp: str | None = None
    nonce: str | None = None
    sig: str | None = None
    message_hash: str | None = None
    verification_status: str = "LEGACY_SERVER_VERIFIED_NO_SIGNATURE"
    source_export_hash: str | None = None
    source_export_path: str | None = None
    evidence_id: str | None = None

    @property
    def location_id(self) -> str:
        return f"{self.room} generation {self.generation} seq {self.sequence_id}"

@dataclass(frozen=True)
class EvidenceItem:
    room: str
    seq: int
    timestamp: str | None
    sequence_id: str
    text: str
    evidence_type: str
    specificity: float
    usable: bool
    strong: bool
    reasons: list[str]
    generation: str = UNKNOWN_GENERATION
    did: str | None = None
    nonce: str | None = None
    sig: str | None = None
    message_hash: str | None = None
    verification_status: str = "PROVENANCE_INCOMPLETE"
    source_export_hash: str | None = None
    source_export_path: str | None = None
    evidence_id: str | None = None

@dataclass(frozen=True)
class CapabilityEvidenceDecision:
    capability_id: str
    observation_id: str
    relevant: bool
    relevance_basis: str
    matched_patterns: list[str]
    evidence_type: str
    evidence_quality: str
    support_contribution: str
    passed_threshold: bool
    reason: str
    evidence: EvidenceItem

@dataclass(frozen=True)
class CapabilityRule:
    capability_id: str
    strong_patterns: tuple[str, ...]
    weak_patterns: tuple[str, ...] = ()

CAPABILITY_RULES = [
    CapabilityRule("technocore.api", ("technocore api", "/r/", "format=json", "http 400", "endpoint", "api compatibility")),
    CapabilityRule("technocore.signed_post", ("signed post", "nonce", "ed25519 signature", "signature verifies", "post failure", "signed-post")),
    CapabilityRule("technocore.did", ("did:key", "did rotation", "did identity", "ed25519", "public key", "key lifecycle")),
    CapabilityRule("technocore.protocol", ("auth.md", "patterns.md", "llms.txt", "protocol", "room schema", "message payload")),
    CapabilityRule("technocore.observer", ("observer", "sequence", "seq", "room log", "dedup", "template normalization", "network analytics")),
    CapabilityRule("security.prompt_injection", ("prompt injection", "untrusted message", "hostile input", "jailbreak", "instruction injection")),
    CapabilityRule("security.smart_contract", ("smart contract security", "reentrancy", "audit", "vulnerability", "access control")),
    CapabilityRule("security.general", ("threat model", "security", "exploit", "risk", "validation", "sanitiz")),
    CapabilityRule("blockchain.solidity", ("solidity", "contract", "hardhat", "foundry", "evm")),
    CapabilityRule("blockchain.ethereum", ("ethereum", "evm", "erc20", "erc-20", "gas", "mainnet")),
    CapabilityRule("blockchain.solana", ("solana", "anchor", "spl token", "program derived", "pda")),
    CapabilityRule("blockchain.defi", ("defi", "liquidity", "swap", "amm", "staking", "yield")),
    CapabilityRule("software.python", ("python", "sqlite", "pytest", "unittest", "venv", ".py")),
    CapabilityRule("software.javascript", ("javascript", "typescript", "node", "npm", "react", "fetch")),
    CapabilityRule("software.rust", ("rust", "cargo", "borrow checker", "crate", "tokio")),
    CapabilityRule("software.testing", ("test case", "test cases", "fixture", "regression", "assert", "bug report", "unit test", "edge case")),
    CapabilityRule("software.debugging", ("debug", "failure", "trace", "stack", "bisect", "root cause", "diagnosed", "isolated")),
    CapabilityRule("software.api", ("api", "http", "json", "request", "response", "endpoint", "compatibility")),
    CapabilityRule("research.crypto", ("crypto research", "cryptographic", "signature scheme", "protocol research", "ed25519")),
    CapabilityRule("research.market", ("market research", "market structure", "liquidity", "order book", "pricing")),
    CapabilityRule("research.technical", ("technical research", "compare implementations", "spec", "documentation", "benchmark")),
    CapabilityRule("data.market_data", ("market data", "ohlcv", "price feed", "order book", "volume", "spread")),
    CapabilityRule("data.onchain", ("onchain", "on-chain", "block explorer", "transaction data", "wallet graph")),
    CapabilityRule("data.analytics", ("analytics", "dashboard", "metrics", "feature store", "signals", "dataset")),
    CapabilityRule("ai.agent_frameworks", ("agent framework", "mcp", "a2a", "tool calling", "agent integration", "orchestration")),
    CapabilityRule("ai.inference", ("inference", "model", "llm", "latency", "tokens", "sampling")),
    CapabilityRule("ai.model_evaluation", ("model evaluation", "eval", "benchmark", "rubric", "judge")),
]

def normalize_text(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = re.sub(r"https?://\S+|www\.\S+", "<url>", text, flags=re.I)
    text = re.sub(r"\s+", " ", text).strip().casefold()
    return text

def template_count_key(obs: AgentObservation) -> str:
    return f"{obs.room}:{obs.generation}:{obs.template_hash}"

def pattern_matches(text: str, pattern: str) -> bool:
    pattern = pattern.casefold()
    if re.search(r"^[a-z0-9][a-z0-9_ -]*[a-z0-9]$", pattern):
        expr = r"(?<![a-z0-9])" + re.escape(pattern).replace(r"\ ", r"\s+") + r"(?![a-z0-9])"
        return bool(re.search(expr, text))
    return pattern in text

def is_template_or_noise(text: str, duplicate_count: int = 1, template_dids: int = 1) -> bool:
    t = normalize_text(text)
    if duplicate_count > 1 or template_dids > 1:
        return True
    noise_patterns = (
        r"\b(checking in|check-in|daily check|present and signed|autonomous agent active|ready for \$flop)\b",
        r"\b(airdrop|snapshot|referral|promo|claim|powered by)\b",
        r"\b(node synced|signed\.?$|hello\.? i am active|maintained before the next epoch)\b",
        r"^[\w .:-]*(did:key:z6mk|did [a-z0-9]{8,})[\w .:-]*$",
    )
    return any(re.search(pattern, t) for pattern in noise_patterns)

def is_promotional(text: str) -> bool:
    return bool(re.search(r"\b(airdrop|claim|snapshot|referral|promo|ready for \$flop|expert for hire|hire me)\b", normalize_text(text)))

def is_substantive(text: str) -> bool:
    if len(text.split()) < 7:
        return False
    t = normalize_text(text)
    signals = (
        "because", "verified", "reproduce", "tested", "debug", "debugged", "traced",
        "diagnosed", "isolated", "fixed", "failure", "implementation",
        "schema", "nonce", "signature", "risk", "vulnerability", "dataset", "metrics",
        "observed", "compare", "regression", "root cause", "evidence",
    )
    return any(signal in t for signal in signals)

def evidence_type_for(text: str, *, duplicate_count: int = 1, template_dids: int = 1) -> str:
    t = normalize_text(text)
    if is_template_or_noise(text, duplicate_count=duplicate_count, template_dids=template_dids):
        return "TEMPLATE"
    if is_promotional(text):
        return "PROMOTIONAL"
    if re.search(r"\b(i am|i'm|i can|happy to|available to|looking for|expert|specialist|specializes in|experienced with|can help with|know)\b", t) and not re.search(
        r"\b(tested|reproduce|verified|implemented|debugged|observed|returned|failing|root cause)\b", t
    ):
        return "SELF_ASSERTED"
    if re.search(r"\b(reproduce|reproduced|fixture|regression|test case|bug report)\b", t):
        return "REPRODUCED"
    if re.search(r"\b(implementation|schema|endpoint|payload|nonce|signature verifies|http 400|sqlite|json|stack trace|root cause|traced|diagnosed|isolated|fixed)\b", t):
        return "IMPLEMENTATION_DETAIL"
    if re.search(r"\b(yes|answer|because|must|should|the fix|try)\b", t):
        return "TECHNICAL_RESPONSE"
    return "DEMONSTRATED" if is_substantive(text) else "TOPIC_MENTION"

def self_asserted_capability_claim(text: str) -> bool:
    return bool(re.search(
        r"\b(i can|happy to|available to|looking for|my agent specializes|specializes in|can help|help debug|debug if anyone|for hire)\b",
        normalize_text(text),
    ))

def testing_behavior_context(text: str) -> str:
    t = normalize_text(text)
    if re.search(r"\b(workflow|documentation|docs|setup|steps|guide|explainer|onboarding)\b", t):
        return "none"
    if re.search(r"\b(consensus validation|cross-attest|attest|attestation|compute result|proof|validated by|cryptographic verification|verify your did)\b", t):
        return "none"
    if re.search(r"\b(reproduce|reproduced)\b", t) and re.search(r"\b(bug|failure|failing|error|http \d{3}|edge case|test result|regression|fixture)\b", t):
        return "strong"
    if re.search(r"\b(ran|created|wrote|added|implemented|built)\b", t) and re.search(r"\b(test|tests|test case|fixture|regression|assertion)\b", t):
        return "strong"
    if re.search(r"\b(unit test|test case|fixture|regression assertion|regression assertions)\b", t) and re.search(r"\b(api behavior|failure|expected|edge case|condition|conditions)\b", t):
        return "strong"
    if re.search(r"\b(test|testing|fixture|regression|assert|bug report|edge case)\b", t):
        return "limited"
    return "none"

def debugging_behavior_context(text: str) -> str:
    t = normalize_text(text)
    if self_asserted_capability_claim(t) and not re.search(r"\b(traced|diagnosed|isolated|root cause|debugged|fixed|reproduced)\b", t):
        return "signal"
    if (
        re.search(r"\b(returned http \d{3}|http \d{3}|failed|failure|error)\b", t)
        and re.search(r"\b(legacy|current|sharded|endpoint|path|configuration|config|condition|because|caused by|traced to|isolated to)\b", t)
        and re.search(r"\b(switching|changed|changing|change|fixed|resolved|succeeds after|succeeded after|works after)\b", t)
    ):
        return "strong"
    if re.search(r"\b(traced|diagnosed|isolated|root cause|debugged|fixed)\b", t) and re.search(
        r"\b(403|429|nonce|skew|failure|failing|bug|error|http \d{3}|stack trace|payload|response)\b", t
    ):
        return "strong"
    if re.search(r"\b(the failure occurs|fails when|failed when|reproduced the bug)\b", t):
        return "strong"
    if re.search(r"\b(reproduce|reproduced)\b", t) and re.search(r"\b(bug|failure|failing|error|http \d{3}|nonce reuse)\b", t):
        return "strong"
    if re.search(r"\b(debug|failure|failing|bug|error|stack trace|root cause)\b", t):
        return "limited"
    return "none"

def signed_post_behavior_context(text: str) -> str:
    t = normalize_text(text)
    if re.search(r"\b(signed post|signed write|signed writes|signer|signature|nonce|ed25519)\b", t) and re.search(
        r"\b(verified|handles|flowing|monotonic|increment|payload|http \d{3}|returned|reused|reuse|failure)\b", t
    ):
        return "strong"
    if re.search(r"\b(signed post|signed write|signed writes|signer|signature|nonce|ed25519)\b", t):
        return "limited"
    return "none"

def capability_behavior_context(capability_id: str, text: str) -> str:
    if capability_id == "software.testing":
        return testing_behavior_context(text)
    if capability_id == "software.debugging":
        return debugging_behavior_context(text)
    if capability_id == "technocore.signed_post":
        return signed_post_behavior_context(text)
    return "generic"

def context_relevance_basis(context: str, text: str) -> str:
    if context in {"limited", "strong"}:
        return "CONTEXTUAL_BEHAVIOR"
    if context == "signal":
        return "SELF_ASSERTION" if self_asserted_capability_claim(text) else "TOPIC_SIGNAL"
    return "NONE"

def evidence_quality_label(evidence: EvidenceItem) -> str:
    if evidence.strong:
        return "STRONG"
    if evidence.usable:
        return "USABLE"
    return "LOW"

def raw_capability_evidence_decision(
    obs: AgentObservation,
    rule: CapabilityRule,
    duplicate_count: int,
) -> CapabilityEvidenceDecision:
    evidence = assess_evidence(obs, duplicate_count=duplicate_count)
    text = normalize_text(obs.text)
    matched = [pattern for pattern in rule.strong_patterns if pattern_matches(text, pattern)]
    weak_matched = [pattern for pattern in rule.weak_patterns if pattern_matches(text, pattern)]
    context = capability_behavior_context(rule.capability_id, obs.text)
    observation_id = obs.location_id
    evidence_quality = evidence_quality_label(evidence)

    if context == "none":
        reason = "semantic object does not match this capability" if matched or weak_matched else "no strict capability pattern matched"
        return CapabilityEvidenceDecision(
            capability_id=rule.capability_id,
            observation_id=observation_id,
            relevant=False,
            relevance_basis="NONE",
            matched_patterns=matched + weak_matched,
            evidence_type=evidence.evidence_type,
            evidence_quality=evidence_quality,
            support_contribution="NONE",
            passed_threshold=False,
            reason=reason,
            evidence=evidence,
        )

    if context in {"signal", "limited", "strong"}:
        if context == "signal":
            return CapabilityEvidenceDecision(
                capability_id=rule.capability_id,
                observation_id=observation_id,
                relevant=True,
                relevance_basis=context_relevance_basis(context, obs.text),
                matched_patterns=matched + weak_matched,
                evidence_type=evidence.evidence_type,
                evidence_quality=evidence_quality,
                support_contribution="SIGNAL",
                passed_threshold=False,
                reason="self-asserted or weak signal, not demonstrated behavior",
                evidence=evidence,
            )
        if not evidence.usable:
            return CapabilityEvidenceDecision(
                capability_id=rule.capability_id,
                observation_id=observation_id,
                relevant=True,
                relevance_basis="CONTEXTUAL_BEHAVIOR",
                matched_patterns=matched + weak_matched,
                evidence_type=evidence.evidence_type,
                evidence_quality=evidence_quality,
                support_contribution="SIGNAL",
                passed_threshold=False,
                reason=", ".join(evidence.reasons) if evidence.reasons else "insufficient evidence quality",
                evidence=evidence,
            )
        if rule.capability_id == "software.debugging" and context == "strong":
            reason = "observed failure + concrete condition/change + reported successful fix"
        else:
            reason = "contextual behavior matched this capability"
        adjusted = replace(evidence, strong=True) if context == "strong" else replace(evidence, strong=False)
        return CapabilityEvidenceDecision(
            capability_id=rule.capability_id,
            observation_id=observation_id,
            relevant=True,
            relevance_basis="CONTEXTUAL_BEHAVIOR",
            matched_patterns=matched + weak_matched,
            evidence_type=adjusted.evidence_type,
            evidence_quality=evidence_quality_label(adjusted),
            support_contribution="STRONG" if context == "strong" else "LIMITED",
            passed_threshold=True,
            reason=reason,
            evidence=adjusted,
        )

    if matched:
        if not evidence.usable:
            return CapabilityEvidenceDecision(
                capability_id=rule.capability_id,
                observation_id=observation_id,
                relevant=True,
                relevance_basis="TOPIC_SIGNAL",
                matched_patterns=matched,
                evidence_type=evidence.evidence_type,
                evidence_quality=evidence_quality,
                support_contribution="SIGNAL",
                passed_threshold=False,
                reason=", ".join(evidence.reasons) if evidence.reasons else "strict pattern matched but evidence quality is insufficient",
                evidence=evidence,
            )
        return CapabilityEvidenceDecision(
            capability_id=rule.capability_id,
            observation_id=observation_id,
            relevant=True,
            relevance_basis="STRICT_PATTERN",
            matched_patterns=matched,
            evidence_type=evidence.evidence_type,
            evidence_quality=evidence_quality,
            support_contribution="STRONG" if evidence.strong else "LIMITED",
            passed_threshold=True,
            reason="strict capability pattern matched",
            evidence=evidence,
        )

    if weak_matched:
        return CapabilityEvidenceDecision(
            capability_id=rule.capability_id,
            observation_id=observation_id,
            relevant=True,
            relevance_basis="TOPIC_SIGNAL",
            matched_patterns=weak_matched,
            evidence_type=evidence.evidence_type,
            evidence_quality=evidence_quality,
            support_contribution="SIGNAL",
            passed_threshold=False,
            reason="weak capability pattern matched",
            evidence=evidence,
        )

    return CapabilityEvidenceDecision(
        capability_id=rule.capability_id,
        observation_id=observation_id,
        relevant=False,
        relevance_basis="NONE",
        matched_patterns=[],
        evidence_type=evidence.evidence_type,
        evidence_quality=evidence_quality,
        support_contribution="NONE",
        passed_threshold=False,
        reason="no strict capability pattern matched",
        evidence=evidence,
    )

def capability_evidence_decisions(
    observations: Iterable[AgentObservation],
    capability_id: str,
    duplicate_counts: Counter[str] | None = None,
) -> list[CapabilityEvidenceDecision]:
    rule = next((rule for rule in CAPABILITY_RULES if rule.capability_id == capability_id), None)
    if not rule:
        return []
    observations = list(observations)
    duplicate_counts = duplicate_counts or Counter(template_count_key(obs) for obs in observations)
    decisions = []
    seen_templates: set[str] = set()
    for obs in observations:
        decision = raw_capability_evidence_decision(obs, rule, duplicate_counts[template_count_key(obs)])
        template_key = f"{obs.room}:{obs.generation}:{obs.template_hash or decision.observation_id}"
        if decision.support_contribution != "NONE":
            if template_key in seen_templates:
                decision = replace(
                    decision,
                    support_contribution="NONE",
                    passed_threshold=False,
                    reason=f"{decision.reason}; duplicate template already counted",
                )
            else:
                seen_templates.add(template_key)
        decisions.append(decision)
    return decisions

def specificity_score(text: str) -> float:
    t = normalize_text(text)
    score = 0.0
    score += 0.20 if len(text.split()) >= 10 else 0.0
    score += 0.20 if re.search(r"\b(http \d{3}|/r/|format=json|sqlite|json|nonce|seq|signature|fixture|regression|root cause)\b", t) else 0.0
    score += 0.20 if re.search(r"\b(returned|verified|reproduce|reproduced|tested|implemented|observed|debugged|traced|diagnosed|isolated|fixed|failed|failing)\b", t) else 0.0
    score += 0.20 if re.search(r"\b(because|when|after|against|with|without)\b", t) else 0.0
    score += 0.20 if re.search(r"\b(ed25519|did:key|technocore|solidity|reentrancy|prompt injection|market data|api)\b", t) else 0.0
    return min(1.0, score)

def assess_evidence(obs: AgentObservation, duplicate_count: int = 1) -> EvidenceItem:
    evidence_type = evidence_type_for(
        obs.text,
        duplicate_count=duplicate_count,
        template_dids=obs.template_dids,
    )
    specificity = specificity_score(obs.text)
    reasons = []
    if evidence_type in {"TEMPLATE", "PROMOTIONAL"}:
        reasons.append(evidence_type.lower())
    if evidence_type == "SELF_ASSERTED":
        reasons.append("self_asserted")
    if obs.verification_status == "INVALID_SIGNATURE":
        reasons.append("invalid_signature")
    if obs.verification_status == "PROVENANCE_INCOMPLETE":
        reasons.append("provenance_incomplete")
    if specificity < 0.55:
        reasons.append("low_specificity")
    substantive = is_substantive(obs.text)
    if not substantive:
        reasons.append("not_substantive")
    usable = obs.verification_status != "INVALID_SIGNATURE" and substantive and specificity >= 0.55 and evidence_type in {
        "DEMONSTRATED",
        "TECHNICAL_RESPONSE",
        "REPRODUCED",
        "IMPLEMENTATION_DETAIL",
    }
    strong = usable and (
        evidence_type in {"REPRODUCED", "IMPLEMENTATION_DETAIL"} and specificity >= 0.75
    )
    return EvidenceItem(
        room=obs.room,
        seq=obs.sequence_id,
        timestamp=obs.server_timestamp or obs.timestamp,
        sequence_id=obs.location_id,
        text=obs.text[:220],
        evidence_type=evidence_type,
        specificity=round(specificity, 2),
        usable=usable,
        strong=strong,
        reasons=reasons,
        generation=obs.generation,
        did=obs.identity.did,
        nonce=obs.nonce,
        sig=obs.sig,
        message_hash=obs.message_hash,
        verification_status=obs.verification_status,
        source_export_hash=obs.source_export_hash,
        source_export_path=obs.source_export_path,
        evidence_id=obs.evidence_id,
    )
