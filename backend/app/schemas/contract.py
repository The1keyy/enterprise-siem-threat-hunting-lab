"""Pydantic models for the shared /fixtures JSON files."""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

SeverityName = Literal["critical", "high", "medium", "low", "info"]
AlertSeverity = Literal["critical", "high", "medium", "low"]
IncidentStatusName = Literal[
    "New",
    "Investigating",
    "Contained",
    "Resolved",
    "False Positive",
]
ValidationName = Literal[
    "NOT TESTED",
    "SYNTAX VALID",
    "LOGTEST VALID",
    "LAB VALIDATED",
    "NEEDS TUNING",
]
HealthName = Literal["Healthy", "Degraded", "Offline"]
AssetType = Literal["workstation", "server", "domain_controller"]
TimelineSource = Literal[
    "windows_security",
    "sysmon",
    "powershell",
    "linux_auth",
    "auditd",
]
TelemetryName = Literal[
    "windows_security",
    "sysmon",
    "powershell",
    "linux_auth",
    "auditd",
    "suricata",
]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class NoticeFile(Strict):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    notice: str = Field(alias="_notice")


class MitreTechnique(Strict):
    id: str
    name: str
    tactic: str


class OverviewKpis(Strict):
    demo: Literal[True]
    activeIncidents: int
    criticalAlerts24h: int
    highAlerts24h: int
    monitoredEndpoints: int
    detectionRulesEnabled: int
    eventsIngested24h: int
    meanTimeToInvestigateMinutes: int | None


class AlertTimeBucket(Strict):
    demo: Literal[True]
    bucketStart: str
    label: str
    critical: int
    high: int
    medium: int
    low: int


class SeverityTotal(Strict):
    demo: Literal[True]
    severity: AlertSeverity
    count: int


class TacticTotal(Strict):
    demo: Literal[True]
    tactic: str
    count: int


class CountBucket(Strict):
    demo: Literal[True]
    bucketStart: str
    label: str
    count: int


class RankedCount(Strict):
    demo: Literal[True]
    label: str
    count: int


class RankedRisk(Strict):
    demo: Literal[True]
    name: str
    detail: str
    riskScore: int


class OverviewIncident(Strict):
    demo: Literal[True]
    id: str
    title: str
    severity: AlertSeverity
    status: IncidentStatusName
    host: str
    user: str
    lastSeen: str


class RecentDetection(Strict):
    demo: Literal[True]
    id: str
    name: str
    severity: AlertSeverity
    host: str
    time: str


class TechniqueChip(Strict):
    demo: Literal[True]
    id: str
    name: str


class HealthSignal(Strict):
    demo: Literal[True]
    name: str
    status: HealthName
    lastEvent: str


class OverviewFile(NoticeFile):
    demo: Literal[True]
    generatedAt: str
    kpis: OverviewKpis
    alertsOverTime: list[AlertTimeBucket]
    alertsBySeverity: list[SeverityTotal]
    alertsByTactic: list[TacticTotal]
    authFailuresOverTime: list[CountBucket]
    topSourceIps: list[RankedCount]
    topTargetedUsers: list[RankedCount]
    topRiskyHosts: list[RankedRisk]
    topRiskyUsers: list[RankedRisk]
    incidents: list[OverviewIncident]
    recentDetections: list[RecentDetection]
    activeTechniques: list[TechniqueChip]
    health: list[HealthSignal]


class TimelineEvent(Strict):
    time: str
    title: str
    source: TimelineSource
    host: str
    user: str
    eventId: str
    ruleId: str
    severity: SeverityName
    raw: dict[str, Any]


class EntitiesBlock(Strict):
    users: list[str]
    hosts: list[str]
    srcIps: list[str]
    dstIps: list[str]
    processes: list[str]
    domains: list[str]
    hashes: list[str]


class RiskItem(Strict):
    event: str
    ruleId: str
    points: int


class RiskBreakdown(Strict):
    items: list[RiskItem]
    subtotal: int
    assetType: AssetType
    multiplier: float
    final: int
    severityBand: SeverityName


class NoteModel(Strict):
    id: str
    author: str
    time: str
    text: str


class AuditModel(Strict):
    id: str
    action: str
    target: str
    time: str
    message: str


class IncidentDetailModel(Strict):
    id: str
    title: str
    severity: SeverityName
    riskScore: int
    status: IncidentStatusName
    owner: str
    users: list[str]
    hosts: list[str]
    mitre: list[MitreTechnique]
    firstSeen: str
    lastSeen: str
    demo: Literal[True]
    timeline: list[TimelineEvent]
    entities: EntitiesBlock
    risk: RiskBreakdown
    notes: list[NoteModel]
    disposition: Literal["Undetermined", "True positive", "Benign", "False positive"]
    summary: str
    recommendedContainment: list[str]
    audit: list[AuditModel]


class IncidentFile(NoticeFile):
    incidents: list[IncidentDetailModel]


class TuningChange(Strict):
    time: str
    author: str
    note: str


class DetectionModel(Strict):
    id: str
    name: str
    description: str
    severity: AlertSeverity
    mitre: list[MitreTechnique]
    telemetry: list[TelemetryName]
    wazuhRuleIds: list[str]
    version: str
    enabled: bool
    status: ValidationName
    windowsValidationRequired: bool
    falsePositives: str
    tuningNotes: str
    testProcedure: str
    expectedEvent: str
    expectedAlert: str
    observedResult: str
    lastTriggered: str | None
    alertCount: int | None
    wazuhRuleXml: str
    sigmaYaml: str
    tuningHistory: list[TuningChange]
    demo: Literal[True]


class DetectionFile(NoticeFile):
    detections: list[DetectionModel]


class HuntModel(Strict):
    id: str
    name: str
    hypothesis: str
    dataSource: str
    query: str
    expectedBehavior: str
    suspiciousBehavior: str
    mitre: list[MitreTechnique]
    investigationGuidance: str
    status: ValidationName
    demo: Literal[True]


class HuntFile(NoticeFile):
    hunts: list[HuntModel]


class EntityRowModel(Strict):
    name: str
    riskScore: int
    incidentIds: list[str]
    lastActivity: str | None


class NamedLink(Strict):
    id: str
    name: str


class RiskLine(Strict):
    incidentId: str
    title: str
    subtotal: int
    multiplier: float
    assetType: AssetType
    final: int


class HistoryPoint(Strict):
    label: str
    score: int


class LoginRow(Strict):
    time: str
    host: str
    sourceIp: str
    logonType: str
    result: Literal["success", "fail"]


class UserProfileModel(EntityRowModel):
    sourceIps: list[str]
    endpoints: list[str]
    detections: list[NamedLink]
    incidents: list[NamedLink]
    mitre: list[MitreTechnique]
    logins: list[LoginRow]
    history: list[HistoryPoint]
    lines: list[RiskLine]


class HostConnection(Strict):
    time: str
    src: str
    dst: str
    detail: str


class ProcessCount(Strict):
    name: str
    count: int


class HostProfileModel(EntityRowModel):
    ip: str
    os: str
    assetType: AssetType
    multiplier: float
    agentStatus: Literal["never connected"]
    users: list[str]
    processes: list[ProcessCount]
    detections: list[NamedLink]
    incidents: list[NamedLink]
    connections: list[HostConnection]
    history: list[HistoryPoint]
    lines: list[RiskLine]


class EntityFile(NoticeFile):
    users: list[EntityRowModel]
    hosts: list[EntityRowModel]
    userProfiles: list[UserProfileModel]
    hostProfiles: list[HostProfileModel]


class VolumePoint(Strict):
    label: str
    count: int


class SourceCard(Strict):
    id: str
    name: str
    status: HealthName
    optional: bool
    hosts: list[str]
    agent: str
    lastEvent: str | None
    volume: list[VolumePoint]
    ingestionErrors: int | None
    windowsValidationRequired: bool


class SourceFile(NoticeFile):
    sources: list[SourceCard]


class HealthComponent(Strict):
    id: str
    name: str
    status: HealthName
    version: str
    lastCheck: str | None


class AgentModel(Strict):
    name: str
    ip: str
    os: str
    status: Literal["active", "disconnected", "never connected"]
    version: str | None
    lastKeepAlive: str | None
    lastTelemetry: str | None


class HealthFile(NoticeFile):
    components: list[HealthComponent]
    pipeline: list[str]
    agents: list[AgentModel]
    diskPercent: float | None
    failedIngestion: int | None
    activeRules: int


FIXTURE_MODELS: dict[str, type[NoticeFile]] = {
    "overview.json": OverviewFile,
    "incidents.json": IncidentFile,
    "detections.json": DetectionFile,
    "hunts.json": HuntFile,
    "entities.json": EntityFile,
    "sources.json": SourceFile,
    "health.json": HealthFile,
}
