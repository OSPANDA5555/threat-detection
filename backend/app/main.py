from fastapi import FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
import time
import uuid


from app.config import settings
from app.tools.gateway import ToolGateway
from app.schemas.tool import ToolDefinition, ToolExecutionRequest, ToolExecutionResult
from app.schemas.hunt import Hunt, HuntPlanStep, HuntStatus, HypothesisState, ExecutionMode
from app.schemas.evidence import Evidence, EvidenceSource
from app.schemas.finding import Finding, Severity
from app.telemetry.models import EvaluationReport, EvaluationRun
from app.security.adversarial import AdversarialSecurityReport, AdversarialTestEngine
from app.hunting.engine import AutonomousHuntingEngine, HUNT_STATE_STORE
from app.hunting.graph import InvestigationGraphBuilder
from app.telemetry.generator import telemetry_engine
from app.telemetry.evaluation import EvaluationEngine
from app.telemetry.lab import EvaluationLabRunner, EVALUATION_RUN_STORE
from app.core.security import check_rate_limit






# Initialize FastAPI application
app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Autonomous Threat-Hunting Copilot Backend — Phase 1 Foundation API",
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    docs_url="/docs"
)

from fastapi import Request
from fastapi.responses import JSONResponse
from app.core.security import check_rate_limit

# CORS: never combine a wildcard origin with credentials (browsers reject it
# and it weakens the security posture). Fall back to explicit origins.
_cors_origins = settings.cors_origin_list()
_cors_allow_credentials = True
if "*" in _cors_origins:
    _cors_allow_credentials = False

# Set up CORS middleware for frontend UI access
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=_cors_allow_credentials,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

@app.middleware("http")
async def add_security_headers_and_rate_limit(request: Request, call_next):
    # Rate Limiting Check (bounds from settings, overridable via .env)
    client_ip = request.client.host if request.client else "127.0.0.1"
    allowed, msg = check_rate_limit(
        client_ip,
        max_requests=settings.RATE_LIMIT_MAX_REQUESTS,
        window_seconds=settings.RATE_LIMIT_WINDOW_SECONDS,
    )
    if not allowed:
        return JSONResponse(status_code=429, content={"detail": msg})

    request.state.request_id = f"req-{uuid.uuid4().hex[:12]}"
    response = await call_next(request)
    
    # Secure HTTP Headers
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; font-src 'self' data:;"
    response.headers["X-Request-ID"] = getattr(request.state, "request_id", "")
    return response


@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError):
    return JSONResponse(status_code=400, content={"detail": str(exc)})


# In-memory cache for the expensive adversarial suite (re-running 8 full
# hunts per GET was a self-inflicted DoS vector).
_ADVERSARIAL_CACHE: Dict[str, Any] = {"report": None, "timestamp": 0.0}


async def _get_cached_adversarial_report() -> AdversarialSecurityReport:
    now = time.time()
    ttl = settings.ADVERSARIAL_CACHE_TTL_SECONDS
    cached = _ADVERSARIAL_CACHE["report"]
    if cached is not None and (ttl <= 0 or now - _ADVERSARIAL_CACHE["timestamp"] < ttl):
        return cached
    report = await AdversarialTestEngine.run_security_test_suite()
    _ADVERSARIAL_CACHE["report"] = report
    _ADVERSARIAL_CACHE["timestamp"] = now
    return report

# Global Tool Gateway Instance
gateway = ToolGateway()


@app.get("/")
async def root():
    return {
        "project": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "status": "ONLINE",
        "docs": "/docs"
    }

@app.get(f"{settings.API_V1_STR}/health", tags=["Health"])
async def health_check() -> Dict[str, Any]:
    """
    System Health Check Endpoint.
    Returns backend status, environment, registered tool count, and active security controls.
    """
    registered_tools = gateway.get_registered_tools()
    return {
        "status": "HEALTHY",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "environment": settings.ENVIRONMENT,
        "version": settings.VERSION,
        "tool_gateway": {
            "status": "ACTIVE",
            "enforce_read_only": settings.ENFORCE_READ_ONLY,
            "registered_tools_count": len(registered_tools),
            "max_tool_result_count": settings.MAX_TOOL_RESULT_COUNT,
            "timeout_seconds": settings.TOOL_TIMEOUT_SECONDS
        },
        "modules": {
            "backend": "OK",
            "schemas": "OK",
            "tool_gateway": "OK",
            "audit_logger": "OK",
            "ai_interface": "READY"
        }
    }

@app.get(f"{settings.API_V1_STR}/tools", response_model=List[ToolDefinition], tags=["Tool Gateway"])
async def list_tools() -> List[ToolDefinition]:
    """List all approved read-only tools registered in the Tool Gateway."""
    return gateway.get_registered_tools()

@app.post(f"{settings.API_V1_STR}/tools/execute", response_model=ToolExecutionResult, tags=["Tool Gateway"])
async def execute_tool_endpoint(request: ToolExecutionRequest) -> ToolExecutionResult:
    """
    Execute a query through the controlled Tool Gateway.
    Strictly validates tool registration, arguments, read-only status, and caps.
    """
    return await gateway.execute_tool(request)

@app.get(f"{settings.API_V1_STR}/telemetry/scenarios", tags=["Telemetry Engine"])
async def list_telemetry_scenarios():
    """List all available synthetic security laboratory attack scenarios."""
    return telemetry_engine.get_scenarios()

@app.post(f"{settings.API_V1_STR}/telemetry/scenarios/select/{{scenario_id}}", tags=["Telemetry Engine"])
async def select_telemetry_scenario(scenario_id: str):
    """Switch current active synthetic laboratory scenario."""
    success = telemetry_engine.set_active_scenario(scenario_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Scenario '{scenario_id}' not found.")
    return {"status": "SUCCESS", "active_scenario_id": scenario_id}

@app.get(f"{settings.API_V1_STR}/telemetry/events", tags=["Telemetry Engine"])
async def query_telemetry_events(
    host: Optional[str] = Query(default=None, max_length=200),
    user: Optional[str] = Query(default=None, max_length=200),
    source_ip: Optional[str] = Query(default=None, max_length=50),
    destination_ip: Optional[str] = Query(default=None, max_length=50),
    event_type: Optional[str] = Query(default=None, max_length=50),
    action: Optional[str] = Query(default=None, max_length=100),
    status: Optional[str] = Query(default=None, max_length=20),
    limit: int = Query(default=100, ge=1, le=500),
):
    """
    Telemetry Explorer API: Query raw synthetic enterprise telemetry events with filtering.
    """
    from app.telemetry.models import EventFilter, EventType

    parsed_event_type = None
    if event_type:
        try:
            parsed_event_type = EventType(event_type)
        except ValueError:
            raise HTTPException(
                status_code=422,
                detail=f"Invalid event_type '{event_type}'. Valid values: {[e.value for e in EventType]}",
            )

    flt = EventFilter(
        host=host,
        user=user,
        source_ip=source_ip,
        destination_ip=destination_ip,
        event_type=parsed_event_type,
        action=action,
        status=status,
        limit=limit
    )
    events = telemetry_engine.query_events(flt)
    return [evt.model_dump() for evt in events]

class CrossWorkstationCollectRequest(BaseModel):
    hosts: List[str] = ["all"]
    log_sources: List[str] = ["auth", "process", "network", "dns", "file"]
    indicator: str = None
    limit: int = 100

@app.post(f"{settings.API_V1_STR}/telemetry/collect", tags=["Telemetry Engine"])
async def collect_cross_workstation_telemetry(req: CrossWorkstationCollectRequest):
    """
    Collect, aggregate, and correlate security logs across specified workstations and endpoints.
    """
    from app.telemetry.generator import telemetry_engine
    return telemetry_engine.collect_cross_workstation_telemetry(
        hosts=req.hosts,
        log_sources=req.log_sources,
        indicator=req.indicator,
        limit=req.limit
    )

@app.get(f"{settings.API_V1_STR}/telemetry/workstations", tags=["Telemetry Engine"])
async def get_workstation_inventory():
    """
    Retrieve inventory of enterprise endpoints and workstations with telemetry status.
    """
    from app.telemetry.generator import telemetry_engine
    return telemetry_engine.get_workstation_inventory()

# ==========================================
# DATASET INGESTION & NORMALIZATION ROUTES
# ==========================================
from fastapi import UploadFile, File, Form
from typing import Optional
from app.schemas.dataset import (
    NormalizedEvent,
    DatasetMetadata,
    DatasetImportReport,
    DatasetQueryFilter
)
from app.ingestion.service import dataset_service

class RawDatasetImportRequest(BaseModel):
    content: str
    file_name: str
    dataset_name: Optional[str] = None
    format_hint: Optional[str] = None

@app.post(f"{settings.API_V1_STR}/datasets/import/file", response_model=DatasetImportReport, tags=["Dataset Ingestion"])
async def import_dataset_file(
    file: UploadFile = File(...),
    dataset_name: Optional[str] = Form(None),
    format_hint: Optional[str] = Form(None)
) -> DatasetImportReport:
    """
    Import and normalize cybersecurity datasets (CIC-IDS2017 CSV, NetFlow, JSON events, or PCAP).
    """
    file_bytes = await file.read()
    return dataset_service.import_dataset(
        content=file_bytes,
        file_name=file.filename,
        dataset_name=dataset_name,
        format_hint=format_hint
    )

@app.post(f"{settings.API_V1_STR}/datasets/import/raw", response_model=DatasetImportReport, tags=["Dataset Ingestion"])
async def import_raw_dataset(req: RawDatasetImportRequest) -> DatasetImportReport:
    """
    Import and normalize dataset from raw text / payload string.
    """
    return dataset_service.import_dataset(
        content=req.content.encode("utf-8"),
        file_name=req.file_name,
        dataset_name=req.dataset_name,
        format_hint=req.format_hint
    )

@app.post(f"{settings.API_V1_STR}/datasets/sample/load", response_model=DatasetImportReport, tags=["Dataset Ingestion"])
async def load_bundled_sample_dataset() -> DatasetImportReport:
    """
    Load bundled benchmark CIC-IDS2017 sample dataset into the platform.
    """
    import os
    sample_path = "sample_data/cic_ids2017_sample.csv"
    if os.path.exists(sample_path):
        with open(sample_path, "rb") as f:
            content = f.read()
        return dataset_service.import_dataset(
            content=content,
            file_name="cic_ids2017_sample.csv",
            dataset_name="CIC-IDS2017 Benchmark Flow Sample"
        )
    else:
        # Fallback inline
        dataset_service._preload_samples()
        ds = dataset_service.list_datasets()
        return DatasetImportReport(
            dataset=ds[0] if ds else DatasetMetadata(dataset_name="CIC-IDS2017 Sample", file_name="sample.csv"),
            status="SUCCESS",
            message="Loaded default sample dataset."
        )

@app.get(f"{settings.API_V1_STR}/datasets", response_model=List[DatasetMetadata], tags=["Dataset Ingestion"])
async def list_imported_datasets() -> List[DatasetMetadata]:
    """
    List all imported datasets and their normalization metadata.
    """
    return dataset_service.list_datasets()

@app.get(f"{settings.API_V1_STR}/datasets/{{dataset_id}}", response_model=DatasetMetadata, tags=["Dataset Ingestion"])
async def get_dataset_metadata(dataset_id: str) -> DatasetMetadata:
    """
    Get metadata, statistics, and validation errors for a specific dataset.
    """
    ds = dataset_service.get_dataset(dataset_id)
    if not ds:
        raise HTTPException(status_code=404, detail=f"Dataset '{dataset_id}' not found.")
    return ds

@app.get(f"{settings.API_V1_STR}/datasets/{{dataset_id}}/events", tags=["Dataset Ingestion"])
async def query_dataset_events(
    dataset_id: str,
    label: Optional[str] = None,
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
    destination_port: Optional[int] = None,
    protocol: Optional[str] = None,
    is_malicious: Optional[bool] = None,
    offset: int = 0,
    limit: int = 50
):
    """
    Query normalized events from an imported dataset with filtering and pagination.
    """
    ds = dataset_service.get_dataset(dataset_id)
    if not ds:
        raise HTTPException(status_code=404, detail=f"Dataset '{dataset_id}' not found.")
    
    flt = DatasetQueryFilter(
        label=label,
        source_ip=source_ip,
        destination_ip=destination_ip,
        destination_port=destination_port,
        protocol=protocol,
        is_malicious=is_malicious,
        offset=offset,
        limit=limit
    )
    events, total = dataset_service.get_dataset_events(dataset_id, flt)
    return {
        "dataset_id": dataset_id,
        "dataset_name": ds.dataset_name,
        "total_matching": total,
        "offset": offset,
        "limit": limit,
        "events": [evt.model_dump() for evt in events]
    }

@app.delete(f"{settings.API_V1_STR}/datasets/{{dataset_id}}", tags=["Dataset Ingestion"])
async def delete_imported_dataset(dataset_id: str):
    """
    Delete an imported dataset and its normalized records.
    """
    deleted = dataset_service.delete_dataset(dataset_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Dataset '{dataset_id}' not found.")
    return {"status": "SUCCESS", "message": f"Dataset '{dataset_id}' removed successfully."}

class EvaluateRequest(BaseModel):
    scenario_id: str = Field(max_length=200)
    finding: Finding
    evidence_list: List[Evidence] = Field(default_factory=list, max_length=500)



@app.post(f"{settings.API_V1_STR}/telemetry/evaluate", response_model=EvaluationReport, tags=["Evaluation Engine"])
async def evaluate_finding_against_ground_truth(req: EvaluateRequest) -> EvaluationReport:
    """
    Evaluation Engine API: Compare an AI Finding against hidden scenario Ground Truth metadata.
    Returns Precision, Recall, F1 Score, and Evidence Coverage %.
    """
    gt = telemetry_engine.get_ground_truth(req.scenario_id)
    if not gt:
        raise HTTPException(status_code=404, detail=f"Ground truth metadata for scenario '{req.scenario_id}' not found.")

    return EvaluationEngine.evaluate_finding(req.finding, req.evidence_list, gt)

@app.post(f"{settings.API_V1_STR}/telemetry/lab/run", response_model=EvaluationRun, tags=["Evaluation Lab"])
async def run_full_evaluation_benchmark():
    """
    Run full AI Threat Hunter benchmark evaluation across all 8 attack scenarios.
    Calculates strict empirical Detection Rate, Precision, Recall, FP/FN rates, Evidence Coverage, and Tool Efficiency.
    """
    return await EvaluationLabRunner.run_full_benchmark()

@app.get(f"{settings.API_V1_STR}/telemetry/lab/runs", tags=["Evaluation Lab"])
async def list_evaluation_runs():
    """
    List all historical evaluation benchmark runs for side-by-side reproducibility comparison.
    """
    return list(EVALUATION_RUN_STORE.values())

@app.get(f"{settings.API_V1_STR}/telemetry/lab/runs/{{run_id}}", response_model=EvaluationRun, tags=["Evaluation Lab"])
async def get_evaluation_run_detail(run_id: str) -> EvaluationRun:
    """
    Fetch specific evaluation benchmark run details.
    """
    if run_id not in EVALUATION_RUN_STORE:
        raise HTTPException(status_code=404, detail=f"Evaluation run '{run_id}' not found.")
    return EVALUATION_RUN_STORE[run_id]

@app.post(f"{settings.API_V1_STR}/security/adversarial/run", response_model=AdversarialSecurityReport, tags=["Adversarial Security Lab"])
async def run_adversarial_security_suite():
    """
    Run synthetic adversarial security test suite evaluating prompt injection resistance,
    log payload sanitization, zero tool policy violations, and context flooding defenses.
    """
    _ADVERSARIAL_CACHE["report"] = None  # Force a fresh run on explicit POST.
    return await _get_cached_adversarial_report()

@app.get(f"{settings.API_V1_STR}/security/adversarial/results", response_model=AdversarialSecurityReport, tags=["Adversarial Security Lab"])
async def get_latest_adversarial_security_results() -> AdversarialSecurityReport:
    """
    Retrieve latest adversarial security test suite report and system security boundaries disclosure.
    """
    return await _get_cached_adversarial_report()





class HuntRunRequest(BaseModel):
    question: str = Field(min_length=1, max_length=2000)
    mode: ExecutionMode = ExecutionMode.AUTONOMOUS

class HuntApproveRequest(BaseModel):
    approved: bool

@app.post(f"{settings.API_V1_STR}/hunts/run", response_model=Hunt, tags=["Threat Hunting"])
async def run_autonomous_hunt(request: HuntRunRequest) -> Hunt:
    """
    Execute a controlled threat hunt in ASSISTED or AUTONOMOUS mode.
    """
    engine = AutonomousHuntingEngine()
    try:
        return await engine.execute_hunt(question=request.question, mode=request.mode)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post(f"{settings.API_V1_STR}/hunts/{{hunt_id}}/approve", response_model=Hunt, tags=["Threat Hunting"])
async def approve_assisted_tool_call(hunt_id: str, request: HuntApproveRequest) -> Hunt:
    """
    Approve or reject a pending tool execution request in ASSISTED mode.
    """
    engine = AutonomousHuntingEngine()
    try:
        return await engine.resume_assisted_hunt(hunt_id=hunt_id, approved=request.approved)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.get(f"{settings.API_V1_STR}/hunts/{{hunt_id}}/audit", tags=["Threat Hunting"])
async def get_hunt_audit_log(hunt_id: str):
    """
    Retrieve the complete reproducible audit trail for a hunt.
    """
    if hunt_id not in HUNT_STATE_STORE:
        raise HTTPException(status_code=404, detail=f"Hunt '{hunt_id}' not found.")
    hunt = HUNT_STATE_STORE[hunt_id]
    return {
        "huntId": hunt.id,
        "mode": hunt.mode,
        "auditTrail": hunt.auditTrail
    }

@app.get(f"{settings.API_V1_STR}/hunts/{{hunt_id}}/graph", tags=["Threat Hunting"])
async def get_hunt_investigation_graph(hunt_id: str):
    """
    Retrieve the evidence-grounded Security Indicator relationship graph (IP -> USER -> HOST -> PROCESS -> FILE).
    """
    if hunt_id not in HUNT_STATE_STORE:
        # Explicit demo alias only — unknown IDs are a 404, not silent
        # sample data (the old fallback masked missing hunts from analysts).
        if hunt_id != "demo":
            raise HTTPException(status_code=404, detail=f"Hunt '{hunt_id}' not found.")
        sample_ev = [
            Evidence(
                id="evd-ssh-bruteforce-01",
                source=EvidenceSource.AUTHENTICATION,
                timestamp="2026-08-10T19:30:15Z",
                host="web-server-01",
                user="root",
                sourceIp="192.168.100.99",
                destinationIp="10.0.1.10",
                eventType="SSH_FAILED_PASSWORD",
                rawReference="auth.log:line_1482",
                normalizedData={"process_name": "sshd", "filepath": "/etc/shadow", "failed_attempts": 25},
                relevance="Detected failed root login attempts",
                confidence=0.95
            )
        ]
        return InvestigationGraphBuilder.build_graph(sample_ev).model_dump()

    hunt = HUNT_STATE_STORE[hunt_id]
    graph = InvestigationGraphBuilder.build_graph(hunt.evidence, hunt.findings)
    return graph.model_dump()



@app.get(f"{settings.API_V1_STR}/hunts/sample", response_model=Hunt, tags=["Threat Hunting"])
async def get_sample_hunt() -> Hunt:
    """
    Return a structured sample Hunt object demonstrating Phase 1-5 schema validation & UI layout.
    """
    from app.schemas.hunt import ExecutionTraceStep
    sample_evidence = Evidence(
        id="evd-ssh-bruteforce-01",
        source=EvidenceSource.AUTHENTICATION,
        timestamp="2026-08-10T19:30:15Z",
        host="web-server-01",
        user="root",
        sourceIp="192.168.100.99",
        destinationIp="10.0.1.10",
        eventType="SSH_FAILED_PASSWORD",
        rawReference="auth.log:line_1482",
        normalizedData={"failed_attempts": 25, "port": 22},
        relevance="Detected 25 failed root login attempts within a 75-second window from 192.168.100.99",
        confidence=0.95
    )

    sample_finding = Finding(
        id="fnd-ssh-bruteforce-01",
        title="SSH Credential Access Attempt via Password Spray",
        severity=Severity.HIGH,
        confidence=0.92,
        description="Suspicious activity detected on web-server-01 because high volume SSH authentication failures were observed from IP 192.168.100.99.",
        evidenceIds=["evd-ssh-bruteforce-01"],
        affectedHosts=["web-server-01"],
        sourceIps=["192.168.100.99"],
        timeline=[
            {"timestamp": "2026-08-10T19:30:15Z", "event": "SSH authentication failure surge detected"}
        ],
        mitreTechniques=["T1110", "T1110.001"],
        recommendation="Isolate IP 192.168.100.99 at edge firewall, disable root SSH logins, and enforce fail2ban."
    )

    return Hunt(
        id="hunt-demo-ssh-01",
        question="Find evidence of suspicious SSH activity.",
        hypothesis="An attacker may have attempted credential-based access against an internal Linux host.",
        hypothesisState=HypothesisState.SUPPORTED,
        mode=ExecutionMode.AUTONOMOUS,
        toolCallsExecuted=3,
        currentIteration=1,
        maxIterations=5,
        status=HuntStatus.COMPLETED,
        createdAt="2026-08-10T19:30:00Z",
        updatedAt="2026-08-10T19:32:00Z",
        executionTrace=[
            ExecutionTraceStep(
                step_number=1,
                tool_name="search_authentication_events",
                arguments={"host": "web-server-01", "status": "FAILURE"},
                resultCount=25,
                evidenceIds=["evd-ssh-bruteforce-01"],
                duration_ms=42.5
            )
        ],
        toolsUsed=["search_authentication_events"],
        evidence=[sample_evidence],
        findings=[sample_finding],
        confidence=0.92,
        mitreTechniques=["T1110", "T1110.001"],
        recommendations=["Isolate host 192.168.100.99", "Enforce SSH key-only authentication", "Review sudo logs for web-server-01"]
    )
