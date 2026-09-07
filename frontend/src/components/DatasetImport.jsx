import React, { useState, useEffect, useRef } from 'react';
import { 
  UploadCloud, 
  FileText, 
  CheckCircle2, 
  AlertTriangle, 
  Database, 
  RefreshCw, 
  ShieldAlert, 
  Trash2, 
  Eye, 
  Layers, 
  Activity, 
  Globe, 
  Server, 
  Lock, 
  Search, 
  Download, 
  Sparkles,
  ArrowRight,
  Code2,
  FastForward
} from 'lucide-react';

export default function DatasetImport({ onNavigateToReplay }) {
  const [datasets, setDatasets] = useState([]);
  const [activeDatasetId, setActiveDatasetId] = useState(null);
  const [activeDataset, setActiveDataset] = useState(null);
  const [eventsData, setEventsData] = useState([]);
  const [totalMatchingEvents, setTotalMatchingEvents] = useState(0);
  const [loading, setLoading] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [importStatusMessage, setImportStatusMessage] = useState(null);
  const [selectedRawEvent, setSelectedRawEvent] = useState(null);

  // Upload Form State
  const [selectedFile, setSelectedFile] = useState(null);
  const [datasetName, setDatasetName] = useState('');
  const [formatHint, setFormatHint] = useState('');
  const [rawTextContent, setRawTextContent] = useState('');
  const [uploadMode, setUploadMode] = useState('FILE'); // 'FILE' or 'RAW_TEXT'

  // Filter State
  const [labelFilter, setLabelFilter] = useState('');
  const [ipSearch, setIpSearch] = useState('');
  const [limit, setLimit] = useState(50);
  const [offset, setOffset] = useState(0);

  const fileInputRef = useRef(null);

  useEffect(() => {
    fetchDatasets();
  }, []);

  useEffect(() => {
    if (activeDatasetId) {
      fetchDatasetDetails(activeDatasetId);
      fetchDatasetEvents(activeDatasetId, 0);
    }
  }, [activeDatasetId, labelFilter, ipSearch, limit]);

  const fetchDatasets = async () => {
    try {
      const res = await fetch('/api/v1/datasets');
      if (!res.ok) throw new Error("Fetch datasets non-200");
      const data = await res.json();
      setDatasets(data);
      if (data.length > 0 && !activeDatasetId) {
        setActiveDatasetId(data[0].dataset_id);
      }
    } catch (err) {
      console.error("Failed to fetch datasets:", err);
    }
  };

  const fetchDatasetDetails = async (id) => {
    try {
      const res = await fetch(`/api/v1/datasets/${id}`);
      if (!res.ok) throw new Error("Fetch dataset details non-200");
      const data = await res.json();
      setActiveDataset(data);
    } catch (err) {
      console.error("Failed to fetch dataset detail:", err);
    }
  };

  const fetchDatasetEvents = async (id, currentOffset = 0) => {
    setLoading(true);
    try {
      let url = `/api/v1/datasets/${id}/events?offset=${currentOffset}&limit=${limit}`;
      if (labelFilter) url += `&label=${encodeURIComponent(labelFilter)}`;
      if (ipSearch) url += `&source_ip=${encodeURIComponent(ipSearch)}`;

      const res = await fetch(url);
      if (!res.ok) throw new Error("Fetch events non-200");
      const data = await res.json();
      setEventsData(data.events || []);
      setTotalMatchingEvents(data.total_matching || 0);
      setOffset(currentOffset);
    } catch (err) {
      console.error("Failed to fetch dataset events:", err);
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = async (e) => {
    e.preventDefault();
    if (!selectedFile && uploadMode === 'FILE') {
      alert("Please select a dataset file (.csv, .json, .pcap)");
      return;
    }

    setUploading(true);
    setUploadProgress(20);
    setImportStatusMessage("Ingesting dataset and parsing stream...");

    try {
      let res;
      if (uploadMode === 'FILE') {
        const formData = new FormData();
        formData.append('file', selectedFile);
        if (datasetName) formData.append('dataset_name', datasetName);
        if (formatHint) formData.append('format_hint', formatHint);

        setUploadProgress(50);
        setImportStatusMessage("Validating IP addresses, ports, and normalizing schema...");

        res = await fetch('/api/v1/datasets/import/file', {
          method: 'POST',
          body: formData
        });
      } else {
        if (!rawTextContent.trim()) {
          alert("Please paste dataset content.");
          setUploading(false);
          return;
        }
        setUploadProgress(50);
        res = await fetch('/api/v1/datasets/import/raw', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            content: rawTextContent,
            file_name: datasetName ? `${datasetName.toLowerCase().replace(/\s+/g, '_')}.csv` : 'raw_import.csv',
            dataset_name: datasetName || 'Raw Data Import',
            format_hint: formatHint || 'CSV_NETWORK_FLOW'
          })
        });
      }

      setUploadProgress(85);
      if (!res.ok) throw new Error("Dataset import failed");
      const report = await res.json();

      setUploadProgress(100);
      setImportStatusMessage(report.message);

      // Refresh datasets
      await fetchDatasets();
      setActiveDatasetId(report.dataset.dataset_id);
      setActiveDataset(report.dataset);

      // Reset form
      setSelectedFile(null);
      setDatasetName('');
      setRawTextContent('');
      if (fileInputRef.current) fileInputRef.current.value = '';
    } catch (err) {
      console.error("Upload error:", err);
      setImportStatusMessage(`Import error: ${err.message}`);
    } finally {
      setTimeout(() => setUploading(false), 800);
    }
  };

  const handleLoadBenchmarkSample = async () => {
    setUploading(true);
    setUploadProgress(30);
    setImportStatusMessage("Loading bundled CIC-IDS2017 benchmark dataset...");

    try {
      const res = await fetch('/api/v1/datasets/sample/load', { method: 'POST' });
      if (!res.ok) throw new Error("Sample load non-200");
      const report = await res.json();
      setUploadProgress(100);
      setImportStatusMessage(report.message);
      await fetchDatasets();
      setActiveDatasetId(report.dataset.dataset_id);
      setActiveDataset(report.dataset);
    } catch (err) {
      console.error("Load sample error:", err);
      setImportStatusMessage("Failed to load sample dataset.");
    } finally {
      setTimeout(() => setUploading(false), 800);
    }
  };

  const handleDeleteDataset = async (id, name) => {
    if (!window.confirm(`Are you sure you want to delete dataset '${name}'?`)) return;
    try {
      const res = await fetch(`/api/v1/datasets/${id}`, { method: 'DELETE' });
      if (!res.ok) throw new Error("Delete non-200");
      await fetchDatasets();
      if (activeDatasetId === id) {
        setActiveDatasetId(null);
        setActiveDataset(null);
        setEventsData([]);
      }
    } catch (err) {
      console.error("Delete error:", err);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      
      {/* HEADER BANNER */}
      <div className="soc-card" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <UploadCloud size={24} color="var(--accent-blue)" />
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <h2 style={{ fontSize: '1.05rem', fontWeight: 800, color: '#f8fafc' }}>
                CYBERSECURITY DATASET INGESTION & NORMALIZATION HUB
              </h2>
              <span className="badge badge-info">CIC-IDS2017 & PCAP READY</span>
            </div>
            <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
              Import real network flow logs (CSV), event telemetry (JSON), and PCAP packet streams with strict schema normalization and label preservation.
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '10px' }}>
          {onNavigateToReplay && (
            <button
              onClick={() => onNavigateToReplay(activeDatasetId)}
              style={{
                background: 'rgba(16, 185, 129, 0.15)',
                border: '1px solid rgba(16, 185, 129, 0.4)',
                color: '#34d399',
                padding: '8px 16px',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.78rem',
                fontWeight: 800,
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                cursor: 'pointer'
              }}
            >
              <FastForward size={14} />
              OPEN IN REPLAY ENGINE
            </button>
          )}
          <button
            onClick={handleLoadBenchmarkSample}
            disabled={uploading}
            style={{
              background: 'var(--accent-blue-subtle)',
              border: '1px solid rgba(59, 130, 246, 0.4)',
              color: '#60a5fa',
              padding: '8px 16px',
              borderRadius: 'var(--radius-sm)',
              fontSize: '0.78rem',
              fontWeight: 800,
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              cursor: 'pointer'
            }}
          >
            <Sparkles size={14} />
            LOAD BENCHMARK SAMPLE (CIC-IDS2017)
          </button>
        </div>
      </div>

      {/* INGESTION WORKSPACE: UPLOAD PANEL & DATASET REPOSITORY */}
      <div style={{ display: 'grid', gridTemplateColumns: '420px 1fr', gap: '20px' }}>
        
        {/* LEFT COLUMN: UPLOAD PANEL */}
        <div className="soc-card" style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-color)', paddingBottom: '8px' }}>
            <span style={{ fontSize: '0.78rem', fontWeight: 800, color: '#f8fafc', letterSpacing: '0.04em' }}>
              IMPORT NEW DATASET
            </span>
            <div style={{ display: 'flex', background: 'var(--bg-subtle)', border: '1px solid var(--border-color)', borderRadius: 'var(--radius-sm)', padding: '2px' }}>
              <button
                onClick={() => setUploadMode('FILE')}
                style={{
                  background: uploadMode === 'FILE' ? 'var(--accent-blue)' : 'transparent',
                  color: uploadMode === 'FILE' ? '#ffffff' : 'var(--text-dim)',
                  padding: '3px 8px',
                  borderRadius: 'var(--radius-sm)',
                  fontSize: '0.70rem',
                  fontWeight: 800
                }}
              >
                FILE UPLOAD
              </button>
              <button
                onClick={() => setUploadMode('RAW_TEXT')}
                style={{
                  background: uploadMode === 'RAW_TEXT' ? 'var(--accent-blue)' : 'transparent',
                  color: uploadMode === 'RAW_TEXT' ? '#ffffff' : 'var(--text-dim)',
                  padding: '3px 8px',
                  borderRadius: 'var(--radius-sm)',
                  fontSize: '0.70rem',
                  fontWeight: 800
                }}
              >
                RAW TEXT
              </button>
            </div>
          </div>

          <form onSubmit={handleFileUpload} style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <div>
              <label style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--text-dim)', display: 'block', marginBottom: '4px' }}>
                DATASET NAME (OPTIONAL)
              </label>
              <input
                type="text"
                placeholder="e.g. CIC-IDS2017 Friday Infiltration"
                value={datasetName}
                onChange={(e) => setDatasetName(e.target.value)}
                style={{ width: '100%', background: 'var(--bg-subtle)', border: '1px solid var(--border-color)', color: '#f8fafc', padding: '8px 10px', borderRadius: 'var(--radius-sm)', fontSize: '0.78rem' }}
              />
            </div>

            <div>
              <label style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--text-dim)', display: 'block', marginBottom: '4px' }}>
                FORMAT PARSER HINT
              </label>
              <select
                value={formatHint}
                onChange={(e) => setFormatHint(e.target.value)}
                style={{ width: '100%', background: 'var(--bg-subtle)', border: '1px solid var(--border-color)', color: '#f8fafc', padding: '8px 10px', borderRadius: 'var(--radius-sm)', fontSize: '0.78rem' }}
              >
                <option value="">Auto-Detect Format (.csv, .json, .pcap)</option>
                <option value="CSV_NETWORK_FLOW">CIC-IDS2017 / NetFlow CSV</option>
                <option value="JSON_EVENTS">JSON Event Telemetry Array</option>
                <option value="PCAP">Libpcap Packet Capture (.pcap)</option>
              </select>
            </div>

            {uploadMode === 'FILE' ? (
              <div>
                <label style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--text-dim)', display: 'block', marginBottom: '4px' }}>
                  DATASET FILE (.CSV, .JSON, .PCAP)
                </label>
                <input
                  type="file"
                  ref={fileInputRef}
                  accept=".csv,.txt,.json,.jsonl,.pcap,.cap"
                  onChange={(e) => setSelectedFile(e.target.files[0] || null)}
                  style={{
                    width: '100%',
                    background: 'var(--bg-subtle)',
                    border: '1px dashed var(--accent-blue)',
                    padding: '16px',
                    borderRadius: 'var(--radius-sm)',
                    fontSize: '0.75rem',
                    color: '#cbd5e1',
                    cursor: 'pointer'
                  }}
                />
                {selectedFile && (
                  <div style={{ fontSize: '0.72rem', color: '#60a5fa', marginTop: '4px', fontFamily: 'var(--font-mono)' }}>
                    Selected: {selectedFile.name} ({(selectedFile.size / 1024).toFixed(1)} KB)
                  </div>
                )}
              </div>
            ) : (
              <div>
                <label style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--text-dim)', display: 'block', marginBottom: '4px' }}>
                  PASTE CSV OR JSON DATASET TEXT
                </label>
                <textarea
                  rows={6}
                  placeholder="Paste CSV header + rows or JSON array..."
                  value={rawTextContent}
                  onChange={(e) => setRawTextContent(e.target.value)}
                  style={{ width: '100%', background: 'var(--bg-subtle)', border: '1px solid var(--border-color)', color: '#f8fafc', padding: '8px 10px', borderRadius: 'var(--radius-sm)', fontSize: '0.75rem', fontFamily: 'var(--font-mono)' }}
                />
              </div>
            )}

            <button
              type="submit"
              disabled={uploading}
              style={{
                background: 'var(--accent-blue)',
                color: '#ffffff',
                padding: '10px',
                borderRadius: 'var(--radius-sm)',
                fontWeight: 800,
                fontSize: '0.80rem',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '8px',
                cursor: 'pointer',
                marginTop: '4px'
              }}
            >
              <RefreshCw size={14} className={uploading ? 'spin' : ''} />
              {uploading ? 'INGESTING & NORMALIZING...' : 'IMPORT & NORMALIZE DATASET'}
            </button>
          </form>

          {/* PROGRESS & STATUS BANNER */}
          {uploading && (
            <div style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border-color)', borderRadius: 'var(--radius-sm)', padding: '10px 12px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.72rem', fontWeight: 800, color: '#f8fafc', marginBottom: '6px' }}>
                <span>IMPORT PROGRESS</span>
                <span>{uploadProgress}%</span>
              </div>
              <div style={{ width: '100%', height: '6px', background: 'var(--border-color)', borderRadius: '3px', overflow: 'hidden' }}>
                <div style={{ width: `${uploadProgress}%`, height: '100%', background: 'var(--accent-blue)', transition: 'width 0.3s ease' }} />
              </div>
              {importStatusMessage && (
                <div style={{ fontSize: '0.70rem', color: 'var(--text-muted)', marginTop: '6px' }}>
                  {importStatusMessage}
                </div>
              )}
            </div>
          )}

          {/* IMPORTED DATASETS LIBRARY */}
          <div style={{ borderTop: '1px solid var(--border-color)', paddingTop: '12px' }}>
            <div style={{ fontSize: '0.75rem', fontWeight: 800, color: 'var(--text-dim)', letterSpacing: '0.04em', marginBottom: '8px' }}>
              IMPORTED DATASETS ({datasets.length})
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', maxHeight: '200px', overflowY: 'auto' }}>
              {datasets.map(ds => {
                const isSelected = activeDatasetId === ds.dataset_id;
                return (
                  <div
                    key={ds.dataset_id}
                    onClick={() => setActiveDatasetId(ds.dataset_id)}
                    className="soc-card-subtle"
                    style={{
                      border: isSelected ? '1px solid var(--accent-blue)' : '1px solid var(--border-subtle)',
                      background: isSelected ? 'var(--accent-blue-subtle)' : 'var(--bg-subtle)',
                      cursor: 'pointer',
                      padding: '8px 10px',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center'
                    }}
                  >
                    <div>
                      <div style={{ fontSize: '0.78rem', fontWeight: 800, color: isSelected ? '#f8fafc' : '#cbd5e1' }}>
                        {ds.dataset_name}
                      </div>
                      <div style={{ fontSize: '0.68rem', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
                        {ds.total_events} events • {ds.source_format}
                      </div>
                    </div>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        handleDeleteDataset(ds.dataset_id, ds.dataset_name);
                      }}
                      style={{ background: 'transparent', color: 'var(--text-dim)', padding: '4px', borderRadius: '4px' }}
                      title="Delete dataset"
                    >
                      <Trash2 size={13} color="#f87171" />
                    </button>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* RIGHT COLUMN: ACTIVE DATASET METRICS & NORMALIZED EVENTS TABLE */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          
          {activeDataset ? (
            <>
              {/* METRIC GAUGES STRIP */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '10px' }}>
                <div className="soc-card" style={{ padding: '12px 14px' }}>
                  <span style={{ fontSize: '0.66rem', fontWeight: 800, color: 'var(--text-dim)' }}>TOTAL EVENTS</span>
                  <div style={{ fontSize: '1.2rem', fontWeight: 800, color: '#f8fafc', marginTop: '2px' }}>
                    {activeDataset.total_events}
                  </div>
                </div>

                <div className="soc-card" style={{ padding: '12px 14px' }}>
                  <span style={{ fontSize: '0.66rem', fontWeight: 800, color: 'var(--text-dim)' }}>BENIGN FLOWS</span>
                  <div style={{ fontSize: '1.2rem', fontWeight: 800, color: '#34d399', marginTop: '2px' }}>
                    {activeDataset.benign_events}
                  </div>
                </div>

                <div className="soc-card" style={{ padding: '12px 14px' }}>
                  <span style={{ fontSize: '0.66rem', fontWeight: 800, color: 'var(--text-dim)' }}>MALICIOUS ATTACKS</span>
                  <div style={{ fontSize: '1.2rem', fontWeight: 800, color: 'var(--status-red)', marginTop: '2px' }}>
                    {activeDataset.malicious_events}
                  </div>
                </div>

                <div className="soc-card" style={{ padding: '12px 14px' }}>
                  <span style={{ fontSize: '0.66rem', fontWeight: 800, color: 'var(--text-dim)' }}>ATTACK CATEGORIES</span>
                  <div style={{ fontSize: '1.2rem', fontWeight: 800, color: '#60a5fa', marginTop: '2px' }}>
                    {Object.keys(activeDataset.available_labels || {}).length}
                  </div>
                </div>

                <div className="soc-card" style={{ padding: '12px 14px' }}>
                  <span style={{ fontSize: '0.66rem', fontWeight: 800, color: 'var(--text-dim)' }}>MALFORMED ROWS</span>
                  <div style={{ fontSize: '1.2rem', fontWeight: 800, color: activeDataset.malformed_records_count > 0 ? '#fbbf24' : '#94a3b8', marginTop: '2px' }}>
                    {activeDataset.malformed_records_count}
                  </div>
                </div>
              </div>

              {/* ATTACK CATEGORIES BREAKDOWN BADGES */}
              <div className="soc-card" style={{ padding: '12px 16px' }}>
                <span style={{ fontSize: '0.72rem', fontWeight: 800, color: 'var(--text-dim)', letterSpacing: '0.04em', display: 'block', marginBottom: '8px' }}>
                  DETECTED ATTACK LABELS & DISTRIBUTION:
                </span>
                <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                  {Object.entries(activeDataset.available_labels || {}).map(([lbl, count]) => {
                    const isBenign = lbl.toUpperCase() === 'BENIGN';
                    const isSelected = labelFilter === lbl;
                    return (
                      <button
                        key={lbl}
                        onClick={() => setLabelFilter(isSelected ? '' : lbl)}
                        style={{
                          background: isSelected ? 'var(--accent-blue)' : isBenign ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)',
                          border: isSelected ? '1px solid var(--accent-blue)' : isBenign ? '1px solid #10b981' : '1px solid #ef4444',
                          color: isSelected ? '#ffffff' : isBenign ? '#34d399' : '#f87171',
                          padding: '4px 10px',
                          borderRadius: 'var(--radius-sm)',
                          fontSize: '0.74rem',
                          fontWeight: 800,
                          display: 'flex',
                          alignItems: 'center',
                          gap: '6px',
                          cursor: 'pointer'
                        }}
                      >
                        <span>{lbl}</span>
                        <span style={{ background: 'rgba(0,0,0,0.3)', padding: '1px 6px', borderRadius: '4px', fontSize: '0.68rem', fontFamily: 'var(--font-mono)' }}>
                          {count}
                        </span>
                      </button>
                    );
                  })}
                  {labelFilter && (
                    <button
                      onClick={() => setLabelFilter('')}
                      style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border-color)', color: 'var(--text-dim)', padding: '4px 8px', borderRadius: '4px', fontSize: '0.70rem' }}
                    >
                      CLEAR FILTER ✕
                    </button>
                  )}
                </div>
              </div>

              {/* VALIDATION ERRORS BANNER IF MALFORMED ROWS OCCURRED */}
              {activeDataset.malformed_records_count > 0 && (
                <div style={{ background: 'rgba(245, 158, 11, 0.12)', border: '1px solid #f59e0b', borderRadius: 'var(--radius-sm)', padding: '12px 16px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
                    <AlertTriangle size={16} color="#fbbf24" />
                    <strong style={{ color: '#fbbf24', fontSize: '0.82rem' }}>
                      VALIDATION NOTICE: {activeDataset.malformed_records_count} MALFORMED RECORDS DETECTED & ISOLATED
                    </strong>
                  </div>
                  <p style={{ fontSize: '0.75rem', color: '#e2e8f0', margin: 0 }}>
                    Individual invalid rows (e.g. invalid IP strings, out-of-range ports, missing timestamps) were safely reported and skipped without rejecting valid dataset records.
                  </p>
                  {activeDataset.errors?.length > 0 && (
                    <div style={{ marginTop: '8px', maxHeight: '120px', overflowY: 'auto', fontSize: '0.70rem', fontFamily: 'var(--font-mono)', color: '#fef08a' }}>
                      {activeDataset.errors.slice(0, 5).map((err, i) => (
                        <div key={i}>• Row {err.row_index} [{err.field}]: {err.error_message}</div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* NORMALIZED EVENTS DATA GRID */}
              <div className="soc-card" style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-color)', paddingBottom: '8px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Layers size={16} color="var(--accent-blue)" />
                    <span style={{ fontSize: '0.85rem', fontWeight: 800, color: '#f8fafc' }}>
                      NORMALIZED EVENT STREAM ({totalMatchingEvents} MATCHING)
                    </span>
                  </div>

                  <div style={{ display: 'flex', gap: '8px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px', background: 'var(--bg-subtle)', padding: '4px 8px', borderRadius: '4px', border: '1px solid var(--border-color)' }}>
                      <Search size={13} color="var(--text-dim)" />
                      <input
                        type="text"
                        placeholder="Search IP..."
                        value={ipSearch}
                        onChange={(e) => setIpSearch(e.target.value)}
                        style={{ background: 'transparent', border: 'none', color: '#f8fafc', fontSize: '0.74rem', width: '110px' }}
                      />
                    </div>
                  </div>
                </div>

                {/* Table */}
                <div style={{ overflowX: 'auto', maxHeight: '440px', overflowY: 'auto' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.76rem' }}>
                    <thead>
                      <tr style={{ borderBottom: '1px solid var(--border-color)', color: 'var(--text-dim)' }}>
                        <th style={{ padding: '8px 10px' }}>TIMESTAMP</th>
                        <th style={{ padding: '8px 10px' }}>SOURCE IP : PORT</th>
                        <th style={{ padding: '8px 10px' }}>DESTINATION IP : PORT</th>
                        <th style={{ padding: '8px 10px' }}>PROTO</th>
                        <th style={{ padding: '8px 10px' }}>BYTES (IN/OUT)</th>
                        <th style={{ padding: '8px 10px' }}>DURATION</th>
                        <th style={{ padding: '8px 10px' }}>LABEL</th>
                        <th style={{ padding: '8px 10px' }}>RAW</th>
                      </tr>
                    </thead>
                    <tbody>
                      {eventsData.map((evt, idx) => {
                        const isBenign = (evt.label || '').toUpperCase() === 'BENIGN';
                        return (
                          <tr
                            key={idx}
                            onClick={() => setSelectedRawEvent(evt)}
                            style={{
                              borderBottom: '1px solid var(--border-subtle)',
                              background: selectedRawEvent === evt ? 'var(--accent-blue-subtle)' : 'transparent',
                              cursor: 'pointer'
                            }}
                          >
                            <td style={{ padding: '8px 10px', fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>
                              {evt.timestamp?.split('T')[1] || evt.timestamp}
                            </td>
                            <td style={{ padding: '8px 10px', fontFamily: 'var(--font-mono)', color: '#60a5fa' }}>
                              {evt.source_ip || '-'}:{evt.source_port ?? '-'}
                            </td>
                            <td style={{ padding: '8px 10px', fontFamily: 'var(--font-mono)', color: '#f8fafc' }}>
                              {evt.destination_ip || '-'}:{evt.destination_port ?? '-'}
                            </td>
                            <td style={{ padding: '8px 10px' }}>
                              <span className="badge" style={{ background: 'rgba(59,130,246,0.15)', color: '#93c5fd', fontSize: '0.65rem' }}>
                                {evt.protocol || 'IP'}
                              </span>
                            </td>
                            <td style={{ padding: '8px 10px', fontFamily: 'var(--font-mono)' }}>
                              {evt.bytes_in ?? '-'} / {evt.bytes_out ?? '-'}
                            </td>
                            <td style={{ padding: '8px 10px', fontFamily: 'var(--font-mono)' }}>
                              {evt.duration !== null && evt.duration !== undefined ? `${evt.duration}s` : '-'}
                            </td>
                            <td style={{ padding: '8px 10px' }}>
                              <span className={`badge ${isBenign ? 'badge-success' : 'badge-danger'}`} style={{ fontSize: '0.68rem' }}>
                                {evt.label}
                              </span>
                            </td>
                            <td style={{ padding: '8px 10px' }}>
                              <Code2 size={13} color="var(--accent-blue)" />
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>

                {/* Pagination Controls */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderTop: '1px solid var(--border-subtle)', paddingTop: '10px', fontSize: '0.74rem', color: 'var(--text-dim)' }}>
                  <div>
                    Showing {eventsData.length} of {totalMatchingEvents} events
                  </div>
                  <div style={{ display: 'flex', gap: '6px' }}>
                    <button
                      onClick={() => fetchDatasetEvents(activeDatasetId, Math.max(0, offset - limit))}
                      disabled={offset === 0}
                      style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border-color)', color: '#f8fafc', padding: '4px 10px', borderRadius: '4px', opacity: offset === 0 ? 0.5 : 1 }}
                    >
                      PREVIOUS
                    </button>
                    <button
                      onClick={() => fetchDatasetEvents(activeDatasetId, offset + limit)}
                      disabled={offset + limit >= totalMatchingEvents}
                      style={{ background: 'var(--bg-subtle)', border: '1px solid var(--border-color)', color: '#f8fafc', padding: '4px 10px', borderRadius: '4px', opacity: offset + limit >= totalMatchingEvents ? 0.5 : 1 }}
                    >
                      NEXT
                    </button>
                  </div>
                </div>

              </div>
            </>
          ) : (
            <div className="soc-card" style={{ textAlign: 'center', color: 'var(--text-dim)', padding: '60px 20px' }}>
              <Database size={32} color="var(--text-muted)" style={{ margin: '0 auto 12px' }} />
              <div style={{ fontWeight: 800, color: '#f8fafc', fontSize: '0.95rem' }}>NO DATASET SELECTED</div>
              <p style={{ fontSize: '0.78rem', marginTop: '4px' }}>
                Upload a CIC-IDS2017 CSV, JSON events file, PCAP, or click "Load Benchmark Sample".
              </p>
            </div>
          )}

        </div>

      </div>

      {/* RAW RECORD INSPECTOR MODAL */}
      {selectedRawEvent && (
        <div className="modal-overlay" onClick={() => setSelectedRawEvent(null)}>
          <div className="soc-card" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '700px', width: '100%', maxHeight: '80vh', overflowY: 'auto' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-color)', paddingBottom: '10px' }}>
              <div>
                <span className={`badge ${selectedRawEvent.label === 'BENIGN' ? 'badge-success' : 'badge-danger'}`}>
                  {selectedRawEvent.label}
                </span>
                <h3 style={{ fontSize: '0.95rem', fontWeight: 800, color: '#f8fafc', marginTop: '4px', fontFamily: 'var(--font-mono)' }}>
                  {selectedRawEvent.source_ip}:{selectedRawEvent.source_port} → {selectedRawEvent.destination_ip}:{selectedRawEvent.destination_port}
                </h3>
              </div>
              <button onClick={() => setSelectedRawEvent(null)} style={{ background: 'transparent', color: 'var(--text-dim)', fontSize: '0.85rem', fontWeight: 700 }}>✕</button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', marginTop: '12px' }}>
              <div>
                <span style={{ fontSize: '0.70rem', fontWeight: 800, color: 'var(--text-dim)' }}>NORMALIZED FIELDS:</span>
                <div className="code-block" style={{ fontSize: '0.75rem', marginTop: '4px' }}>
                  {JSON.stringify({
                    timestamp: selectedRawEvent.timestamp,
                    source_ip: selectedRawEvent.source_ip,
                    source_port: selectedRawEvent.source_port,
                    destination_ip: selectedRawEvent.destination_ip,
                    destination_port: selectedRawEvent.destination_port,
                    protocol: selectedRawEvent.protocol,
                    event_type: selectedRawEvent.event_type,
                    action: selectedRawEvent.action,
                    username: selectedRawEvent.username,
                    hostname: selectedRawEvent.hostname,
                    process: selectedRawEvent.process,
                    bytes_in: selectedRawEvent.bytes_in,
                    bytes_out: selectedRawEvent.bytes_out,
                    duration: selectedRawEvent.duration,
                    label: selectedRawEvent.label,
                    source: selectedRawEvent.source
                  }, null, 2)}
                </div>
              </div>

              <div>
                <span style={{ fontSize: '0.70rem', fontWeight: 800, color: 'var(--text-dim)' }}>ORIGINAL RAW RECORD:</span>
                <div className="code-block" style={{ fontSize: '0.75rem', marginTop: '4px' }}>
                  {JSON.stringify(selectedRawEvent.raw_data, null, 2)}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
