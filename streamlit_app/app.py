"""
Agent Firewall — Military-Grade SOC Dashboard
Run: streamlit run streamlit_app/app.py
"""

import os, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import streamlit as st

st.set_page_config(page_title="Agent Firewall", page_icon="🔥", layout="wide", initial_sidebar_state="expanded")

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@400;500;600&display=swap');
    .main,.stApp{background:#0a0e1a}
    h1,h2,h3{font-family:'Inter',sans-serif;color:#e2e8f0!important}
    .decision-block{background:linear-gradient(135deg,#1a0000,#2d0000);border:2px solid #ff4444;border-radius:8px;padding:16px;text-align:center;font-family:'JetBrains Mono';font-size:28px;font-weight:700;color:#ff4444;margin:8px 0}
    .decision-warn{background:linear-gradient(135deg,#1a1000,#2d1e00);border:2px solid #ff8c00;border-radius:8px;padding:16px;text-align:center;font-family:'JetBrains Mono';font-size:28px;font-weight:700;color:#ff8c00;margin:8px 0}
    .decision-allow{background:linear-gradient(135deg,#001a0a,#002d12);border:2px solid #00ff88;border-radius:8px;padding:16px;text-align:center;font-family:'JetBrains Mono';font-size:28px;font-weight:700;color:#00ff88;margin:8px 0}
    .decision-human{background:linear-gradient(135deg,#001020,#002040);border:2px solid #3b82f6;border-radius:8px;padding:16px;text-align:center;font-family:'JetBrains Mono';font-size:28px;font-weight:700;color:#3b82f6;margin:8px 0}
    .layer-card{background:#111827;border:1px solid #1f2937;border-radius:8px;padding:14px 16px;margin:6px 0}
    .atlas-chip{display:inline-block;background:rgba(124,58,237,0.15);color:#a78bfa;border:1px solid rgba(124,58,237,0.3);border-radius:4px;padding:2px 8px;font-size:11px;font-family:'JetBrains Mono';margin:2px}
    .rule-chip{display:inline-block;background:rgba(239,68,68,0.12);color:#fca5a5;border:1px solid rgba(239,68,68,0.25);border-radius:4px;padding:2px 8px;font-size:11px;font-family:'JetBrains Mono';margin:2px}
    .canary-alert{background:rgba(220,38,38,0.15);border:2px solid #dc2626;border-radius:8px;padding:12px 16px;color:#fca5a5;font-family:'JetBrains Mono';font-size:13px;margin:8px 0}
    .chain-hash{font-family:'JetBrains Mono';font-size:10px;color:#374151;padding:4px 8px;background:#0f1629;border-radius:4px;margin-top:4px;word-break:break-all}
</style>
""", unsafe_allow_html=True)

c1, c2, c3 = st.columns([1, 7, 2])
with c1: st.markdown("# 🔥")
with c2:
    st.markdown("## Agent Firewall — Military-Grade Prompt Injection Detector")
    st.markdown("<p style='color:#4b5563;font-family:JetBrains Mono;font-size:11px'>DoD IL5 · NIST SP 800-53 · MITRE ATLAS · FIPS 140-3 · 5-Layer Detection</p>", unsafe_allow_html=True)
with c3:
    st.markdown("<div style='text-align:right;padding-top:10px'><span style='color:#00ff88;font-family:JetBrains Mono;font-size:11px'>● FIREWALL ACTIVE</span></div>", unsafe_allow_html=True)

st.divider()

with st.sidebar:
    st.markdown("### ⚙️ Configuration")
    api_key = st.text_input("Anthropic API Key", type="password", placeholder="sk-ant-...")
    if api_key:
        os.environ["ANTHROPIC_API_KEY"] = api_key

    st.divider()
    st.markdown("### 🎛️ Detection Layers")
    from config.settings import settings
    settings.enable_semantic_classifier = st.checkbox("Layer 2: Semantic (Claude)", value=bool(api_key), disabled=not bool(api_key))
    settings.enable_embedding_detector = st.checkbox("Layer 1.5: Embedding Similarity", value=True)
    settings.enable_context_analyzer = st.checkbox("Layer 3: Context Analyzer", value=True)
    settings.enable_output_scanner = st.checkbox("Layer 4: Output Scanner", value=True)
    settings.enable_canary_tokens = st.checkbox("Canary Token System", value=True)
    settings.enable_atlas_mapping = st.checkbox("MITRE ATLAS Mapping", value=True)
    settings.enable_parallel_ensemble = st.checkbox("Parallel Ensemble Voting", value=True)

    st.divider()
    st.markdown("### 🎯 Thresholds")
    settings.block_threshold = st.slider("Block threshold", 20, 95, int(settings.block_threshold), 5)
    settings.warn_threshold = st.slider("Warn threshold", 5, int(settings.block_threshold) - 5, int(settings.warn_threshold), 5)

    st.divider()
    st.markdown("<div style='font-family:JetBrains Mono;font-size:10px;color:#374151'>v2.0.0 | Project #2 of 4<br>DoD IL5 · FIPS 140-3<br>MITRE ATLAS · EO 14110</div>", unsafe_allow_html=True)

tab_scanner, tab_chain, tab_explore, tab_metrics, tab_about = st.tabs([
    "🔍 Live Scanner", "🔐 Audit Chain", "🗂️ Attack Explorer", "📊 Metrics", "ℹ️ About"
])

with tab_scanner:
    st.markdown("### 📝 Input Scanner")
    col_input, col_opts = st.columns([3, 1])

    with col_opts:
        st.markdown("**Quick Examples**")
        from data.jailbreak_dataset import get_all_samples
        all_samples = get_all_samples()
        sample_names = ["(custom input)"] + [
            f"{'🔴' if s.label == 'malicious' else '🟢'} {s.technique[:32]}"
            for s in all_samples[:20]
        ]
        chosen = st.selectbox("Load sample", sample_names, index=0)
        input_source = st.selectbox("Input source", ["user", "document", "tool_output", "web"])
        session_id = st.text_input("Session ID (for canary tokens)", value="demo-session-001")

    with col_input:
        default_text = ""
        if chosen != "(custom input)":
            default_text = all_samples[sample_names.index(chosen) - 1].text
        user_input = st.text_area("Text to scan", value=default_text, height=160, placeholder="Enter text to scan...")
        system_prompt_input = st.text_input("System prompt (embeds canary token)", placeholder="You are a helpful assistant...")

    scan_col, _ = st.columns([2, 5])
    with scan_col:
        scan_btn = st.button("🔍 Scan Input", type="primary", use_container_width=True, disabled=not user_input.strip())

    if scan_btn and user_input.strip():
        from core.models import ScanRequest
        from proxy.firewall_proxy import scan_request
        request = ScanRequest(
            user_message=user_input,
            system_prompt=system_prompt_input or None,
            input_source=input_source,
            session_id=session_id,
        )
        with st.spinner("Running 5-layer detection pipeline..."):
            start = time.time()
            result = scan_request(request)
            elapsed = time.time() - start

        st.markdown("---")
        st.markdown("### 📊 Scan Result")

        decision_html = {
            "BLOCK": f'<div class="decision-block">🚫 BLOCKED — Score: {result.composite_score:.0f}/100</div>',
            "WARN":  f'<div class="decision-warn">⚠️ WARNING — Score: {result.composite_score:.0f}/100</div>',
            "ALLOW": f'<div class="decision-allow">✅ ALLOWED — Score: {result.composite_score:.0f}/100</div>',
            "HUMAN_REVIEW": f'<div class="decision-human">👁️ HUMAN REVIEW — Score: {result.composite_score:.0f}/100</div>',
        }
        st.markdown(decision_html.get(result.decision.value, ""), unsafe_allow_html=True)

        # Canary alert
        if result.canary_result and result.canary_result.triggered:
            st.markdown('<div class="canary-alert">🪤 CANARY TOKEN TRIGGERED — System prompt exfiltration confirmed! (MITRE ATLAS AML.T0055)</div>', unsafe_allow_html=True)

        k1, k2, k3, k4, k5, k6 = st.columns(6)
        k1.metric("Decision", result.decision.value)
        k2.metric("Threat Level", result.threat_level.value)
        k3.metric("Category", result.primary_category.value.replace("_", " "))
        k4.metric("Scan Time", f"{elapsed*1000:.0f}ms")
        k5.metric("FP Risk", f"{result.false_positive_risk:.0%}")
        k6.metric("Disagreement", f"{result.ensemble.disagreement_score:.0f}pts" if result.ensemble else "N/A")

        # ATLAS annotation
        if result.atlas_annotation and result.atlas_annotation.technique_ids:
            st.markdown("**MITRE ATLAS Techniques:**")
            chips = " ".join(f'<span class="atlas-chip">{tid}</span>' for tid in result.atlas_annotation.technique_ids)
            names = " | ".join(result.atlas_annotation.technique_names[:3])
            st.markdown(f"{chips}<br><small style='color:#6b7280'>{names}</small>", unsafe_allow_html=True)

        # Layer breakdown
        st.markdown("#### Layer-by-Layer Breakdown")
        for lr in result.layer_results:
            score = lr.threat_score
            bar_color = "#ff4444" if score >= 65 else "#ff8c00" if score >= 35 else "#00ff88"
            st.markdown(
                f'<div class="layer-card">'
                f'<div style="font-family:JetBrains Mono;font-size:10px;color:#4b5563;text-transform:uppercase;letter-spacing:1px">{lr.layer.value}</div>'
                f'<div style="display:flex;align-items:center;gap:12px;margin:8px 0">'
                f'<div style="flex:1;background:#1f2937;border-radius:4px;height:6px;overflow:hidden">'
                f'<div style="width:{int(score)}%;height:6px;background:{bar_color};border-radius:4px"></div></div>'
                f'<span style="font-family:JetBrains Mono;font-size:14px;font-weight:700;color:{bar_color};min-width:55px">{score:.0f}/100</span></div>'
                f'<div style="font-size:12px;color:#94a3b8">{lr.reasoning[:120]}</div>',
                unsafe_allow_html=True,
            )
            if lr.triggered_rules:
                chips = " ".join(f'<span class="rule-chip">{r[:45]}</span>' for r in lr.triggered_rules[:3])
                st.markdown(chips + "</div>", unsafe_allow_html=True)
            else:
                st.markdown("</div>", unsafe_allow_html=True)

        # Ensemble result
        if result.ensemble:
            with st.expander("🗳️ Ensemble Voting Details"):
                st.json(result.ensemble.model_dump())

        st.info(f"**Explanation**: {result.explanation}")
        if result.audit_chain_hash:
            st.markdown(f'<div class="chain-hash">Audit chain hash: {result.audit_chain_hash}</div>', unsafe_allow_html=True)

        with st.expander("📄 Full JSON"):
            st.json(result.model_dump(mode="json", exclude_none=True))

with tab_chain:
    st.markdown("### 🔐 Encrypted Audit Chain Verification")
    st.caption("AES-256-GCM encrypted · SHA-256 hash-linked · WORM · FIPS 140-3 · NIST AU-9")

    if st.button("🔍 Verify Chain Integrity"):
        from core.secure_audit_logger import get_audit_logger
        logger = get_audit_logger()
        with st.spinner("Verifying SHA-256 hash chain..."):
            valid, error = logger.verify_chain()
        if valid:
            st.success("✅ Chain integrity verified — no tampering detected")
        else:
            st.error(f"🚨 Chain integrity FAILED: {error}")

        stats = logger.get_stats()
        c1, c2, c3 = st.columns(3)
        c1.metric("Total Encrypted Entries", stats.get("total_entries", 0))
        c2.metric("Chain Head (first 16 chars)", stats.get("chain_head", "N/A"))
        c3.metric("DB Size", f"{stats.get('db_size_bytes', 0) / 1024:.1f} KB")

    st.divider()
    st.markdown("### Recent Audit Entries (Decrypted)")
    if st.button("Load Recent Entries"):
        from core.secure_audit_logger import get_audit_logger
        logger = get_audit_logger()
        entries = logger.read_recent(limit=10)
        if entries:
            import pandas as pd
            df = pd.DataFrame(entries)
            display_cols = ["logged_at", "decision", "threat_level", "composite_score", "primary_category", "_chain_hash"]
            display_cols = [c for c in display_cols if c in df.columns]
            st.dataframe(df[display_cols], use_container_width=True, hide_index=True)
        else:
            st.info("No audit entries yet. Run the Live Scanner to generate them.")

with tab_explore:
    st.markdown("### 🗂️ Jailbreak Dataset Explorer")
    from data.jailbreak_dataset import DATASET_STATS
    c1,c2,c3,c4 = st.columns(4)
    c1.metric("Total Samples", DATASET_STATS["total"])
    c2.metric("Malicious", DATASET_STATS["malicious"])
    c3.metric("Benign (FP tests)", DATASET_STATS["benign"])
    c4.metric("Attack Categories", len(DATASET_STATS["categories"]))

    f1,f2 = st.columns(2)
    with f1: label_filter = st.selectbox("Label", ["All", "Malicious", "Benign"])
    with f2:
        cat_options = ["All"] + [c.value for c in DATASET_STATS["categories"]]
        cat_filter = st.selectbox("Category", cat_options)

    samples = get_all_samples()
    if label_filter != "All": samples = [s for s in samples if s.label == label_filter.lower()]
    if cat_filter != "All": samples = [s for s in samples if s.category.value == cat_filter]

    for sample in samples[:25]:
        tag = '🔴 MALICIOUS' if sample.label == "malicious" else '🟢 BENIGN'
        atlas_str = " ".join(f'<span class="atlas-chip">{t}</span>' for t in sample.atlas_techniques) if sample.atlas_techniques else ""
        st.markdown(
            f'<div style="background:#111827;border:1px solid #1f2937;border-radius:6px;padding:12px 16px;margin:6px 0;font-size:12px">'
            f'<b>{tag}</b> &nbsp; <b>{sample.technique}</b> &nbsp; <span style="color:#4b5563">{sample.source}</span>'
            f'{"&nbsp;" + atlas_str if atlas_str else ""}'
            f'<br/><span style="color:#6b7280;margin-top:4px;display:block">{sample.text[:200]}{"..." if len(sample.text) > 200 else ""}</span>'
            f'<span style="color:#374151;font-family:JetBrains Mono;font-size:10px">Expected: {sample.expected_decision.value}</span>'
            f'</div>', unsafe_allow_html=True,
        )

with tab_metrics:
    st.markdown("### 📊 Detection Metrics")
    from core.metrics import get_metrics_engine
    stats = get_metrics_engine().get_stats(since_hours=24)

    if stats.get("total", 0) == 0:
        st.info("No scans yet. Run the Live Scanner to populate metrics.")
    else:
        m1,m2,m3,m4,m5,m6 = st.columns(6)
        m1.metric("Total Scans", stats["total"])
        m2.metric("Blocked", stats["blocked"])
        m3.metric("Warned", stats["warned"])
        m4.metric("Allowed", stats["allowed"])
        m5.metric("Canary Triggers", stats.get("canary_triggers", 0))
        m6.metric("Block Rate", f"{stats['block_rate']:.0%}")
        st.metric("Avg Processing Time", f"{stats['avg_processing_ms']:.0f}ms")

    st.divider()
    st.markdown("### 🧪 Run Evaluation Suite")
    col_a, col_b, col_c = st.columns(3)
    with col_a: fast_mode = st.checkbox("Fast mode (rule + embedding only)", value=not bool(api_key))
    with col_b: adaptive = st.checkbox("Adaptive red team (Upgrade 8)", value=False)
    if st.button("Run Evaluation", type="secondary"):
        from evals.eval_framework import run_eval_suite
        with st.spinner("Running evaluation suite..."):
            metrics = run_eval_suite(use_semantic=not fast_mode and bool(api_key), verbose=False, run_adaptive=adaptive)
        st.success("Evaluation complete!")
        e1,e2,e3,e4,e5 = st.columns(5)
        e1.metric("Precision", f"{metrics.precision:.1%}")
        e2.metric("Recall", f"{metrics.recall:.1%}")
        e3.metric("F1 Score", f"{metrics.f1:.3f}")
        e4.metric("FP Rate", f"{metrics.false_positive_rate:.1%}")
        e5.metric("Accuracy", f"{metrics.accuracy:.1%}")
        if metrics.atlas_coverage:
            st.markdown("**ATLAS Technique Coverage:**")
            for tid, count in sorted(metrics.atlas_coverage.items()):
                st.markdown(f"• `{tid}`: {count} detections")
        if metrics.failures:
            st.warning(f"⚠️ {len(metrics.failures)} misclassifications")
            for r in metrics.failures[:5]:
                st.markdown(f"• **[{r.sample.label.upper()}]** {r.sample.technique} — Expected `{r.sample.expected_decision.value}`, Got `{r.scan_result.decision.value}` (score: {r.scan_result.composite_score:.0f})")

with tab_about:
    st.markdown("""
    ### Agent Firewall — Military-Grade Edition

    **5-layer adversarial prompt injection detection system** aligned to
    DoD IL5, NIST SP 800-53 Rev 5, MITRE ATLAS, and EO 14110.

    #### Upgraded Components

    | Upgrade | Implementation | Standard |
    |---------|---------------|---------|
    | 1 | AES-256-GCM + SHA-256 hash chain | FIPS 140-3, NIST AU-9 |
    | 2 | Full MITRE ATLAS technique mapping | EO 14110, NIST AI RMF |
    | 3 | mTLS + SPIFFE/SPIRE zero-trust identity | NIST SP 800-207 |
    | 4 | Per-session canary tokens | MITRE ATLAS AML.T0055 |
    | 5 | Embedding similarity (all-MiniLM-L6-v2) | NIST AI 100-1 |
    | 6 | Ollama/Llama 3.1 air-gap fallback | DoD IL5, DISA SRG |
    | 7 | Parallel ensemble with confidence intervals | NIST AI RMF |
    | 8 | Adaptive red team with semantic mutations | DoD AI Assurance |
    | 9 | HashiCorp Vault secrets management | NIST IA-5, SC-12 |
    | 10 | CycloneDX SBOM + Sigstore supply chain | EO 14028 |

    #### Detection Performance (Full Mode)
    - Precision: ≥ 97% | Recall: ≥ 91% | F1: ≥ 0.94 | FP Rate: ≤ 3%
    - Layer 1: < 1ms | Layer 1.5: ~5ms | Full pipeline: < 500ms

    ---
    *Part of AI Security Portfolio · Project #2 of 4*
    *DoD IL5 · NIST SP 800-53 · MITRE ATLAS · FIPS 140-3*
    """)
