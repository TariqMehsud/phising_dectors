"""
app.py - Main Streamlit UI for Phishing Email Detector & Reporter
Run with:  streamlit run app.py
"""

import os
import json
import time
import datetime
import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from pathlib import Path
from dataclasses import asdict

# ── Page config (MUST be first Streamlit call) ────────────────────────────────
st.set_page_config(
    page_title="Phishing Email Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

from utils import (
    load_history, risk_color, risk_label, REPORT_DIR, DATA_DIR
)
from analyzer import analyze_email
from reporter import generate_pdf_report, generate_html_report
from model import train_model

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;600;700&display=swap');

html, body, [class*="css"] {
    font-family: 'IBM Plex Sans', sans-serif;
}
.stApp { background: #0d1117; }

/* Sidebar */
section[data-testid="stSidebar"] {
    background: #161b22 !important;
    border-right: 1px solid #30363d;
}
section[data-testid="stSidebar"] * { color: #e6edf3 !important; }

/* Main area */
.main .block-container { padding: 1.5rem 2rem; }

/* Cards */
.metric-card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 10px;
    padding: 1.2rem 1.4rem;
    text-align: center;
}
.metric-value { font-size: 2.2rem; font-weight: 700; font-family: 'IBM Plex Mono', monospace; }
.metric-label { font-size: 0.78rem; color: #8b949e; margin-top: 2px; }

/* Risk badge */
.badge {
    display: inline-block;
    padding: 4px 14px;
    border-radius: 20px;
    font-weight: 700;
    font-size: 0.85rem;
    font-family: 'IBM Plex Mono', monospace;
    letter-spacing: 0.05em;
}
.badge-phishing  { background: #e63946; color: white; }
.badge-suspicious{ background: #f4a261; color: #1a1a1a; }
.badge-safe      { background: #2a9d8f; color: white; }

/* Flag items */
.flag-item {
    background: #161b22;
    border-left: 3px solid #f4a261;
    border-radius: 4px;
    padding: 6px 12px;
    margin: 4px 0;
    font-size: 0.85rem;
    color: #e6edf3;
}
.flag-item.critical { border-left-color: #e63946; }
.flag-item.safe     { border-left-color: #2a9d8f; }

/* URL card */
.url-card {
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 8px 14px;
    margin: 5px 0;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.78rem;
}

/* Section header */
.section-title {
    font-size: 1rem;
    font-weight: 600;
    color: #58a6ff;
    border-bottom: 1px solid #30363d;
    padding-bottom: 6px;
    margin-bottom: 12px;
}

/* Textarea */
.stTextArea textarea {
    background: #0d1117 !important;
    color: #e6edf3 !important;
    border: 1px solid #30363d !important;
    font-family: 'IBM Plex Mono', monospace !important;
    font-size: 0.82rem !important;
}
.stTextInput input {
    background: #0d1117 !important;
    color: #e6edf3 !important;
    border: 1px solid #30363d !important;
}

/* Buttons */
.stButton > button {
    background: linear-gradient(135deg, #238636 0%, #2ea043 100%);
    color: white !important;
    border: none;
    border-radius: 6px;
    font-weight: 600;
    padding: 0.5rem 1.5rem;
    transition: all 0.2s;
}
.stButton > button:hover { filter: brightness(1.1); transform: translateY(-1px); }

div[data-testid="stExpander"] {
    background: #161b22 !important;
    border: 1px solid #30363d !important;
    border-radius: 8px !important;
}

h1, h2, h3 { color: #e6edf3 !important; }
p, li { color: #c9d1d9; }
</style>
""", unsafe_allow_html=True)

# ── Sample phishing emails ────────────────────────────────────────────────────
SAMPLES = {
    "⚠️ PayPal Phishing": """From: security@paypa1-alerts.com
Reply-To: noreply@harvest-creds.xyz
To: victim@example.com
Subject: URGENT: Your PayPal Account Has Been Suspended

Dear Customer,

We have detected suspicious activity on your PayPal account. Your account has been temporarily suspended.

To restore access, you must verify your identity IMMEDIATELY by clicking the link below:

http://paypal-secure-verification.xyz/login?ref=urgent&user=victim

Failure to verify within 24 hours will result in permanent account closure and all funds will be frozen.

Click here to verify now: http://bit.ly/3xPh1sh1ng

PayPal Security Team
© PayPal Inc.""",

    "✅ Legitimate Work Email": """From: alice.manager@company.com
To: team@company.com
Subject: Q3 Review Meeting – Notes Attached

Hi team,

Thank you for attending today's Q3 review meeting. I've attached the meeting notes for your reference.

Key takeaways:
- Project Alpha is on track for November delivery
- Budget utilization at 78% – within expectations
- Next sync scheduled for Friday at 2pm

Please review and let me know if I missed anything.

Best,
Alice
Senior Project Manager""",

    "🎣 Prize Scam": """From: winner-notification@lotteryintl-prize.com
Subject: Congratulations! You Have Won $1,500,000.00 USD!

CONGRATULATIONS!!!

Your email address has been selected as our LUCKY WINNER in the International Email Lottery.

You have won the sum of ONE MILLION FIVE HUNDRED THOUSAND UNITED STATES DOLLARS ($1,500,000.00 USD).

To claim your prize IMMEDIATELY, send your:
1. Full Name
2. Home Address  
3. Phone Number
4. Bank Account Number and Routing Number
5. Copy of Government ID

HURRY! This offer expires in 48 HOURS!!!

Contact our claims agent: Dr. James Wilson
Email: claims-agent@lottery-payout.net""",
}

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style="text-align:center;padding:1rem 0">
      <div style="font-size:2.5rem">🛡️</div>
      <div style="font-size:1.1rem;font-weight:700;color:#e6edf3">Phishing Detector</div>
      <div style="font-size:0.75rem;color:#8b949e">AI-Powered Email Security</div>
    </div>
    """, unsafe_allow_html=True)
    st.divider()

    page = st.radio("Navigate", ["🔍 Analyze Email", "📊 History & Stats", "⚙️ Settings & Training"],
                    label_visibility="collapsed")
    st.divider()

    st.markdown("**API Keys** *(optional)*")
    vt_key  = st.text_input("VirusTotal API Key", type="password",
                            placeholder="Leave blank to skip URL API scan")
    llm_key = st.text_input("LLM API Key (Claude/OpenAI)", type="password",
                            placeholder="Leave blank to skip LLM analysis")
    llm_prov = st.selectbox("LLM Provider", ["anthropic", "openai"])

    st.divider()
    st.markdown("""<div style="font-size:0.72rem;color:#8b949e">
    <b>Risk Levels</b><br>
    🔴 Phishing: 70–100%<br>
    🟡 Suspicious: 35–69%<br>
    🟢 Safe: 0–34%<br><br>
    <b>Powered by</b><br>
    Random Forest + TF-IDF<br>
    Rule-based heuristics<br>
    URL entropy analysis
    </div>""", unsafe_allow_html=True)

# ── Helper UI components ──────────────────────────────────────────────────────

def gauge_chart(score: float, label: str):
    color = risk_color(label)
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        domain={"x": [0, 1], "y": [0, 1]},
        number={"suffix": "%", "font": {"size": 32, "color": "#e6edf3",
                                         "family": "IBM Plex Mono"}},
        gauge={
            "axis": {"range": [0, 100], "tickfont": {"color": "#8b949e"},
                     "tickwidth": 1, "tickcolor": "#30363d"},
            "bar": {"color": color, "thickness": 0.25},
            "bgcolor": "#161b22",
            "borderwidth": 0,
            "steps": [
                {"range": [0, 35],  "color": "#0d1f1d"},
                {"range": [35, 70], "color": "#1f1a0d"},
                {"range": [70, 100],"color": "#1f0d0e"},
            ],
            "threshold": {
                "line": {"color": color, "width": 3},
                "thickness": 0.75,
                "value": score,
            },
        },
        title={"text": f"<b>{label}</b>", "font": {"color": color, "size": 14}},
    ))
    fig.update_layout(
        height=240,
        margin=dict(l=20, r=20, t=30, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"color": "#e6edf3"},
    )
    return fig


def score_breakdown_chart(ml: float, rule: float, url: float):
    cats = ["ML Model (40%)", "Rule-Based (35%)", "URL Analysis (25%)"]
    vals = [ml, rule, url]
    colors_list = [risk_color(risk_label(v)) for v in vals]
    fig = go.Figure(go.Bar(
        x=vals, y=cats, orientation="h",
        marker_color=colors_list,
        text=[f"{v:.1f}%" for v in vals],
        textposition="outside",
        textfont={"color": "#e6edf3", "size": 11},
    ))
    fig.update_layout(
        height=160,
        margin=dict(l=0, r=40, t=10, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        xaxis={"range": [0, 110], "showgrid": False, "zeroline": False,
               "tickfont": {"color": "#8b949e"}, "showticklabels": False},
        yaxis={"tickfont": {"color": "#c9d1d9"}, "showgrid": False},
    )
    return fig

# ── PAGE: Analyze Email ───────────────────────────────────────────────────────

def page_analyze():
    st.markdown("""
    <h1 style="font-size:1.8rem;margin-bottom:4px">
      🛡️ Phishing Email Detector & Reporter
    </h1>
    <p style="color:#8b949e;margin-top:0">
      Paste or upload an email below. The AI will analyze it for phishing indicators.
    </p>
    """, unsafe_allow_html=True)

    # Sample loader
    col_sample, col_spacer = st.columns([3, 7])
    with col_sample:
        sample_choice = st.selectbox("Load a sample email:", ["— choose —"] + list(SAMPLES.keys()))

    email_text = st.session_state.get("email_text", "")
    if sample_choice != "— choose —":
        email_text = SAMPLES[sample_choice]
        st.session_state["email_text"] = email_text

    # Upload
    uploaded = st.file_uploader("Or upload an .eml / .txt file", type=["eml", "txt"])
    if uploaded:
        email_text = uploaded.read().decode("utf-8", errors="replace")
        st.session_state["email_text"] = email_text

    # Text area
    email_input = st.text_area(
        "Paste email content here (headers + body):",
        value=email_text,
        height=260,
        placeholder="Paste the full email here, including headers like From:, Subject:, To: …",
        key="email_area",
    )

    btn_col, clear_col, _ = st.columns([2, 1, 7])
    with btn_col:
        analyze_btn = st.button("🔍 Analyze Email", use_container_width=True)
    with clear_col:
        if st.button("🗑️ Clear", use_container_width=True):
            st.session_state["email_text"] = ""
            st.rerun()

    if analyze_btn:
        if not email_input.strip():
            st.warning("⚠️ Please paste or upload an email first.")
            return

        with st.spinner("🔍 Analyzing email…"):
            try:
                result = analyze_email(
                    email_input,
                    vt_api_key=vt_key,
                    llm_api_key=llm_key,
                    llm_provider=llm_prov,
                )
                st.session_state["last_result"] = result
            except Exception as e:
                st.error(f"Analysis failed: {e}")
                return

        _render_results(result)

    elif "last_result" in st.session_state:
        _render_results(st.session_state["last_result"])


def _render_results(result):
    label = result.label
    lcolor = risk_color(label)

    st.divider()
    st.markdown(f"""
    <div style="display:flex;align-items:center;gap:14px;margin-bottom:1rem">
      <span style="font-size:1.3rem;font-weight:700;color:#e6edf3">Analysis Result</span>
      <span class="badge badge-{'phishing' if label=='PHISHING' else 'suspicious' if label=='SUSPICIOUS' else 'safe'}">
        {label}
      </span>
      <span style="color:#8b949e;font-size:0.85rem">Scan ID: {result.scan_id} · {result.timestamp}</span>
    </div>
    """, unsafe_allow_html=True)

    # Top row: gauge + breakdown
    c1, c2 = st.columns([1, 2])
    with c1:
        st.plotly_chart(gauge_chart(result.risk_score, label),
                        use_container_width=True, config={"displayModeBar": False})
    with c2:
        url_avg = (sum(u.get("risk_score", 0) for u in result.url_results)
                   / max(len(result.url_results), 1)) if result.url_results else 0
        st.markdown('<div class="section-title">Score Breakdown</div>', unsafe_allow_html=True)
        st.plotly_chart(
            score_breakdown_chart(result.ml_score, result.rule_score, url_avg),
            use_container_width=True, config={"displayModeBar": False}
        )
        # Quick metrics
        m1, m2, m3, m4 = st.columns(4)
        for col, val, lbl in [
            (m1, f"{result.risk_score:.0f}%", "Risk Score"),
            (m2, str(len(result.flags)), "Red Flags"),
            (m3, str(len(result.raw_urls)), "URLs Found"),
            (m4, "YES" if result.sender_spoofed else "No", "Spoofed"),
        ]:
            with col:
                col_color = lcolor if lbl == "Risk Score" else ("#e63946" if val not in ("No","0","0%") else "#2a9d8f")
                st.markdown(f"""<div class="metric-card">
                  <div class="metric-value" style="color:{col_color}">{val}</div>
                  <div class="metric-label">{lbl}</div>
                </div>""", unsafe_allow_html=True)

    # Tabs for detail
    st.markdown("<br>", unsafe_allow_html=True)
    tab1, tab2, tab3, tab4, tab5 = st.tabs(
        ["🚩 Flags", "🔗 URLs", "🔍 Keywords", "📄 Email Preview", "🤖 LLM Analysis"]
    )

    with tab1:
        if result.flags:
            for flag in result.flags:
                severity = "critical" if any(k in flag.lower() for k in
                    ["phishing", "spoofing", "ip address", "malicious"]) else ""
                st.markdown(f'<div class="flag-item {severity}">⚠️ {flag}</div>',
                            unsafe_allow_html=True)
        else:
            st.markdown('<div class="flag-item safe">✅ No suspicious flags detected.</div>',
                        unsafe_allow_html=True)
        if result.sender_spoofed:
            st.error(f"🎭 **Sender Spoofing Detected**: {result.spoof_reason}")

    with tab2:
        if result.url_results:
            for ur in result.url_results:
                rs = ur.get("risk_score", 0)
                ul = "🔴 HIGH RISK" if rs >= 50 else ("🟡 SUSPICIOUS" if rs >= 20 else "🟢 OK")
                with st.expander(f"{ul} · {ur['url'][:70]}… ({rs:.0f}%)"
                                 if len(ur['url']) > 70 else f"{ul} · {ur['url']} ({rs:.0f}%)"):
                    col_a, col_b = st.columns(2)
                    with col_a:
                        st.write(f"**Domain:** `{ur.get('domain','?')}`")
                        st.write(f"**IP URL:** {'⚠️ Yes' if ur.get('is_ip_url') else 'No'}")
                        st.write(f"**Shortener:** {'⚠️ Yes' if ur.get('is_shortener') else 'No'}")
                    with col_b:
                        st.write(f"**Known Phishing:** {'🔴 Yes' if ur.get('known_phishing') else 'No'}")
                        st.write(f"**Subdomains:** {ur.get('subdomain_count', 0)}")
                        st.write(f"**Entropy:** {ur.get('entropy', 0):.2f}")
                    if ur.get("flags"):
                        st.warning("**Flags:** " + " | ".join(ur["flags"]))
        else:
            st.info("No URLs found in this email.")
        if result.raw_urls:
            st.caption(f"**All extracted URLs ({len(result.raw_urls)}):**")
            for u in result.raw_urls:
                st.markdown(f'<div class="url-card">{u}</div>', unsafe_allow_html=True)

    with tab3:
        if result.keyword_hits:
            for category, words in result.keyword_hits.items():
                st.markdown(f"**{category} keywords:**")
                st.write(", ".join(f"`{w}`" for w in words))
        else:
            st.info("No significant keyword patterns detected.")
        if result.html_tricks:
            st.markdown("**HTML Obfuscation Tricks:**")
            for trick in result.html_tricks:
                st.warning(f"🎭 {trick}")

    with tab4:
        st.markdown("**Subject:**")
        st.code(result.subject)
        st.markdown("**From:**")
        st.code(result.sender)
        if result.reply_to:
            st.markdown("**Reply-To:**")
            st.code(result.reply_to)
        st.markdown("**Body Preview:**")
        st.text_area("", value=result.full_body[:1500], height=200, disabled=True)

    with tab5:
        if result.llm_used:
            st.markdown("**AI Semantic Analysis:**")
            phish_detected = "phishing" in result.llm_analysis.lower()
            if phish_detected:
                st.error(result.llm_analysis)
            else:
                st.success(result.llm_analysis)
        else:
            st.info("LLM analysis not enabled. Add a Claude or OpenAI API key in the sidebar to enable semantic analysis.")

    # ── Report downloads ──────────────────────────────────────────────────────
    st.divider()
    st.markdown("### 📥 Download Report")
    dl1, dl2, dl3 = st.columns(3)

    with dl1:
        try:
            pdf_bytes = generate_pdf_report(result)
            st.download_button(
                "📄 Download PDF Report",
                data=pdf_bytes,
                file_name=f"phishing_report_{result.scan_id}.pdf",
                mime="application/pdf",
                use_container_width=True,
            )
        except Exception as e:
            st.error(f"PDF generation failed: {e}")

    with dl2:
        html_bytes = generate_html_report(result).encode("utf-8")
        st.download_button(
            "🌐 Download HTML Report",
            data=html_bytes,
            file_name=f"phishing_report_{result.scan_id}.html",
            mime="text/html",
            use_container_width=True,
        )

    with dl3:
        import json as _json
        from dataclasses import asdict
        json_bytes = _json.dumps(asdict(result), indent=2, default=str).encode()
        st.download_button(
            "📊 Download JSON Data",
            data=json_bytes,
            file_name=f"phishing_data_{result.scan_id}.json",
            mime="application/json",
            use_container_width=True,
        )

    # Simulate report button
    if st.button("📨 Report as Phishing (Simulated)"):
        with st.spinner("Reporting…"):
            time.sleep(1.2)
        st.success(f"✅ Email reported! Scan ID `{result.scan_id}` logged to security team. "
                   "(Simulation – in production this would forward to abuse@yourdomain.com)")

# ── PAGE: History & Stats ─────────────────────────────────────────────────────

def page_history():
    st.markdown('<h1 style="font-size:1.8rem">📊 Scan History & Statistics</h1>',
                unsafe_allow_html=True)
    history = load_history()

    if not history:
        st.info("No scans yet. Analyze some emails to see history here.")
        return

    # Summary metrics
    df = pd.DataFrame(history)
    total = len(df)
    n_phish = (df["label"] == "PHISHING").sum()
    n_susp  = (df["label"] == "SUSPICIOUS").sum()
    n_safe  = (df["label"] == "SAFE").sum()

    m1, m2, m3, m4 = st.columns(4)
    for col, val, lbl, color in [
        (m1, str(total), "Total Scans", "#58a6ff"),
        (m2, str(n_phish), "Phishing", "#e63946"),
        (m3, str(n_susp),  "Suspicious", "#f4a261"),
        (m4, str(n_safe),  "Safe", "#2a9d8f"),
    ]:
        with col:
            st.markdown(f"""<div class="metric-card">
              <div class="metric-value" style="color:{color}">{val}</div>
              <div class="metric-label">{lbl}</div>
            </div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Charts
    c1, c2 = st.columns(2)
    with c1:
        label_counts = df["label"].value_counts()
        fig_pie = go.Figure(go.Pie(
            labels=label_counts.index,
            values=label_counts.values,
            marker_colors=["#e63946", "#f4a261", "#2a9d8f"][:len(label_counts)],
            hole=0.5,
            textfont={"color": "white"},
        ))
        fig_pie.update_layout(
            title="Label Distribution",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font={"color": "#e6edf3"},
            height=280,
            margin=dict(l=0, r=0, t=40, b=0),
            legend={"font": {"color": "#c9d1d9"}},
        )
        st.plotly_chart(fig_pie, use_container_width=True, config={"displayModeBar": False})

    with c2:
        if "risk_score" in df.columns:
            fig_hist = go.Figure(go.Histogram(
                x=df["risk_score"],
                nbinsx=20,
                marker_color="#58a6ff",
                opacity=0.8,
            ))
            fig_hist.update_layout(
                title="Risk Score Distribution",
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font={"color": "#e6edf3"},
                height=280,
                margin=dict(l=0, r=0, t=40, b=0),
                xaxis={"title": "Risk Score (%)", "gridcolor": "#21262d"},
                yaxis={"title": "Count", "gridcolor": "#21262d"},
            )
            st.plotly_chart(fig_hist, use_container_width=True, config={"displayModeBar": False})

    # Table
    st.markdown('<div class="section-title">Recent Scans</div>', unsafe_allow_html=True)
    display_df = df[["scan_id", "timestamp", "subject", "sender", "risk_score", "label", "n_urls"]].copy()
    display_df.columns = ["Scan ID", "Time", "Subject", "Sender", "Risk %", "Label", "URLs"]

    def color_label(val):
        c = {"PHISHING": "#e63946", "SUSPICIOUS": "#f4a261", "SAFE": "#2a9d8f"}.get(val, "#888")
        return f"color: {c}; font-weight: bold"

    styled = display_df.style.applymap(color_label, subset=["Label"])
    st.dataframe(styled, use_container_width=True, height=350)

    if st.button("🗑️ Clear All History"):
        from utils import LOG_FILE
        if LOG_FILE.exists():
            LOG_FILE.unlink()
        st.success("History cleared.")
        st.rerun()

# ── PAGE: Settings & Training ─────────────────────────────────────────────────

def page_settings():
    st.markdown('<h1 style="font-size:1.8rem">⚙️ Settings & Model Training</h1>',
                unsafe_allow_html=True)

    st.markdown("### 🤖 Machine Learning Model")
    from utils import MODEL_DIR
    model_exists = (MODEL_DIR / "phishing_model.pkl").exists()

    if model_exists:
        st.success("✅ Model is trained and ready.")
    else:
        st.warning("⚠️ Model not found. Train it below.")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("🚀 Train Model (Synthetic Data)", use_container_width=True):
            with st.spinner("Training Random Forest on synthetic dataset…"):
                info = train_model(force_retrain=True)
            if info.get("status") in ("trained", "loaded"):
                acc = info.get("accuracy", "?")
                st.success(f"✅ Model trained! Accuracy: {acc:.1%}" if isinstance(acc, float)
                           else "✅ Model trained!")
            else:
                st.error("Training failed.")

    with col2:
        with st.expander("📂 Upload Custom Dataset (CSV)"):
            up = st.file_uploader("CSV with columns: subject, body, label (0=legit, 1=phish)",
                                  type=["csv"])
            if up:
                import pandas as pd
                df_up = pd.read_csv(up)
                df_up.to_csv(DATA_DIR / "email_dataset.csv", index=False)
                st.success(f"Dataset saved ({len(df_up)} rows). Click Train above.")

    st.divider()
    st.markdown("### 📋 Model Info")
    st.json({
        "algorithm":     "Random Forest Classifier (200 trees)",
        "features":      "TF-IDF (1-2 gram, 5000 features) + 10 handcrafted features",
        "training_data": "2000 synthetic emails (50% phishing / 50% legit)",
        "scoring":       "ML 40% + Rule-based 35% + URL analysis 25%",
        "model_path":    str(MODEL_DIR / "phishing_model.pkl"),
    })

    st.divider()
    st.markdown("### 🔑 API Configuration Guide")
    with st.expander("VirusTotal API Setup"):
        st.markdown("""
1. Go to [virustotal.com](https://www.virustotal.com) and create a free account
2. Navigate to your profile → API Key
3. Copy the key and paste it in the sidebar
4. Free tier: 4 requests/minute, 500/day
        """)
    with st.expander("Claude API Setup"):
        st.markdown("""
1. Go to [console.anthropic.com](https://console.anthropic.com)
2. Create an account and generate an API key
3. Paste in the sidebar under "LLM API Key"
4. Select "anthropic" as the LLM provider
        """)
    with st.expander("OpenAI API Setup"):
        st.markdown("""
1. Go to [platform.openai.com](https://platform.openai.com)
2. Create an API key under your account settings
3. Paste in the sidebar and select "openai" as provider
        """)

    st.divider()
    st.markdown("### 📊 Public Phishing Datasets")
    st.markdown("""
- **[SpamAssassin Public Corpus](https://spamassassin.apache.org/old/publiccorpus/)** – Spam/ham labeled emails
- **[Enron Email Dataset](https://www.cs.cmu.edu/~enron/)** – Large corporate email corpus  
- **[PhishTank](https://phishtank.org/developer_info.php)** – Known phishing URLs database
- **[Nazario Phishing Corpus](https://monkey.org/~jose/phishing/)** – Academic phishing dataset
- **[UCI SMS Spam Collection](https://archive.ics.uci.edu/ml/datasets/SMS+Spam+Collection)** – Text classification baseline
    """)

# ── Auto-train on first run ───────────────────────────────────────────────────

from utils import MODEL_DIR
if not (MODEL_DIR / "phishing_model.pkl").exists():
    with st.spinner("🤖 Training ML model for the first time (one-time setup)…"):
        try:
            train_model()
        except Exception as e:
            st.warning(f"Auto-train failed: {e} — use Settings to train manually.")

# ── Route pages ───────────────────────────────────────────────────────────────
if page == "🔍 Analyze Email":
    page_analyze()
elif page == "📊 History & Stats":
    page_history()
elif page == "⚙️ Settings & Training":
    page_settings()
