"""
Streamlit UI for ST Configuration Promotion.
Run with:  streamlit run app.py
"""

import configparser
import subprocess
import sys
import os
import streamlit as st

# ── Helpers ─────────────────────────────────────────────────────────────────

CONFIG_PATH = "conf/config.ini"


@st.cache_data
def get_st_sections() -> list[str]:
    """Return config.ini sections that define an ST server (have ST_HOST)."""
    config = configparser.RawConfigParser(allow_no_value=True)
    config.optionxform = str
    config.read(CONFIG_PATH)
    sections = []
    for sec in config.sections():
        try:
            host = config.get(sec, "ST_HOST")
            if host:
                sections.append(sec)
        except (configparser.NoOptionError, configparser.NoSectionError):
            pass
    return sections


def section_label(section: str) -> str:
    """Build a human-readable label: SECTION_NAME (host:port)."""
    config = configparser.RawConfigParser(allow_no_value=True)
    config.optionxform = str
    config.read(CONFIG_PATH)
    try:
        host = config.get(section, "ST_HOST")
        port = config.get(section, "ST_PORT")
        return f"{section}  ({host}:{port})"
    except Exception:
        return section


# ── Page config ─────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="ST Configuration Promotion",
    page_icon="🔄",
    layout="centered",
)

st.title("ST Configuration Promotion")
st.markdown("Promote accounts or individual transfer sites between SecureTransport servers.")

# ── Server selection ────────────────────────────────────────────────────────

st.header("1 · Select servers")

sections = get_st_sections()
labels = {sec: section_label(sec) for sec in sections}

col1, col2 = st.columns(2)
with col1:
    source = st.selectbox(
        "Source ST",
        options=sections,
        format_func=lambda s: labels[s],
        index=sections.index("ST_NON_PROD") if "ST_NON_PROD" in sections else 0,
    )
with col2:
    target = st.selectbox(
        "Target ST",
        options=sections,
        format_func=lambda s: labels[s],
        index=sections.index("ST_PROD") if "ST_PROD" in sections else 0,
    )

if source == target:
    st.warning("⚠️ Source and Target must be different servers.")

# ── Promotion mode ──────────────────────────────────────────────────────────

st.header("2 · Choose what to promote")

mode = st.radio(
    "Promotion mode",
    options=["Full account", "Single transfer site"],
    horizontal=True,
)

account_name = st.text_input("Account name", placeholder="e.g. hrisy")

site_name = None
if mode == "Single transfer site":
    site_name = st.text_input("Transfer site name", placeholder="e.g. SMB")

# ── Run ─────────────────────────────────────────────────────────────────────

st.header("3 · Run promotion")

can_run = (
    source != target
    and account_name.strip()
    and (mode == "Full account" or (site_name and site_name.strip()))
)

if st.button("Start promotion", disabled=not can_run, type="primary", use_container_width=True):
    account = account_name.strip()

    # Build the environment for the subprocess — pass the chosen source/target
    env = os.environ.copy()
    env["ST_SOURCE"] = source
    env["ST_TARGET"] = target
    env["ACCOUNT_NAME"] = account

    if mode == "Full account":
        script = "stPromotion.py"
        env["SITE_NAME"] = ""
    else:
        script = "stSitePromotion.py"
        env["SITE_NAME"] = site_name.strip()

    st.info(f"Running **{script}** — promoting **{account}** from **{source}** → **{target}** …")

    with st.spinner("Promotion in progress …"):
        result = subprocess.run(
            [sys.executable, script],
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.abspath(__file__)),
            env=env,
        )

    # ── Show results ────────────────────────────────────────────────────────
    if result.returncode == 0:
        st.success("Promotion completed successfully!")
    else:
        st.error(f"Promotion failed (exit code {result.returncode})")

    # Standard output
    if result.stdout.strip():
        st.subheader("Output")
        st.code(result.stdout, language="text")

    # Standard error (warnings / tracebacks)
    if result.stderr.strip():
        with st.expander("stderr", expanded=result.returncode != 0):
            st.code(result.stderr, language="text")

    # Show log
    log_path = "Logs/master.log"
    if os.path.exists(log_path):
        with st.expander("Full log (Logs/master.log)"):
            with open(log_path) as f:
                st.code(f.read(), language="text")

