"""
app.py - AI-Based Cybersecurity Monitoring Agent Dashboard
Member 1: Frontend Ingestion, UI Validation, and Backend Integration

Premium Stripe-inspired Technology Dashboard with Subtle 3D UI/UX Effects
Defensive Security Operations Center (SOC) for log ingestion, schema validation,
intrusion detection integration, and alert visualization.
Light theme palette: White Lilac (#F8F8F9), Deep Navy (#111439), Indigo (#635BFF),
Violet (#8B5CF6), Cyan (#22B8CF).
"""

from typing import Dict, Any, Optional
import base64
import glob
import io
import os
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

# Import frontend CSV validator (Member 1)
try:
    from csv_validator import validate_uploaded_csv, ValidationResult
except ImportError as err:
    st.error(f"Critical Dependency Error: Failed to import csv_validator module ({err}).")
    validate_uploaded_csv = None

# Attempt to import detection pipeline (Member 2)
# If detector.py is not yet implemented, gracefully degrade with informational status.
try:
    from detector import run_full_detection_pipeline
    BACKEND_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    run_full_detection_pipeline = None
    BACKEND_AVAILABLE = False

# Attempt to import incident intelligence module (Attack Story & Risk Prioritization)
try:
    from incident_intelligence import (
        build_incident_intelligence,
        CorrelatedIncident,
        RiskAssessment,
        AttackStory,
    )
    INTELLIGENCE_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    build_incident_intelligence = None
    INTELLIGENCE_AVAILABLE = False



# -----------------------------------------------------------------------------
# Streamlit Page Configuration & Styling
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="AI-Based Cybersecurity Monitoring Agent",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Lightweight Static 3D Security Shield SVG Illustration
SHIELD_3D_SVG = """
<svg width="68" height="68" viewBox="0 0 72 72" fill="none" xmlns="http://www.w3.org/2000/svg" style="filter: drop-shadow(0 10px 20px rgba(99, 91, 255, 0.28)); flex-shrink: 0;">
    <defs>
        <linearGradient id="shieldGrad3d" x1="8" y1="6" x2="64" y2="66" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stop-color="#635BFF"/>
            <stop offset="48%" stop-color="#8B5CF6"/>
            <stop offset="100%" stop-color="#22B8CF"/>
        </linearGradient>
        <linearGradient id="specular3d" x1="12" y1="8" x2="60" y2="36" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stop-color="#FFFFFF" stop-opacity="0.55"/>
            <stop offset="100%" stop-color="#FFFFFF" stop-opacity="0"/>
        </linearGradient>
        <linearGradient id="bevelShade3d" x1="36" y1="8" x2="62" y2="62" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stop-color="#111439" stop-opacity="0"/>
            <stop offset="100%" stop-color="#111439" stop-opacity="0.25"/>
        </linearGradient>
        <radialGradient id="nodeOrb3d" cx="36" cy="34" r="15" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stop-color="#FFFFFF"/>
            <stop offset="35%" stop-color="#22B8CF"/>
            <stop offset="85%" stop-color="#111439"/>
        </radialGradient>
    </defs>
    <!-- Base 3D Shell -->
    <path d="M36 6L12 16.5V34C12 49 22 62.5 36 66C50 62.5 60 49 60 34V16.5L36 6Z" fill="url(#shieldGrad3d)"/>
    <!-- 3D Bevel Right Shade -->
    <path d="M36 6L60 16.5V34C60 49 50 62.5 36 66V6Z" fill="url(#bevelShade3d)"/>
    <!-- Specular Highlight Curve -->
    <path d="M36 8L14 18V34C14 41 17 48 22 53L36 8Z" fill="url(#specular3d)"/>
    <!-- Core Recessed Shield Face -->
    <path d="M36 13L18 21.5V34C18 45 25.5 55 36 58.5C46.5 55 54 45 54 34V21.5L36 13Z" fill="#111439" fill-opacity="0.9"/>
    <!-- 3D Luminous Node Sphere -->
    <circle cx="36" cy="35" r="10" fill="url(#nodeOrb3d)" opacity="0.96"/>
    <circle cx="33" cy="32" r="2.8" fill="#FFFFFF" opacity="0.9"/>
    <path d="M36 28V42M29 35H43" stroke="#FFFFFF" stroke-width="2" stroke-linecap="round" opacity="0.95"/>
</svg>
"""

CUSTOM_CSS = """
<style>
    /* Google Fonts - Inter & JetBrains Mono */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

    /* Design System Tokens: Premium Stripe-inspired SaaS Light Theme */
    :root {
        --bg-main: #F8F8F9;
        --bg-card: #FFFFFF;
        --primary-navy: #111439;
        --secondary-navy: #24294F;
        --primary-indigo: #635BFF;
        --violet-accent: #8B5CF6;
        --cyan-accent: #22B8CF;
        --text-primary: #111439;
        --text-secondary: #111439;
        --border-color: #E7E7F0;
        --severity-critical: #DC3545;
        --severity-medium: #C27A00;
        --severity-low: #2563EB;
        --status-success: #16845B;
        --gradient-stripe: linear-gradient(115deg, #635BFF 0%, #8B5CF6 48%, #22B8CF 100%);
    }

    /* Overall App Background & Typography */
    .stApp {
        background-color: #111439;
        color: #FFFFFF !important;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
    }

    [data-testid="stAppViewContainer"] {
        background-color: transparent !important;
    }

    [data-testid="stMain"] {
        background-color: transparent !important;
        position: relative !important;
        z-index: 1 !important;
    }

    /* Transparent Content Canvas - Allows Animated Globe to Shine Through */
    [data-testid="stMain"] .block-container {
        background-color: transparent !important;
        backdrop-filter: none !important;
        -webkit-backdrop-filter: none !important;
        border-radius: 0 !important;
        padding: 1.8rem 2.8rem 3rem 2.8rem !important;
        margin-top: 0 !important;
        margin-bottom: 2rem !important;
        border: none !important;
        box-shadow: none !important;
    }

    [data-testid="stHeader"] {
        background-color: transparent !important;
        backdrop-filter: none !important;
        z-index: 2 !important;
    }

    /* Animated Hero Component Container */
    [data-testid="stIFrame"] {
        width: 100% !important;
        border: none !important;
        border-radius: 14px !important;
        margin-bottom: 20px !important;
        overflow: hidden !important;
    }

    /* Sidebar Customization - Deep Navy #111439 with Subtle 3D Glass Accents */
    [data-testid="stSidebar"] {
        background-color: #111439 !important;
        border-right: 1px solid #24294F !important;
        z-index: 3 !important;
    }

    [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p,
    [data-testid="stSidebar"] span,
    [data-testid="stSidebar"] label {
        color: #E7E7F0 !important;
    }

    [data-testid="stSidebar"] h1,
    [data-testid="stSidebar"] h2,
    [data-testid="stSidebar"] h3 {
        color: #FFFFFF !important;
        letter-spacing: -0.02em !important;
    }

    [data-testid="stSidebar"] hr {
        border-color: #24294F !important;
    }

    /* Sidebar Radio Navigation items with 3D Depth Indicator */
    [data-testid="stSidebar"] div[role="radiogroup"] label {
        background: transparent;
        padding: 9px 14px;
        border-radius: 8px;
        margin-bottom: 5px;
        transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
        border: 1px solid transparent;
        cursor: pointer;
    }

    [data-testid="stSidebar"] div[role="radiogroup"] label:hover {
        background: rgba(99, 91, 255, 0.16) !important;
        transform: translateX(2px);
    }

    [data-testid="stSidebar"] div[role="radiogroup"] label[data-checked="true"] {
        background: rgba(99, 91, 255, 0.26) !important;
        border-left: 3px solid #22B8CF !important;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.25), inset 0 1px 0 rgba(255, 255, 255, 0.1) !important;
    }

    [data-testid="stSidebar"] div[role="radiogroup"] label[data-checked="true"] span {
        color: #22B8CF !important;
        font-weight: 600 !important;
    }

    /* Sidebar Brand Header */
    .sidebar-brand {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 10px 0 16px 0;
        margin-bottom: 8px;
    }

    .sidebar-brand-title {
        font-size: 1.15rem;
        font-weight: 700;
        color: #FFFFFF;
        letter-spacing: 0.04em;
        margin: 0;
    }

    .sidebar-brand-subtitle {
        font-size: 0.75rem;
        color: #CBD5E1;
        margin: 0;
        font-weight: 500;
    }

    /* Glassmorphic Sidebar Status Cards */
    .sidebar-status-card {
        background: rgba(25, 30, 71, 0.70) !important;
        backdrop-filter: blur(12px) !important;
        -webkit-backdrop-filter: blur(12px) !important;
        border: 1px solid rgba(255, 255, 255, 0.12) !important;
        border-radius: 10px !important;
        padding: 14px 16px !important;
        margin-top: 10px !important;
        margin-bottom: 12px !important;
        box-shadow: 
            0 4px 16px rgba(0, 0, 0, 0.22),
            inset 0 1px 0 rgba(255, 255, 255, 0.12) !important;
        transition: transform 0.2s ease, box-shadow 0.2s ease;
    }

    .sidebar-status-card:hover {
        transform: translateY(-1px);
        box-shadow: 
            0 6px 20px rgba(0, 0, 0, 0.30),
            inset 0 1px 0 rgba(255, 255, 255, 0.18) !important;
    }

    .sidebar-status-label {
        font-size: 0.70rem;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        color: #CBD5E1;
        font-weight: 600;
        margin-bottom: 4px;
    }

    .sidebar-status-val {
        font-size: 0.82rem;
        color: #FFFFFF;
        font-weight: 600;
    }

    /* Main Area Headers and Typography - High Contrast against Animated Cyber Background */
    [data-testid="stMain"] h1, 
    [data-testid="stMain"] h2, 
    [data-testid="stMain"] h3,
    [data-testid="stMain"] h4,
    [data-testid="stMain"] h5,
    [data-testid="stMain"] h6 {
        color: #FFFFFF !important;
        font-weight: 700 !important;
        letter-spacing: -0.02em !important;
        text-shadow: 0 2px 8px rgba(0, 0, 0, 0.65) !important;
    }

    [data-testid="stMain"] p, 
    [data-testid="stMain"] li {
        color: #F1F5F9 !important;
        line-height: 1.6 !important;
        text-shadow: 0 1px 4px rgba(0, 0, 0, 0.6) !important;
    }

    [data-testid="stMain"] [data-testid="stCaptionContainer"] p,
    [data-testid="stCaptionContainer"] p,
    .stCaptionContainer p {
        color: #CBD5E1 !important;
        font-weight: 500 !important;
        text-shadow: 0 1px 3px rgba(0, 0, 0, 0.5) !important;
    }

    /* Preserve high-contrast dark text inside white SaaS cards */
    .saas-card h1, .saas-card h2, .saas-card h3, .saas-card h4, .saas-card h5, .saas-card h6 {
        color: #111439 !important;
        text-shadow: none !important;
    }
    .saas-card p, .saas-card li {
        color: #111439 !important;
        text-shadow: none !important;
    }

    /* Sidebar Captions & Light Elements on Deep Navy Dark Background */
    [data-testid="stSidebar"] [data-testid="stCaptionContainer"] p,
    [data-testid="stSidebar"] .stCaptionContainer p,
    [data-testid="stSidebar"] small {
        color: #CBD5E1 !important;
        font-weight: 500 !important;
    }

    /* Form & Filter Widget Labels & Inputs Contrast */
    [data-testid="stWidgetLabel"] label,
    [data-testid="stWidgetLabel"] p,
    [data-testid="stWidgetLabel"] span {
        color: #FFFFFF !important;
        font-weight: 700 !important;
        font-size: 0.88rem !important;
        text-shadow: 0 1px 4px rgba(0, 0, 0, 0.6) !important;
    }

    div[data-baseweb="select"] {
        background-color: #FFFFFF !important;
        border-radius: 8px !important;
    }

    div[data-baseweb="select"] span {
        color: #111439 !important;
        font-weight: 500 !important;
    }

    div[data-baseweb="input"] {
        background-color: #FFFFFF !important;
        border-radius: 8px !important;
    }

    div[data-baseweb="input"] input {
        color: #111439 !important;
        font-weight: 500 !important;
    }

    [data-baseweb="tag"] {
        background-color: rgba(99, 91, 255, 0.12) !important;
        border: 1px solid rgba(99, 91, 255, 0.25) !important;
        border-radius: 6px !important;
    }

    [data-baseweb="tag"] span {
        color: #635BFF !important;
        font-weight: 600 !important;
    }

    /* Main Area Inline Code Elements */
    [data-testid="stMain"] code {
        background-color: rgba(25, 30, 71, 0.80) !important;
        color: #22B8CF !important;
        font-family: 'JetBrains Mono', Consolas, monospace !important;
        font-weight: 600 !important;
        padding: 2px 6px !important;
        border-radius: 4px !important;
        border: 1px solid rgba(99, 91, 255, 0.30) !important;
    }

    /* File Uploader Text Readability */
    [data-testid="stFileUploader"] section {
        background-color: rgba(17, 20, 57, 0.60) !important;
        backdrop-filter: blur(10px) !important;
        border: 2px dashed rgba(99, 91, 255, 0.40) !important;
        border-radius: 10px !important;
    }
    /* Security Log CSV File Uploader Text Color - Black #000000 */
    [data-testid="stFileUploader"] [data-testid="stWidgetLabel"] label,
    [data-testid="stFileUploader"] [data-testid="stWidgetLabel"] p,
    [data-testid="stFileUploader"] [data-testid="stWidgetLabel"] span,
    [data-testid="stFileUploader"] label,
    [data-testid="stFileUploader"] label p,
    [data-testid="stFileUploader"] button,
    [data-testid="stFileUploader"] button span,
    [data-testid="stFileUploader"] button p,
    [data-testid="stFileUploader"] button:hover,
    [data-testid="stFileUploader"] button:hover span,
    [data-testid="stFileUploader"] button:hover p,
    [data-testid="stFileUploader"] small,
    [data-testid="stFileUploader"] span,
    [data-testid="stFileUploader"] p {
        color: #000000 !important;
        text-shadow: none !important;
    }

    /* Sliders and Selectors */
    [data-testid="stSlider"] div[data-testid="stThumbValue"] {
        color: #FFFFFF !important;
        font-weight: 700 !important;
    }
    [data-testid="stSlider"] div[data-testid="stTickBar"] div {
        color: #CBD5E1 !important;
    }

    /* Main Area Radio & Checkbox Labels */
    [data-testid="stMain"] div[role="radiogroup"] label p,
    [data-testid="stMain"] div[role="radiogroup"] label span,
    [data-testid="stMain"] [data-testid="stCheckbox"] label p,
    [data-testid="stMain"] [data-testid="stCheckbox"] label span {
        color: #FFFFFF !important;
        font-weight: 600 !important;
        text-shadow: 0 1px 3px rgba(0, 0, 0, 0.5) !important;
    }

    /* Dashboard Hero Banner with 3D Depth & Layered Radial Lighting */
    .stripe-hero-card {
        background: 
            radial-gradient(circle at 92% 20%, rgba(99, 91, 255, 0.07) 0%, transparent 40%),
            radial-gradient(circle at 8% 85%, rgba(34, 184, 207, 0.06) 0%, transparent 35%),
            #FFFFFF;
        border: 1px solid #E7E7F0;
        border-radius: 14px;
        padding: 26px 30px;
        margin-bottom: 24px;
        position: relative;
        overflow: hidden;
        box-shadow: 
            0 2px 4px rgba(17, 20, 57, 0.03),
            0 10px 24px rgba(17, 20, 57, 0.05),
            0 20px 42px -8px rgba(99, 91, 255, 0.07),
            inset 0 1px 0 rgba(255, 255, 255, 0.95);
        transition: box-shadow 0.22s ease, transform 0.22s ease;
    }

    .stripe-hero-card::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        height: 4px;
        background: linear-gradient(115deg, #635BFF 0%, #8B5CF6 48%, #22B8CF 100%);
    }

    .stripe-hero-badge {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        background: rgba(255, 255, 255, 0.85);
        backdrop-filter: blur(8px);
        -webkit-backdrop-filter: blur(8px);
        color: #635BFF;
        border: 1px solid rgba(99, 91, 255, 0.22);
        padding: 5px 14px;
        border-radius: 9999px;
        font-size: 0.75rem;
        font-weight: 600;
        letter-spacing: 0.03em;
        margin-bottom: 12px;
        box-shadow: 0 2px 8px rgba(99, 91, 255, 0.08), inset 0 1px 0 #FFFFFF;
    }

    .stripe-pulse-dot {
        width: 7px;
        height: 7px;
        border-radius: 50%;
        background-color: #16845B;
        box-shadow: 0 0 0 2px rgba(22, 132, 91, 0.25);
    }

    .stripe-hero-title {
        font-size: 1.60rem;
        font-weight: 700;
        color: #111439;
        margin: 0;
        line-height: 1.25;
        letter-spacing: -0.015em;
    }

    .stripe-hero-subtitle {
        font-size: 0.92rem;
        color: #111439 !important;
        font-weight: 500 !important;
        margin-top: 6px;
        margin-bottom: 0;
        line-height: 1.45;
    }

    .hero-3d-shield-container {
        display: flex;
        align-items: center;
        justify-content: center;
        background: rgba(255, 255, 255, 0.70);
        backdrop-filter: blur(10px);
        -webkit-backdrop-filter: blur(10px);
        border: 1px solid rgba(231, 231, 240, 0.85);
        border-radius: 16px;
        padding: 12px;
        box-shadow: 
            0 4px 14px rgba(17, 20, 57, 0.06),
            0 12px 28px rgba(99, 91, 255, 0.10),
            inset 0 1px 0 #FFFFFF;
        transition: transform 0.25s cubic-bezier(0.16, 1, 0.3, 1), box-shadow 0.25s ease;
    }

    .hero-3d-shield-container:hover {
        transform: translateY(-2px) scale(1.02);
        box-shadow: 
            0 6px 18px rgba(17, 20, 57, 0.08),
            0 16px 36px rgba(99, 91, 255, 0.16),
            inset 0 1px 0 #FFFFFF;
    }

    /* 3D KPI Metric Card Styling - Multi-Layer Shadow & Restrained Gradient Top Edge */
    [data-testid="stMetric"] {
        background-color: rgba(255, 255, 255, 0.96) !important;
        backdrop-filter: blur(12px) !important;
        -webkit-backdrop-filter: blur(12px) !important;
        border: 1px solid #E7E7F0 !important;
        border-radius: 12px !important;
        padding: 20px 22px !important;
        position: relative !important;
        overflow: hidden !important;
        box-shadow: 
            0 1px 3px rgba(17, 20, 57, 0.04),
            0 6px 16px rgba(17, 20, 57, 0.04),
            0 14px 28px rgba(17, 20, 57, 0.02),
            inset 0 1px 0 rgba(255, 255, 255, 0.95) !important;
        transition: 
            transform 0.22s cubic-bezier(0.16, 1, 0.3, 1),
            box-shadow 0.22s cubic-bezier(0.16, 1, 0.3, 1),
            border-color 0.22s ease !important;
        min-height: 114px !important;
    }

    [data-testid="stMetric"]::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        height: 3px;
        background: linear-gradient(115deg, #635BFF 0%, #8B5CF6 48%, #22B8CF 100%);
        opacity: 0.85;
        border-radius: 12px 12px 0 0;
    }

    [data-testid="stMetric"]:hover {
        border-color: #635BFF !important;
        box-shadow: 
            0 4px 10px rgba(99, 91, 255, 0.08),
            0 12px 26px rgba(99, 91, 255, 0.10),
            0 22px 38px rgba(17, 20, 57, 0.06),
            inset 0 1px 0 #FFFFFF !important;
        transform: translateY(-3px) !important;
    }

    [data-testid="stMetricLabel"] p {
        color: #24294F !important;
        font-size: 0.78rem !important;
        font-weight: 700 !important;
        text-transform: uppercase !important;
        letter-spacing: 0.05em !important;
        margin-bottom: 6px !important;
    }

    [data-testid="stMetricValue"] {
        color: #111439 !important;
        font-size: 1.95rem !important;
        font-weight: 700 !important;
        font-family: 'JetBrains Mono', Consolas, monospace !important;
        letter-spacing: -0.02em !important;
    }

    /* Standard SaaS Cards with 3D Depth & Subtle Elevation */
    .saas-card {
        background: rgba(255, 255, 255, 0.96) !important;
        backdrop-filter: blur(12px) !important;
        -webkit-backdrop-filter: blur(12px) !important;
        border: 1px solid #E7E7F0;
        border-radius: 12px;
        padding: 22px 26px;
        margin-bottom: 22px;
        box-shadow: 
            0 1px 3px rgba(17, 20, 57, 0.04),
            0 6px 18px rgba(17, 20, 57, 0.03),
            inset 0 1px 0 rgba(255, 255, 255, 0.95);
        transition: 
            transform 0.22s cubic-bezier(0.16, 1, 0.3, 1),
            box-shadow 0.22s cubic-bezier(0.16, 1, 0.3, 1),
            border-color 0.22s ease;
    }

    .saas-card:hover {
        border-color: #D8D8E5;
        box-shadow: 
            0 4px 10px rgba(17, 20, 57, 0.05),
            0 12px 26px rgba(17, 20, 57, 0.05),
            inset 0 1px 0 rgba(255, 255, 255, 1);
        transform: translateY(-2px);
    }

    .saas-card-title {
        font-size: 0.85rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: #24294F;
        margin-bottom: 14px;
        display: flex;
        align-items: center;
        gap: 8px;
    }

    /* Severity Distribution Bar with Inset 3D Channel */
    .sev-bar-container {
        background-color: #F0F0F5;
        border-radius: 6px;
        height: 12px;
        width: 100%;
        overflow: hidden;
        display: flex;
        margin: 12px 0 14px 0;
        border: 1px solid #E7E7F0;
        box-shadow: inset 0 1px 3px rgba(17, 20, 57, 0.08);
    }

    .sev-bar-segment {
        height: 100%;
        background-image: linear-gradient(180deg, rgba(255, 255, 255, 0.22) 0%, rgba(0, 0, 0, 0.05) 100%);
    }

    .sev-legend {
        display: flex;
        flex-wrap: wrap;
        gap: 16px;
        font-size: 0.82rem;
        color: #111439 !important;
        font-weight: 600 !important;
    }

    .sev-legend-item {
        display: flex;
        align-items: center;
        gap: 6px;
    }

    .sev-color-dot {
        width: 10px;
        height: 10px;
        border-radius: 50%;
        box-shadow: 0 1px 2px rgba(0, 0, 0, 0.15);
    }

    /* 3D Telemetry Chips */
    .saas-chip {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        background-color: #FFFFFF;
        border: 1px solid #E7E7F0;
        padding: 6px 12px;
        border-radius: 8px;
        font-size: 0.82rem;
        color: #111439;
        margin-right: 8px;
        margin-bottom: 8px;
        font-family: 'JetBrains Mono', monospace;
        box-shadow: 0 1px 3px rgba(17, 20, 57, 0.04), inset 0 1px 0 #FFFFFF;
        transition: transform 0.18s ease, box-shadow 0.18s ease, border-color 0.18s ease;
    }

    .saas-chip:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 10px rgba(99, 91, 255, 0.12), inset 0 1px 0 #FFFFFF;
        border-color: #635BFF;
    }

    .saas-chip-count {
        background-color: rgba(99, 91, 255, 0.1);
        color: #635BFF;
        font-weight: 700;
        padding: 2px 7px;
        border-radius: 5px;
        font-size: 0.75rem;
        box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.5);
    }

    /* Buttons - 3D Stripe Indigo with Depth Elevation */
    .stButton > button {
        border-radius: 8px !important;
        font-weight: 600 !important;
        border: 1px solid #E7E7F0 !important;
        background-color: #FFFFFF !important;
        color: #111439 !important;
        box-shadow: 0 1px 3px rgba(17, 20, 57, 0.05), inset 0 1px 0 #FFFFFF !important;
        transition: transform 0.2s cubic-bezier(0.16, 1, 0.3, 1), box-shadow 0.2s cubic-bezier(0.16, 1, 0.3, 1), border-color 0.2s ease !important;
        padding: 8px 18px !important;
        cursor: pointer !important;
    }

    .stButton > button:hover {
        border-color: #635BFF !important;
        color: #635BFF !important;
        background-color: #F8F8F9 !important;
        box-shadow: 0 4px 10px rgba(99, 91, 255, 0.12), inset 0 1px 0 #FFFFFF !important;
        transform: translateY(-2px) !important;
    }

    .stButton > button:active {
        transform: translateY(0px) !important;
        box-shadow: 0 1px 2px rgba(17, 20, 57, 0.06) !important;
    }

    .stButton > button[kind="primary"] {
        background: linear-gradient(115deg, #635BFF 0%, #8B5CF6 100%) !important;
        border: 1px solid #635BFF !important;
        color: #FFFFFF !important;
        box-shadow: 
            0 2px 4px rgba(99, 91, 255, 0.2),
            0 6px 16px rgba(99, 91, 255, 0.28),
            inset 0 1px 0 rgba(255, 255, 255, 0.30) !important;
        transition: transform 0.2s cubic-bezier(0.16, 1, 0.3, 1), box-shadow 0.2s cubic-bezier(0.16, 1, 0.3, 1) !important;
    }

    .stButton > button[kind="primary"]:hover {
        background: linear-gradient(115deg, #5147e5 0%, #7c4beb 100%) !important;
        box-shadow: 
            0 4px 8px rgba(99, 91, 255, 0.25),
            0 12px 24px rgba(99, 91, 255, 0.38),
            inset 0 1px 0 rgba(255, 255, 255, 0.40) !important;
        color: #FFFFFF !important;
        transform: translateY(-2px) !important;
    }

    .stButton > button[kind="primary"]:active {
        transform: translateY(0px) !important;
        box-shadow: 0 2px 4px rgba(99, 91, 255, 0.3), inset 0 2px 4px rgba(0, 0, 0, 0.15) !important;
    }

    /* Download button with 3D Depth */
    .stDownloadButton > button {
        background: linear-gradient(115deg, #635BFF 0%, #8B5CF6 100%) !important;
        border: 1px solid #635BFF !important;
        color: #FFFFFF !important;
        border-radius: 8px !important;
        font-weight: 600 !important;
        box-shadow: 
            0 2px 4px rgba(99, 91, 255, 0.2),
            0 6px 16px rgba(99, 91, 255, 0.28),
            inset 0 1px 0 rgba(255, 255, 255, 0.30) !important;
        transition: transform 0.2s cubic-bezier(0.16, 1, 0.3, 1), box-shadow 0.2s cubic-bezier(0.16, 1, 0.3, 1) !important;
        cursor: pointer !important;
    }

    .stDownloadButton > button:hover {
        background: linear-gradient(115deg, #5147e5 0%, #7c4beb 100%) !important;
        box-shadow: 
            0 4px 8px rgba(99, 91, 255, 0.25),
            0 12px 24px rgba(99, 91, 255, 0.38),
            inset 0 1px 0 rgba(255, 255, 255, 0.40) !important;
        color: #FFFFFF !important;
        transform: translateY(-2px) !important;
    }

    .stDownloadButton > button:active {
        transform: translateY(0px) !important;
        box-shadow: 0 2px 4px rgba(99, 91, 255, 0.3), inset 0 2px 4px rgba(0, 0, 0, 0.15) !important;
    }

    /* 3D Elevated Upload Container */
    [data-testid="stFileUploader"] {
        background-color: rgba(255, 255, 255, 0.96) !important;
        backdrop-filter: blur(12px) !important;
        -webkit-backdrop-filter: blur(12px) !important;
        border: 2px dashed #D5D5E2 !important;
        border-radius: 12px !important;
        padding: 22px !important;
        box-shadow: 
            0 2px 6px rgba(17, 20, 57, 0.03),
            0 8px 20px rgba(17, 20, 57, 0.03),
            inset 0 1px 0 #FFFFFF !important;
        transition: all 0.22s ease !important;
    }

    [data-testid="stFileUploader"]:hover {
        border-color: #635BFF !important;
        box-shadow: 
            0 4px 12px rgba(99, 91, 255, 0.08),
            0 14px 28px rgba(99, 91, 255, 0.06),
            inset 0 1px 0 #FFFFFF !important;
        transform: translateY(-2px);
    }

    /* Raised Dataframe Container */
    [data-testid="stDataFrame"] {
        border: 1px solid #E7E7F0 !important;
        border-radius: 10px !important;
        overflow: hidden !important;
        background-color: rgba(255, 255, 255, 0.98) !important;
        backdrop-filter: blur(12px) !important;
        -webkit-backdrop-filter: blur(12px) !important;
        box-shadow: 
            0 2px 6px rgba(17, 20, 57, 0.04),
            0 10px 24px rgba(17, 20, 57, 0.03),
            inset 0 1px 0 #FFFFFF !important;
    }

    /* Expander with Subtle Depth */
    [data-testid="stExpander"] {
        background-color: rgba(255, 255, 255, 0.96) !important;
        backdrop-filter: blur(12px) !important;
        -webkit-backdrop-filter: blur(12px) !important;
        border: 1px solid #E7E7F0 !important;
        border-radius: 10px !important;
        margin-bottom: 14px !important;
        box-shadow: 0 1px 4px rgba(17, 20, 57, 0.04), inset 0 1px 0 #FFFFFF !important;
    }

    [data-testid="stExpander"] summary {
        color: #111439 !important;
        font-weight: 600 !important;
    }

    /* 3D Dimensional Severity Badges */
    .badge-critical, .badge-high {
        background-color: rgba(220, 53, 69, 0.09);
        color: #DC3545;
        border: 1px solid rgba(220, 53, 69, 0.25);
        padding: 3px 10px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.75rem;
        box-shadow: 0 1px 2px rgba(220, 53, 69, 0.12), inset 0 1px 0 rgba(255, 255, 255, 0.6);
        display: inline-flex;
        align-items: center;
        gap: 4px;
    }

    .badge-medium {
        background-color: rgba(194, 122, 0, 0.09);
        color: #C27A00;
        border: 1px solid rgba(194, 122, 0, 0.25);
        padding: 3px 10px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.75rem;
        box-shadow: 0 1px 2px rgba(194, 122, 0, 0.12), inset 0 1px 0 rgba(255, 255, 255, 0.6);
        display: inline-flex;
        align-items: center;
        gap: 4px;
    }

    .badge-low {
        background-color: rgba(37, 99, 235, 0.09);
        color: #2563EB;
        border: 1px solid rgba(37, 99, 235, 0.25);
        padding: 3px 10px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.75rem;
        box-shadow: 0 1px 2px rgba(37, 99, 235, 0.12), inset 0 1px 0 rgba(255, 255, 255, 0.6);
        display: inline-flex;
        align-items: center;
        gap: 4px;
    }

    .badge-success {
        background-color: rgba(22, 132, 91, 0.09);
        color: #16845B;
        border: 1px solid rgba(22, 132, 91, 0.25);
        padding: 3px 10px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.75rem;
        box-shadow: 0 1px 2px rgba(22, 132, 91, 0.12), inset 0 1px 0 rgba(255, 255, 255, 0.6);
        display: inline-flex;
        align-items: center;
        gap: 4px;
    }

    /* Priority Badges for Risk Prioritization */
    .badge-priority-critical {
        background-color: rgba(220, 53, 69, 0.12);
        color: #DC3545;
        border: 1px solid rgba(220, 53, 69, 0.35);
        padding: 4px 12px;
        border-radius: 9999px;
        font-weight: 700;
        font-size: 0.78rem;
        letter-spacing: 0.04em;
        text-transform: uppercase;
        display: inline-flex;
        align-items: center;
        gap: 6px;
        box-shadow: 0 1px 3px rgba(220, 53, 69, 0.15), inset 0 1px 0 rgba(255, 255, 255, 0.6);
    }

    .badge-priority-high {
        background-color: rgba(224, 82, 96, 0.12);
        color: #C92A3A;
        border: 1px solid rgba(224, 82, 96, 0.35);
        padding: 4px 12px;
        border-radius: 9999px;
        font-weight: 700;
        font-size: 0.78rem;
        letter-spacing: 0.04em;
        text-transform: uppercase;
        display: inline-flex;
        align-items: center;
        gap: 6px;
        box-shadow: 0 1px 3px rgba(224, 82, 96, 0.15), inset 0 1px 0 rgba(255, 255, 255, 0.6);
    }

    .badge-priority-medium {
        background-color: rgba(194, 122, 0, 0.12);
        color: #C27A00;
        border: 1px solid rgba(194, 122, 0, 0.35);
        padding: 4px 12px;
        border-radius: 9999px;
        font-weight: 700;
        font-size: 0.78rem;
        letter-spacing: 0.04em;
        text-transform: uppercase;
        display: inline-flex;
        align-items: center;
        gap: 6px;
        box-shadow: 0 1px 3px rgba(194, 122, 0, 0.15), inset 0 1px 0 rgba(255, 255, 255, 0.6);
    }

    .badge-priority-low {
        background-color: rgba(37, 99, 235, 0.12);
        color: #2563EB;
        border: 1px solid rgba(37, 99, 235, 0.35);
        padding: 4px 12px;
        border-radius: 9999px;
        font-weight: 700;
        font-size: 0.78rem;
        letter-spacing: 0.04em;
        text-transform: uppercase;
        display: inline-flex;
        align-items: center;
        gap: 6px;
        box-shadow: 0 1px 3px rgba(37, 99, 235, 0.15), inset 0 1px 0 rgba(255, 255, 255, 0.6);
    }

    /* Risk Score Gauge Pill */
    .risk-score-pill {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        background: #111439;
        color: #FFFFFF;
        padding: 4px 12px;
        border-radius: 9999px;
        font-family: 'JetBrains Mono', Consolas, monospace;
        font-weight: 700;
        font-size: 0.85rem;
        box-shadow: 0 2px 6px rgba(17, 20, 57, 0.25);
    }

    /* High-Contrast Glassmorphic Tab Bar & Panels */
    [data-testid="stTabs"] [data-baseweb="tab-list"] {
        background-color: rgba(17, 20, 57, 0.65) !important;
        backdrop-filter: blur(12px) !important;
        -webkit-backdrop-filter: blur(12px) !important;
        border-radius: 10px !important;
        padding: 4px 6px !important;
        border: 1px solid rgba(99, 91, 255, 0.25) !important;
        gap: 6px !important;
        margin-bottom: 12px !important;
        box-shadow: 0 4px 16px rgba(0, 0, 0, 0.25) !important;
    }

    [data-testid="stTabs"] button[role="tab"] {
        color: #CBD5E1 !important;
        font-weight: 600 !important;
        font-size: 0.88rem !important;
        border-radius: 8px !important;
        padding: 8px 16px !important;
        background-color: transparent !important;
        border: none !important;
        transition: all 0.18s ease !important;
    }

    [data-testid="stTabs"] button[role="tab"]:hover {
        background-color: rgba(99, 91, 255, 0.20) !important;
        color: #FFFFFF !important;
    }

    [data-testid="stTabs"] button[role="tab"][aria-selected="true"] {
        background: linear-gradient(115deg, #635BFF 0%, #8B5CF6 100%) !important;
        color: #FFFFFF !important;
        font-weight: 700 !important;
        box-shadow: 0 2px 8px rgba(99, 91, 255, 0.35) !important;
    }

    [data-testid="stTabs"] [data-baseweb="tab-panel"] {
        background-color: rgba(17, 20, 57, 0.60) !important;
        backdrop-filter: blur(12px) !important;
        -webkit-backdrop-filter: blur(12px) !important;
        border: 1px solid rgba(99, 91, 255, 0.22) !important;
        border-radius: 12px !important;
        padding: 22px 24px !important;
        box-shadow: 0 6px 20px rgba(0, 0, 0, 0.30) !important;
        color: #FFFFFF !important;
    }

    /* Expander Glassmorphic High Contrast */
    [data-testid="stExpander"] {
        background-color: rgba(17, 20, 57, 0.60) !important;
        backdrop-filter: blur(10px) !important;
        -webkit-backdrop-filter: blur(10px) !important;
        border: 1px solid rgba(99, 91, 255, 0.22) !important;
        border-radius: 10px !important;
    }

    [data-testid="stExpander"] summary p,
    [data-testid="stExpander"] summary span {
        color: #FFFFFF !important;
        font-weight: 700 !important;
        text-shadow: 0 1px 3px rgba(0, 0, 0, 0.5) !important;
    }

    [data-testid="stExpander"] [data-testid="stExpanderDetails"] {
        background-color: transparent !important;
        color: #E2E8F0 !important;
    }


    /* 3D Feature Card Icon Badge */
    .about-icon-3d {
        width: 42px;
        height: 42px;
        border-radius: 10px;
        background: linear-gradient(135deg, #635BFF 0%, #8B5CF6 100%);
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 1.25rem;
        color: #FFFFFF;
        box-shadow: 0 4px 12px rgba(99, 91, 255, 0.28), inset 0 1px 0 rgba(255, 255, 255, 0.35);
        margin-bottom: 12px;
    }

    /* =========================================================================
       Glassmorphic Streamlit Notification & Alert Containers (Readability Fix)
       ========================================================================= */
    [data-testid="stAlert"],
    .stAlert,
    [data-testid="stNotification"],
    div[data-baseweb="notification"] {
        background-color: rgba(17, 20, 57, 0.78) !important;
        backdrop-filter: blur(14px) !important;
        -webkit-backdrop-filter: blur(14px) !important;
        border-radius: 12px !important;
        border: 1px solid rgba(255, 255, 255, 0.15) !important;
        box-shadow: 
            0 4px 16px rgba(0, 0, 0, 0.30),
            inset 0 1px 0 rgba(255, 255, 255, 0.10) !important;
        padding: 16px 20px !important;
        margin: 14px 0 18px 0 !important;
        overflow: hidden !important;
        position: relative !important;
        z-index: 5 !important;
    }

    [data-testid="stAlertContainer"],
    .stAlertContainer {
        background-color: transparent !important;
        background: transparent !important;
        border: none !important;
        box-shadow: none !important;
    }

    /* Universal notification text styling for optimal readability */
    [data-testid="stAlert"] [data-testid="stMarkdownContainer"] p,
    [data-testid="stAlert"] [data-testid="stMarkdownContainer"] span,
    [data-testid="stAlert"] [data-testid="stMarkdownContainer"] div,
    [data-testid="stAlert"] [data-testid="stMarkdownContainer"] li,
    [data-testid="stAlertContainer"] p,
    [data-testid="stAlertContainer"] span,
    [data-testid="stAlertContainer"] div,
    .stAlert p,
    .stAlert span {
        color: #FFFFFF !important;
        font-size: 0.93rem !important;
        font-weight: 500 !important;
        line-height: 1.55 !important;
    }

    [data-testid="stAlert"] strong,
    [data-testid="stAlertContainer"] strong,
    .stAlert strong {
        color: #FFFFFF !important;
        font-weight: 700 !important;
    }

    [data-testid="stAlert"] code,
    [data-testid="stAlertContainer"] code,
    .stAlert code {
        background-color: rgba(99, 91, 255, 0.25) !important;
        color: #22B8CF !important;
        font-family: 'JetBrains Mono', Consolas, monospace !important;
        font-size: 0.85rem !important;
        font-weight: 600 !important;
        padding: 2px 7px !important;
        border-radius: 5px !important;
        border: 1px solid rgba(34, 184, 207, 0.35) !important;
    }

    [data-testid="stAlert"] a,
    [data-testid="stAlertContainer"] a,
    .stAlert a {
        color: #22B8CF !important;
        text-decoration: underline !important;
        font-weight: 600 !important;
    }

    /* Warning Alerts */
    [data-testid="stAlert"]:has([data-testid="stAlertContentWarning"]),
    [data-testid="stAlert"]:has([role="alert"]),
    [data-testid="stAlert"]:has(svg[data-testid="stAlertDynamicIcon"][aria-label*="warning"]),
    [data-testid="stAlert"]:has(svg[data-testid="stAlertDynamicIcon"][aria-label*="Warning"]),
    [data-testid="stAlertContainer"]:has([data-testid="stAlertContentWarning"]),
    [data-testid="stAlertContentWarning"],
    .stAlert:has([data-testid="stAlertContentWarning"]) {
        border-left: 5px solid #F59E0B !important;
        border-color: rgba(245, 158, 11, 0.40) !important;
        background: linear-gradient(90deg, rgba(245, 158, 11, 0.16) 0%, rgba(17, 20, 57, 0.85) 120px) !important;
        background-color: rgba(17, 20, 57, 0.85) !important;
    }

    /* Warning Icons */
    [data-testid="stAlert"]:has([data-testid="stAlertContentWarning"]) svg,
    [data-testid="stAlertContentWarning"] svg,
    [data-testid="stAlert"]:has([role="alert"]) svg {
        color: #F59E0B !important;
        fill: #F59E0B !important;
        stroke: #F59E0B !important;
    }

    /* Info Alerts */
    [data-testid="stAlert"]:has([data-testid="stAlertContentInfo"]),
    [data-testid="stAlertContainer"]:has([data-testid="stAlertContentInfo"]),
    [data-testid="stAlertContentInfo"],
    .stAlert:has([data-testid="stAlertContentInfo"]) {
        border-left: 5px solid #635BFF !important;
        border-color: rgba(99, 91, 255, 0.40) !important;
        background: linear-gradient(90deg, rgba(99, 91, 255, 0.16) 0%, rgba(17, 20, 57, 0.85) 120px) !important;
        background-color: rgba(17, 20, 57, 0.85) !important;
    }

    /* Info Icons */
    [data-testid="stAlert"]:has([data-testid="stAlertContentInfo"]) svg,
    [data-testid="stAlertContentInfo"] svg {
        color: #22B8CF !important;
        fill: #22B8CF !important;
        stroke: #22B8CF !important;
    }

    /* Success Alerts */
    [data-testid="stAlert"]:has([data-testid="stAlertContentSuccess"]),
    [data-testid="stAlertContainer"]:has([data-testid="stAlertContentSuccess"]),
    [data-testid="stAlertContentSuccess"],
    .stAlert:has([data-testid="stAlertContentSuccess"]) {
        border-left: 5px solid #10B981 !important;
        border-color: rgba(16, 185, 129, 0.40) !important;
        background: linear-gradient(90deg, rgba(16, 185, 129, 0.16) 0%, rgba(17, 20, 57, 0.85) 120px) !important;
        background-color: rgba(17, 20, 57, 0.85) !important;
    }

    /* Success Icons */
    [data-testid="stAlert"]:has([data-testid="stAlertContentSuccess"]) svg,
    [data-testid="stAlertContentSuccess"] svg {
        color: #10B981 !important;
        fill: #10B981 !important;
        stroke: #10B981 !important;
    }

    /* Error Alerts */
    [data-testid="stAlert"]:has([data-testid="stAlertContentError"]),
    [data-testid="stAlertContainer"]:has([data-testid="stAlertContentError"]),
    [data-testid="stAlertContentError"],
    .stAlert:has([data-testid="stAlertContentError"]) {
        border-left: 5px solid #EF4444 !important;
        border-color: rgba(239, 68, 68, 0.40) !important;
        background: linear-gradient(90deg, rgba(239, 68, 68, 0.16) 0%, rgba(17, 20, 57, 0.85) 120px) !important;
        background-color: rgba(17, 20, 57, 0.85) !important;
    }

    /* Error Icons */
    [data-testid="stAlert"]:has([data-testid="stAlertContentError"]) svg,
    [data-testid="stAlertContentError"] svg {
        color: #EF4444 !important;
        fill: #EF4444 !important;
        stroke: #EF4444 !important;
    }

    /* Sidebar Alerts - Match Deep Navy Sidebar Aesthetic */
    [data-testid="stSidebar"] [data-testid="stAlert"],
    [data-testid="stSidebar"] .stAlert,
    [data-testid="stSidebar"] [data-testid="stAlertContainer"] {
        background-color: rgba(25, 30, 71, 0.88) !important;
        backdrop-filter: blur(12px) !important;
        -webkit-backdrop-filter: blur(12px) !important;
        border: 1px solid rgba(255, 255, 255, 0.15) !important;
        border-radius: 8px !important;
        padding: 10px 14px !important;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.25) !important;
    }

    [data-testid="stSidebar"] [data-testid="stAlert"] [data-testid="stMarkdownContainer"] p,
    [data-testid="stSidebar"] [data-testid="stAlert"] span,
    [data-testid="stSidebar"] [data-testid="stAlertContainer"] p,
    [data-testid="stSidebar"] [data-testid="stAlertContainer"] span {
        color: #E7E7F0 !important;
        font-size: 0.82rem !important;
    }

    [data-testid="stSidebar"] [data-testid="stAlert"] strong,
    [data-testid="stSidebar"] [data-testid="stAlertContainer"] strong {
        color: #FFFFFF !important;
    }

    [data-testid="stSidebar"] [data-testid="stAlert"] code,
    [data-testid="stSidebar"] [data-testid="stAlertContainer"] code {
        background: rgba(99, 91, 255, 0.25) !important;
        color: #22B8CF !important;
        border: 1px solid rgba(34, 184, 207, 0.3) !important;
    }

    [data-testid="stSidebar"] [data-testid="stAlert"]:has([data-testid="stAlertContentSuccess"]) {
        border-left: 3px solid #16845B !important;
    }

    [data-testid="stSidebar"] [data-testid="stAlert"]:has([data-testid="stAlertContentWarning"]) {
        border-left: 3px solid #C27A00 !important;
    }

    /* Accessible Focus States */
    .stButton > button:focus-visible,
    .stDownloadButton > button:focus-visible,
    input:focus-visible,
    [data-testid="stFileUploader"]:focus-within {
        outline: 2px solid #635BFF !important;
        outline-offset: 2px !important;
    }

    /* Prefers Reduced Motion */
    @media (prefers-reduced-motion: reduce) {
        *,
        [data-testid="stMetric"],
        .saas-card,
        .stButton > button,
        .stDownloadButton > button,
        .hero-3d-shield-container {
            transition: none !important;
            transform: none !important;
            animation: none !important;
        }
    }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# Full-Application Cybersecurity Background: Globe Image + Animated Vanta.NET Particles
# -----------------------------------------------------------------------------
def load_globe_background_image() -> Optional[str]:
    """
    Checks for the exact user-supplied cybersecurity globe image at
    assets/cybersecurity_globe.png (or any valid image in assets/).
    Returns base64 data URI if present, or None if awaiting user file.
    """
    assets_dir = os.path.join(os.path.dirname(__file__), "assets")
    exact_target_jpg = os.path.join(assets_dir, "cybersecurity_globe.jpg")
    exact_target_png = os.path.join(assets_dir, "cybersecurity_globe.png")
    exact_target_double_jpg = os.path.join(assets_dir, "cybersecurity_globe.jpg.jpg")
    root_target_jpg = os.path.join(os.path.dirname(__file__), "cybersecurity_globe.jpg")
    root_target_png = os.path.join(os.path.dirname(__file__), "cybersecurity_globe.png")

    target_img = None
    for candidate in [
        exact_target_jpg,
        exact_target_png,
        exact_target_double_jpg,
        root_target_jpg,
        root_target_png,
    ]:
        if os.path.isfile(candidate) and os.path.getsize(candidate) > 0:
            target_img = candidate
            break

    if not target_img and os.path.isdir(assets_dir):
        for pat in ("*.jpg", "*.jpeg", "*.png", "*.webp", "*.svg"):
            matched = glob.glob(os.path.join(assets_dir, pat))
            if matched:
                matched.sort(
                    key=lambda p: 0 if any(k in os.path.basename(p).lower() for k in ("globe", "cyber", "bg", "network")) else 1
                )
                target_img = matched[0]
                break

    if not target_img:
        return None

    try:
        with open(target_img, "rb") as f:
            encoded = base64.b64encode(f.read()).decode("utf-8")
        ext = os.path.splitext(target_img)[1].lower().replace(".", "")
        if ext in ("jpg", "jpeg"):
            mime = "image/jpeg"
        elif ext == "svg":
            mime = "image/svg+xml"
        else:
            mime = f"image/{ext}"
        return f"data:{mime};base64,{encoded}"
    except Exception:
        return None


globe_bg_uri = load_globe_background_image()

# Layer 1: Full-Page Animated Background Coverage (Dashboard, Log Upload, Alerts, About)
if globe_bg_uri:
    st.markdown(
        f"""
        <style>
            @keyframes cinematicGlobeMotion {{
                0% {{
                    transform: translate3d(0, 0, 0) scale(1.00) rotate(0deg);
                }}
                25% {{
                    transform: translate3d(-1.5%, 0.8%, 0) scale(1.03) rotate(0.4deg);
                }}
                50% {{
                    transform: translate3d(0.8%, -1.2%, 0) scale(1.06) rotate(-0.5deg);
                }}
                75% {{
                    transform: translate3d(1.8%, 0.6%, 0) scale(1.08) rotate(0.3deg);
                }}
                100% {{
                    transform: translate3d(-0.5%, -0.4%, 0) scale(1.05) rotate(-0.2deg);
                }}
            }}

            .stApp {{
                position: relative !important;
                background-color: transparent !important;
            }}

            .stApp::before {{
                content: '' !important;
                position: fixed !important;
                top: -8% !important;
                left: -8% !important;
                width: 116% !important;
                height: 116% !important;
                background-image: 
                    linear-gradient(180deg, rgba(17, 20, 57, 0.40) 0%, rgba(99, 91, 255, 0.10) 50%, rgba(17, 20, 57, 0.65) 100%),
                    url('{globe_bg_uri}') !important;
                background-size: cover !important;
                background-position: center center !important;
                background-repeat: no-repeat !important;
                z-index: 0 !important;
                pointer-events: none !important;
                animation: cinematicGlobeMotion 26s ease-in-out infinite alternate !important;
                will-change: transform !important;
            }}

            [data-testid="stAppViewContainer"] {{
                background-color: transparent !important;
                position: relative !important;
                z-index: 1 !important;
            }}

            [data-testid="stMain"] {{
                background-color: transparent !important;
                position: relative !important;
                z-index: 1 !important;
            }}

            [data-testid="stSidebar"] {{
                z-index: 100 !important;
            }}

            @media (prefers-reduced-motion: reduce) {{
                .stApp::before {{
                    animation: none !important;
                    transform: none !important;
                }}
            }}
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_hero_banner(title: str, subtitle: str, badge_text: str, show_shield: bool = False) -> None:
    """
    Renders an animated hero banner across all pages:
    - Layer 1: Cybersecurity globe image (if present in assets/) or radial SaaS gradient.
    - Layer 2: Animated Vanta.js NET particle network in indigo (#635BFF), violet (#8B5CF6),
      and cyan (#22B8CF) with resilient HTML5 Canvas fallback.
    - Layer 3: High-contrast hero typography, status badge, and optional 3D shield illustration.
    """
    shield_html = f'<div class="hero-3d-shield-container">{SHIELD_3D_SVG}</div>' if show_shield else ""
    
    if globe_bg_uri:
        hero_bg_style = f"""
            background-image: 
                linear-gradient(180deg, rgba(17, 20, 57, 0.58) 0%, rgba(17, 20, 57, 0.72) 100%),
                url('{globe_bg_uri}');
            background-size: cover;
            background-position: center center;
            background-repeat: no-repeat;
        """
        vanta_bg_hex = "0x000000"
        vanta_blend_mode = "mix-blend-mode: screen; opacity: 0.88;"
        hero_title_color = "#FFFFFF"
        hero_sub_color = "#CBD5E1"
        badge_bg = "rgba(255, 255, 255, 0.18)"
        badge_border = "rgba(255, 255, 255, 0.30)"
        badge_text_color = "#FFFFFF"
        shield_container_bg = "rgba(255, 255, 255, 0.15)"
    else:
        hero_bg_style = """
            background: 
                radial-gradient(circle at 92% 20%, rgba(99, 91, 255, 0.08) 0%, transparent 40%),
                radial-gradient(circle at 8% 85%, rgba(34, 184, 207, 0.07) 0%, transparent 35%),
                #FFFFFF;
        """
        vanta_bg_hex = "0xffffff"
        vanta_blend_mode = "mix-blend-mode: multiply; opacity: 0.80;"
        hero_title_color = "#111439"
        hero_sub_color = "#24294F"
        badge_bg = "rgba(255, 255, 255, 0.88)"
        badge_border = "rgba(99, 91, 255, 0.22)"
        badge_text_color = "#635BFF"
        shield_container_bg = "rgba(255, 255, 255, 0.70)"

    hero_html = f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
    * {{
        box-sizing: border-box;
        margin: 0;
        padding: 0;
    }}
    html, body {{
        width: 100%;
        height: 100%;
        overflow: hidden;
        background: transparent;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }}
    #hero-wrapper {{
        position: relative;
        width: 100%;
        height: 160px;
        border-radius: 14px;
        border: 1px solid #E7E7F0;
        overflow: hidden;
        box-shadow: 
            0 2px 4px rgba(17, 20, 57, 0.03),
            0 10px 24px rgba(17, 20, 57, 0.05),
            0 20px 42px -8px rgba(99, 91, 255, 0.07),
            inset 0 1px 0 rgba(255, 255, 255, 0.95);
    }}
    #hero-wrapper::before {{
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        height: 4px;
        background: linear-gradient(115deg, #635BFF 0%, #8B5CF6 48%, #22B8CF 100%);
        z-index: 10;
    }}
    #hero-bg {{
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        {hero_bg_style}
        z-index: 1;
    }}
    #vanta-net-layer {{
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        z-index: 2;
        {vanta_blend_mode}
        pointer-events: none;
    }}
    #hero-content {{
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        z-index: 5;
        padding: 20px 28px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 20px;
        pointer-events: none;
    }}
    .stripe-hero-badge {{
        display: inline-flex;
        align-items: center;
        gap: 8px;
        background: {badge_bg};
        backdrop-filter: blur(8px);
        -webkit-backdrop-filter: blur(8px);
        color: {badge_text_color};
        border: 1px solid {badge_border};
        padding: 4px 12px;
        border-radius: 9999px;
        font-size: 0.75rem;
        font-weight: 600;
        letter-spacing: 0.03em;
        margin-bottom: 8px;
        box-shadow: 0 2px 8px rgba(99, 91, 255, 0.08), inset 0 1px 0 #FFFFFF;
        pointer-events: auto;
    }}
    .stripe-pulse-dot {{
        width: 7px;
        height: 7px;
        border-radius: 50%;
        background-color: #16845B;
        box-shadow: 0 0 0 2px rgba(22, 132, 91, 0.25);
    }}
    .stripe-hero-title {{
        font-size: 1.55rem;
        font-weight: 700;
        color: {hero_title_color};
        margin: 0;
        line-height: 1.25;
        letter-spacing: -0.015em;
        pointer-events: auto;
    }}
    .stripe-hero-subtitle {{
        font-size: 0.88rem;
        color: {hero_sub_color};
        margin-top: 5px;
        margin-bottom: 0;
        line-height: 1.4;
        pointer-events: auto;
    }}
    .hero-3d-shield-container {{
        display: flex;
        align-items: center;
        justify-content: center;
        background: {shield_container_bg};
        backdrop-filter: blur(10px);
        -webkit-backdrop-filter: blur(10px);
        border: 1px solid rgba(231, 231, 240, 0.85);
        border-radius: 12px;
        padding: 8px;
        box-shadow: 0 4px 14px rgba(17, 20, 57, 0.05), inset 0 1px 0 rgba(255, 255, 255, 0.95);
        flex-shrink: 0;
        pointer-events: auto;
    }}
</style>
<script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r134/three.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/vanta@latest/dist/vanta.net.min.js"></script>
</head>
<body>
<div id="hero-wrapper">
    <div id="hero-bg"></div>
    <div id="vanta-net-layer"></div>
    <div id="hero-content">
        <div style="flex: 1; min-width: 260px;">
            <div class="stripe-hero-badge">
                <span class="stripe-pulse-dot"></span> {badge_text}
            </div>
            <h1 class="stripe-hero-title">{title}</h1>
            <p class="stripe-hero-subtitle">{subtitle}</p>
        </div>
        {shield_html}
    </div>
</div>
<script>
    var vantaEffect = null;
    function initVanta() {{
        if (typeof VANTA !== 'undefined' && VANTA.NET && typeof THREE !== 'undefined') {{
            try {{
                vantaEffect = VANTA.NET({{
                    el: "#vanta-net-layer",
                    mouseControls: false,
                    touchControls: false,
                    gyroControls: false,
                    minHeight: 150.00,
                    minWidth: 200.00,
                    scale: 1.00,
                    scaleMobile: 1.00,
                    color: 0x635BFF,            // Indigo #635BFF
                    backgroundColor: {vanta_bg_hex},
                    points: 11.00,              // Moderate point density
                    maxDistance: 22.00,         // Connecting distance
                    spacing: 16.00,
                    showDots: true
                }});
                return;
            }} catch (err) {{
                console.warn('Vanta initialization notice, falling back to canvas:', err);
            }}
        }}
        initFallbackCanvas();
    }}

    function initFallbackCanvas() {{
        var container = document.getElementById("vanta-net-layer");
        if (!container) return;
        var canvas = document.createElement("canvas");
        canvas.style.width = "100%";
        canvas.style.height = "100%";
        canvas.style.display = "block";
        container.appendChild(canvas);
        var ctx = canvas.getContext("2d");
        var width, height;
        var particles = [];

        function resize() {{
            width = canvas.width = container.clientWidth || window.innerWidth;
            height = canvas.height = container.clientHeight || 160;
        }}
        window.addEventListener("resize", resize);
        resize();

        var colors = ["#635BFF", "#8B5CF6", "#22B8CF"];
        for (var i = 0; i < 35; i++) {{
            particles.push({{
                x: Math.random() * width,
                y: Math.random() * height,
                vx: (Math.random() - 0.5) * 0.7,
                vy: (Math.random() - 0.5) * 0.7,
                radius: Math.random() * 2 + 1.2,
                color: colors[i % colors.length]
            }});
        }}

        function draw() {{
            ctx.clearRect(0, 0, width, height);
            for (var i = 0; i < particles.length; i++) {{
                var p = particles[i];
                p.x += p.vx;
                p.y += p.vy;
                if (p.x < 0 || p.x > width) p.vx *= -1;
                if (p.y < 0 || p.y > height) p.vy *= -1;

                ctx.beginPath();
                ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
                ctx.fillStyle = p.color;
                ctx.fill();

                for (var j = i + 1; j < particles.length; j++) {{
                    var p2 = particles[j];
                    var dist = Math.hypot(p.x - p2.x, p.y - p2.y);
                    if (dist < 110) {{
                        ctx.beginPath();
                        ctx.moveTo(p.x, p.y);
                        ctx.lineTo(p2.x, p2.y);
                        var alpha = (1 - dist / 110) * 0.35;
                        ctx.strokeStyle = "rgba(99, 91, 255, " + alpha + ")";
                        ctx.lineWidth = 1;
                        ctx.stroke();
                    }}
                }}
            }}
            requestAnimationFrame(draw);
        }}
        draw();
    }}

    if (document.readyState === 'complete') {{
        initVanta();
    }} else {{
        window.addEventListener('load', initVanta);
    }}
</script>
</body>
</html>
"""
    components.html(hero_html, height=168)


# -----------------------------------------------------------------------------
# Session State Management
# -----------------------------------------------------------------------------
if "validated_df" not in st.session_state:
    st.session_state["validated_df"] = None

if "validation_meta" not in st.session_state:
    st.session_state["validation_meta"] = {
        "filename": None,
        "filesize": None,
        "valid_rows": 0,
        "skipped_rows": 0,
        "warnings": [],
    }

if "pipeline_results" not in st.session_state:
    st.session_state["pipeline_results"] = None

if "pipeline_error" not in st.session_state:
    st.session_state["pipeline_error"] = None


# -----------------------------------------------------------------------------
# Sidebar Navigation & System Status (Deep Navy Theme with 3D Accents)
# -----------------------------------------------------------------------------
st.sidebar.markdown(
    """
    <div class="sidebar-brand">
        <div style="font-size: 1.8rem; line-height: 1;">🛡️</div>
        <div>
            <div class="sidebar-brand-title">CYBER AGENT</div>
            <div class="sidebar-brand-subtitle">Intelligent Security Monitoring</div>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

if "nav_selection" not in st.session_state or st.session_state["nav_selection"] not in [
    "Dashboard", "Log Upload", "Alerts", "Incident Intelligence", "About"
]:
    st.session_state["nav_selection"] = "Dashboard"

if "target_nav" in st.session_state:
    st.session_state["nav_selection"] = st.session_state.pop("target_nav")

def navigate_to_log_upload():
    st.session_state["target_nav"] = "Log Upload"

nav_choice = st.sidebar.radio(
    "Navigation",
    ["Dashboard", "Log Upload", "Alerts", "Incident Intelligence", "About"],
    key="nav_selection",
)

st.sidebar.divider()
st.sidebar.markdown("### Integration Status")

if BACKEND_AVAILABLE:
    st.sidebar.success("Detection Engine: **Available** (`detector.py`)")
else:
    st.sidebar.warning("Detection Engine: **Pending** (Member 2 development)")

if INTELLIGENCE_AVAILABLE:
    st.sidebar.success("Incident Intelligence: **Active** (`incident_intelligence.py`)")


if globe_bg_uri:
    st.sidebar.caption("🌐 Background Globe: **Active** (`assets/cybersecurity_globe.jpg`)")
else:
    st.sidebar.caption("🌐 Background Globe: Ready in `assets/`")

if st.session_state["validated_df"] is not None:
    filename = st.session_state["validation_meta"]["filename"] or "Active Dataset"
    valid_count = st.session_state["validation_meta"]["valid_rows"]
    st.sidebar.markdown(
        f"""
        <div class="sidebar-status-card">
            <div class="sidebar-status-label">Active Dataset</div>
            <div class="sidebar-status-val">{filename}</div>
            <div style="font-size: 0.75rem; color: #CBD5E1; margin-top: 4px; font-weight: 500;">
                Verified Events: <strong style="color: #22B8CF;">{valid_count:,}</strong>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
else:
    st.sidebar.caption("No log dataset currently loaded.")


# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------
def run_backend_detection(df: pd.DataFrame) -> None:
    """Invokes Member 2's backend pipeline safely with error trapping."""
    if not BACKEND_AVAILABLE or run_full_detection_pipeline is None:
        return

    # Resolve backend URL and timeout from Streamlit secrets (cloud) with env var fallback
    api_base_url: Optional[str] = None
    api_timeout: Optional[float] = None

    try:
        if hasattr(st, "secrets"):
            if "CYBER_AGENT_API_URL" in st.secrets:
                val = st.secrets["CYBER_AGENT_API_URL"]
                if val and str(val).strip():
                    api_base_url = str(val).strip()
            if "CYBER_AGENT_API_TIMEOUT" in st.secrets:
                val_t = st.secrets["CYBER_AGENT_API_TIMEOUT"]
                if val_t is not None:
                    api_timeout = float(val_t)
    except Exception:
        pass

    if not api_base_url:
        env_url = os.getenv("CYBER_AGENT_API_URL")
        if env_url and env_url.strip():
            api_base_url = env_url.strip()

    if api_timeout is None:
        env_timeout = os.getenv("CYBER_AGENT_API_TIMEOUT")
        if env_timeout:
            try:
                api_timeout = float(env_timeout)
            except (ValueError, TypeError):
                api_timeout = None

    with st.spinner("Analyzing security logs for intrusion patterns and anomalies..."):
        try:
            results = run_full_detection_pipeline(
                df, api_base_url=api_base_url, timeout=api_timeout
            )
            if isinstance(results, dict):
                # Check if backend explicitly returned an error field or non-empty errors list
                raw_errors = results.get("errors")
                raw_error = results.get("error")

                err_msg = None
                if isinstance(raw_errors, (list, tuple)) and len(raw_errors) > 0:
                    err_msg = "; ".join(str(e) for e in raw_errors if str(e).strip())
                elif isinstance(raw_errors, str) and raw_errors.strip():
                    err_msg = raw_errors.strip()
                elif isinstance(raw_error, str) and raw_error.strip():
                    err_msg = raw_error.strip()

                if err_msg:
                    st.session_state["pipeline_error"] = f"Backend Detection Error: {err_msg}"
                    st.session_state["pipeline_results"] = None
                else:
                    st.session_state["pipeline_results"] = results
                    st.session_state["pipeline_error"] = None
            else:
                st.session_state["pipeline_error"] = (
                    "Backend pipeline returned an unexpected data structure. Expected dictionary."
                )
                st.session_state["pipeline_results"] = None
        except Exception as exc:
            st.session_state["pipeline_error"] = (
                f"Detection pipeline encountered an unexpected issue: {str(exc)}"
            )
            st.session_state["pipeline_results"] = None


# -----------------------------------------------------------------------------
# PAGE 1: Dashboard
# -----------------------------------------------------------------------------
if nav_choice == "Dashboard":
    status_badge_text = "Live Pipeline Active • Multi-Layer Threat Triage" if BACKEND_AVAILABLE else "Detection Engine Pending Integration"
    render_hero_banner(
        title="AI-Based Cybersecurity Monitoring Agent",
        subtitle="Intelligent Network Intrusion & Log Anomaly Detection Platform • Enterprise Defensive Security Operations",
        badge_text=status_badge_text,
        show_shield=True,
    )

    # Backend notice if detector not imported
    if not BACKEND_AVAILABLE:
        st.info(
            "ℹ️ **Backend Integration Notice**: The detection engine (`detector.py`) is under independent "
            "development. The ingestion pipeline is ready. Once `detector.py` is available, "
            "detection analytics, anomaly metrics, and rule triggers will automatically populate here."
        )

    # State 1: No file uploaded yet (Helpful Empty State with 3D Depth)
    if st.session_state["validated_df"] is None:
        st.markdown(
            """
            <div style="text-align: center; padding: 44px 32px 20px 32px; background: rgba(17, 20, 57, 0.68); backdrop-filter: blur(14px); -webkit-backdrop-filter: blur(14px); border: 1px solid rgba(99, 91, 255, 0.30); border-radius: 14px; box-shadow: 0 8px 32px rgba(0, 0, 0, 0.35); margin-bottom: 16px;">
                <div style="font-size: 3rem; margin-bottom: 12px; filter: drop-shadow(0 4px 12px rgba(99, 91, 255, 0.4));">📁</div>
                <h3 style="color: #FFFFFF; margin-bottom: 8px; font-weight: 700; text-shadow: 0 2px 6px rgba(0, 0, 0, 0.5);">No Security Log Dataset Loaded</h3>
                <p style="color: #CBD5E1; max-width: 560px; margin: 0 auto; font-size: 0.95rem; font-weight: 500; line-height: 1.6;">
                    Upload an authorized server, proxy, or firewall log CSV to initiate intrusion pattern recognition
                    and unsupervised machine learning anomaly detection.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        _, col_btn, _ = st.columns([1.4, 1.2, 1.4])
        with col_btn:
            if st.button(
                "Navigate to Log Upload",
                type="primary",
                on_click=navigate_to_log_upload,
                use_container_width=True,
            ):
                st.session_state["target_nav"] = "Log Upload"
                st.rerun()

    # State 2: Log file uploaded
    else:
        validated_df = st.session_state["validated_df"]
        meta = st.session_state["validation_meta"]
        results = st.session_state["pipeline_results"]
        err = st.session_state["pipeline_error"]

        if err:
            st.error(f"Detection Processing Error: {err}")

        # Metrics display: ONLY show detection metrics if real backend has returned them
        if results is not None and isinstance(results, dict):
            # Display backend warnings if provided
            raw_backend_warns = results.get("warnings")
            dash_backend_warns = []
            if isinstance(raw_backend_warns, (list, tuple)):
                dash_backend_warns = [str(w).strip() for w in raw_backend_warns if str(w).strip()]
            elif isinstance(raw_backend_warns, str) and raw_backend_warns.strip():
                dash_backend_warns = [raw_backend_warns.strip()]

            if dash_backend_warns:
                with st.expander("⚠️ Pipeline Notices & Warnings", expanded=True):
                    for warn_msg in dash_backend_warns:
                        st.warning(f"• {warn_msg}")

            summary = results.get("summary")
            if not isinstance(summary, dict):
                summary = {}
            alerts_df = results.get("alerts", pd.DataFrame())

            # Safe numeric conversion for metrics
            try:
                total_events = int(summary.get("total_events", len(validated_df)))
            except (ValueError, TypeError):
                total_events = len(validated_df)

            try:
                total_alerts = int(summary.get("total_alerts", len(alerts_df) if isinstance(alerts_df, pd.DataFrame) else 0))
            except (ValueError, TypeError):
                total_alerts = len(alerts_df) if isinstance(alerts_df, pd.DataFrame) else 0

            # Case-insensitive severity counts
            crit_count = 0
            high_count = 0
            med_count = 0
            low_count = 0

            sev_breakdown = summary.get("severity_breakdown")
            if isinstance(sev_breakdown, dict):
                for k, v in sev_breakdown.items():
                    key_upper = str(k).strip().upper()
                    try:
                        val_int = int(v)
                    except (ValueError, TypeError):
                        val_int = 0

                    if key_upper == "CRITICAL":
                        crit_count = val_int
                    elif key_upper == "HIGH":
                        high_count = val_int
                    elif key_upper == "MEDIUM":
                        med_count = val_int
                    elif key_upper == "LOW":
                        low_count = val_int
            elif isinstance(alerts_df, pd.DataFrame) and "severity" in alerts_df.columns and not alerts_df.empty:
                crit_count = int((alerts_df["severity"].astype(str).str.strip().str.upper() == "CRITICAL").sum())
                high_count = int((alerts_df["severity"].astype(str).str.strip().str.upper() == "HIGH").sum())
                med_count = int((alerts_df["severity"].astype(str).str.strip().str.upper() == "MEDIUM").sum())
                low_count = int((alerts_df["severity"].astype(str).str.strip().str.upper() == "LOW").sum())

            try:
                rule_count = int(summary.get("rule_alert_count", 0))
            except (ValueError, TypeError):
                rule_count = 0

            try:
                anomaly_count = int(summary.get("anomaly_alert_count", 0))
            except (ValueError, TypeError):
                anomaly_count = 0

            # 5 Core 3D KPI Metrics Cards
            col1, col2, col3, col4, col5 = st.columns(5)
            with col1:
                st.metric("Total Events Ingested", f"{total_events:,}")
            with col2:
                st.metric("Total Alerts", f"{total_alerts:,}")
            with col3:
                st.metric("Critical Alerts", f"{crit_count:,}")
            with col4:
                st.metric("Rule-Based Alerts", f"{rule_count:,}")
            with col5:
                st.metric("Anomaly Alerts", f"{anomaly_count:,}")

            st.write("")

            # Section 1: Severity Distribution & Detection Comparison Cards with 3D Depth
            soc_col1, soc_col2 = st.columns(2)
            with soc_col1:
                # Severity Distribution Breakdown Bar
                crit_pct = (crit_count / total_alerts * 100) if total_alerts > 0 else 0
                high_pct = (high_count / total_alerts * 100) if total_alerts > 0 else 0
                med_pct = (med_count / total_alerts * 100) if total_alerts > 0 else 0
                low_pct = (low_count / total_alerts * 100) if total_alerts > 0 else 0

                bar_html = f"""
                <div class="saas-card">
                    <div class="saas-card-title">🛡️ Alert Severity Distribution</div>
                    <div class="sev-bar-container">
                        <div class="sev-bar-segment" style="width: {crit_pct}%; background-color: #DC3545;" title="Critical: {crit_count}"></div>
                        <div class="sev-bar-segment" style="width: {high_pct}%; background-color: #DC3545;" title="High: {high_count}"></div>
                        <div class="sev-bar-segment" style="width: {med_pct}%; background-color: #C27A00;" title="Medium: {med_count}"></div>
                        <div class="sev-bar-segment" style="width: {low_pct}%; background-color: #2563EB;" title="Low: {low_count}"></div>
                    </div>
                    <div class="sev-legend">
                        <div class="sev-legend-item"><span class="sev-color-dot" style="background-color: #DC3545;"></span> Critical: {crit_count}</div>
                        <div class="sev-legend-item"><span class="sev-color-dot" style="background-color: #DC3545;"></span> High: {high_count}</div>
                        <div class="sev-legend-item"><span class="sev-color-dot" style="background-color: #C27A00;"></span> Medium: {med_count}</div>
                        <div class="sev-legend-item"><span class="sev-color-dot" style="background-color: #2563EB;"></span> Low: {low_count}</div>
                    </div>
                </div>
                """
                st.markdown(bar_html, unsafe_allow_html=True)

            with soc_col2:
                # Rule-Based vs Anomaly Comparison Card
                rule_pct = round((rule_count / total_alerts * 100), 1) if total_alerts > 0 else 0
                anomaly_pct = round((anomaly_count / total_alerts * 100), 1) if total_alerts > 0 else 0

                comp_html = f"""
                <div class="saas-card">
                    <div class="saas-card-title">⚖️ Detection Engine Comparison</div>
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                        <div>
                            <span style="font-size: 0.82rem; color: #111439; font-weight: 700;">Rule-Based Triggers</span>
                            <div style="font-size: 1.15rem; font-weight: 700; color: #111439;">{rule_count} <span style="font-size: 0.78rem; color: #24294F; font-weight: 600;">({rule_pct}%)</span></div>
                        </div>
                        <div style="text-align: right;">
                            <span style="font-size: 0.82rem; color: #111439; font-weight: 700;">ML Anomaly Outliers</span>
                            <div style="font-size: 1.15rem; font-weight: 700; color: #635BFF;">{anomaly_count} <span style="font-size: 0.78rem; color: #24294F; font-weight: 600;">({anomaly_pct}%)</span></div>
                        </div>
                    </div>
                    <div class="sev-bar-container" style="height: 8px;">
                        <div class="sev-bar-segment" style="width: {rule_pct}%; background-color: #24294F;"></div>
                        <div class="sev-bar-segment" style="width: {anomaly_pct}%; background-color: #635BFF;"></div>
                    </div>
                    <div style="font-size: 0.78rem; color: #111439; line-height: 1.4; font-weight: 500;">
                        Signature matching evaluates known attack patterns (Express microservice); Isolation Forest detects statistical anomalies (Scikit-Learn).
                    </div>
                </div>
                """
                st.markdown(comp_html, unsafe_allow_html=True)

            # Section 2: Telemetry Activity Timeline & Top Offending IPs
            events_df = results.get("events")
            act_col1, act_col2 = st.columns([3, 2])

            with act_col1:
                st.markdown(
                    """
                    <div class="saas-card">
                        <div class="saas-card-title">📈 Event Ingestion Activity Stream</div>
                    """,
                    unsafe_allow_html=True,
                )
                # Event activity chart if supported by actual timestamps
                has_chart = False
                if isinstance(events_df, pd.DataFrame) and "timestamp" in events_df.columns and not events_df.empty:
                    try:
                        time_s = pd.to_datetime(events_df["timestamp"], errors="coerce")
                        clean_time = time_s.dropna().dt.strftime("%H:%M:%S")
                        if not clean_time.empty:
                            activity_series = clean_time.value_counts().sort_index()
                            if len(activity_series) > 1:
                                chart_data = pd.DataFrame({"Events": activity_series})
                                st.bar_chart(chart_data, color="#635BFF")
                                has_chart = True
                    except Exception:
                        has_chart = False

                if not has_chart:
                    st.info("Continuous event stream recorded. Discrete multi-point timestamp variance not present for chart plotting.")

                st.markdown("</div>", unsafe_allow_html=True)

            with act_col2:
                # Top Offending IPs panel with 3D Chips
                top_ips = summary.get("top_offending_ips", {})
                chips_html = ""
                if isinstance(top_ips, dict) and top_ips:
                    for ip, cnt in list(top_ips.items())[:5]:
                        chips_html += f'<div class="saas-chip"><code>{ip}</code> <span class="saas-chip-count">{cnt}</span></div>'
                elif isinstance(alerts_df, pd.DataFrame) and "source_ip" in alerts_df.columns and not alerts_df.empty:
                    ip_counts = alerts_df["source_ip"].dropna().value_counts()
                    for ip, cnt in ip_counts.head(5).items():
                        chips_html += f'<div class="saas-chip"><code>{ip}</code> <span class="saas-chip-count">{cnt}</span></div>'
                else:
                    chips_html = '<span style="color: #111439; font-size: 0.85rem; font-weight: 500;">No anomalous source IP activity flagged in sample.</span>'

                threat_html = f"""
                <div class="saas-card">
                    <div class="saas-card-title">🌐 Top Offending Source Telemetry</div>
                    <div>{chips_html}</div>
                    <div style="font-size: 0.78rem; color: #111439; margin-top: 10px; font-weight: 500;">
                        High-frequency or signature-flagged source IP addresses requiring defensive evaluation.
                    </div>
                </div>
                """
                st.markdown(threat_html, unsafe_allow_html=True)

            st.divider()

            # Alerts Summary or Zero-Threat State
            # Rule: Never claim the dataset is safe simply because no alerts were generated.
            if isinstance(alerts_df, pd.DataFrame) and not alerts_df.empty:
                st.markdown("### 🚨 Recent Threat Alerts")
                st.write(f"Identified **{len(alerts_df):,}** potential security alerts across the analyzed log stream.")

                # Show top 5 recent alerts preview (alert_id first if available)
                preview_cols = [c for c in ["alert_id", "timestamp", "source_ip", "event_type", "severity", "detection_type", "detection_reason"] if c in alerts_df.columns]
                st.dataframe(alerts_df[preview_cols].head(5), width="stretch")
                st.caption("View complete details, multidimensional filters, and remediation actions on the **Alerts** page.")

                if INTELLIGENCE_AVAILABLE:
                    st.markdown(
                        """
                        <div class="saas-card" style="border-left: 4px solid #635BFF; margin-top: 14px; padding: 16px 20px;">
                            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
                                <div>
                                    <div style="font-weight: 700; color: #111439; font-size: 0.95rem;">
                                        🧠 Incident Intelligence & Attack Stories Generated
                                    </div>
                                    <div style="color: #111439; font-size: 0.82rem; margin-top: 4px; font-weight: 500;">
                                        Correlated security alerts into actionable threat campaigns with chronological timelines, evidence breakdowns, and 0–100 risk prioritization.
                                    </div>
                                </div>
                                <div style="font-size: 0.82rem; color: #635BFF; font-weight: 600;">
                                    Switch to <strong>Incident Intelligence</strong> in sidebar ➔
                                </div>
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
            else:
                st.markdown(
                    """
                    <div class="saas-card" style="border-left: 4px solid #16845B;">
                        <div style="display: flex; align-items: center; gap: 8px;">
                            <span class="badge-success">Analysis Complete</span>
                            <span style="font-weight: 600; color: #111439;">Zero Threat Signatures or Anomalies Detected</span>
                        </div>
                        <p style="color: #111439; font-size: 0.85rem; margin-top: 6px; margin-bottom: 0; font-weight: 500;">
                            No known malicious intrusion signatures or multivariate statistical deviations were flagged in this ingested sample.
                            Continuous telemetry monitoring should remain active for defense-in-depth.
                        </p>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

            # Scored Event Telemetry Expander
            with st.expander("📊 Scored Event Telemetry Stream", expanded=False):
                if isinstance(events_df, pd.DataFrame):
                    if not events_df.empty:
                        st.caption(
                            "Telemetry stream processed by the detection pipeline. "
                            "Anomaly scores and flags are displayed if provided by the model."
                        )
                        preferred_cols = [
                            "timestamp", "source_ip", "event_type", "status",
                            "anomaly_score", "is_anomaly", "request_count"
                        ]
                        lead_cols = [c for c in preferred_cols if c in events_df.columns]
                        tail_cols = [c for c in events_df.columns if c not in lead_cols]
                        display_event_cols = lead_cols + tail_cols
                        st.dataframe(events_df[display_event_cols], width="stretch")
                    else:
                        st.info("No scored events were returned in the event telemetry stream.")
                else:
                    st.info("No scored event telemetry was provided by the detection pipeline.")

        # Backend not executed or not available: Show Ingestion Baseline Metrics only
        else:
            st.markdown("### Ingested Log Telemetry")
            mcol1, mcol2, mcol3 = st.columns(3)
            with mcol1:
                st.metric("Ingested Valid Events", f"{meta['valid_rows']:,}")
            with mcol2:
                st.metric("Skipped Rows (Invalid Time)", f"{meta['skipped_rows']:,}")
            with mcol3:
                st.metric("Detected Columns", f"{len(validated_df.columns)}")

            st.markdown("#### Sample Ingested Event Stream")
            st.dataframe(validated_df.head(10), width="stretch")

            if BACKEND_AVAILABLE:
                st.divider()
                if st.button("⚡ Run Detection Pipeline on Ingested Logs", type="primary"):
                    run_backend_detection(validated_df)
                    st.rerun()


# -----------------------------------------------------------------------------
# PAGE 2: Log Upload
# -----------------------------------------------------------------------------
elif nav_choice == "Log Upload":
    render_hero_banner(
        title="Security Log Ingestion & Validation",
        subtitle="Upload authorized system, server, or firewall CSV logs for defensive intrusion and anomaly analysis",
        badge_text="Ingestion & Preprocessing Gateway",
        show_shield=False,
    )

    # Spacious Upload Specification Card with 3D Depth
    st.markdown(
        """
        <div class="saas-card">
            <div class="saas-card-title">📋 Canonical Schema Specifications</div>
            <div style="font-size: 0.88rem; color: #24294F; line-height: 1.6;">
                <span style="color: #635BFF; font-weight: 600;">• Mandatory Columns:</span> <code>timestamp</code> (ISO-8601), <code>event_type</code>, <code>status</code><br>
                <span style="color: #111439; font-weight: 700;">• Optional Telemetry:</span> <code>source_ip</code>, <code>destination_ip</code>, <code>user</code>, <code>message</code>, <code>request_count</code><br>
                <span style="color: #111439; font-size: 0.82rem; font-weight: 500;">* Header normalizer automatically maps common telemetry aliases (e.g., <code>src_ip</code>, <code>action</code>, <code>count</code>) into canonical format.</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    uploaded_file = st.file_uploader(
        "Choose a security log CSV file",
        type=["csv"],
        help="Upload standard comma-separated security logs. Real credentials or private data should not be used.",
    )

    if uploaded_file is not None:
        file_size_bytes = len(uploaded_file.getvalue()) if hasattr(uploaded_file, "getvalue") else 0
        file_size_kb = round(file_size_bytes / 1024, 2)
        filename = getattr(uploaded_file, "name", "security_logs.csv")

        st.caption(f"File selected: **{filename}** ({file_size_kb} KB)")

        if validate_uploaded_csv is None:
            st.error("Validation module is not available. Please inspect csv_validator.py.")
        else:
            # Validate using Member 1's validation module
            validation_result = validate_uploaded_csv(uploaded_file)

            if not validation_result.is_valid:
                st.error("❌ **CSV Validation Failed**")
                for err_msg in validation_result.errors:
                    st.write(f"• {err_msg}")
                st.info("Please correct the file structure according to the canonical schema and re-upload.")
                # Reset state on failed upload
                st.session_state["validated_df"] = None
                st.session_state["pipeline_results"] = None

            else:
                valid_df = validation_result.df
                st.success(
                    f"✅ **CSV Validation Passed**: Successfully verified **{len(valid_df):,}** event records."
                )

                # Report any non-fatal parsing warnings
                if validation_result.warnings:
                    with st.expander("Validation Notices & Warnings", expanded=True):
                        for warn_msg in validation_result.warnings:
                            st.warning(warn_msg)

                # Check if a new or different file was uploaded; reset stale detection results
                if st.session_state["validation_meta"]["filename"] != filename:
                    st.session_state["pipeline_results"] = None
                    st.session_state["pipeline_error"] = None

                # Store in session state
                st.session_state["validated_df"] = valid_df
                st.session_state["validation_meta"] = {
                    "filename": filename,
                    "filesize": f"{file_size_kb} KB",
                    "valid_rows": len(valid_df),
                    "skipped_rows": validation_result.skipped_rows,
                    "warnings": validation_result.warnings,
                }

                # Preview verified DataFrame
                st.markdown("### Validated Data Preview")
                st.dataframe(valid_df.head(10), width="stretch")

                st.divider()

                # Action Button: Run Detection with 3D Primary Styling
                if BACKEND_AVAILABLE:
                    st.write("Detection engine is ready to analyze this log dataset.")
                    if st.button("🚀 Analyze Logs with Detection Agent", type="primary"):
                        run_backend_detection(valid_df)
                        if st.session_state["pipeline_results"] is not None:
                            res_summary = st.session_state["pipeline_results"].get("summary", {})
                            tot_al = res_summary.get("total_alerts", 0)
                            st.success(
                                f"✅ **Analysis Complete**: Successfully processed **{len(valid_df):,}** events. "
                                f"Generated **{tot_al:,}** alerts across rule-based and anomaly models. "
                                "Switch to **Dashboard** or **Alerts** to review results."
                            )
                        elif st.session_state["pipeline_error"]:
                            st.error(f"Detection Error: {st.session_state['pipeline_error']}")
                else:
                    st.info(
                        "ℹ️ **Member 2 Integration Staging**: Detection functions in `detector.py` are pending. "
                        "Validated logs are held in memory ready for the detection pipeline."
                    )


# -----------------------------------------------------------------------------
# PAGE 3: Alerts
# -----------------------------------------------------------------------------
elif nav_choice == "Alerts":
    render_hero_banner(
        title="Security Alerts & Incident Review",
        subtitle="Review explainable rule-based triggers, anomaly deviations, and recommended defensive actions",
        badge_text="Incident Triage & Threat Response",
        show_shield=False,
    )

    results = st.session_state["pipeline_results"]

    if results is None:
        if st.session_state["validated_df"] is None:
            st.warning("No log dataset has been uploaded. Please upload logs in the **Log Upload** section.")
        elif not BACKEND_AVAILABLE:
            st.info(
                "ℹ️ **Detection Backend Pending**: No alerts available yet because `detector.py` is currently under "
                "development. Once the backend is integrated, alerts will be displayed here."
            )
        else:
            st.info("Logs are uploaded, but detection has not been executed yet. Click below to analyze:")
            if st.button("Run Detection Now", type="primary"):
                run_backend_detection(st.session_state["validated_df"])
                st.rerun()

    else:
        # Display backend warnings if provided
        raw_alerts_warns = results.get("warnings")
        alerts_backend_warns = []
        if isinstance(raw_alerts_warns, (list, tuple)):
            alerts_backend_warns = [str(w).strip() for w in raw_alerts_warns if str(w).strip()]
        elif isinstance(raw_alerts_warns, str) and raw_alerts_warns.strip():
            alerts_backend_warns = [raw_alerts_warns.strip()]

        if alerts_backend_warns:
            with st.expander("⚠️ Pipeline Notices & Warnings", expanded=True):
                for warn_msg in alerts_backend_warns:
                    st.warning(f"• {warn_msg}")

        alerts_df = results.get("alerts", pd.DataFrame())

        if not isinstance(alerts_df, pd.DataFrame) or alerts_df.empty:
            st.markdown(
                """
                <div class="saas-card" style="border-left: 4px solid #16845B;">
                    <div style="font-weight: 600; color: #111439; margin-bottom: 4px;">✅ No Security Alerts Found</div>
                    <div style="color: #111439; font-size: 0.88rem; font-weight: 500;">
                        The detection engine did not identify signature matches or statistical anomaly outliers in this ingested sample.
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        else:
            st.write(f"Displaying **{len(alerts_df):,}** generated alert records.")

            # Filtering Controls Card with 3D Depth
            with st.expander("🔍 Filter & Search Alerts", expanded=True):
                fcol1, fcol2, fcol3 = st.columns([1, 1, 2])

                # Derive filter options from base alerts table to prevent cross-contamination
                available_severities = (
                    sorted(list(alerts_df["severity"].dropna().unique()))
                    if "severity" in alerts_df.columns
                    else []
                )
                selected_severities = (
                    fcol1.multiselect(
                        "Filter by Severity",
                        options=available_severities,
                        default=available_severities,
                    )
                    if available_severities
                    else []
                )

                available_types = (
                    sorted(list(alerts_df["detection_type"].dropna().unique()))
                    if "detection_type" in alerts_df.columns
                    else []
                )
                selected_types = (
                    fcol2.multiselect(
                        "Detection Type",
                        options=available_types,
                        default=available_types,
                    )
                    if available_types
                    else []
                )

                filtered_df = alerts_df.copy()
                if available_severities:
                    if selected_severities:
                        filtered_df = filtered_df[filtered_df["severity"].isin(selected_severities)]
                    else:
                        filtered_df = filtered_df.iloc[0:0]

                if available_types and not filtered_df.empty:
                    if selected_types:
                        filtered_df = filtered_df[filtered_df["detection_type"].isin(selected_types)]
                    else:
                        filtered_df = filtered_df.iloc[0:0]

                # Search filter with regex=False for safe literal substring search
                search_query = fcol3.text_input("Search (IP, Event, or Reason)", value="").strip().lower()
                if search_query and not filtered_df.empty:
                    match_mask = pd.Series(False, index=filtered_df.index)
                    for col in ["source_ip", "event_type", "detection_reason", "recommended_action"]:
                        if col in filtered_df.columns:
                            match_mask |= (
                                filtered_df[col]
                                .astype(str)
                                .str.lower()
                                .str.contains(search_query, regex=False, na=False)
                            )
                    filtered_df = filtered_df[match_mask]

            st.markdown(f"**Showing {len(filtered_df):,} matching alert(s)**")

            # Table display - First dataframe on Alerts page (tested by unit tests)
            expected_order = [
                "alert_id", "timestamp", "source_ip", "event_type", "severity",
                "detection_type", "detection_reason", "recommended_action"
            ]
            display_cols = [c for c in expected_order if c in filtered_df.columns]
            other_cols = [c for c in filtered_df.columns if c not in display_cols]
            final_cols = display_cols + other_cols

            st.dataframe(filtered_df[final_cols], width="stretch")

            # Expandable alert details with 3D elevation
            if not filtered_df.empty:
                with st.expander("📑 Detailed Incident Analysis & Recommended Actions", expanded=False):
                    for idx, row in filtered_df.iterrows():
                        aid = row.get("alert_id", f"ALT-{idx}")
                        sev = str(row.get("severity", "UNKNOWN")).upper()
                        badge_cls = "badge-critical" if sev in ("CRITICAL", "HIGH") else ("badge-medium" if sev == "MEDIUM" else "badge-low")
                        det_type = row.get("detection_type", "Unknown")
                        src_ip = row.get("source_ip", "N/A")
                        reason = row.get("detection_reason", "No reason provided")
                        rec_action = row.get("recommended_action", "Investigate endpoint telemetry")

                        st.markdown(
                            f"""
                            <div class="saas-card" style="margin-bottom: 12px; padding: 14px 18px;">
                                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                                    <div><strong>{aid}</strong> • <code>{src_ip}</code> ({det_type})</div>
                                    <span class="{badge_cls}">{sev}</span>
                                </div>
                                <div style="font-size: 0.85rem; color: #24294F; margin-bottom: 4px;">
                                    <strong>Trigger Reason:</strong> {reason}
                                </div>
                                <div style="font-size: 0.85rem; color: #635BFF; font-weight: 500;">
                                    <strong>Defensive Action:</strong> {rec_action}
                                </div>
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )

            # Export section: ONLY enabled when actual alerts exist
            st.divider()
            if not filtered_df.empty:
                csv_buffer = io.StringIO()
                filtered_df.to_csv(csv_buffer, index=False)
                st.download_button(
                    label="📥 Export Alerts Report (CSV)",
                    data=csv_buffer.getvalue(),
                    file_name="security_alerts_report.csv",
                    mime="text/csv",
                    type="primary",
                    help="Download the filtered security alerts table as a CSV report.",
                )


# -----------------------------------------------------------------------------
# PAGE 4: Incident Intelligence (Attack Story Generator & Risk Prioritization)
# -----------------------------------------------------------------------------
elif nav_choice == "Incident Intelligence":
    render_hero_banner(
        title="Incident Intelligence & Attack Story Generator",
        subtitle="Correlated Threat Campaigns, Chronological Attack Timelines & Heuristic Risk Prioritization",
        badge_text="SOC Threat Correlation & Triage",
        show_shield=True,
    )

    results = st.session_state["pipeline_results"]

    if results is None:
        if st.session_state["validated_df"] is None:
            st.markdown(
                """
                <div style="text-align: center; padding: 48px 32px; background: rgba(17, 20, 57, 0.68); backdrop-filter: blur(14px); -webkit-backdrop-filter: blur(14px); border: 1px solid rgba(99, 91, 255, 0.30); border-radius: 14px; box-shadow: 0 8px 32px rgba(0, 0, 0, 0.35);">
                    <div style="font-size: 3rem; margin-bottom: 12px; filter: drop-shadow(0 4px 12px rgba(99, 91, 255, 0.4));">📁</div>
                    <h3 style="color: #FFFFFF; margin-bottom: 8px; font-weight: 700; text-shadow: 0 2px 6px rgba(0, 0, 0, 0.5);">No Log Telemetry Loaded</h3>
                    <p style="color: #CBD5E1; max-width: 560px; margin: 0 auto 20px auto; font-size: 0.95rem; font-weight: 500; line-height: 1.6;">
                        Upload a security log CSV file and execute threat detection to generate correlated incident intelligence and attack stories.
                    </p>
                </div>
                """,
                unsafe_allow_html=True,
            )
        elif not BACKEND_AVAILABLE:
            st.info(
                "ℹ️ **Detection Engine Pending**: Security alerts are required to build incident intelligence. "
                "Once `detector.py` is available, correlated incidents will be automatically generated here."
            )
        else:
            st.info("Logs are uploaded, but detection has not been executed yet. Click below to analyze:")
            if st.button("Run Detection Pipeline Now", type="primary"):
                run_backend_detection(st.session_state["validated_df"])
                st.rerun()

    elif not INTELLIGENCE_AVAILABLE or build_incident_intelligence is None:
        st.error("Incident Intelligence module (`incident_intelligence.py`) is unavailable. Please verify module installation.")

    else:
        alerts_df = results.get("alerts", pd.DataFrame())
        events_df = results.get("events", pd.DataFrame())

        intel = build_incident_intelligence(alerts_df, events_df)

        if not intel.get("has_data") or not intel.get("incidents"):
            st.markdown(
                """
                <div class="saas-card" style="border-left: 4px solid #16845B; padding: 24px;">
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <span class="badge-success">Analysis Complete</span>
                        <span style="font-weight: 700; color: #111439; font-size: 1rem;">Zero Security Incidents Correlated</span>
                    </div>
                    <p style="color: #111439; font-size: 0.88rem; margin-top: 8px; margin-bottom: 0; font-weight: 500;">
                        No threat signatures or statistical anomalies were flagged in the analyzed telemetry sample.
                        Because there is no evidence of anomalous activity, no attack stories or incident campaigns were fabricated.
                    </p>
                </div>
                """,
                unsafe_allow_html=True,
            )
        else:
            incidents = intel["incidents"]
            summary = intel["summary"]

            # 4 KPI Metrics Cards
            kcol1, kcol2, kcol3, kcol4 = st.columns(4)
            with kcol1:
                st.metric("Correlated Incidents", f"{summary['total_incidents']:,}")
            with kcol2:
                st.metric("Critical Priority", f"{summary['priority_breakdown']['Critical']:,}")
            with kcol3:
                st.metric("High Priority", f"{summary['priority_breakdown']['High']:,}")
            with kcol4:
                st.metric("Peak Risk Score", f"{summary['max_risk_score']} / 100")

            # Prioritization Methodology Notice
            st.markdown(
                """
                <div style="background: rgba(17, 20, 57, 0.65); backdrop-filter: blur(10px); border: 1px solid rgba(99, 91, 255, 0.30); border-radius: 8px; padding: 12px 18px; margin: 16px 0 20px 0; font-size: 0.84rem; color: #FFFFFF; box-shadow: 0 4px 16px rgba(0, 0, 0, 0.25);">
                    <strong style="color: #22B8CF;">⚖️ Heuristic Prioritization Methodology:</strong>
                    Risk scores (0–100) are defensive triage heuristics derived from detection severity, exploit signatures (SQLi, auth brute force), ML anomaly deviations, multi-vector behavior, and sublinear volume scaling. Scores represent operational review urgency for SOC analysts, <em>not</em> a mathematically calibrated probability that an attack succeeded.
                </div>
                """,
                unsafe_allow_html=True,
            )

            # Filtering & Sorting Controls
            with st.expander("🔍 Filter & Sort Incidents", expanded=True):
                fcol1, fcol2, fcol3, fcol4 = st.columns([1.2, 1.2, 1.8, 1.4])

                selected_prios = fcol1.multiselect(
                    "Filter by Priority",
                    options=["Critical", "High", "Medium", "Low"],
                    default=["Critical", "High", "Medium", "Low"],
                )

                min_score = fcol2.slider(
                    "Minimum Risk Score",
                    min_value=0,
                    max_value=100,
                    value=0,
                    step=5,
                )

                search_term = fcol3.text_input(
                    "Search (IP, Headline, Threat)",
                    value="",
                ).strip().lower()

                sort_order = fcol4.selectbox(
                    "Sort Incidents By",
                    options=[
                        "Highest Risk First",
                        "Lowest Risk First",
                        "Most Events First",
                        "Fewest Events First",
                    ],
                    index=0,
                )

            # Apply Filtering
            filtered_incidents = [
                inc for inc in incidents
                if inc.risk_assessment.priority in selected_prios
                and inc.risk_assessment.score >= min_score
            ]

            if search_term:
                filtered_incidents = [
                    inc for inc in filtered_incidents
                    if search_term in f"{inc.incident_id} {inc.source_ip} {inc.primary_threat} {inc.attack_story.headline} {inc.attack_story.what_was_observed}".lower()
                ]

            # Apply Sorting
            if sort_order == "Highest Risk First":
                filtered_incidents.sort(key=lambda x: x.risk_assessment.score, reverse=True)
            elif sort_order == "Lowest Risk First":
                filtered_incidents.sort(key=lambda x: x.risk_assessment.score, reverse=False)
            elif sort_order == "Most Events First":
                filtered_incidents.sort(key=lambda x: x.event_count, reverse=True)
            elif sort_order == "Fewest Events First":
                filtered_incidents.sort(key=lambda x: x.event_count, reverse=False)

            st.write(f"Displaying **{len(filtered_incidents):,}** of **{len(incidents):,}** correlated incident(s)")

            if not filtered_incidents:
                st.info("No incidents match the active filter criteria. Try adjusting the priority selection, score slider, or search term.")

            # Render Incident Cards
            for inc in filtered_incidents:
                score = inc.risk_assessment.score
                prio = inc.risk_assessment.priority
                prio_lower = prio.lower()

                border_color = (
                    "#DC3545" if prio == "Critical" else
                    ("#E05260" if prio == "High" else
                    ("#C27A00" if prio == "Medium" else "#2563EB"))
                )

                ip_display = (
                    f"<code>{inc.source_ip}</code>" if not inc.is_unattributed_ip
                    else '<span style="color: #111439; font-style: italic; font-weight: 600;">Unattributed Source</span>'
                )

                card_header_html = f"""
                <div class="saas-card" style="border-left: 5px solid {border_color}; margin-bottom: 18px; padding: 20px 24px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px; margin-bottom: 8px;">
                        <div style="display: flex; align-items: center; gap: 10px;">
                            <span style="font-weight: 700; font-size: 1.05rem; color: #111439;">{inc.incident_id}</span>
                            <span>•</span>
                            <span class="saas-chip" style="margin: 0;">{ip_display}</span>
                            <span style="font-size: 0.82rem; color: #111439; font-weight: 600; background: #F0F0F5; padding: 4px 10px; border-radius: 6px; border: 1px solid #D8D8E5;">⏱️ {inc.time_span_str}</span>
                        </div>
                        <div style="display: flex; align-items: center; gap: 8px;">
                            <span class="risk-score-pill">Risk: {score} / 100</span>
                            <span class="badge-priority-{prio_lower}">{prio} Priority</span>
                        </div>
                    </div>
                    <div style="font-weight: 700; font-size: 1.15rem; color: #111439; margin-bottom: 4px;">
                        {inc.attack_story.headline}
                    </div>
                    <div style="font-size: 0.88rem; color: #24294F; font-weight: 500;">
                        Primary Detection Signature: <strong style="color: #111439;">{inc.primary_threat}</strong> • Correlated Alerts: <strong style="color: #635BFF;">{inc.event_count}</strong>
                    </div>
                </div>
                """
                st.markdown(card_header_html, unsafe_allow_html=True)

                # Tabbed Interface for Detailed Investigation
                tab_story, tab_risk, tab_timeline = st.tabs([
                    "📖 Attack Story & Narrative",
                    "⚡ Risk Prioritization Factors",
                    "⏱️ Event Timeline & Evidence",
                ])

                with tab_story:
                    story = inc.attack_story
                    st.markdown("#### 🔍 What Was Observed (Factual Record)")
                    st.markdown(
                        f"""
                        <div style="background: rgba(17, 20, 57, 0.65); backdrop-filter: blur(10px); border: 1px solid rgba(255, 255, 255, 0.12); border-radius: 8px; padding: 16px 20px; margin-bottom: 16px; font-size: 0.92rem; color: #FFFFFF; font-weight: 500; line-height: 1.6; box-shadow: 0 4px 16px rgba(0, 0, 0, 0.25);">
                            {story.what_was_observed}
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

                    st.markdown("#### 🚨 Why It Is Suspicious (Threat Analysis)")
                    st.markdown(
                        f"""
                        <div style="background: rgba(17, 20, 57, 0.65); backdrop-filter: blur(10px); border: 1px solid rgba(255, 255, 255, 0.12); border-radius: 8px; padding: 16px 20px; margin-bottom: 16px; font-size: 0.92rem; color: #FFFFFF; font-weight: 500; line-height: 1.6; box-shadow: 0 4px 16px rgba(0, 0, 0, 0.25);">
                            {story.why_it_is_suspicious}
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

                    # Observed Facts vs Possible Interpretations
                    st.markdown("#### ⚖️ Observed Facts vs. Possible Interpretations")
                    fact_col, interp_col = st.columns(2)

                    with fact_col:
                        facts_html = "<ul>" + "".join([f"<li style='margin-bottom: 6px; color: #F1F5F9;'>{f}</li>" for f in story.observed_facts]) + "</ul>"
                        st.markdown(
                            f"""
                            <div style="background: rgba(17, 20, 57, 0.65); backdrop-filter: blur(10px); border: 1px solid rgba(22, 132, 91, 0.40); border-radius: 8px; padding: 16px 18px; min-height: 160px; box-shadow: 0 4px 16px rgba(0, 0, 0, 0.25);">
                                <div style="font-weight: 700; color: #10B981; font-size: 0.88rem; text-transform: uppercase; margin-bottom: 10px; display: flex; align-items: center; gap: 6px;">
                                    <span>✅</span> Verified Telemetry Facts
                                </div>
                                <div style="font-size: 0.86rem; color: #F1F5F9; line-height: 1.6; font-weight: 500;">
                                    {facts_html}
                                </div>
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )

                    with interp_col:
                        interp_html = "<ul>" + "".join([f"<li style='margin-bottom: 6px; color: #F1F5F9;'>{p}</li>" for p in story.possible_interpretations]) + "</ul>"
                        st.markdown(
                            f"""
                            <div style="background: rgba(17, 20, 57, 0.65); backdrop-filter: blur(10px); border: 1px solid rgba(99, 91, 255, 0.40); border-radius: 8px; padding: 16px 18px; min-height: 160px; box-shadow: 0 4px 16px rgba(0, 0, 0, 0.25);">
                                <div style="font-weight: 700; color: #8B5CF6; font-size: 0.88rem; text-transform: uppercase; margin-bottom: 10px; display: flex; align-items: center; gap: 6px;">
                                    <span>💡</span> Analytical Hypotheses & Explanations
                                </div>
                                <div style="font-size: 0.86rem; color: #F1F5F9; line-height: 1.6; font-weight: 500;">
                                    {interp_html}
                                </div>
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )

                    st.markdown("#### 🛡️ Recommended Defensive Investigation Steps")
                    st.caption("Actionable suggestions for human SOC analyst verification. No automated or disruptive actions will be taken.")
                    steps_html = "".join([f"<li style='margin-bottom: 8px; color: #F1F5F9; font-weight: 500;'>{step_txt}</li>" for step_txt in story.recommended_investigation_steps])
                    st.markdown(
                        f"""
                        <div style="background: rgba(17, 20, 57, 0.65); backdrop-filter: blur(10px); border: 1px solid rgba(255, 255, 255, 0.12); border-radius: 8px; padding: 16px 20px; margin-top: 6px; box-shadow: 0 4px 16px rgba(0, 0, 0, 0.25);">
                            <ul style="margin: 0; padding-left: 20px; line-height: 1.6;">
                                {steps_html}
                            </ul>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

                with tab_risk:
                    risk = inc.risk_assessment
                    st.markdown(f"#### Risk Prioritization Score: **{risk.score} / 100** ({risk.priority} Priority)")
                    st.progress(risk.score / 100.0)

                    # Score Breakdown Factors Table
                    factors_data = []
                    for factor_item in risk.contributing_factors:
                        factors_data.append({
                            "Scoring Component": factor_item.get("factor", "Standard Factor"),
                            "Points Contributed": f"+{factor_item.get('points', 0)}",
                            "Evidence / Heuristic Basis": factor_item.get("details", ""),
                        })

                    if factors_data:
                        st.dataframe(pd.DataFrame(factors_data), width="stretch", hide_index=True)

                    st.markdown(
                        f"""
                        <div style="background: rgba(17, 20, 57, 0.65); backdrop-filter: blur(10px); border: 1px solid rgba(255, 255, 255, 0.12); border-radius: 6px; padding: 10px 14px; font-size: 0.80rem; color: #CBD5E1; margin-top: 10px; font-style: italic; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);">
                            {risk.methodology_note}
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

                with tab_timeline:
                    st.markdown(f"#### Associated Event Timeline ({len(inc.events)} events)")
                    timeline_rows = []
                    for ev in inc.events:
                        timeline_rows.append({
                            "Alert ID": ev.alert_id,
                            "Timestamp": ev.timestamp_str,
                            "Source IP": ev.source_ip,
                            "Event Type": ev.event_type,
                            "Status": ev.status,
                            "Severity": ev.severity,
                            "Detection Mechanism": ev.detection_type,
                            "Reason / Evidence": ev.detection_reason,
                        })
                    st.dataframe(pd.DataFrame(timeline_rows), width="stretch", hide_index=True)

                st.write("")

            # Export Incidents Summary
            st.divider()
            if filtered_incidents:
                export_rows = []
                for inc in filtered_incidents:
                    export_rows.append({
                        "incident_id": inc.incident_id,
                        "source_ip": inc.source_ip,
                        "event_count": inc.event_count,
                        "max_severity": inc.max_severity,
                        "risk_score": inc.risk_assessment.score,
                        "priority": inc.risk_assessment.priority,
                        "primary_threat": inc.primary_threat,
                        "time_span": inc.time_span_str,
                        "headline": inc.attack_story.headline,
                    })
                incidents_export_df = pd.DataFrame(export_rows)
                inc_csv_buffer = io.StringIO()
                incidents_export_df.to_csv(inc_csv_buffer, index=False)

                st.download_button(
                    label="📥 Export Incident Intelligence Report (CSV)",
                    data=inc_csv_buffer.getvalue(),
                    file_name="incident_intelligence_report.csv",
                    mime="text/csv",
                    type="primary",
                    help="Download the filtered correlated incidents and risk scores as a CSV report.",
                )


# -----------------------------------------------------------------------------
# PAGE 5: About
# -----------------------------------------------------------------------------
elif nav_choice == "About":
    render_hero_banner(
        title="About the AI Cybersecurity Monitoring Agent",
        subtitle="Procedure & workflow, system architecture flowchart, and verified technology stack",
        badge_text="System Documentation & Architecture",
        show_shield=False,
    )

    # -------------------------------------------------------------------------
    # 1. PROCEDURE / WORKING PROCESS
    # -------------------------------------------------------------------------
    st.markdown(
        """
        <div style="background: rgba(17, 20, 57, 0.70); backdrop-filter: blur(14px); -webkit-backdrop-filter: blur(14px); border: 1px solid rgba(99, 91, 255, 0.30); border-radius: 14px; padding: 26px 30px; margin-bottom: 24px; box-shadow: 0 8px 32px rgba(0, 0, 0, 0.35);">
            <div style="font-size: 0.82rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em; color: #22B8CF; margin-bottom: 6px;">
                Workflow & Implementation Details
            </div>
            <h3 style="color: #FFFFFF; margin-top: 0; margin-bottom: 18px; font-weight: 700; font-size: 1.35rem; display: flex; align-items: center; gap: 10px;">
                <span>📋</span> 1. PROCEDURE / WORKING PROCESS
            </h3>
            <p style="color: #CBD5E1; font-size: 0.92rem; line-height: 1.6; margin-bottom: 20px;">
                The AI-Based Cybersecurity Monitoring Agent operates as a multi-stage defensive telemetry pipeline combining strict data ingestion, dual-engine threat recognition, narrative incident clustering, and analyst reporting:
            </p>
            <div style="display: flex; flex-direction: column; gap: 14px;">
                <div style="display: flex; align-items: flex-start; gap: 14px; background: rgba(25, 30, 71, 0.65); border: 1px solid rgba(255, 255, 255, 0.10); border-radius: 10px; padding: 14px 18px;">
                    <div style="background: linear-gradient(135deg, #635BFF 0%, #8B5CF6 100%); color: #FFFFFF; font-weight: 700; font-size: 0.85rem; width: 28px; height: 28px; border-radius: 50%; display: flex; align-items: center; justify-content: center; flex-shrink: 0; box-shadow: 0 2px 6px rgba(99, 91, 255, 0.3);">1</div>
                    <div style="color: #F1F5F9; font-size: 0.90rem; line-height: 1.55;">
                        <strong style="color: #FFFFFF;">User uploads a security log CSV file:</strong> The user selects and uploads an authorized server, proxy, or firewall log CSV dataset using the upload interface on the Log Upload page.
                    </div>
                </div>
                <div style="display: flex; align-items: flex-start; gap: 14px; background: rgba(25, 30, 71, 0.65); border: 1px solid rgba(255, 255, 255, 0.10); border-radius: 10px; padding: 14px 18px;">
                    <div style="background: linear-gradient(135deg, #635BFF 0%, #8B5CF6 100%); color: #FFFFFF; font-weight: 700; font-size: 0.85rem; width: 28px; height: 28px; border-radius: 50%; display: flex; align-items: center; justify-content: center; flex-shrink: 0; box-shadow: 0 2px 6px rgba(99, 91, 255, 0.3);">2</div>
                    <div style="color: #F1F5F9; font-size: 0.90rem; line-height: 1.55;">
                        <strong style="color: #FFFFFF;">The system validates the CSV structure and required columns:</strong> The validation module (<code>csv_validator.py</code>) inspects the file schema, ensuring valid CSV formatting, file non-emptiness, maximum row bounds, and the presence of mandatory columns (<code>timestamp</code>, <code>event_type</code>, <code>status</code>) to prevent malformed telemetry ingestion.
                    </div>
                </div>
                <div style="display: flex; align-items: flex-start; gap: 14px; background: rgba(25, 30, 71, 0.65); border: 1px solid rgba(255, 255, 255, 0.10); border-radius: 10px; padding: 14px 18px;">
                    <div style="background: linear-gradient(135deg, #635BFF 0%, #8B5CF6 100%); color: #FFFFFF; font-weight: 700; font-size: 0.85rem; width: 28px; height: 28px; border-radius: 50%; display: flex; align-items: center; justify-content: center; flex-shrink: 0; box-shadow: 0 2px 6px rgba(99, 91, 255, 0.3);">3</div>
                    <div style="color: #F1F5F9; font-size: 0.90rem; line-height: 1.55;">
                        <strong style="color: #FFFFFF;">The log data is normalized and preprocessed:</strong> Column headers are mapped from common alias conventions to canonical attributes, timestamps are converted into ISO-8601 DatetimeIndex structures, and telemetry features are cleaned for downstream analysis.
                    </div>
                </div>
                <div style="display: flex; align-items: flex-start; gap: 14px; background: rgba(25, 30, 71, 0.65); border: 1px solid rgba(255, 255, 255, 0.10); border-radius: 10px; padding: 14px 18px;">
                    <div style="background: linear-gradient(135deg, #635BFF 0%, #8B5CF6 100%); color: #FFFFFF; font-weight: 700; font-size: 0.85rem; width: 28px; height: 28px; border-radius: 50%; display: flex; align-items: center; justify-content: center; flex-shrink: 0; box-shadow: 0 2px 6px rgba(99, 91, 255, 0.3);">4</div>
                    <div style="color: #F1F5F9; font-size: 0.90rem; line-height: 1.55;">
                        <strong style="color: #FFFFFF;">The backend uses rule-based detection to identify known suspicious patterns, such as SQL injection and repeated failed login attempts:</strong> The Node.js Express service tests normalized records against deterministic signature rules and frequency thresholds for known threat patterns (SQLi payloads, authentication brute-force floods, and unauthorized access).
                    </div>
                </div>
                <div style="display: flex; align-items: flex-start; gap: 14px; background: rgba(25, 30, 71, 0.65); border: 1px solid rgba(255, 255, 255, 0.10); border-radius: 10px; padding: 14px 18px;">
                    <div style="background: linear-gradient(135deg, #635BFF 0%, #8B5CF6 100%); color: #FFFFFF; font-weight: 700; font-size: 0.85rem; width: 28px; height: 28px; border-radius: 50%; display: flex; align-items: center; justify-content: center; flex-shrink: 0; box-shadow: 0 2px 6px rgba(99, 91, 255, 0.3);">5</div>
                    <div style="color: #F1F5F9; font-size: 0.90rem; line-height: 1.55;">
                        <strong style="color: #FFFFFF;">The Python detection module applies Isolation Forest anomaly detection to identify unusual patterns in log data:</strong> <code>detector.py</code> engineers cyclical temporal features (sine/cosine hour-of-day), failure ratios, and frequency counters, then fits an unsupervised Scikit-learn <code>IsolationForest</code> estimator to isolate multidimensional outliers without requiring pre-labeled training data.
                    </div>
                </div>
                <div style="display: flex; align-items: flex-start; gap: 14px; background: rgba(25, 30, 71, 0.65); border: 1px solid rgba(255, 255, 255, 0.10); border-radius: 10px; padding: 14px 18px;">
                    <div style="background: linear-gradient(135deg, #635BFF 0%, #8B5CF6 100%); color: #FFFFFF; font-weight: 700; font-size: 0.85rem; width: 28px; height: 28px; border-radius: 50%; display: flex; align-items: center; justify-content: center; flex-shrink: 0; box-shadow: 0 2px 6px rgba(99, 91, 255, 0.3);">6</div>
                    <div style="color: #F1F5F9; font-size: 0.90rem; line-height: 1.55;">
                        <strong style="color: #FFFFFF;">The system integrates the available detection results and generates alerts:</strong> The ingestion pipeline unifies rule-based matches and statistical anomaly scores into a consolidated, deduplicated alert table with categorized severity tags (Critical, High, Medium, Low).
                    </div>
                </div>
                <div style="display: flex; align-items: flex-start; gap: 14px; background: rgba(25, 30, 71, 0.65); border: 1px solid rgba(255, 255, 255, 0.10); border-radius: 10px; padding: 14px 18px;">
                    <div style="background: linear-gradient(135deg, #635BFF 0%, #8B5CF6 100%); color: #FFFFFF; font-weight: 700; font-size: 0.85rem; width: 28px; height: 28px; border-radius: 50%; display: flex; align-items: center; justify-content: center; flex-shrink: 0; box-shadow: 0 2px 6px rgba(99, 91, 255, 0.3);">7</div>
                    <div style="color: #F1F5F9; font-size: 0.90rem; line-height: 1.55;">
                        <strong style="color: #FFFFFF;">The Incident Intelligence module groups related alerts using source IP and time, creates incident summaries, and assigns heuristic risk scores:</strong> Alerts sharing an identical source IP within correlated time windows are grouped into coherent security incidents. The integrated <strong>Attack Story Generator</strong> writes non-speculative factual summaries and chronological timelines, while the <strong>Risk Prioritization</strong> engine calculates transparent 0–100 heuristic scores to classify triage urgency into Critical, High, Medium, or Low tiers.
                    </div>
                </div>
                <div style="display: flex; align-items: flex-start; gap: 14px; background: rgba(25, 30, 71, 0.65); border: 1px solid rgba(255, 255, 255, 0.10); border-radius: 10px; padding: 14px 18px;">
                    <div style="background: linear-gradient(135deg, #635BFF 0%, #8B5CF6 100%); color: #FFFFFF; font-weight: 700; font-size: 0.85rem; width: 28px; height: 28px; border-radius: 50%; display: flex; align-items: center; justify-content: center; flex-shrink: 0; box-shadow: 0 2px 6px rgba(99, 91, 255, 0.3);">8</div>
                    <div style="color: #F1F5F9; font-size: 0.90rem; line-height: 1.55;">
                        <strong style="color: #FFFFFF;">The dashboard displays detection results, incident details, timelines, and risk priorities:</strong> Security analysts view total event volume, detection engine distribution charts, top offending IP telemetry, detailed incident inspection cards, and step-by-step SOC recommendations.
                    </div>
                </div>
                <div style="display: flex; align-items: flex-start; gap: 14px; background: rgba(25, 30, 71, 0.65); border: 1px solid rgba(255, 255, 255, 0.10); border-radius: 10px; padding: 14px 18px;">
                    <div style="background: linear-gradient(135deg, #635BFF 0%, #8B5CF6 100%); color: #FFFFFF; font-weight: 700; font-size: 0.85rem; width: 28px; height: 28px; border-radius: 50%; display: flex; align-items: center; justify-content: center; flex-shrink: 0; box-shadow: 0 2px 6px rgba(99, 91, 255, 0.3);">9</div>
                    <div style="color: #F1F5F9; font-size: 0.90rem; line-height: 1.55;">
                        <strong style="color: #FFFFFF;">The user can filter alerts and export reports as CSV files:</strong> Analysts can slice telemetry by severity tier, event type, priority rating, minimum risk score threshold, or search substring, and export verified finding summaries to standardized CSV audit reports.
                    </div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # -------------------------------------------------------------------------
    # 2. SYSTEM FLOWCHART
    # -------------------------------------------------------------------------
    st.markdown(
        """
<div style="background: rgba(17, 20, 57, 0.70); backdrop-filter: blur(14px); -webkit-backdrop-filter: blur(14px); border: 1px solid rgba(99, 91, 255, 0.30); border-radius: 14px; padding: 22px 28px; margin-bottom: 20px; box-shadow: 0 8px 32px rgba(0, 0, 0, 0.35);">
    <div style="font-size: 0.82rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em; color: #8B5CF6; margin-bottom: 6px;">
        Visual Architecture & Logic Routing
    </div>
    <h3 style="color: #FFFFFF; margin-top: 0; margin-bottom: 10px; font-weight: 700; font-size: 1.35rem; display: flex; align-items: center; gap: 10px;">
        <span>📊</span> 2. SYSTEM FLOWCHART
    </h3>
    <p style="color: #CBD5E1; font-size: 0.92rem; line-height: 1.6; margin: 0;">
        End-to-end telemetry flow from raw log ingestion through validation branching, dual-engine correlation, and analyst export:
    </p>
</div>
        """,
        unsafe_allow_html=True,
    )

    st.graphviz_chart(
        """
        digraph {
            graph [rankdir=TB, bgcolor="transparent", fontname="Inter, -apple-system, sans-serif"]
            node [shape=box, style="filled,rounded", fontname="Inter, -apple-system, sans-serif", fontsize=11, fontcolor="#FFFFFF", color="#635BFF", fillcolor="#111439", penwidth=2, margin="0.25,0.15"]
            edge [color="#22B8CF", penwidth=2, fontname="Inter, -apple-system, sans-serif", fontsize=10, fontcolor="#CBD5E1"]

            Start [shape=oval, fillcolor="#635BFF", color="#FFFFFF", fontcolor="#FFFFFF", label="Start", style="filled", width=1.4, height=0.5]
            Upload [label="Upload Security Log CSV"]
            Validate [label="Validate CSV"]
            Decision [shape=diamond, label="Valid Input?", fillcolor="#1E2248", color="#F59E0B", fontcolor="#FFFFFF", style="filled", width=1.8, height=0.9]
            Errors [label="Display Validation Errors\\n(Upload CSV Again)", fillcolor="#351826", color="#EF4444", fontcolor="#FCA5A5", style="filled,rounded"]
            Preprocess [label="Normalize and Preprocess Logs", color="#22B8CF"]
            Engines [label="Rule-Based Detection +\\nIsolation Forest Anomaly Detection", fillcolor="#1A1F4D", color="#8B5CF6", style="filled,rounded"]
            Combine [label="Combine Available Findings"]
            Alerts [label="Generate Alerts", color="#F59E0B"]
            Correlation [label="Incident Correlation & Risk Scoring\\n(Attack Story Generator & Risk Prioritization)", fillcolor="#1A1F4D", color="#8B5CF6", style="filled,rounded"]
            Dashboard [label="Display Results on Dashboard", color="#22B8CF"]
            Export [label="Filter / Inspect / Export CSV Report", color="#10B981"]
            EndNode [shape=oval, fillcolor="#10B981", color="#FFFFFF", fontcolor="#FFFFFF", label="End", style="filled", width=1.4, height=0.5]

            Start -> Upload
            Upload -> Validate
            Validate -> Decision
            Decision -> Errors [label=" No", color="#EF4444", fontcolor="#EF4444", penwidth=2]
            Errors -> Upload [style="dashed", color="#EF4444", penwidth=2]
            Decision -> Preprocess [label=" Yes", color="#10B981", fontcolor="#10B981", penwidth=2]
            Preprocess -> Engines
            Engines -> Combine
            Combine -> Alerts
            Alerts -> Correlation
            Correlation -> Dashboard
            Dashboard -> Export
            Export -> EndNode [color="#10B981", penwidth=2]
        }
        """,
        use_container_width=True,
    )

    # -------------------------------------------------------------------------
    # 3. TECHNOLOGIES USED
    # -------------------------------------------------------------------------
    st.html(
        """
<div style="background: rgba(17, 20, 57, 0.70); backdrop-filter: blur(14px); -webkit-backdrop-filter: blur(14px); border: 1px solid rgba(99, 91, 255, 0.30); border-radius: 14px; padding: 26px 30px; margin-top: 24px; margin-bottom: 24px; box-shadow: 0 8px 32px rgba(0, 0, 0, 0.35);">
    <div style="font-size: 0.82rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em; color: #10B981; margin-bottom: 6px;">
        Verified Project Stack
    </div>
    <h3 style="color: #FFFFFF; margin-top: 0; margin-bottom: 18px; font-weight: 700; font-size: 1.35rem; display: flex; align-items: center; gap: 10px;">
        <span>🛠️</span> 3. TECHNOLOGIES USED
    </h3>
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px;">
        <div style="background: rgba(25, 30, 71, 0.65); border: 1px solid rgba(255, 255, 255, 0.10); border-radius: 10px; padding: 16px 20px;">
            <div style="font-size: 0.80rem; text-transform: uppercase; letter-spacing: 0.06em; color: #22B8CF; font-weight: 700; margin-bottom: 10px;">
                Frontend and UI
            </div>
            <div style="display: flex; flex-wrap: wrap; gap: 8px;">
                <span style="background: rgba(34, 184, 207, 0.15); border: 1px solid rgba(34, 184, 207, 0.40); color: #FFFFFF; font-size: 0.85rem; font-weight: 600; padding: 5px 12px; border-radius: 6px;">Python</span>
                <span style="background: rgba(34, 184, 207, 0.15); border: 1px solid rgba(34, 184, 207, 0.40); color: #FFFFFF; font-size: 0.85rem; font-weight: 600; padding: 5px 12px; border-radius: 6px;">Streamlit</span>
                <span style="background: rgba(34, 184, 207, 0.15); border: 1px solid rgba(34, 184, 207, 0.40); color: #FFFFFF; font-size: 0.85rem; font-weight: 600; padding: 5px 12px; border-radius: 6px;">HTML</span>
                <span style="background: rgba(34, 184, 207, 0.15); border: 1px solid rgba(34, 184, 207, 0.40); color: #FFFFFF; font-size: 0.85rem; font-weight: 600; padding: 5px 12px; border-radius: 6px;">CSS</span>
            </div>
        </div>

        <div style="background: rgba(25, 30, 71, 0.65); border: 1px solid rgba(255, 255, 255, 0.10); border-radius: 10px; padding: 16px 20px;">
            <div style="font-size: 0.80rem; text-transform: uppercase; letter-spacing: 0.06em; color: #635BFF; font-weight: 700; margin-bottom: 10px;">
                Backend and API
            </div>
            <div style="display: flex; flex-wrap: wrap; gap: 8px;">
                <span style="background: rgba(99, 91, 255, 0.15); border: 1px solid rgba(99, 91, 255, 0.40); color: #FFFFFF; font-size: 0.85rem; font-weight: 600; padding: 5px 12px; border-radius: 6px;">Node.js</span>
                <span style="background: rgba(99, 91, 255, 0.15); border: 1px solid rgba(99, 91, 255, 0.40); color: #FFFFFF; font-size: 0.85rem; font-weight: 600; padding: 5px 12px; border-radius: 6px;">Express.js</span>
                <span style="background: rgba(99, 91, 255, 0.15); border: 1px solid rgba(99, 91, 255, 0.40); color: #FFFFFF; font-size: 0.85rem; font-weight: 600; padding: 5px 12px; border-radius: 6px;">REST API</span>
            </div>
        </div>

        <div style="background: rgba(25, 30, 71, 0.65); border: 1px solid rgba(255, 255, 255, 0.10); border-radius: 10px; padding: 16px 20px;">
            <div style="font-size: 0.80rem; text-transform: uppercase; letter-spacing: 0.06em; color: #8B5CF6; font-weight: 700; margin-bottom: 10px;">
                Data Processing
            </div>
            <div style="display: flex; flex-wrap: wrap; gap: 8px;">
                <span style="background: rgba(139, 92, 246, 0.15); border: 1px solid rgba(139, 92, 246, 0.40); color: #FFFFFF; font-size: 0.85rem; font-weight: 600; padding: 5px 12px; border-radius: 6px;">Pandas</span>
                <span style="background: rgba(139, 92, 246, 0.15); border: 1px solid rgba(139, 92, 246, 0.40); color: #FFFFFF; font-size: 0.85rem; font-weight: 600; padding: 5px 12px; border-radius: 6px;">NumPy</span>
            </div>
        </div>

        <div style="background: rgba(25, 30, 71, 0.65); border: 1px solid rgba(255, 255, 255, 0.10); border-radius: 10px; padding: 16px 20px;">
            <div style="font-size: 0.80rem; text-transform: uppercase; letter-spacing: 0.06em; color: #F59E0B; font-weight: 700; margin-bottom: 10px;">
                Machine Learning
            </div>
            <div style="display: flex; flex-wrap: wrap; gap: 8px;">
                <span style="background: rgba(245, 158, 11, 0.15); border: 1px solid rgba(245, 158, 11, 0.40); color: #FFFFFF; font-size: 0.85rem; font-weight: 600; padding: 5px 12px; border-radius: 6px;">Scikit-learn</span>
                <span style="background: rgba(245, 158, 11, 0.15); border: 1px solid rgba(245, 158, 11, 0.40); color: #FFFFFF; font-size: 0.85rem; font-weight: 600; padding: 5px 12px; border-radius: 6px;">Isolation Forest</span>
            </div>
        </div>

        <div style="background: rgba(25, 30, 71, 0.65); border: 1px solid rgba(255, 255, 255, 0.10); border-radius: 10px; padding: 16px 20px;">
            <div style="font-size: 0.80rem; text-transform: uppercase; letter-spacing: 0.06em; color: #10B981; font-weight: 700; margin-bottom: 10px;">
                Data Format
            </div>
            <div style="display: flex; flex-wrap: wrap; gap: 8px;">
                <span style="background: rgba(16, 185, 129, 0.15); border: 1px solid rgba(16, 185, 129, 0.40); color: #FFFFFF; font-size: 0.85rem; font-weight: 600; padding: 5px 12px; border-radius: 6px;">CSV</span>
            </div>
        </div>

        <div style="background: rgba(25, 30, 71, 0.65); border: 1px solid rgba(255, 255, 255, 0.10); border-radius: 10px; padding: 16px 20px;">
            <div style="font-size: 0.80rem; text-transform: uppercase; letter-spacing: 0.06em; color: #EC4899; font-weight: 700; margin-bottom: 10px;">
                Testing
            </div>
            <div style="display: flex; flex-wrap: wrap; gap: 8px;">
                <span style="background: rgba(236, 72, 153, 0.15); border: 1px solid rgba(236, 72, 153, 0.40); color: #FFFFFF; font-size: 0.85rem; font-weight: 600; padding: 5px 12px; border-radius: 6px;">Python unittest</span>
            </div>
        </div>

        <div style="background: rgba(25, 30, 71, 0.65); border: 1px solid rgba(255, 255, 255, 0.10); border-radius: 10px; padding: 16px 20px; grid-column: 1 / -1;">
            <div style="font-size: 0.80rem; text-transform: uppercase; letter-spacing: 0.06em; color: #CBD5E1; font-weight: 700; margin-bottom: 10px;">
                Development Tools
            </div>
            <div style="display: flex; flex-wrap: wrap; gap: 8px;">
                <span style="background: rgba(203, 213, 225, 0.15); border: 1px solid rgba(203, 213, 225, 0.40); color: #FFFFFF; font-size: 0.85rem; font-weight: 600; padding: 5px 12px; border-radius: 6px;">Antigravity IDE</span>
                <span style="background: rgba(203, 213, 225, 0.15); border: 1px solid rgba(203, 213, 225, 0.40); color: #FFFFFF; font-size: 0.85rem; font-weight: 600; padding: 5px 12px; border-radius: 6px;">Visual Studio Code</span>
                <span style="background: rgba(203, 213, 225, 0.15); border: 1px solid rgba(203, 213, 225, 0.40); color: #FFFFFF; font-size: 0.85rem; font-weight: 600; padding: 5px 12px; border-radius: 6px;">Git</span>
                <span style="background: rgba(203, 213, 225, 0.15); border: 1px solid rgba(203, 213, 225, 0.40); color: #FFFFFF; font-size: 0.85rem; font-weight: 600; padding: 5px 12px; border-radius: 6px;">GitHub</span>
            </div>
        </div>
    </div>
</div>
        """
    )
