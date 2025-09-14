import streamlit as st
import requests
import json
import time
import pandas as pd
from datetime import datetime
import plotly.express as px
import plotly.graph_objects as go
from io import BytesIO
import os

# Page configuration
st.set_page_config(
    page_title="Email Analysis Sandbox",
    page_icon="📧",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #1f77b4;
    }
    .risk-high {
        color: #ff4444;
        font-weight: bold;
    }
    .risk-medium {
        color: #ff8800;
        font-weight: bold;
    }
    .risk-low {
        color: #00aa00;
        font-weight: bold;
    }
    .risk-critical {
        color: #aa0000;
        font-weight: bold;
        font-size: 1.2rem;
    }
    .stFileUploader > div > div > div > div {
        background-color: #f0f2f6;
    }
</style>
""", unsafe_allow_html=True)

# API Configuration
API_BASE_URL = os.getenv("API_BASE_URL", "http://api:8080")

def check_api_health():
    """Check if the API is running"""
    try:
        response = requests.get(f"{API_BASE_URL}/", timeout=5)
        return response.status_code == 200
    except:
        return False

def get_analyses():
    """Get all email analyses"""
    try:
        response = requests.get(f"{API_BASE_URL}/history")
        if response.status_code == 200:
            data = response.json()
            return data.get('history', [])
        return []
    except:
        return []

def get_analysis_summary():
    """Get analysis summary statistics"""
    try:
        response = requests.get(f"{API_BASE_URL}/history")
        if response.status_code == 200:
            data = response.json()
            history = data.get('history', [])
            # Calculate summary from history
            total = len(history)
            risk_counts = {}
            for analysis in history:
                risk = analysis.get('risk_level', 'UNKNOWN')
                risk_counts[risk] = risk_counts.get(risk, 0) + 1
            return {
                'total_analyses': total,
                'risk_distribution': risk_counts
            }
        return None
    except:
        return None

def upload_email(file):
    """Upload email file"""
    try:
        files = {'file': (file.name, file.getvalue(), 'message/rfc822')}
        response = requests.post(f"{API_BASE_URL}/upload", files=files)
        if response.status_code == 200:
            return response.json()
        return None
    except Exception as e:
        st.error(f"Upload failed: {str(e)}")
        return None

def get_analysis_details(analysis_id):
    """Get detailed analysis results"""
    try:
        response = requests.get(f"{API_BASE_URL}/analysis/{analysis_id}")
        if response.status_code == 200:
            return response.json()
        return None
    except:
        return None

# Note: Quarantine and delete functions removed as these endpoints don't exist in the API

def get_risk_color(risk_level):
    """Get color for risk level"""
    colors = {
        'low': '#00aa00',
        'medium': '#ff8800',
        'high': '#ff4444',
        'critical': '#aa0000'
    }
    return colors.get(risk_level, '#666666')

def get_risk_icon(risk_level):
    """Get icon for risk level"""
    icons = {
        'low': '✅',
        'medium': '⚠️',
        'high': '🚨',
        'critical': '💀'
    }
    return icons.get(risk_level, '❓')

# Main App
def main():
    # Header
    st.markdown('<h1 class="main-header">📧 Email Analysis Sandbox</h1>', unsafe_allow_html=True)
    
    # Check API health
    if not check_api_health():
        st.error("🚨 API is not running! Please start the services with: `./setup.sh`")
        st.stop()
    
    # Sidebar
    with st.sidebar:
        st.header("🔧 Controls")
        
        # Refresh button
        if st.button("🔄 Refresh Data"):
            st.rerun()
        
        # Upload section
        st.header("📤 Upload Email")
        uploaded_file = st.file_uploader(
            "Choose an .eml file",
            type=['eml'],
            help="Upload an email file for analysis"
        )
        
        if uploaded_file is not None:
            if st.button("🚀 Analyze Email"):
                with st.spinner("Uploading and analyzing email..."):
                    result = upload_email(uploaded_file)
                    if result:
                        st.success(f"✅ Email uploaded successfully! Analysis ID: {result.get('analysis_id')}")
                        st.rerun()
                    else:
                        st.error("❌ Upload failed!")
        
        # Quick stats
        st.header("📊 Quick Stats")
        summary = get_analysis_summary()
        if summary:
            st.metric("Total Emails", summary.get('total_emails', 0))
            st.metric("Completed", summary.get('completed', 0))
            st.metric("Quarantined", summary.get('quarantined', 0))
            st.metric("High Risk", summary.get('high_risk', 0))
    
    # Main content
    tab1, tab2, tab3, tab4 = st.tabs(["📊 Dashboard", "📧 Email List", "🔍 Analysis Details", "⚙️ Settings"])
    
    with tab1:
        st.header("📊 Analysis Dashboard")
        
        # Get summary data
        summary = get_analysis_summary()
        if summary:
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric(
                    "Total Emails",
                    summary.get('total_emails', 0),
                    delta=None
                )
            
            with col2:
                st.metric(
                    "Completed",
                    summary.get('completed', 0),
                    delta=None
                )
            
            with col3:
                st.metric(
                    "Quarantined",
                    summary.get('quarantined', 0),
                    delta=None
                )
            
            with col4:
                st.metric(
                    "High Risk",
                    summary.get('high_risk', 0),
                    delta=None
                )
            
            # Risk level distribution
            st.subheader("🎯 Risk Level Distribution")
            risk_data = {
                'Low': summary.get('total_emails', 0) - summary.get('high_risk', 0) - summary.get('critical_risk', 0),
                'High': summary.get('high_risk', 0),
                'Critical': summary.get('critical_risk', 0)
            }
            
            fig = px.pie(
                values=list(risk_data.values()),
                names=list(risk_data.keys()),
                color_discrete_map={
                    'Low': '#00aa00',
                    'High': '#ff4444',
                    'Critical': '#aa0000'
                }
            )
            st.plotly_chart(fig, use_container_width=True)
        
        # Recent analyses
        st.subheader("📋 Recent Analyses")
        analyses = get_analyses()
        if analyses:
            # Show last 5 analyses
            recent_analyses = analyses[:5]
            for analysis in recent_analyses:
                with st.container():
                    col1, col2, col3, col4 = st.columns([3, 1, 1, 1])
                    
                    with col1:
                        st.write(f"**{analysis.get('filename', 'Unknown')}**")
                        st.write(f"Subject: {analysis.get('subject', 'No subject')}")
                        st.write(f"From: {analysis.get('sender', 'Unknown sender')}")
                    
                    with col2:
                        risk_level = analysis.get('risk_level', 'unknown')
                        risk_icon = get_risk_icon(risk_level)
                        st.markdown(f"**{risk_icon} {risk_level.upper()}**")
                    
                    with col3:
                        risk_score = analysis.get('risk_score', 0)
                        st.metric("Risk Score", f"{risk_score:.1f}")
                    
                    with col4:
                        status = analysis.get('status', 'unknown')
                        if status == 'completed':
                            st.success("✅ Done")
                        elif status == 'processing':
                            st.info("⏳ Processing")
                        elif status == 'failed':
                            st.error("❌ Failed")
                        else:
                            st.warning("⏳ Pending")
                    
                    st.divider()
        else:
            st.info("No analyses found. Upload an email to get started!")
    
    with tab2:
        st.header("📧 Email Analysis List")
        
        analyses = get_analyses()
        if analyses:
            # Filters
            col1, col2, col3 = st.columns(3)
            
            with col1:
                status_filter = st.selectbox(
                    "Filter by Status",
                    ["All", "pending", "processing", "completed", "failed"]
                )
            
            with col2:
                risk_filter = st.selectbox(
                    "Filter by Risk Level",
                    ["All", "low", "medium", "high", "critical"]
                )
            
            with col3:
                search_term = st.text_input("Search by filename or subject")
            
            # Filter analyses
            filtered_analyses = analyses
            if status_filter != "All":
                filtered_analyses = [a for a in filtered_analyses if a.get('status') == status_filter]
            if risk_filter != "All":
                filtered_analyses = [a for a in filtered_analyses if a.get('risk_level') == risk_filter]
            if search_term:
                filtered_analyses = [
                    a for a in filtered_analyses 
                    if search_term.lower() in a.get('filename', '').lower() or 
                       search_term.lower() in a.get('subject', '').lower()
                ]
            
            # Display analyses
            for analysis in filtered_analyses:
                with st.expander(f"📧 {analysis.get('filename', 'Unknown')} - {get_risk_icon(analysis.get('risk_level', 'unknown'))} {analysis.get('risk_level', 'unknown').upper()}"):
                    col1, col2 = st.columns([2, 1])
                    
                    with col1:
                        st.write(f"**Subject:** {analysis.get('subject', 'No subject')}")
                        st.write(f"**From:** {analysis.get('sender', 'Unknown sender')}")
                        st.write(f"**Date:** {analysis.get('created_at', 'Unknown date')}")
                        st.write(f"**Status:** {analysis.get('status', 'Unknown')}")
                        st.write(f"**Risk Score:** {analysis.get('risk_score', 0):.1f}/100")
                        
                        if analysis.get('summary'):
                            st.write(f"**Summary:** {analysis.get('summary', '')[:200]}...")
                    
                    with col2:
                        # Action buttons
                        if st.button(f"🔍 View Details", key=f"view_{analysis['id']}"):
                            st.session_state.selected_analysis = analysis['id']
                            st.rerun()
                        
                        if st.button(f"🚫 Quarantine", key=f"quarantine_{analysis['id']}"):
                            reason = st.text_input("Quarantine reason:", key=f"reason_{analysis['id']}")
                            if reason:
                                if quarantine_analysis(analysis['id'], reason):
                                    st.success("Email quarantined!")
                                    st.rerun()
                                else:
                                    st.error("Failed to quarantine email")
                        
                        if st.button(f"🗑️ Delete", key=f"delete_{analysis['id']}"):
                            if delete_analysis(analysis['id']):
                                st.success("Email deleted!")
                                st.rerun()
                            else:
                                st.error("Failed to delete email")
        else:
            st.info("No analyses found. Upload an email to get started!")
    
    with tab3:
        st.header("🔍 Analysis Details")
        
        if 'selected_analysis' in st.session_state:
            analysis_id = st.session_state.selected_analysis
            analysis = get_analysis_details(analysis_id)
            
            if analysis:
                # Basic info
                col1, col2 = st.columns(2)
                
                with col1:
                    st.subheader("📧 Email Information")
                    st.write(f"**Filename:** {analysis.get('filename', 'Unknown')}")
                    st.write(f"**Subject:** {analysis.get('subject', 'No subject')}")
                    st.write(f"**From:** {analysis.get('sender', 'Unknown sender')}")
                    st.write(f"**Date:** {analysis.get('created_at', 'Unknown date')}")
                    st.write(f"**Status:** {analysis.get('status', 'Unknown')}")
                
                with col2:
                    st.subheader("🎯 Risk Assessment")
                    risk_level = analysis.get('risk_level', 'unknown')
                    risk_score = analysis.get('risk_score', 0)
                    
                    st.markdown(f"**Risk Level:** {get_risk_icon(risk_level)} {risk_level.upper()}")
                    st.markdown(f"**Risk Score:** {risk_score:.1f}/100")
                    
                    # Risk score gauge
                    fig = go.Figure(go.Indicator(
                        mode = "gauge+number",
                        value = risk_score,
                        domain = {'x': [0, 1], 'y': [0, 1]},
                        title = {'text': "Risk Score"},
                        gauge = {
                            'axis': {'range': [None, 100]},
                            'bar': {'color': get_risk_color(risk_level)},
                            'steps': [
                                {'range': [0, 30], 'color': "lightgray"},
                                {'range': [30, 60], 'color': "yellow"},
                                {'range': [60, 80], 'color': "orange"},
                                {'range': [80, 100], 'color': "red"}
                            ],
                            'threshold': {
                                'line': {'color': "red", 'width': 4},
                                'thickness': 0.75,
                                'value': 90
                            }
                        }
                    ))
                    st.plotly_chart(fig, use_container_width=True)
                
                # AI Analysis
                if analysis.get('summary'):
                    st.subheader("🤖 AI Analysis")
                    st.write(f"**Summary:** {analysis.get('summary', '')}")
                    st.write(f"**Risk Assessment:** {analysis.get('ai_risk_assessment', '')}")
                    st.write(f"**Recommendations:** {analysis.get('recommendations', '')}")
                
                # Threats detected
                if analysis.get('threats_detected'):
                    st.subheader("⚠️ Threats Detected")
                    for threat in analysis.get('threats_detected', []):
                        st.write(f"• {threat}")
                
                # Attachments
                if analysis.get('attachments'):
                    st.subheader("📎 Attachments")
                    for attachment in analysis.get('attachments', []):
                        st.write(f"• {attachment.get('filename', 'Unknown')} ({attachment.get('size', 0)} bytes)")
                        if attachment.get('quarantined'):
                            st.warning("🚫 This attachment has been quarantined")
                
                # URLs
                if analysis.get('urls'):
                    st.subheader("🔗 URLs Found")
                    for url in analysis.get('urls', []):
                        st.write(f"• {url.get('url', 'Unknown')}")
                        if url.get('risk_level'):
                            st.write(f"  Risk: {url.get('risk_level', 'unknown')}")
            else:
                st.error("Failed to load analysis details")
        else:
            st.info("Select an analysis from the Email List tab to view details")
    
    with tab4:
        st.header("⚙️ Settings")
        
        st.subheader("🔧 System Status")
        
        # API Health
        if check_api_health():
            st.success("✅ API is running")
        else:
            st.error("❌ API is not running")
        
        # Service status
        st.subheader("📊 Service Status")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("API", "🟢 Running", "Port 8080")
        
        with col2:
            st.metric("Worker", "🟢 Running", "Background")
        
        with col3:
            st.metric("Watcher", "🟢 Running", "File Monitor")
        
        # Configuration
        st.subheader("🔧 Configuration")
        st.write("**API Base URL:**", API_BASE_URL)
        st.write("**Upload Directory:**", "./data/inbox/")
        st.write("**Database:**", "./data/db/email_analysis.db")
        
        # Actions
        st.subheader("🛠️ Actions")
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("🔄 Refresh All Data"):
                st.rerun()
        
        with col2:
            if st.button("🧹 Clear Cache"):
                st.cache_data.clear()
                st.success("Cache cleared!")

if __name__ == "__main__":
    main()
