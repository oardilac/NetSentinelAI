# PySentry Dashboard - Real-Time Threat Detection Visualization
# Written by: @dukebismaya
import streamlit as st
import pandas as pd
import plotly.express as px
import json
import os

st.set_page_config(page_title="PySentry Dashboard", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap');

html, body, [class*="css"] {
    font-family: 'Share Tech Mono', monospace;
    background-color: #050510;
    color: #00ff41;
}
.stApp {
    background-color: #050510;
}

[data-testid="stMetricValue"] {
    color: #00ff41 !important;
    text-shadow: 0 0 5px #00ff41;
}

[data-testid="stMetricLabel"] {
    color: #008f11 !important;
}

h1, h2, h3, h4 {
    color: #00ff41 !important;
    text-shadow: 0 0 10px #00ff41, 0 0 20px #00ff41;
}

.stButton>button {
    background-color: #000 !important;
    border: 1px solid #00ff41 !important;
    color: #00ff41 !important;
    box-shadow: 0 0 10px #00ff41;
    transition: all 0.3s ease;
}
.stButton>button:hover {
    background-color: #00ff41 !important;
    color: #000 !important;
    box-shadow: 0 0 20px #00ff41;
}

.stAlert {
    background-color: #0a0a0a !important;
    border-left: 5px solid #00ff41;
    color: #00ff41;
}

.status-box {
    padding: 15px;
    border-radius: 5px;
    margin-bottom: 20px;
    text-align: center;
    font-size: 22px;
    font-weight: bold;
    text-transform: uppercase;
    letter-spacing: 2px;
}
.running {
    border: 2px solid #00ff41;
    color: #00ff41;
    text-shadow: 0 0 10px #00ff41;
    box-shadow: 0 0 15px #00ff41 inset, 0 0 15px #00ff41;
    background-color: rgba(0, 255, 65, 0.1);
}
.stopped {
    border: 2px solid #ff003c;
    color: #ff003c;
    text-shadow: 0 0 10px #ff003c;
    box-shadow: 0 0 15px #ff003c inset, 0 0 15px #ff003c;
    background-color: rgba(255, 0, 60, 0.1);
}

div.stDataFrame {
    border: 1px solid #00ff41;
    border-radius: 5px;
    background-color: #0a0a0a;
}
</style>
""", unsafe_allow_html=True)

st.title("🛡️ PYSENTRY_BY BISMAYA // REAL-TIME_MONITOR")
st.markdown("`[LIVE_THREAT_DETECTION_PROTOCOL :: INITIATED]`")

# Check Engine Status
if os.path.exists(".engine_status"):
    st.markdown('<div class="status-box running">[ SYSTEM ONLINE :: ENGINE HAS STARTED ]</div>', unsafe_allow_html=True)
else:
    st.markdown('<div class="status-box stopped">[ SYSTEM OFFLINE :: START THE ENGINE (main.py) ]</div>', unsafe_allow_html=True)

def load_data():
    try:
        data = []
        with open("logs/ids_alerts.log", "r") as f:
            for line in f:
                if line.strip(): # Skip empty lines
                    data.append(json.loads(line.strip()))
        return pd.DataFrame(data)
    except FileNotFoundError:
        return pd.DataFrame()
    
df = load_data()

if df.empty:
    st.info("🟢 System Secure. Listening for network anomalies... (Waiting for logs in logs/ids_alerts.log)")
else:
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Threats Detected", len(df))
    col2.metric("Signature Matches (Known)", len(df[df['threat_type'] == 'Signature']))
    col3.metric("Anomalies (AI Detected)", len(df[df['threat_type'] == 'Anomaly']))

    st.divider()

    chart_col1, chart_col2 = st.columns(2)
    with chart_col1:
        st.subheader("Threat Types")
        fig1 = px.pie(df, names='threat_type', hole=0.4, color_discrete_sequence=['#ff4b4b', '#ffa421'])
        st.plotly_chart(fig1, width='stretch')

    with chart_col2:
        st.subheader("Top Attacking IPs")
        top_ips = df['source_ip'].value_counts().head(5).reset_index()
        top_ips.columns = ['IP Address', 'Count']
        fig2 = px.bar(top_ips, x='IP Address', y='Count', color='Count', color_continuous_scale='Reds')
        st.plotly_chart(fig2, width='stretch')

    st.subheader("Recent Alert Logs")
    st.dataframe(df.tail(15).iloc[::-1], width='stretch')

    st.divider()

    col_btn1, col_btn2 = st.columns([1, 2])
    with col_btn1:
        if st.button("📸 Generate PNG Report"):
            from datetime import datetime
            import io
            import subprocess
            import tempfile
            from PIL import Image, ImageDraw, ImageFont

            # Generate the image
            width, height = 800, 500
            img = Image.new('RGB', (width, height), color=(5, 5, 16))
            d = ImageDraw.Draw(img)
            
            try:
                # Try loading the Windows Consolas font
                font_title = ImageFont.truetype("consola.ttf", 36)
                font_body = ImageFont.truetype("consola.ttf", 20)
            except:
                font_title = font_body = ImageFont.load_default()
                
            d.text((40, 40), "PYSENTRY_BISMAYA // THREAT REPORT", fill=(0, 255, 65), font=font_title)
            d.text((40, 90), f"LOG_TIMESTAMP: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", fill=(0, 255, 65), font=font_body)
            d.line([(40, 130), (760, 130)], fill=(0, 255, 65), width=2)
            
            total = len(df)
            sig_count = len(df[df['threat_type'] == 'Signature'])
            ano_count = len(df[df['threat_type'] == 'Anomaly'])
            top_ip = df['source_ip'].value_counts().index[0] if not df['source_ip'].empty else "NONE"
            
            y = 160
            d.text((40, y), f"> TOTAL THREATS DETECTED  : {total}", fill=(0, 255, 65), font=font_body)
            d.text((40, y+40), f"> SIGNATURE MATCHES       : {sig_count}", fill=(0, 255, 65), font=font_body)
            d.text((40, y+80), f"> AI ANOMALIES            : {ano_count}", fill=(0, 255, 65), font=font_body)
            d.text((40, y+120), f"> TOP ATTACKING IP        : {top_ip}", fill=(255, 0, 60), font=font_body)
            
            d.text((40, height - 60), "[ STATUS: SECURE ] // END OF REPORT", fill=(0, 255, 65), font=font_body)

            # Save to buffer for Streamlit download
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            st.session_state['report_bytes'] = buf.getvalue()
            
            # Copy to Windows clipboard via PowerShell
            try:
                tmp_bmp = tempfile.NamedTemporaryFile(suffix=".bmp", delete=False).name
                img.save(tmp_bmp, format="BMP")
                cmd = f"Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.Clipboard]::SetImage([System.Drawing.Image]::FromFile('{tmp_bmp}'))"
                subprocess.run(["powershell", "-WindowStyle", "Hidden", "-Command", cmd], shell=True)
                st.session_state['report_copied'] = True
            except:
                st.session_state['report_copied'] = False

    with col_btn2:
        if 'report_bytes' in st.session_state:
            st.download_button(label="💾 Download Extracted PNG", data=st.session_state['report_bytes'], file_name="PySentry_Report.png", mime="image/png")
            if st.session_state.get('report_copied'):
                st.success("✅ Report generated, downloaded to session, and copied to clipboard!")

if st.button("🔄 Refresh Data"):
    st.rerun()