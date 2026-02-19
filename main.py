"""
RIFT 2026 HACKATHON - Money Mule Detection Engine
Graph-Based Financial Crime Detection Web Application

Author: [Your Team Name]
Track: Graph Theory / Financial Crime Detection
"""

import streamlit as st
import pandas as pd
import networkx as nx
import json
import time
import tempfile
import os
from datetime import datetime, timedelta
from collections import defaultdict
from pyvis.network import Network
import streamlit.components.v1 as components

# Page Configuration
st.set_page_config(
    page_title="RIFT Financial Forensics Engine",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- CUSTOM CSS ---
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1e3a8a;
        text-align: center;
        margin-bottom: 1rem;
    }
    .sub-header {
        font-size: 1.5rem;
        font-weight: bold;
        color: #1e40af;
    }
    .metric-card {
        background-color: #f0f9ff;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #3b82f6;
    }
    .warning-card {
        background-color: #fef3c7;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #f59e0b;
    }
    .danger-card {
        background-color: #fee2e2;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #ef4444;
    }
    .stButton>button {
        background-color: #3b82f6;
        color: white;
        border-radius: 0.5rem;
    }
</style>
""", unsafe_allow_html=True)

# --- DETECTION ALGORITHMS ---

class MoneyMuleDetector:
    """Core detection engine for money muling patterns."""
    
    def __init__(self, df):
        self.df = df
        self.graph = self._build_graph()
        self.scores = defaultdict(lambda: {'score': 0.0, 'patterns': set(), 'rings': set()})
        self.rings = []
        self.high_volume_accounts = self._identify_high_volume_merchants()
        
    def _build_graph(self):
        """Construct directed graph from transaction data."""
        G = nx.DiGraph()
        for _, row in self.df.iterrows():
            G.add_edge(
                row['sender_id'], 
                row['receiver_id'],
                amount=row['amount'],
                timestamp=row['timestamp']
            )
        return G
    
    def _identify_high_volume_merchants(self):
        """Identify legitimate high-volume accounts to reduce false positives."""
        # Accounts with >500 transactions are likely legitimate merchants
        return {node for node in self.graph.nodes() if self.graph.degree(node) > 500}
    
    def detect_cycles(self, min_len=3, max_len=5):
        """Detect circular fund routing patterns."""
        try:
            all_cycles = list(nx.simple_cycles(self.graph))
            ring_id = len(self.rings) + 1
            
            for cycle in all_cycles:
                if min_len <= len(cycle) <= max_len:
                    # Calculate risk score (shorter cycles = higher risk)
                    risk_score = 100.0 - (len(cycle) * 3)
                    ring_id_str = f"RING_{str(ring_id).zfill(3)}"
                    
                    for node in cycle:
                        if node not in self.high_volume_accounts:
                            self.scores[node]['score'] += 50
                            self.scores[node]['patterns'].add(f'cycle_length_{len(cycle)}')
                            self.scores[node]['rings'].add(ring_id_str)
                    
                    self.rings.append({
                        'ring_id': ring_id_str,
                        'member_accounts': cycle,
                        'pattern_type': 'cycle',
                        'risk_score': round(risk_score, 1)
                    })
                    ring_id += 1
        except Exception as e:
            st.error(f"Cycle detection error: {e}")
    
    def detect_smurfing(self, threshold=10, time_window_hours=72):
        """Detect smurfing patterns (fan-in/fan-out)."""
        # Fan-in: Many senders to one receiver
        fan_in = self.df.groupby('receiver_id')['sender_id'].nunique()
        suspicious_receivers = fan_in[fan_in >= threshold].index.tolist()
        
        # Fan-out: One sender to many receivers
        fan_out = self.df.groupby('sender_id')['receiver_id'].nunique()
        suspicious_senders = fan_out[fan_out >= threshold].index.tolist()
        
        ring_id = len(self.rings) + 1
        
        for node in suspicious_receivers:
            if node not in self.high_volume_accounts:
                self.scores[node]['score'] += 40
                self.scores[node]['patterns'].add('high_velocity_fan_in')
                
                if not self.scores[node]['rings']:
                    rid = f"RING_{str(ring_id).zfill(3)}"
                    self.scores[node]['rings'].add(rid)
                    self.rings.append({
                        'ring_id': rid,
                        'member_accounts': [node],
                        'pattern_type': 'smurfing_fan_in',
                        'risk_score': 85.0
                    })
                    ring_id += 1
        
        for node in suspicious_senders:
            if node not in self.high_volume_accounts:
                self.scores[node]['score'] += 40
                self.scores[node]['patterns'].add('high_velocity_fan_out')
                
                if not self.scores[node]['rings']:
                    rid = f"RING_{str(ring_id).zfill(3)}"
                    self.scores[node]['rings'].add(rid)
                    self.rings.append({
                        'ring_id': rid,
                        'member_accounts': [node],
                        'pattern_type': 'smurfing_fan_out',
                        'risk_score': 85.0
                    })
                    ring_id += 1
    
    def detect_shell_networks(self):
        """Detect layered shell accounts (intermediaries with 2-3 transactions)."""
        shell_candidates = []
        
        for node in self.graph.nodes():
            in_deg = self.graph.in_degree(node)
            out_deg = self.graph.out_degree(node)
            total_deg = in_deg + out_deg
            
            # Shell accounts: low transaction count, act as intermediaries
            if 2 <= total_deg <= 3 and in_deg > 0 and out_deg > 0:
                shell_candidates.append(node)
        
        ring_id = len(self.rings) + 1
        
        for node in shell_candidates:
            if node not in self.high_volume_accounts:
                self.scores[node]['score'] += 30
                self.scores[node]['patterns'].add('layered_shell')
                
                if not self.scores[node]['rings']:
                    rid = f"RING_{str(ring_id).zfill(3)}"
                    self.scores[node]['rings'].add(rid)
                    self.rings.append({
                        'ring_id': rid,
                        'member_accounts': [node],
                        'pattern_type': 'shell_layer',
                        'risk_score': 70.0
                    })
                    ring_id += 1
    
    def run_detection(self):
        """Execute all detection algorithms."""
        self.detect_cycles()
        self.detect_smurfing()
        self.detect_shell_networks()
        
        # Prepare final output
        suspicious_accounts = []
        
        for acc_id, data in self.scores.items():
            final_score = min(data['score'], 100.0)
            
            # Filter: Only flag if score > 35
            if final_score > 35:
                suspicious_accounts.append({
                    "account_id": acc_id,
                    "suspicion_score": round(final_score, 1),
                    "detected_patterns": sorted(list(data['patterns'])),
                    "ring_id": sorted(list(data['rings']))[0] if data['rings'] else "NONE"
                })
        
        # Sort by suspicion score descending
        suspicious_accounts.sort(key=lambda x: x['suspicion_score'], reverse=True)
        
        return suspicious_accounts, self.rings


def create_visualization(G, suspicious_nodes):
    """Generate interactive PyVis network visualization."""
    net = Network(
        height="600px",
        width="100%",
        bgcolor="#1a1a2e",
        font_color="white",
        directed=True,
        notebook=False
    )
    
    # Physics settings for better layout
    net.set_options("""
    {
        "nodes": {
            "borderWidth": 2,
            "borderWidthSelected": 4,
            "font": { "size": 14, "face": "arial" }
        },
        "edges": {
            "color": { "inherit": true },
            "smooth": { "type": "continuous" }
        },
        "physics": {
            "forceAtlas2Based": { "gravitationalConstant": -50, "springLength": 100 },
            "minVelocity": 0.75,
            "solver": "forceAtlas2Based"
        }
    }
    """)
    
    for node in G.nodes():
        is_suspicious = node in suspicious_nodes
        degree = G.degree(node)
        
        if is_suspicious:
            color = "#ff4757"
            size = 25 + (degree * 0.5)
            title = f"⚠️ SUSPICIOUS ACCOUNT\nID: {node}\nConnections: {degree}\nStatus: Flagged"
        elif degree > 50:
            color = "#ffa502"
            size = 20
            title = f"⚡ High Activity\nID: {node}\nConnections: {degree}"
        else:
            color = "#3742fa"
            size = 10 + (degree * 0.2)
            title = f"ID: {node}\nConnections: {degree}"
        
        net.add_node(
            node,
            label=node[:12] + "..." if len(node) > 12 else node,
            color=color,
            size=size,
            title=title,
            borderWidth=3 if is_suspicious else 1
        )
    
    # Add edges with transaction amounts
    for u, v, data in G.edges(data=True):
        amount = data.get('amount', 0)
        net.add_edge(u, v, value=min(amount/100, 10), title=f"${amount:,.2f}")
    
    return net


# --- UI COMPONENTS ---

def display_metrics(summary):
    """Display key metrics in a row."""
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Accounts", summary['total_accounts_analyzed'])
    with col2:
        st.metric("Suspicious Accounts", summary['suspicious_accounts_flagged'], 
                 delta_color="inverse")
    with col3:
        st.metric("Fraud Rings Detected", summary['fraud_rings_detected'],
                 delta_color="inverse")
    with col4:
        st.metric("Processing Time", f"{summary['processing_time_seconds']}s")


def display_rings_table(rings):
    """Display fraud rings in a formatted table."""
    if not rings:
        st.info("No fraud rings detected.")
        return
    
    ring_data = []
    for ring in rings:
        ring_data.append({
            "Ring ID": ring['ring_id'],
            "Pattern Type": ring['pattern_type'],
            "Member Count": len(ring['member_accounts']),
            "Risk Score": ring['risk_score'],
            "Member Accounts": ", ".join(ring['member_accounts'][:5]) + 
                              ("..." if len(ring['member_accounts']) > 5 else "")
        })
    
    df_rings = pd.DataFrame(ring_data)
    st.dataframe(df_rings, use_container_width=True, hide_index=True)


def display_suspicious_accounts(accounts):
    """Display suspicious accounts table."""
    if not accounts:
        st.info("No suspicious accounts detected based on current thresholds.")
        return
    
    df_acc = pd.DataFrame(accounts)
    
    # Format for display
    display_df = df_acc.copy()
    display_df['Patterns'] = display_df['detected_patterns'].apply(lambda x: ", ".join(x))
    display_df = display_df[['account_id', 'suspicion_score', 'Patterns', 'ring_id']]
    display_df.columns = ['Account ID', 'Suspicion Score', 'Detected Patterns', 'Ring ID']
    
    st.dataframe(
        display_df.style.background_gradient(subset=['Suspicion Score'], cmap='Reds'),
        use_container_width=True,
        hide_index=True
    )


# --- MAIN APPLICATION ---

def main():
    """Main Streamlit application entry point."""
    
    # Header
    st.markdown("""
    <div class="main-header">
        🛡️ RIFT 2026 Financial Forensics Engine
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("### Graph-Based Money Muling Detection System")
    st.markdown("---")
    
    # Sidebar
    with st.sidebar:
        st.header("📋 Instructions")
        st.markdown("""
        1. Upload a CSV file with transaction data
        2. The system will analyze for:
           - **Circular Fund Routing** (Cycles)
           - **Smurfing Patterns** (Fan-in/Fan-out)
           - **Layered Shell Networks**
        3. View results in tables and graph
        4. Download JSON report
        """)
        
        st.markdown("---")
        st.header("⚙️ Detection Settings")
        cycle_len = st.slider("Max Cycle Length", 3, 6, 5)
        smurf_thresh = st.slider("Smurfing Threshold", 5, 20, 10)
        
        st.markdown("---")
        st.markdown("**Expected CSV Format:**")
        st.code("""
transaction_id,sender_id,receiver_id,amount,timestamp
TXN001,ACC_001,ACC_002,500.00,2024-01-01 10:00:00
        """, language="csv")
    
    # File Upload
    uploaded_file = st.file_uploader(
        "📁 Upload Transaction CSV File",
        type=['csv'],
        help="Upload CSV with columns: transaction_id, sender_id, receiver_id, amount, timestamp"
    )
    
    if uploaded_file is not None:
        with st.spinner('🔄 Processing transactions and building graph...'):
            try:
                # Load data
                df = pd.read_csv(uploaded_file)
                
                # Validate columns
                required_cols = ['sender_id', 'receiver_id', 'amount', 'timestamp']
                if not all(col in df.columns for col in required_cols):
                    st.error(f"❌ CSV must contain columns: {', '.join(required_cols)}")
                    st.stop()
                
                # Parse timestamp
                df['timestamp'] = pd.to_datetime(df['timestamp'])
                df = df.sort_values('timestamp').reset_index(drop=True)
                
                start_time = time.time()
                
                # Run detection
                detector = MoneyMuleDetector(df)
                suspicious_accounts, fraud_rings = detector.run_detection()
                
                processing_time = time.time() - start_time
                
                # Build summary
                summary = {
                    "total_accounts_analyzed": detector.graph.number_of_nodes(),
                    "suspicious_accounts_flagged": len(suspicious_accounts),
                    "fraud_rings_detected": len(fraud_rings),
                    "processing_time_seconds": round(processing_time, 2)
                }
                
                # Build output JSON
                output_data = {
                    "suspicious_accounts": suspicious_accounts,
                    "fraud_rings": fraud_rings,
                    "summary": summary
                }
                
                # --- RESULTS DISPLAY ---
                st.success(f"✅ Analysis Complete in {processing_time:.2f} seconds")
                
                # Metrics
                display_metrics(summary)
                
                st.markdown("---")
                
                # Tabs for different views
                tab1, tab2, tab3 = st.tabs(["📊 Summary", "🕸️ Network Graph", "📥 Download"])
                
                with tab1:
                    st.subheader("🚨 Detected Fraud Rings")
                    display_rings_table(fraud_rings)
                    
                    st.markdown("###")
                    st.subheader("⚠️ Suspicious Accounts")
                    display_suspicious_accounts(suspicious_accounts)
                
                with tab2:
                    st.subheader("Interactive Network Visualization")
                    st.markdown("*Hover over nodes for details. Red nodes are suspicious.*")
                    
                    # Get suspicious node set
                    susp_set = {acc['account_id'] for acc in suspicious_accounts}
                    
                    # Create visualization
                    net = create_visualization(detector.graph, susp_set)
                    
                    # Save with tempfile.NamedTemporaryFile(delete=False, and display
                    suffix=".html") as tmp:
                        net.save_graph(tmp.name)
                        with open(tmp.name, 'r', encoding='utf-8') as f:
                            html_content = f.read()
                    
                    components.html(html_content, height=650)
                    
                    # Legend
