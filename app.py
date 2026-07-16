import streamlit as st
import pandas as pd
import io

st.set_page_config(page_title="A1 Cyber Services - Firewall Audit Tool", layout="wide")

st.title("🛡️ Firewall Policy Sanity Checker")
st.write("Upload a Palo Alto Excel export to instantly view executive metrics, security gaps, and export remediation reports.")

uploaded_file = st.file_uploader("Upload Firewall Policy Export", type=["xlsx"])

if uploaded_file is not None:
    try:
        # Read the 'firewall' sheet and skip the first row for headers (Exact Sunday Ingestion)
        df = pd.read_excel(uploaded_file, sheet_name='firewall', header=1)
        st.success("File uploaded successfully!")
        
        # --- 1. EXECUTIVE DASHBOARD METRICS (Exact Sunday Logic) ---
        total_rules = len(df)
        
        # Calculate risks for metrics
        permissive_df = df[
            (df['Source Address'].astype(str).str.lower() == 'any') | 
            (df['Destination Address'].astype(str).str.lower() == 'any')
        ]
        
        insecure_apps = ['telnet', 'http', 'ftp']
        protocol_df = df[
            df['Application'].astype(str).str.lower().isin(insecure_apps) & 
            (df['Action'].astype(str).str.lower() == 'allow')
        ]
        
        profile_df = df[
            (df['Profile'].astype(str).str.lower() == 'none') & 
            (df['Action'].astype(str).str.lower() == 'allow')
        ]
        
        logging_df = df[
            (df['Log Setting'].astype(str).str.lower() == 'none')
        ]
        
        total_gaps = len(permissive_df) + len(protocol_df) + len(profile_df) + len(logging_df)

        # --- ONE STEP FORWARD: MULTI-TAB WORKSPACE FOR V1.1 ---
        tab1, tab2 = st.tabs(["📊 Executive Dashboard", "🔍 Detailed Audit Findings"])

        # --- TAB 1: EXECUTIVE DASHBOARD ---
        with tab1:
            st.subheader("📊 Executive Summary")
            m_col1, m_col2, m_col3, m_col4 = st.columns(4)
            m_col1.metric("Total Rules Analyzed", total_rules)
            m_col2.metric("Total Compliance Gaps", total_gaps, delta=f"{total_gaps} issues", delta_color="inverse")
            m_col3.metric("Wide-Open Address Rules", len(permissive_df))
            m_col4.metric("Unsecured Allowed Rules", len(profile_df))

        # --- TAB 2: DETAILED AUDIT FINDINGS ---
        with tab2:
            st.subheader("🔍 Technical Security Audit")
            col1, col2 = st.columns(2)
            
            # Left Column: Network & Protocol Exposures (Exact Sunday UI)
            with col1:
                st.markdown("### 🌐 Network & Protocol Risks")
                
                # Address Exposure
                if not permissive_df.empty:
                    st.warning(f"⚠️ Found {len(permissive_df)} rules with 'any' configurations:")
                    st.dataframe(permissive_df[['Rule Name', 'Source Address', 'Destination Address', 'Action']], use_container_width=True)
                else:
                    st.success("✅ No wide-open 'any' address rules found.")
                    
                # Protocol Violations
                if not protocol_df.empty:
                    st.error(f"🚨 Found {len(protocol_df)} ALLOWED rules using insecure cleartext protocols:")
                    st.dataframe(protocol_df[['Rule Name', 'Application', 'Service', 'Action']], use_container_width=True)
                else:
                    st.success("✅ No rules are allowing unencrypted management protocols (Telnet/HTTP/FTP).")
            
            # Right Column: Profile & Logging Hygiene (Exact Sunday UI)
            with col2:
                st.markdown("### 🧽 Security Profile & Logging Hygiene")
                
                # Missing Security Profiles
                if not profile_df.empty:
                    st.error(f"🚨 Found {len(profile_df)} ALLOWED rules completely missing Security Profiles:")
                    st.dataframe(profile_df[['Rule Name', 'Source Zone', 'Destination Zone', 'Profile', 'Action']], use_container_width=True)
                else:
                    st.success("✅ All allowed rules have an attached Security Profile.")
                    
                # Disabled/Missing Logging
                if not logging_df.empty:
                    st.warning(f"⚠️ Found {len(logging_df)} rules with logging explicitly set to 'none':")
                    st.dataframe(logging_df[['Rule Name', 'Source Zone', 'Destination Zone', 'Log Setting']], use_container_width=True)
                else:
                    st.success("✅ All rules have valid log settings configured.")

            st.divider()

            # --- 3. EXPORT & REMEDIATION REPORT GENERATION (Exact Sunday Logic) ---
            st.subheader("📋 Actionable Remediation Export")
            st.write("Generate a filtered Excel tracking sheet containing only the identified security gaps for engineering review.")
            
            # Build remediation dataframe
            remediation_frames = [permissive_df, protocol_df, profile_df, logging_df]
            remediation_master = pd.concat(remediation_frames).drop_duplicates(subset=['UUID', 'Rule Name'])
            
            if not remediation_master.empty:
                # Create an in-memory Excel file buffer using openpyxl via pandas
                buffer = io.BytesIO()
                with pd.ExcelWriter(buffer, engine='openpyxl') as writer:
                    remediation_master.to_excel(writer, sheet_name='Remediation Action Items', index=False)
                
                st.download_button(
                    label="📥 Download Remediation Excel Report",
                    data=buffer.getvalue(),
                    file_name="firewall_remediation_report.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                )
            else:
                st.success("🎉 Policy is entirely clean! No remediation report generation required.")
                
    except Exception as e:
        st.error(f"Error reading the data file: {e}")