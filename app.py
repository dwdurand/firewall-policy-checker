import streamlit as st
import pandas as pd
import io
import re
import os
import json

import ai_explainer


def find_missing_profiles(df):
    """Find enabled allow rules without an attached profile in this export.

    Requires an explicit Disabled column so unknown rule state cannot silently
    be treated as enabled. Named profiles/groups are not inspected for content.
    """
    required = {'Action', 'Profile', 'Disabled'}
    missing = sorted(required - set(df.columns))
    if missing:
        raise ValueError('Missing columns for profile check: ' + ', '.join(missing))

    action = df['Action'].astype('string').str.strip().str.casefold()
    profile = df['Profile'].astype('string').str.strip().str.casefold()
    disabled = df['Disabled'].astype('string').str.strip().str.casefold()
    known_states = {'yes', 'no', 'true', 'false', '1', '0'}
    invalid_state = disabled.isna() | ~disabled.isin(known_states)
    if invalid_state.any():
        raise ValueError(
            f'Unknown Disabled state in {int(invalid_state.sum())} row(s). '
            'Use yes/no, true/false, or 1/0; profile check was not completed.'
        )

    enabled = disabled.isin({'no', 'false', '0'})
    no_profile = profile.isna() | profile.isin({'', 'none'})
    return df[enabled & action.eq('allow').fillna(False) & no_profile]


def find_cleartext_applications(df):
    """Match explicit telnet/http/ftp tokens in enabled allow rules.

    Supports semicolon, comma, and whitespace-separated export values. This
    does not resolve application groups, dependencies, any, or service ports.
    """
    required = {'Application', 'Action', 'Disabled'}
    missing = sorted(required - set(df.columns))
    if missing:
        raise ValueError('Missing columns for application check: ' + ', '.join(missing))
    disabled = df['Disabled'].astype('string').str.strip().str.casefold()
    invalid = disabled.isna() | ~disabled.isin({'yes', 'no', 'true', 'false', '1', '0'})
    if invalid.any():
        raise ValueError('Unknown Disabled state; application check was not completed.')
    action = df['Action'].astype('string').str.strip().str.casefold()
    applications = df['Application'].astype('string').fillna('').str.strip().str.casefold()
    target_apps = {'telnet', 'http', 'ftp'}
    matches = applications.map(lambda value: bool(target_apps.intersection(re.split(r'[;,\s]+', value))))
    return df[disabled.isin({'no', 'false', '0'}) & action.eq('allow').fillna(False) & matches]


def assess_logging(df):
    """Assess explicit session flags separately from log-forwarding attachment.

    Export contract: Log Setting is the log-forwarding profile name. This
    checks attachment only, not profile destinations or successful delivery.
    Blank or unrecognized session flags mean unknown, never disabled/enabled.
    """
    required = {'Disabled', 'Log at Session Start', 'Log at Session End', 'Log Setting'}
    missing = sorted(required - set(df.columns))
    if missing:
        raise ValueError('Missing columns for logging check: ' + ', '.join(missing))
    true_values = {'yes', 'true', '1'}
    false_values = {'no', 'false', '0'}
    valid_values = true_values | false_values
    def normalized(column):
        return df[column].astype('string').str.strip().str.casefold()
    disabled = normalized('Disabled')
    if (disabled.isna() | ~disabled.isin(valid_values)).any():
        raise ValueError('Unknown Disabled state; logging check was not completed.')
    enabled = disabled.isin(false_values)
    start = normalized('Log at Session Start')
    end = normalized('Log at Session End')
    known = start.isin(valid_values) & end.isin(valid_values)
    session_off = enabled & start.isin(false_values) & end.isin(false_values)
    forwarding = normalized('Log Setting')
    no_forwarding = enabled & (forwarding.isna() | forwarding.isin({'', 'none'}))
    return df[session_off], df[no_forwarding], df[enabled & ~known]


def find_broad_address_rules(df):
    """Return enabled allow rules with an explicit any address for review.

    This is not a reachability determination. Zones, negation, rule order,
    application/service restrictions, and address-group contents need review.
    """
    required = {'Source Address', 'Destination Address', 'Action', 'Disabled'}
    missing = sorted(required - set(df.columns))
    if missing:
        raise ValueError('Missing columns for address check: ' + ', '.join(missing))
    def normalized(column):
        return df[column].astype('string').str.strip().str.casefold()
    disabled = normalized('Disabled')
    if (disabled.isna() | ~disabled.isin({'yes', 'no', 'true', 'false', '1', '0'})).any():
        raise ValueError('Unknown Disabled state; address check was not completed.')
    action = normalized('Action')
    broad = (normalized('Source Address').eq('any').fillna(False)
             | normalized('Destination Address').eq('any').fillna(False))
    return df[disabled.isin({'no', 'false', '0'})
              & action.eq('allow').fillna(False) & broad]


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
        permissive_df = find_broad_address_rules(df)

        protocol_df = find_cleartext_applications(df)

        profile_df = find_missing_profiles(df)

        logging_df, forwarding_df, logging_unknown_df = assess_logging(df)

        total_gaps = (len(permissive_df) + len(protocol_df) + len(profile_df)
                      + len(logging_df) + len(forwarding_df) + len(logging_unknown_df))

        # --- ONE STEP FORWARD: MULTI-TAB WORKSPACE FOR V1.1 ---
        tab1, tab2, tab3 = st.tabs(["📊 Executive Dashboard", "🔍 Detailed Audit Findings", "🤖 AI Explanations (optional)"])

        # --- TAB 1: EXECUTIVE DASHBOARD ---
        with tab1:
            st.subheader("📊 Executive Summary")
            m_col1, m_col2, m_col3, m_col4 = st.columns(4)
            m_col1.metric("Total Rules Analyzed", total_rules)
            m_col2.metric("Findings Requiring Review", total_gaps, delta=f"{total_gaps} findings", delta_color="inverse")
            m_col3.metric("Enabled Allow Rules with Any Address", len(permissive_df))
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
                    st.warning(f"Found {len(permissive_df)} enabled ALLOW rules with an explicit 'any' source or destination address. Review required.")
                    st.dataframe(permissive_df[['Rule Name', 'Source Address', 'Destination Address', 'Action']], use_container_width=True)
                else:
                    st.write("No enabled ALLOW rules have an explicit 'any' source or destination address.")
                st.write("Address check is a review filter, not proof of exposure. Blank values and address groups are not resolved. Zones, negation, rule order, applications, and services are not assessed.")

                # Protocol Violations
                if not protocol_df.empty:
                    st.warning(f"Found {len(protocol_df)} enabled ALLOW rules explicitly listing telnet, http, or ftp. Review required.")
                    st.dataframe(protocol_df[['Rule Name', 'Application', 'Service', 'Action']], use_container_width=True)
                else:
                    st.success("No enabled ALLOW rules explicitly list telnet, http, or ftp.")
                st.write("Application check covers explicit names only; groups, dependencies, 'any', and service ports are not assessed.")

            # Right Column: Profile & Logging Hygiene (Exact Sunday UI)
            with col2:
                st.markdown("### 🧽 Security Profile & Logging Hygiene")

                # Missing Security Profiles
                if not profile_df.empty:
                    st.error(f"🚨 Found {len(profile_df)} enabled ALLOW rules missing Security Profiles:")
                    st.dataframe(profile_df[['Rule Name', 'Source Zone', 'Destination Zone', 'Profile', 'Action']], use_container_width=True)
                else:
                    st.success("✅ No enabled ALLOW rules have a blank or 'none' Profile value. Profile contents were not assessed.")

                # Session logging and forwarding are independent settings.
                logging_columns = ['Rule Name', 'Source Zone', 'Destination Zone',
                                   'Log at Session Start', 'Log at Session End', 'Log Setting']
                if not logging_df.empty:
                    st.warning(f"Found {len(logging_df)} enabled rules with both session logging flags disabled.")
                    st.dataframe(logging_df[logging_columns], use_container_width=True)
                else:
                    st.write("No enabled rules have both session logging flags explicitly disabled.")
                if not logging_unknown_df.empty:
                    st.warning(f"Session logging could not be fully assessed for {len(logging_unknown_df)} enabled rules: blank or unrecognized flags.")
                    st.dataframe(logging_unknown_df[logging_columns], use_container_width=True)
                if not forwarding_df.empty:
                    st.warning(f"Found {len(forwarding_df)} enabled rules without a log-forwarding profile in Log Setting. This does not mean session logging is disabled.")
                    st.dataframe(forwarding_df[logging_columns], use_container_width=True)
                else:
                    st.write("No enabled rules have a blank or 'none' log-forwarding profile in Log Setting.")
                st.write("Log Setting is interpreted as the forwarding profile. Profile contents, delivery, and effective inherited settings are not verified. Finding counts can overlap on the same rule.")

            st.divider()

            # --- 3. EXPORT & REMEDIATION REPORT GENERATION (Exact Sunday Logic) ---
            st.subheader("📋 Actionable Remediation Export")
            st.write("Generate a filtered Excel tracking sheet containing only the identified security gaps for engineering review.")

            # Build remediation dataframe
            remediation_frames = [permissive_df, protocol_df, profile_df, logging_df,
                                  forwarding_df, logging_unknown_df]
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
                st.success("No findings from the implemented checks. This is not a complete policy assessment.")


        # --- TAB 3: OPTIONAL CLAUDE EXPLANATIONS ---
        # The checks above decide what a finding is; Claude only explains them.
        with tab3:
            st.subheader("🤖 AI Explanations (optional)")
            st.write("Claude explains each finding for a manager and an engineer. "
                     "Only the fields shown below are sent; the full export stays on this machine.")
            findings_by_type = {
                "broad_address": permissive_df,
                "cleartext_application": protocol_df,
                "missing_profile": profile_df,
                "session_logging_disabled": logging_df,
                "session_logging_unknown": logging_unknown_df,
                "missing_log_forwarding": forwarding_df,
            }
            redact = st.checkbox("Replace rule names and addresses with placeholders before sending", value=True)
            payload, placeholders = ai_explainer.build_payload(findings_by_type, redact=redact)
            if not payload:
                st.write("No findings to explain.")
            else:
                total_found = sum(len(f) for f in findings_by_type.values())
                if total_found > len(payload):
                    st.warning(f"Only the first {len(payload)} of {total_found} findings will be sent (cost limit).")
                with st.expander(f"Exactly what will be sent ({len(payload)} findings)"):
                    st.code(json.dumps(payload, indent=2), language="json")
                if not os.environ.get("ANTHROPIC_API_KEY"):
                    st.info("Set the ANTHROPIC_API_KEY environment variable and restart Streamlit to enable this tab.")
                elif st.button("Generate explanations with Claude"):
                    try:
                        with st.spinner("Asking Claude to explain the findings..."):
                            results = ai_explainer.explain_findings(payload, placeholders if redact else None)
                        by_id = {item["id"]: item for item in payload}
                        rows = []
                        for result in results:
                            source = by_id[result["id"]]
                            rule_name = source["rule"].get("Rule Name", "")
                            if redact:
                                rule_name = placeholders.get(rule_name, rule_name)
                            rows.append({
                                "Finding": result["id"],
                                "Type": source["finding_type"],
                                "Rule Name": rule_name,
                                "Manager Summary": result["manager_summary"],
                                "Engineer Note": result["engineer_note"],
                                "Verify Before Change": result["verify_before_change"],
                            })
                        explained = pd.DataFrame(rows)
                        st.dataframe(explained, use_container_width=True, hide_index=True)
                        st.download_button(
                            label="📥 Download AI Explanations (CSV)",
                            data=explained.to_csv(index=False).encode("utf-8"),
                            file_name="firewall_ai_explanations.csv",
                            mime="text/csv",
                        )
                        st.caption("AI-generated explanations. Verify against the rule and your environment before acting.")
                    except Exception as exc:
                        st.error(f"AI explanation failed: {exc}")

    except Exception as e:
        st.error(f"Error reading the data file: {e}")
