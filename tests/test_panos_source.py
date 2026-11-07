"""Offline tests for panos_source. Run: python -m unittest discover -s tests -v."""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import panos_source as ps  # noqa: E402

RULES = """
<rules>
  <entry name="web-out" uuid="u-1">
    <from><member>trust</member></from><to><member>untrust</member></to>
    <source><member>192.0.2.10</member><member>192.0.2.11</member></source>
    <destination><member>any</member></destination>
    <application><member>ssl</member><member>telnet</member></application>
    <service><member>application-default</member></service>
    <action>allow</action>
    <profile-setting><group><member>strict</member></group></profile-setting>
    <log-setting>central-logs</log-setting>
  </entry>
  <entry name="no-profile" uuid="u-2">
    <from><member>trust</member></from><to><member>dmz</member></to>
    <source><member>any</member></source><destination><member>198.51.100.5</member></destination>
    <application><member>ssl</member></application><service><member>application-default</member></service>
    <action>allow</action><log-start>no</log-start><log-end>no</log-end><disabled>no</disabled>
    <negate-source>yes</negate-source>
  </entry>
  <entry name="individual-profiles" uuid="u-3">
    <from><member>trust</member></from><to><member>untrust</member></to>
    <source><member>192.0.2.10</member></source><destination><member>198.51.100.20</member></destination>
    <application><member>ssl</member></application><service><member>application-default</member></service>
    <action>allow</action>
    <profile-setting><profiles><virus><member>av-strict</member></virus>
      <spyware><member>as-strict</member></spyware></profiles></profile-setting>
    <log-setting>central-logs</log-setting><disabled>yes</disabled>
  </entry>
</rules>
"""

CONFIG = f"""<config><devices><entry name="localhost.localdomain">
  <device-group><entry name="Branches"><pre-rulebase><security>{RULES}</security></pre-rulebase></entry></device-group>
</entry></devices></config>"""


class ParseTests(unittest.TestCase):
    def setUp(self):
        import xml.etree.ElementTree as ET
        self.df = ps.to_frame(ps.parse_rules(ET.fromstring(RULES), 'test'))

    def test_columns_match_spreadsheet_contract(self):
        sample = pd.read_excel(ROOT / 'sample-data/firewall-synthetic-validation.xlsx',
                               sheet_name='firewall', header=1)
        self.assertEqual(list(sample.columns), ps.COLUMNS)
        self.assertEqual(list(self.df.columns[:len(ps.COLUMNS)]), ps.COLUMNS)

    def test_members_joined_and_order_kept(self):
        row = self.df.iloc[0]
        self.assertEqual(row['Source Address'], '192.0.2.10;192.0.2.11')
        self.assertEqual(row['Application'], 'ssl;telnet')
        self.assertEqual(list(self.df['Position']), [1, 2, 3])

    def test_defaults_applied_when_absent(self):
        row = self.df.iloc[0]
        self.assertEqual((row['Disabled'], row['Log at Session Start'], row['Log at Session End']),
                         ('no', 'no', 'yes'))
        self.assertEqual(row['Negate Source'], 'no')

    def test_profiles(self):
        self.assertEqual(self.df.iloc[0]['Profile'], 'strict')
        self.assertEqual(self.df.iloc[1]['Profile'], '')
        self.assertEqual(self.df.iloc[2]['Profile'], 'virus=av-strict;spyware=as-strict')

    def test_existing_checks_run_on_ingested_rows(self):
        import types
        sys.modules.setdefault('streamlit', types.ModuleType('streamlit'))
        src = (ROOT / 'app.py').read_text(encoding='utf-8')
        checks_src = src.split('st.set_page_config')[0]
        ns = {}
        exec(compile(checks_src, 'app_checks', 'exec'), ns)  # check functions only
        self.assertEqual(list(ns['find_broad_address_rules'](self.df)['Rule Name']), ['web-out', 'no-profile'])
        self.assertEqual(list(ns['find_cleartext_applications'](self.df)['Rule Name']), ['web-out'])
        self.assertEqual(list(ns['find_missing_profiles'](self.df)['Rule Name']), ['no-profile'])
        off, no_fwd, unknown = ns['assess_logging'](self.df)
        self.assertEqual(list(off['Rule Name']), ['no-profile'])
        self.assertEqual(list(no_fwd['Rule Name']), ['no-profile'])
        self.assertTrue(unknown.empty)


class SourceTests(unittest.TestCase):
    def test_saved_config_and_workbook_roundtrip(self):
        df = ps.rules_from_config_xml(CONFIG, ps.panorama_rulebases('Branches'))
        self.assertEqual(len(df), 3)
        self.assertTrue((df['Rulebase'] == 'DG Branches pre-rulebase').all())
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'rules.xlsx'
            ps.write_workbook(df, str(out), 'Source: test')
            back = pd.read_excel(out, sheet_name='firewall', header=1)
            self.assertEqual(list(back.columns), ps.COLUMNS + ps.EXTRA_COLUMNS)
            self.assertEqual(len(back), 3)

    def test_client_refuses_non_read_actions(self):
        client = ps.PanosReadOnlyClient('fw.test', 'k')
        for action in ('set', 'edit', 'delete', 'commit', 'move'):
            with self.assertRaises(PermissionError):
                client.config('/config', action=action)

    def test_client_sends_key_in_header_and_parses(self):
        client = ps.PanosReadOnlyClient('fw.test', 'secret-key')
        resp = MagicMock(text=f'<response status="success"><result>{RULES}</result></response>')
        client.session.get = MagicMock(return_value=resp)
        df = ps.rules_from_api(client, ps.firewall_rulebases())
        self.assertEqual(len(df), 3)
        _, kwargs = client.session.get.call_args
        self.assertEqual(kwargs['params']['action'], 'show')
        self.assertNotIn('secret-key', str(kwargs['params']))
        self.assertEqual(client.session.headers['X-PAN-KEY'], 'secret-key')

    def test_api_error_raises(self):
        client = ps.PanosReadOnlyClient('fw.test', 'k')
        client.session.get = MagicMock(return_value=MagicMock(
            text='<response status="error"><msg>Invalid credentials</msg></response>'))
        with self.assertRaises(RuntimeError):
            client.config('/config/x')

    def test_empty_rulebase(self):
        client = ps.PanosReadOnlyClient('fw.test', 'k')
        client.session.get = MagicMock(return_value=MagicMock(
            text='<response status="success" total-count="0" count="0"><result/></response>'))
        self.assertTrue(ps.rules_from_api(client, ps.firewall_rulebases()).empty)


if __name__ == '__main__':
    unittest.main()
