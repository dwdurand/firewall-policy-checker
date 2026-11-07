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


def _rule(name):
    return (f'<entry name="{name}" uuid="u-{name}"><from><member>any</member></from>'
            '<to><member>any</member></to><source><member>10.0.0.1</member></source>'
            '<destination><member>10.0.0.2</member></destination>'
            '<application><member>ssl</member></application>'
            '<service><member>application-default</member></service><action>allow</action></entry>')


def _rules(*names):
    return '<security><rules>' + ''.join(_rule(n) for n in names) + '</rules></security>'


# shared > Region > Branches, plus an unrelated top-level DG that must not leak in.
HIER_CONFIG = f"""<config>
  <shared><pre-rulebase>{_rules('s-pre')}</pre-rulebase><post-rulebase>{_rules('s-post')}</post-rulebase></shared>
  <devices><entry name="localhost.localdomain"><device-group>
    <entry name="Region"><pre-rulebase>{_rules('r-pre')}</pre-rulebase><post-rulebase>{_rules('r-post')}</post-rulebase></entry>
    <entry name="Branches"><pre-rulebase>{_rules('b-pre1', 'b-pre2')}</pre-rulebase><post-rulebase>{_rules('b-post')}</post-rulebase></entry>
    <entry name="Other"><pre-rulebase>{_rules('o-pre')}</pre-rulebase></entry>
  </device-group></entry></devices>
  <readonly><devices><entry name="localhost.localdomain"><device-group>
    <entry name="Region"/>
    <entry name="Branches"><parent-dg>Region</parent-dg></entry>
    <entry name="Other"/>
  </device-group></entry></devices></readonly>
</config>"""


class HierarchyTests(unittest.TestCase):
    def test_ancestors_from_saved_config(self):
        config = ps.load_config(HIER_CONFIG)
        lookup = ps.config_parent_lookup(config)
        self.assertEqual(ps.dg_ancestors('Branches', lookup), ['Region'])
        self.assertEqual(ps.dg_ancestors('Region', lookup), [])

    def test_inherited_rules_in_evaluation_order(self):
        config = ps.load_config(HIER_CONFIG)
        anc = ps.dg_ancestors('Branches', ps.config_parent_lookup(config))
        df = ps.rules_from_config_xml(config, ps.panorama_rulebases('Branches', True, anc))
        self.assertEqual(list(df['Rule Name']),
                         ['s-pre', 'r-pre', 'b-pre1', 'b-pre2', 'b-post', 'r-post', 's-post'])
        self.assertNotIn('o-pre', set(df['Rule Name']))
        self.assertEqual(df.loc[df['Rule Name'] == 'r-pre', 'Rulebase'].item(),
                         'DG Region pre-rulebase (inherited)')
        self.assertEqual(df.loc[df['Rule Name'] == 'b-pre1', 'Rulebase'].item(),
                         'DG Branches pre-rulebase')

    def test_multi_level_and_loop(self):
        parents = {'Leaf': 'Mid', 'Mid': 'Top', 'Top': None}
        self.assertEqual(ps.dg_ancestors('Leaf', parents.get), ['Top', 'Mid'])
        self.assertEqual(ps.dg_ancestors('Top', {'Top': 'shared'}.get), [])
        with self.assertRaises(ValueError):
            ps.dg_ancestors('A', {'A': 'B', 'B': 'A'}.get)

    def test_cli_saved_config_with_and_without_inheritance(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / 'running-config.xml'
            cfg.write_text(HIER_CONFIG, encoding='utf-8')
            out = Path(tmp) / 'rules.xlsx'
            ps.main(['--xml-file', str(cfg), '--device-group', 'Branches', '--out', str(out)])
            self.assertEqual(len(pd.read_excel(out, sheet_name='firewall', header=1)), 7)
            ps.main(['--xml-file', str(cfg), '--device-group', 'Branches', '--no-inherit', '--out', str(out)])
            self.assertEqual(len(pd.read_excel(out, sheet_name='firewall', header=1)), 5)

    def test_api_parent_lookup_reads_readonly_xpath(self):
        client = ps.PanosReadOnlyClient('pano.test', 'k')
        replies = {'Branches': '<parent-dg>Region</parent-dg>', 'Region': ''}

        def fake_get(url, params, timeout):
            name = params['xpath'].split("entry[@name='")[-1].split("'")[0]
            self.assertIn('/config/readonly/', params['xpath'])
            self.assertEqual(params['action'], 'show')
            return MagicMock(text=f'<response status="success"><result>{replies[name]}</result></response>')

        client.session.get = fake_get
        self.assertEqual(ps.dg_ancestors('Branches', ps.api_parent_lookup(client)), ['Region'])


HIT_XML = """<response status="success"><result><rule-hit-count><vsys><entry name="vsys1">
<rule-base><entry name="security"><rules>
  <entry name="web-out"><latest>yes</latest><hit-count>42</hit-count>
    <last-hit-timestamp>1793990000</last-hit-timestamp><rule-creation-timestamp>1780000000</rule-creation-timestamp></entry>
  <entry name="no-profile"><latest>yes</latest><hit-count>0</hit-count>
    <last-hit-timestamp>0</last-hit-timestamp><rule-creation-timestamp>1780000000</rule-creation-timestamp></entry>
</rules></entry></rule-base></entry></vsys></rule-hit-count></result></response>"""

FW_CONFIG = f"""<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">
<rulebase><security>{RULES}</security></rulebase></entry></vsys></entry></devices></config>"""


class HitCountTests(unittest.TestCase):
    def test_parse_and_apply(self):
        import xml.etree.ElementTree as ET
        counts = ps.parse_hit_counts(ET.fromstring(HIT_XML))
        self.assertEqual(counts['web-out']['Hit Count'], 42)
        self.assertEqual(counts['no-profile']['Last Hit'], '')            # 0 means never
        self.assertTrue(counts['web-out']['Last Hit'].endswith('UTC'))
        df = ps.apply_hit_counts(ps.rules_from_config_xml(FW_CONFIG, ps.firewall_rulebases()), counts)
        by_name = dict(zip(df['Rule Name'], df['Hit Count']))
        self.assertEqual(by_name['web-out'], 42)
        self.assertEqual(by_name['no-profile'], 0)
        self.assertTrue(pd.isna(by_name['individual-profiles']))       # missing -> unknown, not zero

    def test_op_guard_and_command(self):
        client = ps.PanosReadOnlyClient('fw.test', 'k')
        for cmd in ('<request><restart><system/></restart></request>', '<clear><rule-hit-count/></clear>',
                    '<show><system><info/></system></show>'):
            with self.assertRaises(PermissionError):
                client.op(cmd)
        client.session.get = MagicMock(return_value=MagicMock(text=HIT_XML))
        counts = ps.parse_hit_counts(client.op(ps.hit_count_cmd('vsys1')))
        self.assertEqual(len(counts), 2)
        _, kwargs = client.session.get.call_args
        self.assertEqual(kwargs['params']['type'], 'op')
        self.assertIn("<entry name='vsys1'>", kwargs['params']['cmd'])

    def test_cli_with_saved_hit_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg, hits, out = Path(tmp) / 'cfg.xml', Path(tmp) / 'hits.xml', Path(tmp) / 'rules.xlsx'
            cfg.write_text(FW_CONFIG, encoding='utf-8')
            hits.write_text(HIT_XML, encoding='utf-8')
            ps.main(['--xml-file', str(cfg), '--hit-count-xml', str(hits), '--out', str(out)])
            back = pd.read_excel(out, sheet_name='firewall', header=1)
            self.assertEqual(list(back.columns[-3:]), ps.HIT_COLUMNS)
            with self.assertRaises(SystemExit):
                ps.main(['--xml-file', str(cfg), '--device-group', 'X', '--hit-count-xml', str(hits), '--out', str(out)])
            with self.assertRaises(SystemExit):
                ps.main(['--xml-file', str(cfg), '--hit-counts', '--out', str(out)])


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
