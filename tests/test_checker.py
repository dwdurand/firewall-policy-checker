"""Offline regression tests. Run: python -m unittest discover -s tests -v."""
import io
import json
import runpy
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch
import pandas as pd

ROOT=Path(__file__).resolve().parents[1]
CASES=json.loads((ROOT/'tests/cases.json').read_text(encoding='utf-8'))

class RecordedUI(types.ModuleType):
    def __init__(self):
        super().__init__('streamlit'); self.errors=[]; self.export=None
    def __enter__(self): return self
    def __exit__(self,*args): return False
    def file_uploader(self,*args,**kwargs):
        return str(ROOT/'sample-data/firewall-synthetic-validation.xlsx')
    def tabs(self,labels): return [self for _ in labels]
    def columns(self,n): return [self for _ in range(n)]
    def error(self,message): self.errors.append(message)
    def download_button(self,**kwargs): self.export=kwargs['data']
    def __getattr__(self,name):
        if name in {'set_page_config','title','write','success','subheader','metric','markdown','warning','divider','dataframe'}:
            return lambda *args,**kwargs: None
        raise AttributeError(name)

class CheckerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ui=RecordedUI()
        with patch.dict(sys.modules,{'streamlit':cls.ui}):
            cls.app=runpy.run_path(str(ROOT/'app.py'),run_name='__main__')
        failures=[e for e in cls.ui.errors if e.startswith('Error reading')]
        if failures: raise AssertionError(failures)

    def test_profile_cases(self):
        actual=set(self.app['profile_df']['Rule Name'])
        for name,expected in CASES['profile'].items():
            with self.subTest(case=name): self.assertEqual(name in actual,expected)

    def test_application_cases(self):
        for name,apps,action,disabled,expected in CASES['application']:
            with self.subTest(case=name):
                frame=pd.DataFrame([{'Application':apps,'Action':action,'Disabled':disabled}])
                self.assertEqual(not self.app['find_cleartext_applications'](frame).empty,expected)

    def test_logging_cases(self):
        for name,start,end,forwarding,disabled,expected in CASES['logging']:
            with self.subTest(case=name):
                frame=pd.DataFrame([{'Log at Session Start':start,'Log at Session End':end,'Log Setting':forwarding,'Disabled':disabled}])
                self.assertEqual(tuple(not part.empty for part in self.app['assess_logging'](frame)),tuple(expected))

    def test_address_cases(self):
        for name,source,dest,action,disabled,expected in CASES['address']:
            with self.subTest(case=name):
                frame=pd.DataFrame([{'Source Address':source,'Destination Address':dest,'Action':action,'Disabled':disabled}])
                self.assertEqual(not self.app['find_broad_address_rules'](frame).empty,expected)

    def test_input_guards(self):
        sample=self.app['df'].iloc[[0]].copy()
        for function in ['find_missing_profiles','find_cleartext_applications','assess_logging','find_broad_address_rules']:
            for frame in [sample.drop(columns='Disabled'),sample.assign(Disabled=None),sample.assign(Disabled='unknown')]:
                with self.subTest(function=function),self.assertRaises(ValueError):
                    self.app[function](frame)
        with self.assertRaises(ValueError):
            self.app['assess_logging'](sample.drop(columns='Log at Session End'))

    def test_export_and_counts(self):
        self.assertEqual(len(self.app['df']),13)
        self.assertEqual(len(self.app['profile_df']),6)
        self.assertEqual(len(self.app['protocol_df']),1)
        self.assertTrue(self.app['permissive_df'].empty)
        self.assertTrue(self.app['logging_df'].empty)
        self.assertTrue(self.app['logging_unknown_df'].empty)
        self.assertEqual(len(self.app['forwarding_df']),1)
        exported=pd.read_excel(io.BytesIO(self.ui.export),sheet_name='Remediation Action Items')
        pd.testing.assert_frame_equal(exported,self.app['remediation_master'].reset_index(drop=True))
        expected={'application-list','missing-none','missing-blank','missing-spaced-none','uppercase','spaced-action','missing-whitespace','forwarding-none-local-log-on'}
        self.assertEqual(len(exported),8)
        self.assertEqual(set(exported['Rule Name']),expected)

if __name__=='__main__': unittest.main()
