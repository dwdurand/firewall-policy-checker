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
sys.path.insert(0,str(ROOT))
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
    def checkbox(self,*args,**kwargs): return kwargs.get('value',False)
    def button(self,*args,**kwargs): return False
    def expander(self,*args,**kwargs): return self
    def spinner(self,*args,**kwargs): return self
    def __getattr__(self,name):
        if name in {'set_page_config','title','write','success','subheader','metric','markdown','warning','divider','dataframe','code','info','caption'}:
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

    def test_shadow_on_sample(self):
        shadow=self.app['shadow_df']
        expected={'missing-none','missing-blank','missing-spaced-none','deny-no-profile','uppercase',
                  'profile-group','spaced-action','missing-whitespace','forwarding-none-local-log-on'}
        self.assertEqual(set(shadow['Rule Name']),expected)   # disabled, superset-app and any-source rules excluded
        self.assertTrue((shadow['Shadowed By']=='protected').all())
        self.assertEqual(set(shadow.loc[shadow['Action Conflict']=='yes','Rule Name']),{'deny-no-profile'})
        sheet=pd.read_excel(io.BytesIO(self.ui.export),sheet_name='Shadowed Rules')
        self.assertEqual(set(sheet['Rule Name']),expected)

    def test_shadow_cases(self):
        fn=self.app['find_shadowed_rules']
        def rule(name,src='10.0.0.1',dst='10.0.0.2',app='ssl',svc='application-default',
                 sz='trust',dz='untrust',action='allow',disabled='no',neg='no'):
            return {'Rule Name':name,'Source Zone':sz,'Destination Zone':dz,'Source Address':src,
                    'Destination Address':dst,'Application':app,'Service':svc,'Action':action,
                    'Disabled':disabled,'Negate Source':neg,'Negate Destination':'no'}
        cases=[
            ('any covers specific',[rule('a',src='any'),rule('b')],{'b':'a'}),
            ('superset list covers subset',[rule('a',app='ssl;web-browsing'),rule('b')],{'b':'a'}),
            ('subset does not cover superset',[rule('a'),rule('b',app='ssl;web-browsing')],{}),
            ('specific does not cover any',[rule('a'),rule('b',dst='any')],{}),
            ('later broad rule does not shadow earlier',[rule('a'),rule('b',src='any')],{}),
            ('different zone',[rule('a',dz='dmz'),rule('b')],{}),
            ('different service',[rule('a',svc='service-https'),rule('b')],{}),
            ('disabled shadower ignored',[rule('a',disabled='yes'),rule('b')],{}),
            ('disabled rule not reported',[rule('a'),rule('b',disabled='yes')],{}),
            ('negated rules skipped',[rule('a',src='any',neg='yes'),rule('b')],{}),
            ('blank field skipped',[rule('a',src='any'),rule('b',app='')],{}),
            ('case and separators',[rule('a',app='SSL, Web-Browsing'),rule('b',app='web-browsing')],{'b':'a'}),
            ('first shadower reported',[rule('a',src='any'),rule('c',src='any',dst='any'),rule('b')],{'b':'a'}),
        ]
        for name,rules,expected in cases:
            with self.subTest(case=name):
                result=fn(pd.DataFrame(rules))
                self.assertEqual(dict(zip(result['Rule Name'],result['Shadowed By'])),expected)
        result=fn(pd.DataFrame([rule('a',src='any',action='deny'),rule('b')]))
        self.assertEqual(result['Action Conflict'].tolist(),['yes'])
        with self.assertRaises(ValueError):
            fn(pd.DataFrame([rule('a',disabled='maybe')]))
        with self.assertRaises(ValueError):
            fn(pd.DataFrame([rule('a')]).drop(columns='Service'))

if __name__=='__main__': unittest.main()
