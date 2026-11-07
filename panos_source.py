"""Read-only PAN-OS / Panorama security-rule ingest.

Produces the same row layout as the spreadsheet export the checker already
reads (sheet "firewall", header on row 2), so app.py and every check run
unchanged on live or saved-config data.

Sources:
  * Live XML API  - only type=config with action=get (candidate) or
                    action=show (running) is ever sent. Nothing else is allowed.
  * Saved XML     - a running-config/candidate-config file exported from the
                    device ("Export named configuration snapshot").

Credentials: an API key from the PANOS_API_KEY environment variable (or the
--api-key-env option naming another variable). The key travels in the
X-PAN-KEY header, never in the URL. This module never asks for or handles a
password; generate a key for a read-only admin role on the device.

Usage:
  python panos_source.py --host fw.lab.local --vsys vsys1 --out rules.xlsx
  python panos_source.py --host pano.lab.local --device-group Branches --out rules.xlsx
  python panos_source.py --xml-file running-config.xml --device-group Branches --out rules.xlsx
"""
from __future__ import annotations

import argparse
import os
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Iterable

import pandas as pd

# Column order matches sample-data/firewall-synthetic-validation.xlsx.
COLUMNS = [
    'UUID', 'Rule Name', 'Source Address', 'Destination Address', 'Application',
    'Service', 'Action', 'Profile', 'Log Setting', 'Source Zone',
    'Destination Zone', 'Disabled', 'Log at Session Start', 'Log at Session End',
]
# Extra context columns. The checks ignore them; reviewers need them.
EXTRA_COLUMNS = ['Rulebase', 'Position', 'Negate Source', 'Negate Destination']

DEVICE = "/config/devices/entry[@name='localhost.localdomain']"
READ_ONLY_ACTIONS = {'get', 'show'}

# PAN-OS defaults applied when the element is absent from the rule XML.
DEFAULTS = {'disabled': 'no', 'log-start': 'no', 'log-end': 'yes',
            'negate-source': 'no', 'negate-destination': 'no'}


@dataclass(frozen=True)
class Rulebase:
    label: str   # e.g. "DG Branches pre-rulebase"
    xpath: str   # xpath to .../security/rules


def firewall_rulebases(vsys: str = 'vsys1') -> list[Rulebase]:
    return [Rulebase(f'{vsys} rulebase',
                     f"{DEVICE}/vsys/entry[@name='{_q(vsys)}']/rulebase/security/rules")]


def panorama_rulebases(device_group: str, include_shared: bool = True,
                       ancestors: list[str] | None = None) -> list[Rulebase]:
    """Rulebases in PAN-OS evaluation order for one device group.

    ancestors: parent chain from the top-most DG down to the immediate
    parent (see dg_ancestors). Pre-rules evaluate shared -> top ancestor ->
    ... -> device group; post-rules evaluate in the reverse direction.
    """
    chain = list(ancestors or []) + [device_group]

    def dg_base(name: str, kind: str) -> Rulebase:
        own = ' (inherited)' if name != device_group else ''
        return Rulebase(f'DG {name} {kind}{own}',
                        f"{DEVICE}/device-group/entry[@name='{_q(name)}']/{kind}/security/rules")

    bases = []
    if include_shared:
        bases.append(Rulebase('shared pre-rulebase', '/config/shared/pre-rulebase/security/rules'))
    bases.extend(dg_base(name, 'pre-rulebase') for name in chain)
    bases.extend(dg_base(name, 'post-rulebase') for name in reversed(chain))
    if include_shared:
        bases.append(Rulebase('shared post-rulebase', '/config/shared/post-rulebase/security/rules'))
    return bases


def parent_dg_xpath(device_group: str) -> str:
    """Panorama keeps the hierarchy in the readonly section of the config."""
    return (f"/config/readonly/devices/entry[@name='localhost.localdomain']"
            f"/device-group/entry[@name='{_q(device_group)}']/parent-dg")


def dg_ancestors(device_group: str, get_parent) -> list[str]:
    """Walk parent-dg links. Returns [top-most, ..., immediate parent].

    get_parent(name) -> parent name or None. A DG directly under Shared has
    no parent-dg. Raises on a loop, which would indicate a corrupt config.
    """
    chain, seen, current = [], {device_group}, device_group
    while True:
        parent = get_parent(current)
        if not parent or parent.casefold() == 'shared':
            break
        if parent in seen:
            raise ValueError(f'Device-group hierarchy loop at {parent!r}.')
        seen.add(parent)
        chain.append(parent)
        current = parent
    return list(reversed(chain))


def _q(name: str) -> str:
    if "'" in name:
        raise ValueError(f'Unsupported quote character in name: {name!r}')
    return name


# ---------------------------------------------------------------- parsing

def _members(entry: ET.Element, tag: str) -> str:
    node = entry.find(tag)
    if node is None:
        return ''
    values = [m.text.strip() for m in node.findall('member') if m.text and m.text.strip()]
    return ';'.join(values)


def _text(entry: ET.Element, tag: str) -> str:
    node = entry.find(tag)
    return node.text.strip() if node is not None and node.text else DEFAULTS.get(tag, '')


def _profile(entry: ET.Element) -> str:
    """Group name, or 'type=name' pairs for individual profiles; '' if none."""
    setting = entry.find('profile-setting')
    if setting is None:
        return ''
    group = [m.text.strip() for m in setting.findall('group/member') if m.text]
    if group:
        return ';'.join(group)
    profiles = setting.find('profiles')
    if profiles is None:
        return ''
    pairs = []
    for ptype in profiles:
        for m in ptype.findall('member'):
            if m.text and m.text.strip():
                pairs.append(f'{ptype.tag}={m.text.strip()}')
    return ';'.join(pairs)


def parse_rules(rules: ET.Element | None, label: str) -> list[dict]:
    """Convert a <rules> element into checker rows, keeping rule order."""
    if rules is None:
        return []
    rows = []
    for position, entry in enumerate(rules.findall('entry'), start=1):
        rows.append({
            'UUID': entry.get('uuid', ''),
            'Rule Name': entry.get('name', ''),
            'Source Address': _members(entry, 'source'),
            'Destination Address': _members(entry, 'destination'),
            'Application': _members(entry, 'application'),
            'Service': _members(entry, 'service'),
            'Action': _text(entry, 'action'),
            'Profile': _profile(entry),
            'Log Setting': _text(entry, 'log-setting'),
            'Source Zone': _members(entry, 'from'),
            'Destination Zone': _members(entry, 'to'),
            'Disabled': _text(entry, 'disabled'),
            'Log at Session Start': _text(entry, 'log-start'),
            'Log at Session End': _text(entry, 'log-end'),
            'Rulebase': label,
            'Position': position,
            'Negate Source': _text(entry, 'negate-source'),
            'Negate Destination': _text(entry, 'negate-destination'),
        })
    return rows


def _xpath_to_path(xpath: str) -> str:
    """'/config/a/b[@name='x']/c' -> ElementTree path relative to <config>."""
    parts = xpath.strip('/').split('/')
    if parts[0] != 'config':
        raise ValueError(f'Unexpected xpath root: {xpath}')
    return '/'.join(parts[1:])


def load_config(xml_text: str) -> ET.Element:
    root = ET.fromstring(xml_text)
    config = root if root.tag == 'config' else root.find('.//config')
    if config is None:
        raise ValueError('No <config> element found in XML file.')
    return config


def config_parent_lookup(config: ET.Element):
    """get_parent() for dg_ancestors, backed by a saved config."""
    def get_parent(name: str) -> str | None:
        node = config.find(_xpath_to_path(parent_dg_xpath(name)))
        return node.text.strip() if node is not None and node.text else None
    return get_parent


def api_parent_lookup(client: 'PanosReadOnlyClient', action: str = 'show'):
    """get_parent() for dg_ancestors, backed by the read-only API."""
    def get_parent(name: str) -> str | None:
        node = client.config(parent_dg_xpath(name), action=action)
        return node.text.strip() if node is not None and node.text else None
    return get_parent


def rules_from_config_xml(xml_text: str | ET.Element, rulebases: Iterable[Rulebase]) -> pd.DataFrame:
    """Parse a saved running/candidate config file (text or loaded element)."""
    config = xml_text if isinstance(xml_text, ET.Element) else load_config(xml_text)
    rows = []
    for rb in rulebases:
        rows.extend(parse_rules(config.find(_xpath_to_path(rb.xpath)), rb.label))
    return to_frame(rows)


# ---------------------------------------------------------------- live API

class PanosReadOnlyClient:
    """Minimal XML API client that can only read configuration."""

    def __init__(self, host: str, api_key: str, verify: bool | str = True, timeout: int = 30):
        import requests  # local import keeps offline use dependency-free
        if not api_key:
            raise ValueError('API key is empty.')
        self.url = f'https://{host}/api/'
        self.session = requests.Session()
        self.session.headers['X-PAN-KEY'] = api_key
        self.session.verify = verify
        self.timeout = timeout

    def config(self, xpath: str, action: str = 'show') -> ET.Element | None:
        if action not in READ_ONLY_ACTIONS:
            raise PermissionError(f'Action {action!r} is not read-only; refusing.')
        resp = self.session.get(self.url, params={'type': 'config', 'action': action,
                                                  'xpath': xpath}, timeout=self.timeout)
        resp.raise_for_status()
        root = ET.fromstring(resp.text)
        if root.get('status') != 'success':
            msg = ''.join(root.itertext()).strip()
            raise RuntimeError(f'PAN-OS API error for {xpath}: {msg}')
        result = root.find('result')
        if result is None or len(result) == 0:
            return None          # rulebase exists but is empty / not defined
        return result.find('rules') if result.find('rules') is not None else result[0]


def rules_from_api(client: PanosReadOnlyClient, rulebases: Iterable[Rulebase],
                   action: str = 'show') -> pd.DataFrame:
    rows = []
    for rb in rulebases:
        rows.extend(parse_rules(client.config(rb.xpath, action=action), rb.label))
    return to_frame(rows)


# ---------------------------------------------------------------- output

def to_frame(rows: list[dict]) -> pd.DataFrame:
    return pd.DataFrame(rows, columns=COLUMNS + EXTRA_COLUMNS)


def write_workbook(df: pd.DataFrame, path: str, source_note: str) -> None:
    """Write the layout app.py expects: sheet 'firewall', title row, headers on row 2."""
    with pd.ExcelWriter(path, engine='openpyxl') as writer:
        pd.DataFrame([[source_note]]).to_excel(writer, sheet_name='firewall',
                                               index=False, header=False, startrow=0)
        df.to_excel(writer, sheet_name='firewall', index=False, startrow=1)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description='Read-only PAN-OS security rule export for the checker.')
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument('--host', help='Firewall or Panorama management hostname/IP')
    src.add_argument('--xml-file', help='Saved running/candidate config XML')
    p.add_argument('--device-group', help='Panorama device group (omit for a firewall)')
    p.add_argument('--vsys', default='vsys1', help='Firewall vsys (default vsys1)')
    p.add_argument('--no-shared', action='store_true', help='Skip Panorama shared rulebases')
    p.add_argument('--no-inherit', action='store_true',
                   help='Skip parent device-group rulebases (default: include them)')
    p.add_argument('--candidate', action='store_true', help='Read candidate config (default: running)')
    p.add_argument('--api-key-env', default='PANOS_API_KEY', help='Env var holding the API key')
    p.add_argument('--ca-bundle', help='CA bundle path for a self-signed lab certificate')
    p.add_argument('--insecure', action='store_true', help='Disable TLS verification (lab only)')
    p.add_argument('--out', required=True, help='Output .xlsx path')
    a = p.parse_args(argv)

    action = 'get' if a.candidate else 'show'
    if a.xml_file:
        with open(a.xml_file, encoding='utf-8') as fh:
            config = load_config(fh.read())
        get_parent = config_parent_lookup(config)
        note = f'Source: saved config {os.path.basename(a.xml_file)}'
    else:
        verify: bool | str = a.ca_bundle or True
        if a.insecure:
            print('WARNING: TLS verification disabled. Use only on an isolated lab.', file=sys.stderr)
            verify = False
        client = PanosReadOnlyClient(a.host, os.environ.get(a.api_key_env, ''), verify=verify)
        get_parent = api_parent_lookup(client, action)
        note = f"Source: {a.host} ({'candidate' if a.candidate else 'running'} config, read-only API)"

    if a.device_group:
        ancestors = [] if a.no_inherit else dg_ancestors(a.device_group, get_parent)
        bases = panorama_rulebases(a.device_group, not a.no_shared, ancestors)
        if ancestors:
            print(f"Device-group chain: shared > {' > '.join(ancestors + [a.device_group])}")
            note += f"; DG chain: {' > '.join(ancestors + [a.device_group])}"
    else:
        bases = firewall_rulebases(a.vsys)

    df = (rules_from_config_xml(config, bases) if a.xml_file
          else rules_from_api(client, bases, action=action))
    write_workbook(df, a.out, note)
    print(f'Wrote {len(df)} rules from {len(bases)} rulebase(s) to {a.out}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
