import * as fs from 'fs';
import * as path from 'path';
import { pcscfIncludeCfg } from '../interfaces/rest/ims-controller';

describe('P-CSCF PCRF_REALM generation', () => {
  test('pcscfIncludeCfg uses pcrfRealm when provided and falls back to epcDomain', () => {
    const withPcrfRealm = pcscfIncludeCfg({
      pcscfIp: '10.46.0.1',
      pcscfPort: 5060,
      imsDomain: 'ims.mnc069.mcc202.3gppnetwork.org',
      epcDomain: 'epc.mnc069.mcc202.3gppnetwork.org',
      pcrfRealm: 'localdomain',
      http2N5Available: true,
    });
    expect(withPcrfRealm).toContain('#!subst "/PCRF_REALM/localdomain/g"');
    expect(withPcrfRealm).not.toContain('#!subst "/PCRF_REALM/epc.mnc069.mcc202.3gppnetwork.org/g"');

    const fallbackRealm = pcscfIncludeCfg({
      pcscfIp: '10.46.0.1',
      pcscfPort: 5060,
      imsDomain: 'ims.mnc069.mcc202.3gppnetwork.org',
      epcDomain: 'epc.mnc069.mcc202.3gppnetwork.org',
      http2N5Available: true,
    });
    expect(fallbackRealm).toContain('#!subst "/PCRF_REALM/epc.mnc069.mcc202.3gppnetwork.org/g"');
  });

  test('every pcscfIncludeCfg call site in ims-controller.ts passes pcrfRealm from pcrf.conf', () => {
    const src = fs.readFileSync(path.resolve(__dirname, '../interfaces/rest/ims-controller.ts'), 'utf-8');
    const calls = [...src.matchAll(/pcscfIncludeCfg\(\{[\s\S]*?\}\)/g)];
    expect(calls.length).toBeGreaterThanOrEqual(2);
    for (const m of calls) {
      expect(m[0]).toContain('pcrfRealm');
    }
    expect(src).toMatch(/readPcrfFreeDiameterInfo[\s\S]*?Realm/);
  });
});

