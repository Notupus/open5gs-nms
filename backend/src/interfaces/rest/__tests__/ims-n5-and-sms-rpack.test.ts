import * as fs from 'fs';
import * as path from 'path';

// Static wiring guards for:
// 1. Per-leg `n5_auth_dedup` scoping in P-CSCF MO/MT routes so UE-to-UE VoNR
//    calls through the same P-CSCF authorize N5 PCF QoS on BOTH legs instead
//    of letting MT 183 suppress MO N5 authorization (which left caller uplink/
//    downlink without 5QI=1 PCC rules / one-way audio).
// 2. 3GPP TS 24.011 / 24.341 MO SMS RP-ACK delivery in kamailio-smsc with
//    explicit $uac_req(all) and $rpdata(all) resets so worker state cannot
//    bleed into subsequent MT SMS-DELIVER sends.

const SRC = path.resolve(__dirname, '../../..');
const MO_TPL = fs.readFileSync(
  path.join(SRC, 'config/ims-templates/kamailio_pcscf/route/mo.cfg'),
  'utf-8',
);
const MT_TPL = fs.readFileSync(
  path.join(SRC, 'config/ims-templates/kamailio_pcscf/route/mt.cfg'),
  'utf-8',
);
const ICSCF_TPL = fs.readFileSync(
  path.join(SRC, 'config/ims-templates/kamailio_icscf/kamailio_icscf.cfg'),
  'utf-8',
);
const IMS_CTRL = fs.readFileSync(
  path.join(SRC, 'interfaces/rest/ims-controller.ts'),
  'utf-8',
);

describe('P-CSCF N5 async entry and per-leg dedup scoping', () => {
  it('scopes MO_N5_CALL_PCF_POLICY_AUTH n5_auth_dedup key with mo:$ci', () => {
    expect(MO_TPL).toContain('sht_lock("n5_auth_dedup=>mo:$ci")');
    expect(MO_TPL).toContain('$sht(n5_auth_dedup=>mo:$ci)');
    expect(MO_TPL).toContain('sht_unlock("n5_auth_dedup=>mo:$ci")');
    expect(MO_TPL).not.toContain('n5_auth_dedup=>$ci');
  });

  it('scopes MT_N5_CALL_PCF_POLICY_AUTH n5_auth_dedup key with mt:$ci', () => {
    expect(MT_TPL).toContain('sht_lock("n5_auth_dedup=>mt:$ci")');
    expect(MT_TPL).toContain('$sht(n5_auth_dedup=>mt:$ci)');
    expect(MT_TPL).toContain('sht_unlock("n5_auth_dedup=>mt:$ci")');
    expect(MT_TPL).not.toContain('n5_auth_dedup=>$ci');
  });

  it('sets $avp(n5_async_entry) = 1 before N5 fallback in both MT_aar_reply and MT_indialog_aar_reply', () => {
    for (const routeName of ['route[MT_aar_reply]', 'route[MT_indialog_aar_reply]']) {
      const start = MT_TPL.indexOf(routeName);
      expect(start).toBeGreaterThan(-1);
      const nextRoute = MT_TPL.indexOf('\nroute[', start + routeName.length);
      const body = nextRoute > -1 ? MT_TPL.slice(start, nextRoute) : MT_TPL.slice(start);
      expect(body).toMatch(/\$avp\(n5_async_entry\)\s*=\s*1;\s*route\(MT_N5_CALL_PCF_POLICY_AUTH\);/);
    }
  });
});

describe('kamailio-icscf SUBSCRIBE refresh routing', () => {
  it('excludes SUBSCRIBE from routeless has_totag() relay so reginfo refreshes reach LIR -> S-CSCF', () => {
    const start = ICSCF_TPL.indexOf('if (has_totag())');
    expect(start).toBeGreaterThan(-1);
    const body = ICSCF_TPL.slice(start, start + 1200);
    expect(body).toMatch(/if\s*\(!is_method\("SUBSCRIBE"\)\)/);
  });
});

describe('kamailio-smsc MO RP-ACK, state isolation, and in-flight/retry guards', () => {
  it('sends $smsack back to the MO sender with cleared $uac_req and $rpdata state', () => {
    const start = IMS_CTRL.indexOf('route[SMS_FROM_3GPP]');
    const end = IMS_CTRL.indexOf('route[SMS_FROM_SIP]', start);
    expect(start).toBeGreaterThan(-1);
    expect(end).toBeGreaterThan(start);

    const body = IMS_CTRL.slice(start, end);
    expect(body).toContain('if (route(SMS))');
    expect(body).toContain('$uac_req(body) = $smsack;');
    expect(body).toContain('$uac_req(evroute) = 0;');
    expect(body).toContain('$uac_req(all) = $null;');
    expect(body).toContain('$rpdata(all) = $null;');
  });

  it('clears $uac_req(all) and $rpdata(all) in route[SMS_TO_3GPP]', () => {
    const start = IMS_CTRL.indexOf('route[SMS_TO_3GPP]');
    const end = IMS_CTRL.indexOf('route[SMS_TO_SIP]', start);
    expect(start).toBeGreaterThan(-1);
    expect(end).toBeGreaterThan(start);

    const body = IMS_CTRL.slice(start, end);
    expect(body).toContain('$uac_req(all) = $null;');
    expect(body).toContain('$rpdata(all) = $null;');
    expect(body).toContain('$sht(sms_inflight=>$avp(id)) = 1;');
  });

  it('guards SMS_WORKER against duplicate in-flight sends, throttles reginfo SUBSCRIBE, and handles 200/202 in uac:reply', () => {
    const cfgStart = IMS_CTRL.indexOf('function smscMainCfg');
    const cfgEnd = IMS_CTRL.indexOf('function smscSystemdUnit', cfgStart);
    expect(cfgStart).toBeGreaterThan(-1);
    expect(cfgEnd).toBeGreaterThan(cfgStart);
    const body = IMS_CTRL.slice(cfgStart, cfgEnd);

    expect(body).toContain('sms_inflight=>size=8;autoexpire=45');
    expect(body).toContain('sms_sub_cooldown=>size=8;autoexpire=15');
    expect(body).toContain('if ($sht(sms_inflight=>$avp(id)) != $null)');
    expect(body).toContain('if ($sht(sms_sub_cooldown=>$var(uri)) == $null)');
    expect(body).toContain('$sht(sms_inflight=>$var(msgid)) = $null;');
    expect(body).toMatch(/\(\$uac_req\(evcode\) == 200\) \|\| \(\$uac_req\(evcode\) == 202\)/);
  });
});

