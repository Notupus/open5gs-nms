import * as fs from 'fs';
import * as path from 'path';

// Static wiring guard for per-UE MT INVITE sec-agree compatibility.
//
// Background:
// - Google Pixel IMS stacks reject (480) initial MT INVITEs unless P-CSCF
//   adds Require: sec-agree + Security-Verify via IPSEC_FORWARD_ADD_SECVERIFY.
// - Xiaomi POCO F5 (HyperOS / Qualcomm IMS) enforces RFC 3329 strictly and
//   rejects initial MT INVITEs carrying Require: sec-agree with
//   "420 Bad Extension (Unsupported: sec-agree)".
//
// P-CSCF tracks per-UE opt-outs in the `ipsec_no_secverify` htable keyed by
// UE IP: populated at REGISTER for Xiaomi UEs (and always cleared first so
// dynamically reassigned SMF IPs never inherit a stale opt-out), with a runtime
// fallback in onreply_route[MT_reply] on 420 Unsupported: sec-agree.

const SRC = path.resolve(__dirname, '../../..');
const PCSCF_TPL = fs.readFileSync(
  path.join(SRC, 'config/ims-templates/kamailio_pcscf/kamailio_pcscf.cfg'),
  'utf-8',
);
const MT_TPL = fs.readFileSync(
  path.join(SRC, 'config/ims-templates/kamailio_pcscf/route/mt.cfg'),
  'utf-8',
);

describe('P-CSCF MT sec-agree per-UE compatibility wiring', () => {
  it('declares the ipsec_no_secverify htable in kamailio_pcscf.cfg', () => {
    expect(PCSCF_TPL).toMatch(
      /modparam\("htable", "htable", "ipsec_no_secverify=>size=8;autoexpire=UE_REGISTRATION_EXPIRES;"\)/,
    );
  });

  it('clears ipsec_no_secverify on every REGISTER and sets it for Xiaomi UEs', () => {
    expect(PCSCF_TPL).toContain('$sht(ipsec_no_secverify=>$si) = $null;');
    expect(PCSCF_TPL).toMatch(/\$ua\s*=~\s*"Xiaomi"/);
    expect(PCSCF_TPL).toContain('$sht(ipsec_no_secverify=>$si) = 1;');
  });

  it('gates IPSEC_FORWARD_ADD_SECVERIFY behind ipsec_no_secverify in route[MT] without nesting htable locks', () => {
    const lockPos = MT_TPL.indexOf('sht_lock("ipsec_clients=>ipsec_clients_lock")');
    const optOutReadPos = MT_TPL.indexOf('$sht(ipsec_no_secverify=>$nh(d))');
    expect(optOutReadPos).toBeGreaterThan(-1);
    expect(optOutReadPos).toBeLessThan(lockPos);
    expect(MT_TPL).toContain('ipsec_forward("pcscf_location", IPSEC_FORWARD_FLAGS);');
    expect(MT_TPL).toContain('ipsec_forward("pcscf_location", IPSEC_FORWARD_FLAGS | IPSEC_FORWARD_ADD_SECVERIFY);');
  });

  it('caches 420 Unsupported: sec-agree responses in onreply_route[MT_reply] only', () => {
    const mtReplyStart = MT_TPL.indexOf('onreply_route[MT_reply]');
    const mtIndialogStart = MT_TPL.indexOf('onreply_route[MT_indialog_reply]');
    expect(mtReplyStart).toBeGreaterThan(-1);
    expect(mtIndialogStart).toBeGreaterThan(mtReplyStart);

    const mtReplyBody = MT_TPL.slice(mtReplyStart, mtIndialogStart);
    const mtIndialogBody = MT_TPL.slice(mtIndialogStart);

    expect(mtReplyBody).toMatch(/t_check_status\("420"\)[\s\S]*Unsupported[\s\S]*sec-agree/);
    expect(mtReplyBody).toContain('$sht(ipsec_no_secverify=>$si) = 1;');
    expect(mtIndialogBody).not.toContain('ipsec_no_secverify');
  });
});

