import { buildVowifiScript, VECTORCORE_PATCH_REV } from '../../../application/use-cases/vowifi-build';

// Regression guard for global kernel XFRM flush in vectorcore-ePDG:
// FlushAll() previously called XfrmPolicyFlush()/XfrmStateFlush(XFRM_PROTO_ESP),
// wiping all Kamailio P-CSCF IMS IPsec SAs on every ePDG start/restart.
describe('VoWiFi ePDG build script XFRM isolation and XDP fallback', () => {
  const script = buildVowifiScript();

  it('bumps VECTORCORE_PATCH_REV to at least 8', () => {
    expect(VECTORCORE_PATCH_REV).toBeGreaterThanOrEqual(8);
  });

  it('scopes xfrm.FlushAll() to Ifid == int(IfID) instead of global XfrmPolicyFlush/XfrmStateFlush', () => {
    expect(script).toContain('netlink.XfrmPolicyList(netlink.FAMILY_ALL)');
    expect(script).toContain('policies[i].Ifid == int(IfID)');
    expect(script).toContain('netlink.XfrmPolicyDel(&policies[i])');
    expect(script).toContain('netlink.XfrmStateList(netlink.FAMILY_ALL)');
    expect(script).toContain('states[i].Proto == netlink.XFRM_PROTO_ESP && states[i].Ifid == int(IfID)');
    expect(script).toContain('netlink.XfrmStateDel(&states[i])');
  });

  it('falls back to ifaceForIP(ip4) in bpf_loader.go and allows auto-detection in validate.go', () => {
    expect(script).toContain('autoIface, autoErr := ifaceForIP(ip4)');
    expect(script).toContain('internal/gtpu/bpf_loader.go');
    expect(script).toContain('internal/config/validate.go');
  });
});
