import {
  DEFAULT_TRUNK_CODECS,
  buildTrunkAudioCodecOpts,
  preferDtmfSafePbxSdp,
  parseDtmfInfoBody,
} from '../interfaces/rest/ims-sip-trunk-controller';

describe('IMS SIP trunk DTMF helpers', () => {
  test('DEFAULT_TRUNK_CODECS includes G.711 codecs alongside opus and h264', () => {
    expect(DEFAULT_TRUNK_CODECS).toEqual(['PCMU', 'PCMA', 'opus', 'h264']);
  });

  test('buildTrunkAudioCodecOpts ensures PCMU/PCMA for MO and preserves AMR transcode on MT', () => {
    expect(buildTrunkAudioCodecOpts(['opus', 'h264'], 'mo')).toEqual({
      strip: ['EVS', 'AMR-WB', 'AMR'],
      transcode: ['opus', 'PCMU', 'PCMA'],
    });
    expect(buildTrunkAudioCodecOpts([], 'mo')).toEqual({
      strip: ['EVS', 'AMR-WB', 'AMR'],
      transcode: ['PCMU', 'PCMA', 'opus'],
    });
    expect(buildTrunkAudioCodecOpts(['PCMU'], 'mt')).toEqual({
      strip: ['opus', 'PCMU', 'PCMA', 'G722', 'G729', 'GSM'],
      transcode: ['AMR-WB', 'AMR'],
    });
  });

  test('preferDtmfSafePbxSdp promotes PCMU/PCMA/G722 before opus when only 8 kHz telephone-event exists', () => {
    const pbxSdp = [
      'v=0',
      'o=- 1 1 IN IP4 10.0.0.21',
      's=Asterisk',
      'c=IN IP4 10.0.0.21',
      't=0 0',
      'm=audio 12000 RTP/AVP 107 0 8 101',
      'a=rtpmap:107 opus/48000/2',
      'a=rtpmap:0 PCMU/8000',
      'a=rtpmap:8 PCMA/8000',
      'a=rtpmap:101 telephone-event/8000',
    ].join('\r\n') + '\r\n';

    const reordered = preferDtmfSafePbxSdp(pbxSdp);
    expect(reordered).toContain('m=audio 12000 RTP/AVP 0 8 107 101');
  });

  test('preferDtmfSafePbxSdp leaves SDP untouched when telephone-event/48000 is offered', () => {
    const pbxSdp = [
      'v=0',
      'm=audio 12000 RTP/AVP 107 0 101 102',
      'a=rtpmap:107 opus/48000/2',
      'a=rtpmap:0 PCMU/8000',
      'a=rtpmap:101 telephone-event/8000',
      'a=rtpmap:102 telephone-event/48000',
    ].join('\r\n') + '\r\n';

    expect(preferDtmfSafePbxSdp(pbxSdp)).toBe(pbxSdp);
  });

  test('parseDtmfInfoBody parses RFC 2976 Signal/Duration and numeric events 10-15', () => {
    expect(parseDtmfInfoBody('application/dtmf-relay', 'Signal=5\r\nDuration=200\r\n')).toEqual({
      digit: '5',
      durationMs: 200,
    });
    expect(parseDtmfInfoBody('application/dtmf-relay', 'Signal=10\r\nDuration=10\r\n')).toEqual({
      digit: '*',
      durationMs: 40,
    });
    expect(parseDtmfInfoBody('application/dtmf-relay', 'Signal=11\r\nDuration=5000\r\n')).toEqual({
      digit: '#',
      durationMs: 2000,
    });
    expect(parseDtmfInfoBody('application/dtmf', '9')).toEqual({
      digit: '9',
      durationMs: 160,
    });
    expect(parseDtmfInfoBody('application/sdp', 'Signal=1\r\n')).toBeUndefined();
    expect(parseDtmfInfoBody('application/dtmf-relay', 'Signal=Z\r\n')).toBeUndefined();
  });
});

