import { Router, Request, Response } from 'express';
import * as crypto from 'crypto';
import * as dgram from 'dgram';
import * as fs from 'fs';
import * as net from 'net';
import * as os from 'os';
import * as path from 'path';
import pino from 'pino';
import { requireAdmin } from './middleware/auth-middleware';
import { IAuditLogger } from '../../domain/interfaces/audit-logger';
import { readImsState } from './volte-validation-controller';

// ── Persistent SIP trunk bridge between IMS (Kamailio S-CSCF/I-CSCF) and
//    an external IP PBX / FreePBX (with Digest auth, RPID + PAI, and
//    rtpengine opus/H264 transcoding/passthrough). ─────────────────────────

const DEFAULT_TRUNKS_FILE = '/app/data/ims-sip-trunks.json';
const HOST_TRUNKS_FALLBACK = '/proc/1/root/etc/open5gs/.ims-sip-trunks.json';
const DEFAULT_IMS_BIND_PORT = 15160;
const DEFAULT_PUB_PORT = 5060;
const REGISTER_EXPIRES_SEC = 120;
const REGISTER_REFRESH_MS = 60_000;
export const DEFAULT_TRUNK_CODECS = ['PCMU', 'PCMA', 'opus', 'h264'];
const ALLOW_SIP_METHODS = 'INVITE, ACK, CANCEL, BYE, UPDATE, PRACK, INFO, OPTIONS';
const RTPENGINE_TRUNK_FLAGS = ['replace-origin', 'replace-session-connection', 'trust-address', 'inject-DTMF'];

export interface ImsSipTrunkConfig {
  id: string;
  name: string;
  remoteHost: string;
  remotePort: number;
  username: string;
  password: string;
  localPubIp: string;
  localPubPort: number;
  imsPort: number;
  sendRpid: boolean;
  sendPai: boolean;
  codecs: string[];
  enabled: boolean;
  createdAt: string;
}

export interface ImsSipTrunkStatus {
  id: string;
  name: string;
  remoteHost: string;
  remotePort: number;
  username: string;
  localPubIp: string;
  localPubPort: number;
  imsBindIp: string;
  imsPort: number;
  sendRpid: boolean;
  sendPai: boolean;
  codecs: string[];
  enabled: boolean;
  registered: boolean;
  lastRegisterStatus?: string;
  lastRegisterAt?: string;
  activeCalls: number;
  callsHandled: number;
  createdAt: string;
}

function md5(s: string): string {
  return crypto.createHash('md5').update(s, 'utf-8').digest('hex');
}

function randHex(n: number): string {
  return crypto.randomBytes(n).toString('hex');
}

function resolveLocalBindHost(ip: string): string | undefined {
  for (const addrs of Object.values(os.networkInterfaces())) {
    if (addrs?.some((a) => a.address === ip)) return ip;
  }
  return undefined;
}

function detectFirstLanIp(): string {
  for (const [ifName, addrs] of Object.entries(os.networkInterfaces())) {
    if (!addrs || ifName === 'lo' || ifName.startsWith('ogstun') || ifName.startsWith('docker')) continue;
    for (const a of addrs) {
      if (a.family === 'IPv4' && !a.internal) return a.address;
    }
  }
  return '10.0.0.205';
}

// ── Minimal Bencode encoder/decoder for rtpengine NG protocol ────────────────

type BencodeVal = number | string | Buffer | BencodeVal[] | { [key: string]: BencodeVal };

function bencodeEncode(val: BencodeVal): Buffer {
  if (typeof val === 'number') {
    return Buffer.from(`i${Math.trunc(val)}e`, 'ascii');
  }
  if (typeof val === 'string') {
    const b = Buffer.from(val, 'utf-8');
    return Buffer.concat([Buffer.from(`${b.length}:`, 'ascii'), b]);
  }
  if (Buffer.isBuffer(val)) {
    return Buffer.concat([Buffer.from(`${val.length}:`, 'ascii'), val]);
  }
  if (Array.isArray(val)) {
    return Buffer.concat([Buffer.from('l', 'ascii'), ...val.map(bencodeEncode), Buffer.from('e', 'ascii')]);
  }
  const chunks: Buffer[] = [Buffer.from('d', 'ascii')];
  for (const k of Object.keys(val).sort()) {
    const v = val[k];
    if (v === undefined) continue;
    chunks.push(bencodeEncode(k), bencodeEncode(v));
  }
  chunks.push(Buffer.from('e', 'ascii'));
  return Buffer.concat(chunks);
}

function bencodeDecode(buf: Buffer, offset = 0): { value: any; next: number } {
  const ch = String.fromCharCode(buf[offset]);
  if (ch === 'i') {
    const end = buf.indexOf('e', offset + 1);
    if (end === -1) throw new Error('unterminated bencode int');
    return { value: Number(buf.toString('ascii', offset + 1, end)), next: end + 1 };
  }
  if (ch === 'l') {
    const arr: any[] = [];
    let pos = offset + 1;
    while (pos < buf.length && String.fromCharCode(buf[pos]) !== 'e') {
      const item = bencodeDecode(buf, pos);
      arr.push(item.value);
      pos = item.next;
    }
    return { value: arr, next: pos + 1 };
  }
  if (ch === 'd') {
    const obj: Record<string, any> = {};
    let pos = offset + 1;
    while (pos < buf.length && String.fromCharCode(buf[pos]) !== 'e') {
      const key = bencodeDecode(buf, pos);
      const val = bencodeDecode(buf, key.next);
      obj[String(key.value)] = val.value;
      pos = val.next;
    }
    return { value: obj, next: pos + 1 };
  }
  if (ch >= '0' && ch <= '9') {
    const colon = buf.indexOf(':', offset);
    if (colon === -1) throw new Error('invalid bencode byte string');
    const len = Number(buf.toString('ascii', offset, colon));
    const start = colon + 1;
    const end = start + len;
    return { value: buf.toString('utf-8', start, end), next: end };
  }
  throw new Error(`unexpected bencode token at ${offset}: ${ch}`);
}

class RtpEngineClient {
  private seq = 0;

  constructor(
    private readonly ngHost: string,
    private readonly ngPort: number,
    private readonly bindHost?: string,
  ) {}

  async command(payload: Record<string, BencodeVal>, timeoutMs = 2500): Promise<Record<string, any>> {
    const cookie = `trunk-${process.pid}-${++this.seq}-${randHex(3)}`;
    const packet = Buffer.concat([Buffer.from(`${cookie} `, 'ascii'), bencodeEncode(payload)]);
    return new Promise((resolve, reject) => {
      const sock = dgram.createSocket('udp4');
      let settled = false;
      const done = (fn: () => void) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        try { sock.close(); } catch { /* ignore */ }
        fn();
      };
      const timer = setTimeout(() => done(() => reject(new Error(`rtpengine timeout (${String(payload.command)})`))), timeoutMs);
      sock.on('error', (err) => done(() => reject(err)));
      sock.on('message', (msg) => {
        const space = msg.indexOf(' ');
        if (space === -1) return;
        const replyCookie = msg.toString('ascii', 0, space);
        if (replyCookie !== cookie) return;
        try {
          const decoded = bencodeDecode(msg, space + 1).value as Record<string, any>;
          if (decoded.result !== 'ok') {
            done(() => reject(new Error(`rtpengine ${String(payload.command)} error: ${decoded['error-reason'] ?? JSON.stringify(decoded)}`)));
            return;
          }
          done(() => resolve(decoded));
        } catch (err) {
          done(() => reject(err));
        }
      });
      const sendNow = () => sock.send(packet, this.ngPort, this.ngHost);
      if (this.bindHost) sock.bind({ port: 0, address: this.bindHost }, sendNow);
      else sendNow();
    });
  }
}

// ── SIP parsing & formatting helpers ────────────────────────────────────────

interface ParsedSip {
  statusLine: string;
  headers: Record<string, string>;
  headerLines: Record<string, string[]>;
  body: string;
}

function parseSipMessage(raw: string): ParsedSip {
  const sepIdx = raw.indexOf('\r\n\r\n');
  const head = sepIdx === -1 ? raw : raw.slice(0, sepIdx);
  const body = sepIdx === -1 ? '' : raw.slice(sepIdx + 4);
  const lines = head.split('\r\n');
  const statusLine = lines[0] ?? '';
  const headers: Record<string, string> = {};
  const headerLines: Record<string, string[]> = {};
  for (const line of lines.slice(1)) {
    const idx = line.indexOf(':');
    if (idx === -1) continue;
    const k = line.slice(0, idx).trim().toLowerCase();
    const v = line.slice(idx + 1).trim();
    if (!headerLines[k]) headerLines[k] = [];
    headerLines[k].push(v);
    headers[k] = headers[k] ? `${headers[k]}, ${v}` : v;
  }
  return { statusLine, headers, headerLines, body };
}

class TcpSipFramer {
  private buf = Buffer.alloc(0);

  feed(chunk: Buffer, onMessage: (msg: string) => void): void {
    this.buf = Buffer.concat([this.buf, chunk]);
    while (true) {
      // Drop leading keepalive CRLFs
      while (this.buf.length >= 2 && this.buf[0] === 13 && this.buf[1] === 10) {
        this.buf = this.buf.subarray(2);
      }
      const sep = this.buf.indexOf('\r\n\r\n');
      if (sep === -1) break;
      const headStr = this.buf.subarray(0, sep).toString('utf-8');
      const clMatch = /^content-length\s*:\s*(\d+)/im.exec(headStr);
      const cl = clMatch ? Number(clMatch[1]) : 0;
      const total = sep + 4 + cl;
      if (this.buf.length < total) break;
      const msg = this.buf.subarray(0, total).toString('utf-8');
      this.buf = this.buf.subarray(total);
      onMessage(msg);
    }
  }
}

function parseAuthChallenge(headerVal: string): {
  realm: string;
  nonce: string;
  qop?: string;
  opaque?: string;
  algorithm: string;
} {
  const realm = /realm="([^"]*)"/i.exec(headerVal)?.[1] ?? '';
  const nonce = /nonce="([^"]*)"/i.exec(headerVal)?.[1] ?? '';
  const qop = /qop="?([^",\s]+)"?/i.exec(headerVal)?.[1];
  const opaque = /opaque="([^"]*)"/i.exec(headerVal)?.[1];
  const algorithm = /algorithm=([^,\s]+)/i.exec(headerVal)?.[1] ?? 'MD5';
  return { realm, nonce, qop, opaque, algorithm };
}

function buildDigestHeader(
  hdrName: 'Authorization' | 'Proxy-Authorization',
  method: string,
  uri: string,
  username: string,
  password: string,
  challengeHeader: string,
): string {
  const ch = parseAuthChallenge(challengeHeader);
  const ha1 = md5(`${username}:${ch.realm}:${password}`);
  const ha2 = md5(`${method}:${uri}`);
  const opaquePart = ch.opaque ? `, opaque="${ch.opaque}"` : '';
  if (ch.qop && ch.qop.split(',').map((s) => s.trim()).includes('auth')) {
    const nc = '00000001';
    const cnonce = randHex(6);
    const resp = md5(`${ha1}:${ch.nonce}:${nc}:${cnonce}:auth:${ha2}`);
    return (
      `${hdrName}: Digest username="${username}", realm="${ch.realm}", nonce="${ch.nonce}", ` +
      `uri="${uri}", response="${resp}", algorithm=${ch.algorithm}, qop=auth, nc=${nc}, cnonce="${cnonce}"${opaquePart}\r\n`
    );
  }
  const resp = md5(`${ha1}:${ch.nonce}:${ha2}`);
  return (
    `${hdrName}: Digest username="${username}", realm="${ch.realm}", nonce="${ch.nonce}", ` +
    `uri="${uri}", response="${resp}", algorithm=${ch.algorithm}${opaquePart}\r\n`
  );
}

function extractUriFromHeader(val: string | undefined): string | undefined {
  if (!val) return undefined;
  const bracket = /<([^>]+)>/.exec(val)?.[1];
  if (bracket) return bracket;
  const bare = /((?:sip|sips|tel):[^\s;>,]+)/i.exec(val)?.[1];
  return bare;
}

function extractUserFromUri(uri: string | undefined): string | undefined {
  if (!uri) return undefined;
  const sipMatch = /^sips?:([^@;>]+)@/i.exec(uri);
  if (sipMatch) return sipMatch[1];
  const telMatch = /^tel:([^;>\s]+)/i.exec(uri);
  if (telMatch) return telMatch[1];
  return undefined;
}

function extractDisplayName(val: string | undefined): string | undefined {
  if (!val) return undefined;
  const quoted = /^"([^"]+)"\s*</.exec(val.trim())?.[1];
  if (quoted) return quoted;
  const unquoted = /^([^<":\r\n]+?)\s*</.exec(val.trim())?.[1]?.trim();
  return unquoted || undefined;
}

function extractCallerIdentity(parsed: ParsedSip, fallbackUser: string): { number: string; displayName: string } {
  const candidates: string[] = [
    ...(parsed.headerLines['p-asserted-identity'] ?? []),
    ...(parsed.headerLines['remote-party-id'] ?? []),
    ...(parsed.headerLines['p-preferred-identity'] ?? []),
    ...(parsed.headerLines['from'] ?? []),
  ];
  // Prefer an MSISDN/extension-style identity over a 15-digit raw IMSI when PAI carries multiple values.
  const extracted = candidates
    .flatMap((line) => line.split(','))
    .map((entry) => ({
      user: extractUserFromUri(extractUriFromHeader(entry.trim())),
      display: extractDisplayName(entry),
    }))
    .filter((c): c is { user: string; display: string | undefined } => !!c.user && c.user.toLowerCase() !== 'anonymous');

  const preferred = extracted.find((c) => !/^\d{15}$/.test(c.user)) ?? extracted[0];
  const number = preferred?.user ?? fallbackUser;
  const displayName = (preferred?.display ?? number).replace(/"/g, '');
  return { number, displayName };
}

function formatMultiHeaders(name: string, values: string[] | undefined): string {
  if (!values || values.length === 0) return '';
  return values.map((v) => `${name}: ${v}\r\n`).join('');
}

function forwardRecordRoutes(lines: string[] | undefined): string | undefined {
  if (!lines || lines.length === 0) return undefined;
  const items = lines
    .flatMap((l) => l.split(','))
    .map((s) => s.trim())
    .filter(Boolean);
  return items.length ? items.join(', ') : undefined;
}

function reverseRecordRoutes(lines: string[] | undefined): string | undefined {
  if (!lines || lines.length === 0) return undefined;
  const items = lines
    .flatMap((l) => l.split(','))
    .map((s) => s.trim())
    .filter(Boolean)
    .reverse();
  return items.length ? items.join(', ') : undefined;
}

function stripTrailingTagParam(headerVal: string): string {
  return headerVal.replace(/;tag=[^;\r\n]*/gi, '').trim();
}

function cleanSdpForPbx(sdp: string): string {
  const lines = sdp
    .replace(/\r\n/g, '\n')
    .split('\n')
    .filter((l) => l.length > 0)
    .filter((l) => !/^a=(curr|des|conf):qos\b/i.test(l))
    .map((l) => (/^a=inactive$/i.test(l) ? 'a=sendrecv' : l));
  return lines.join('\r\n') + '\r\n';
}

function injectImsPreconditions(sdp: string): string {
  const rawLines = sdp
    .replace(/\r\n/g, '\n')
    .split('\n')
    .filter((l) => l.length > 0)
    .filter((l) => !/^a=(curr|des|conf):qos\b/i.test(l));

  const out: string[] = [];
  let inAudio = false;
  let injected = false;
  const qosLines = [
    'a=curr:qos local sendrecv',
    'a=des:qos mandatory local sendrecv',
    'a=curr:qos remote none',
    'a=des:qos optional remote sendrecv',
  ];

  for (const line of rawLines) {
    if (/^m=/.test(line)) {
      if (inAudio && !injected) {
        out.push(...qosLines);
        injected = true;
      }
      inAudio = /^m=audio\b/i.test(line);
      out.push(line);
      continue;
    }
    if (inAudio && !injected && /^a=(sendrecv|recvonly|sendonly|inactive)$/i.test(line)) {
      out.push(...qosLines);
      injected = true;
    }
    out.push(line);
  }
  if (inAudio && !injected) out.push(...qosLines);
  return out.join('\r\n') + '\r\n';
}

const AUDIO_CODEC_ALIASES: Record<string, string> = {
  pcmu: 'PCMU',
  ulaw: 'PCMU',
  g711u: 'PCMU',
  pcma: 'PCMA',
  alaw: 'PCMA',
  g711a: 'PCMA',
  g722: 'G722',
  opus: 'opus',
};

const VIDEO_CODECS = new Set(['h264', 'h265', 'vp8', 'vp9', 'av1']);

/**
 * Build rtpengine `codec` options that preserve RFC 4733 `telephone-event` across
 * transcoding legs (avoids `mask`, which hides 8 kHz/16 kHz telephone-event and
 * drops DTMF on Asterisk/FreePBX trunks).
 */
export function buildTrunkAudioCodecOpts(codecs: string[], dir: 'mo' | 'mt'): Record<string, string[]> {
  if (dir === 'mt') {
    return {
      strip: ['opus', 'PCMU', 'PCMA', 'G722', 'G729', 'GSM'],
      transcode: ['AMR-WB', 'AMR'],
    };
  }

  const normalized: string[] = [];
  for (const raw of codecs) {
    const key = raw.trim().toLowerCase();
    if (!key || VIDEO_CODECS.has(key)) continue;
    const mapped = AUDIO_CODEC_ALIASES[key];
    if (mapped && !normalized.includes(mapped)) normalized.push(mapped);
  }
  if (normalized.length === 0) {
    normalized.push('PCMU', 'PCMA', 'opus');
  } else {
    if (!normalized.includes('PCMU')) normalized.push('PCMU');
    if (!normalized.includes('PCMA')) normalized.push('PCMA');
  }
  return {
    strip: ['EVS', 'AMR-WB', 'AMR'],
    transcode: normalized,
  };
}

/**
 * When a PBX MT INVITE advertises both 8 kHz/16 kHz PCM/G722 and opus/48000 alongside
 * only `telephone-event/8000`, reorder `m=audio` payload types so `rtpengine` anchors
 * the PBX leg on PCMU/PCMA instead of opus/48000 (where rtpengine drops 8 kHz DTMF).
 */
export function preferDtmfSafePbxSdp(sdp: string): string {
  const lines = sdp.replace(/\r\n/g, '\n').split('\n');
  const audioIdx = lines.findIndex((l) => /^m=audio\s+\d+\s+\S+\s+/i.test(l));
  if (audioIdx === -1) return sdp;

  const rtpmapByPt = new Map<string, string>();
  for (const line of lines) {
    const m = /^a=rtpmap:(\d+)\s+([^\r\n/]+)\/(\d+)/i.exec(line);
    if (m) rtpmapByPt.set(m[1], `${m[2].toLowerCase()}/${m[3]}`);
  }
  const hasTe48k = [...rtpmapByPt.values()].some((v) => v === 'telephone-event/48000');
  const hasTe8k = [...rtpmapByPt.values()].some((v) => v === 'telephone-event/8000');
  if (hasTe48k || !hasTe8k) return sdp;

  const mParts = lines[audioIdx].trim().split(/\s+/);
  const pts = mParts.slice(3);
  const safePts: string[] = [];
  const otherPts: string[] = [];
  for (const pt of pts) {
    const codec = rtpmapByPt.get(pt) ?? (pt === '0' ? 'pcmu/8000' : pt === '8' ? 'pcma/8000' : pt === '9' ? 'g722/8000' : '');
    if (codec.startsWith('pcmu/') || codec.startsWith('pcma/') || codec.startsWith('g722/')) {
      safePts.push(pt);
    } else {
      otherPts.push(pt);
    }
  }
  if (safePts.length === 0) return sdp;

  lines[audioIdx] = `${mParts.slice(0, 3).join(' ')} ${[...safePts, ...otherPts].join(' ')}`;
  return lines.filter((l, i) => i < lines.length - 1 || l.length > 0).join('\r\n') + '\r\n';
}

const DTMF_EVENT_MAP: Record<string, string> = {
  '10': '*',
  '11': '#',
  '12': 'A',
  '13': 'B',
  '14': 'C',
  '15': 'D',
};

/** Parse RFC 2976 / INFO `application/dtmf-relay` or `application/dtmf` bodies into digit + ms. */
export function parseDtmfInfoBody(contentType: string | undefined, body: string): { digit: string; durationMs: number } | undefined {
  if (!body) return undefined;
  const ct = (contentType ?? '').toLowerCase();
  if (ct && !ct.includes('dtmf-relay') && !ct.includes('application/dtmf')) return undefined;

  let rawSignal = '';
  const sigMatch = /^\s*Signal\s*=\s*([^\r\n]+)/im.exec(body);
  if (sigMatch) {
    rawSignal = sigMatch[1].trim();
  } else if (ct.includes('application/dtmf') && !ct.includes('dtmf-relay')) {
    rawSignal = body.trim();
  }
  if (!rawSignal) return undefined;

  const normalized = DTMF_EVENT_MAP[rawSignal] ?? rawSignal.toUpperCase();
  if (!/^[0-9*#ABCD]$/.test(normalized)) return undefined;

  const durMatch = /^\s*Duration\s*=\s*(\d+)/im.exec(body);
  const parsedDur = durMatch ? Number(durMatch[1]) : 160;
  const durationMs = Math.min(2000, Math.max(40, Number.isFinite(parsedDur) ? parsedDur : 160));
  return { digit: normalized, durationMs };
}

// ── Active B2BUA Call State ─────────────────────────────────────────────────

interface PeerAddress {
  address: string;
  port: number;
  replyFn?: (msg: string) => void;
}

interface TrunkCall {
  direction: 'mo' | 'mt';
  rtpCallId: string;
  rtpFromTag: string;
  rtpToTag: string;
  state: 'early' | 'answered' | 'ended';
  cleanupTimer?: NodeJS.Timeout;

  // IMS side
  imsCid: string;
  imsFromTag: string;
  imsToTag: string;
  imsFromHdr: string;
  imsToBaseHdr: string;
  imsToFullHdr?: string;
  imsCseqNum: number;
  imsCseqHdr: string;
  imsViaLines: string[];
  imsRecordRoutes: string[];
  imsRouteSet?: string;
  imsRemoteTarget?: string;
  imsCallerUri: string;
  imsPeer?: PeerAddress;
  imsOfferSdp?: string;
  imsAnswerSdp?: string;
  imsUpdateSent?: boolean;
  imsPrackSeq?: number;

  // PBX side
  pbxCid: string;
  pbxFromTag: string;
  pbxToTag: string;
  pbxFromHdr: string;
  pbxToBaseHdr: string;
  pbxToFullHdr?: string;
  pbxTargetUri: string;
  pbxCseqNum: number;
  pbxCseqHdr: string;
  pbxViaLines: string[];
  pbxRecordRoutes: string[];
  pbxRouteSet?: string;
  pbxRemoteTarget?: string;
  pbxOfferSdp?: string;
  pbxAnswerSdp?: string;
  pbxAnswerPromise?: Promise<string | undefined>;
  pbxAuthAttempts: number;
  pbxCallerDisplay: string;
  pbxCallerNumber: string;
}

// ── Per-trunk SIP B2BUA + Register Instance ─────────────────────────────────

class ImsSipTrunkInstance {
  private readonly imsSock = dgram.createSocket('udp4');
  private readonly imsTcpServer: net.Server;
  private readonly pubSock = dgram.createSocket('udp4');
  private readonly imsBindHost: string | undefined;
  private readonly pubBindHost: string | undefined;
  private readonly rtp: RtpEngineClient;

  private readonly regCallId = `ims-trunk-reg-${randHex(8)}`;
  private regCseq = 1;
  private regFromTag = randHex(6);
  private regTimer?: NodeJS.Timeout;
  private pbxSeq = 1;
  private imsSeq = 1;

  private registered = false;
  private lastRegisterStatus?: string;
  private lastRegisterAt?: string;
  private callsHandled = 0;

  private readonly callsByImsCid = new Map<string, TrunkCall>();
  private readonly callsByPbxCid = new Map<string, TrunkCall>();
  private readonly pendingPbxInfo = new Map<string, { onResponse: (code: number, reason: string) => Promise<void> | void; timer: NodeJS.Timeout }>();
  private readonly pendingImsInfo = new Map<string, { onResponse: (code: number, reason: string) => Promise<void> | void; timer: NodeJS.Timeout }>();

  constructor(
    public readonly config: ImsSipTrunkConfig,
    private readonly imsDomain: string,
    private readonly imsBindIp: string,
    private readonly icscfIp: string,
    private readonly icscfPort: number,
    private readonly logger: pino.Logger,
  ) {
    this.imsBindHost = resolveLocalBindHost(imsBindIp);
    this.pubBindHost = resolveLocalBindHost(config.localPubIp);
    this.rtp = new RtpEngineClient(imsBindIp, 2223, this.imsBindHost);
    this.imsTcpServer = net.createServer((conn) => {
      const framer = new TcpSipFramer();
      conn.on('data', (chunk) => {
        framer.feed(chunk, (msg) => {
          void this.handleImsMessage(msg, {
            address: conn.remoteAddress?.replace(/^::ffff:/, '') ?? this.icscfIp,
            port: conn.remotePort ?? 5060,
            replyFn: (reply) => { if (!conn.destroyed) conn.write(reply, 'utf-8'); },
          });
        });
      });
      conn.on('error', () => { /* socket reset — benign */ });
    });
  }

  info(): ImsSipTrunkStatus {
    const activeSet = new Set(
      [...this.callsByImsCid.values(), ...this.callsByPbxCid.values()].filter((c) => c.state !== 'ended'),
    );
    return {
      id: this.config.id,
      name: this.config.name,
      remoteHost: this.config.remoteHost,
      remotePort: this.config.remotePort,
      username: this.config.username,
      localPubIp: this.config.localPubIp,
      localPubPort: this.config.localPubPort,
      imsBindIp: this.imsBindIp,
      imsPort: this.config.imsPort,
      sendRpid: this.config.sendRpid,
      sendPai: this.config.sendPai,
      codecs: this.config.codecs,
      enabled: this.config.enabled,
      registered: this.registered,
      lastRegisterStatus: this.lastRegisterStatus,
      lastRegisterAt: this.lastRegisterAt,
      activeCalls: activeSet.size,
      callsHandled: this.callsHandled,
      createdAt: this.config.createdAt,
    };
  }

  async start(): Promise<void> {
    this.imsSock.on('error', (err) => this.logger.warn({ err: String(err), trunk: this.config.id }, 'ims-sip-trunk: IMS UDP socket error'));
    this.pubSock.on('error', (err) => this.logger.warn({ err: String(err), trunk: this.config.id }, 'ims-sip-trunk: PBX UDP socket error'));
    this.imsTcpServer.on('error', (err) => this.logger.warn({ err: String(err), trunk: this.config.id }, 'ims-sip-trunk: IMS TCP server error'));

    this.imsSock.on('message', (msg, rinfo) => {
      void this.handleImsMessage(msg.toString('utf-8'), {
        address: rinfo.address,
        port: rinfo.port,
        replyFn: (reply) => this.imsSock.send(Buffer.from(reply, 'utf-8'), rinfo.port, rinfo.address),
      });
    });

    this.pubSock.on('message', (msg, rinfo) => {
      void this.handlePbxMessage(msg.toString('utf-8'), rinfo.address, rinfo.port);
    });

    await Promise.all([
      new Promise<void>((res, rej) => {
        this.imsSock.once('error', rej);
        this.imsSock.bind({ port: this.config.imsPort, address: this.imsBindHost }, () => {
          this.imsSock.removeListener('error', rej);
          res();
        });
      }),
      new Promise<void>((res, rej) => {
        this.imsTcpServer.once('error', rej);
        this.imsTcpServer.listen(this.config.imsPort, this.imsBindHost ?? '0.0.0.0', () => {
          this.imsTcpServer.removeListener('error', rej);
          res();
        });
      }),
      new Promise<void>((res, rej) => {
        this.pubSock.once('error', rej);
        this.pubSock.bind({ port: this.config.localPubPort, address: this.pubBindHost }, () => {
          this.pubSock.removeListener('error', rej);
          res();
        });
      }),
    ]);

    this.logger.info(
      {
        trunk: this.config.id,
        ims: `${this.imsBindIp}:${this.config.imsPort}`,
        pub: `${this.config.localPubIp}:${this.config.localPubPort}`,
        remote: `${this.config.remoteHost}:${this.config.remotePort}`,
      },
      'ims-sip-trunk: listening',
    );

    if (this.config.enabled) {
      await this.registerOnce().catch((err) => {
        this.logger.warn({ err: String(err), trunk: this.config.id }, 'ims-sip-trunk: initial REGISTER failed (will retry)');
      });
      this.regTimer = setInterval(() => {
        this.registerOnce().catch((err) => {
          this.logger.warn({ err: String(err), trunk: this.config.id }, 'ims-sip-trunk: periodic REGISTER failed');
        });
      }, REGISTER_REFRESH_MS);
    }
  }

  async stop(): Promise<void> {
    if (this.regTimer) clearInterval(this.regTimer);
    if (this.registered) {
      await this.registerOnce(0).catch(() => { /* best-effort deregister */ });
    }
    const calls = new Set([...this.callsByImsCid.values(), ...this.callsByPbxCid.values()]);
    for (const c of calls) {
      if (c.cleanupTimer) clearTimeout(c.cleanupTimer);
      await this.cleanupCall(c);
    }
    this.callsByImsCid.clear();
    this.callsByPbxCid.clear();
    try { this.imsSock.close(); } catch { /* ignore */ }
    try { this.pubSock.close(); } catch { /* ignore */ }
    await new Promise<void>((res) => this.imsTcpServer.close(() => res()));
  }

  private sendIms(msg: string, port: number, ip: string): void {
    this.imsSock.send(Buffer.from(msg, 'utf-8'), port, ip);
  }

  private sendPbx(msg: string, port = this.config.remotePort, ip = this.config.remoteHost): void {
    this.pubSock.send(Buffer.from(msg, 'utf-8'), port, ip);
  }

  private imsContactHeader(user = this.config.username, isCall = false): string {
    const uri = `<sip:${user}@${this.imsBindIp}:${this.config.imsPort};transport=udp>`;
    return isCall
      ? `Contact: ${uri};+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel";audio\r\n`
      : `Contact: ${uri}\r\n`;
  }

  private pubContactHeader(user = this.config.username): string {
    return `Contact: <sip:${user}@${this.config.localPubIp}:${this.config.localPubPort};transport=udp>\r\n`;
  }

  private buildRegister(expiresSec: number, authHdr = ''): string {
    const uri = `sip:${this.config.remoteHost}:${this.config.remotePort}`;
    const cseq = this.regCseq++;
    const branch = `z9hG4bK${randHex(8)}`;
    return (
      `REGISTER ${uri} SIP/2.0\r\n` +
      `Via: SIP/2.0/UDP ${this.config.localPubIp}:${this.config.localPubPort};branch=${branch};rport\r\n` +
      `Max-Forwards: 70\r\n` +
      `From: <sip:${this.config.username}@${this.config.remoteHost}>;tag=${this.regFromTag}\r\n` +
      `To: <sip:${this.config.username}@${this.config.remoteHost}>\r\n` +
      `Call-ID: ${this.regCallId}\r\n` +
      `CSeq: ${cseq} REGISTER\r\n` +
      this.pubContactHeader() +
      `Expires: ${expiresSec}\r\n` +
      authHdr +
      `Content-Length: 0\r\n\r\n`
    );
  }

  private registerResolve?: (p: ParsedSip) => void;

  async registerOnce(expiresSec = REGISTER_EXPIRES_SEC): Promise<void> {
    const uri = `sip:${this.config.remoteHost}:${this.config.remotePort}`;
    const sendAndWait = (msg: string) =>
      new Promise<ParsedSip>((resolve, reject) => {
        const t = setTimeout(() => {
          this.registerResolve = undefined;
          reject(new Error('timeout waiting for PBX REGISTER response'));
        }, 4000);
        this.registerResolve = (p) => {
          clearTimeout(t);
          this.registerResolve = undefined;
          resolve(p);
        };
        this.sendPbx(msg);
      });

    let res = await sendAndWait(this.buildRegister(expiresSec));
    if (/^SIP\/2\.0 401/.test(res.statusLine) && res.headers['www-authenticate']) {
      const authHdr = buildDigestHeader('Authorization', 'REGISTER', uri, this.config.username, this.config.password, res.headers['www-authenticate']);
      res = await sendAndWait(this.buildRegister(expiresSec, authHdr));
    } else if (/^SIP\/2\.0 407/.test(res.statusLine) && res.headers['proxy-authenticate']) {
      const authHdr = buildDigestHeader('Proxy-Authorization', 'REGISTER', uri, this.config.username, this.config.password, res.headers['proxy-authenticate']);
      res = await sendAndWait(this.buildRegister(expiresSec, authHdr));
    }

    this.lastRegisterStatus = res.statusLine;
    this.lastRegisterAt = new Date().toISOString();
    if (/^SIP\/2\.0 200/.test(res.statusLine)) {
      this.registered = expiresSec > 0;
      return;
    }
    this.registered = false;
    throw new Error(`PBX REGISTER rejected: ${res.statusLine}`);
  }

  // ── Shared codec/sdp rtpengine helpers ──────────────────────────────────

  private audioCodecOpts(dir: 'mo' | 'mt'): Record<string, BencodeVal> {
    return buildTrunkAudioCodecOpts(this.config.codecs, dir);
  }

  private clearPendingInfoForCall(call: TrunkCall): void {
    for (const [k, entry] of this.pendingPbxInfo) {
      if (k.startsWith(`${call.pbxCid}:`)) {
        clearTimeout(entry.timer);
        this.pendingPbxInfo.delete(k);
      }
    }
    for (const [k, entry] of this.pendingImsInfo) {
      if (k.startsWith(`${call.imsCid}:`)) {
        clearTimeout(entry.timer);
        this.pendingImsInfo.delete(k);
      }
    }
  }

  private async cleanupCall(call: TrunkCall): Promise<void> {
    if (call.state === 'ended') return;
    call.state = 'ended';
    this.clearPendingInfoForCall(call);
    if (call.cleanupTimer) clearTimeout(call.cleanupTimer);
    // Keep call metadata briefly so late 487 responses / retransmitted BYEs still settle cleanly.
    call.cleanupTimer = setTimeout(() => {
      this.callsByImsCid.delete(call.imsCid);
      this.callsByPbxCid.delete(call.pbxCid);
    }, 10_000);
    call.cleanupTimer.unref?.();
    await this.rtp.command({
      command: 'delete',
      'call-id': call.rtpCallId,
      'from-tag': call.rtpFromTag,
    }).catch(() => { /* already deleted */ });
  }

  // ── IMS-side SIP Message Dispatcher ─────────────────────────────────────

  private async handleImsMessage(raw: string, peer: PeerAddress): Promise<void> {
    if (!raw.trim()) return;
    const parsed = parseSipMessage(raw);
    const reply = (msg: string) => {
      if (peer.replyFn) peer.replyFn(msg);
      else this.sendIms(msg, peer.port, peer.address);
    };

    if (parsed.statusLine.startsWith('SIP/2.0 ')) {
      await this.handleImsResponse(parsed);
      return;
    }

    const reqMatch = /^(\S+)\s+(\S+)\s+SIP\/2\.0/i.exec(parsed.statusLine);
    if (!reqMatch) return;
    const method = reqMatch[1].toUpperCase();
    const ruri = reqMatch[2];
    const cid = parsed.headers['call-id'] ?? '';
    const from = parsed.headers['from'] ?? '';
    const to = parsed.headers['to'] ?? '';
    const cseqHdr = parsed.headers['cseq'] ?? '';
    const viaLines = parsed.headerLines['via'] ?? [];
    const viaBlock = formatMultiHeaders('Via', viaLines);

    if (method === 'OPTIONS') {
      const toReply = /;tag=/i.test(to) ? to : `${to};tag=${randHex(6)}`;
      reply(
        `SIP/2.0 200 OK\r\n${viaBlock}From: ${from}\r\nTo: ${toReply}\r\nCall-ID: ${cid}\r\nCSeq: ${cseqHdr}\r\n` +
        `Allow: ${ALLOW_SIP_METHODS}\r\nContent-Length: 0\r\n\r\n`,
      );
      return;
    }

    if (method === 'INVITE') {
      const existing = this.callsByImsCid.get(cid);
      if (existing && existing.state !== 'ended') {
        // Re-INVITE on established call (e.g., hold/resume or codec switch)
        await this.handleImsReinvite(existing, parsed, reply);
        return;
      }
      await this.handleMoInvite(ruri, parsed, peer, reply);
      return;
    }

    const call = this.callsByImsCid.get(cid);
    if (!call) {
      if (method === 'ACK') return;
      reply(`SIP/2.0 481 Call/Transaction Does Not Exist\r\n${viaBlock}From: ${from}\r\nTo: ${to}\r\nCall-ID: ${cid}\r\nCSeq: ${cseqHdr}\r\nContent-Length: 0\r\n\r\n`);
      return;
    }

    if (method === 'ACK') {
      // Already ACKed PBX immediately on 200 OK; nothing further needed.
      return;
    }

    if (method === 'CANCEL') {
      reply(`SIP/2.0 200 OK\r\n${viaBlock}From: ${from}\r\nTo: ${to}\r\nCall-ID: ${cid}\r\nCSeq: ${cseqHdr}\r\nContent-Length: 0\r\n\r\n`);
      if (call.state === 'ended') return;
      this.logger.info({ trunk: this.config.id, direction: call.direction, imsCid: cid }, 'ims-sip-trunk: IMS CANCEL received');
      reply(
        `SIP/2.0 487 Request Terminated\r\n${formatMultiHeaders('Via', call.imsViaLines)}From: ${call.imsFromHdr}\r\n` +
        `To: ${call.imsToBaseHdr};tag=${call.imsToTag}\r\nCall-ID: ${call.imsCid}\r\nCSeq: ${call.imsCseqHdr}\r\nContent-Length: 0\r\n\r\n`,
      );
      if (call.direction === 'mo') {
        const cancelMsg =
          `CANCEL ${call.pbxTargetUri} SIP/2.0\r\n` +
          `Via: SIP/2.0/UDP ${this.config.localPubIp}:${this.config.localPubPort};branch=${call.pbxViaLines[0] ?? `z9hG4bK${randHex(8)}`};rport\r\n` +
          `Max-Forwards: 70\r\nFrom: ${call.pbxFromHdr}\r\nTo: ${call.pbxToBaseHdr}\r\n` +
          `Call-ID: ${call.pbxCid}\r\nCSeq: ${call.pbxCseqNum} CANCEL\r\nContent-Length: 0\r\n\r\n`;
        this.sendPbx(cancelMsg);
      }
      await this.cleanupCall(call);
      return;
    }

    if (method === 'BYE') {
      reply(`SIP/2.0 200 OK\r\n${viaBlock}From: ${from}\r\nTo: ${to}\r\nCall-ID: ${cid}\r\nCSeq: ${cseqHdr}\r\nContent-Length: 0\r\n\r\n`);
      if (call.state === 'ended') return;
      this.logger.info({ trunk: this.config.id, direction: call.direction, imsCid: cid, pbxCid: call.pbxCid }, 'ims-sip-trunk: IMS BYE received, tearing down PBX leg');
      const pbxReqUri = call.pbxRemoteTarget ?? call.pbxTargetUri;
      const routeHdr = call.pbxRouteSet ? `Route: ${call.pbxRouteSet}\r\n` : '';
      const byePbx =
        `BYE ${pbxReqUri} SIP/2.0\r\n` +
        `Via: SIP/2.0/UDP ${this.config.localPubIp}:${this.config.localPubPort};branch=z9hG4bK${randHex(8)};rport\r\n` +
        `Max-Forwards: 70\r\n` +
        `From: ${call.direction === 'mo' ? call.pbxFromHdr : (call.pbxToFullHdr ?? call.pbxToBaseHdr)}\r\n` +
        `To: ${call.direction === 'mo' ? (call.pbxToFullHdr ?? call.pbxToBaseHdr) : call.pbxFromHdr}\r\n` +
        routeHdr +
        `Call-ID: ${call.pbxCid}\r\n` +
        `CSeq: ${++this.pbxSeq} BYE\r\n` +
        `Content-Length: 0\r\n\r\n`;
      this.sendPbx(byePbx);
      await this.cleanupCall(call);
      return;
    }

    if (method === 'UPDATE') {
      const sdpBody = call.imsOfferSdp ?? call.imsAnswerSdp ?? parsed.body;
      reply(
        `SIP/2.0 200 OK\r\n${viaBlock}From: ${from}\r\nTo: ${to}\r\nCall-ID: ${cid}\r\nCSeq: ${cseqHdr}\r\n` +
        this.imsContactHeader(this.config.username, true) +
        (sdpBody ? `Content-Type: application/sdp\r\nContent-Length: ${Buffer.byteLength(sdpBody)}\r\n\r\n${sdpBody}` : 'Content-Length: 0\r\n\r\n'),
      );
      return;
    }

    if (method === 'PRACK') {
      reply(`SIP/2.0 200 OK\r\n${viaBlock}From: ${from}\r\nTo: ${to}\r\nCall-ID: ${cid}\r\nCSeq: ${cseqHdr}\r\nContent-Length: 0\r\n\r\n`);
      return;
    }

    if (method === 'INFO') {
      await this.handleImsInfo(call, parsed, reply);
      return;
    }

    reply(`SIP/2.0 405 Method Not Allowed\r\n${viaBlock}From: ${from}\r\nTo: ${to}\r\nCall-ID: ${cid}\r\nCSeq: ${cseqHdr}\r\nContent-Length: 0\r\n\r\n`);
  }

  private async tryRtpEnginePlayDtmf(call: TrunkCall, fromRtpTag: string, contentType: string | undefined, body: string): Promise<boolean> {
    const dtmf = parseDtmfInfoBody(contentType, body);
    if (!dtmf) return false;
    try {
      await this.rtp.command({
        command: 'play DTMF',
        'call-id': call.rtpCallId,
        'from-tag': fromRtpTag,
        code: dtmf.digit,
        duration: dtmf.durationMs,
      });
      return true;
    } catch (err) {
      this.logger.warn({ err: String(err), trunk: this.config.id, rtpCallId: call.rtpCallId, digit: dtmf.digit }, 'ims-sip-trunk: rtpengine play DTMF failed');
      return false;
    }
  }

  private async handleImsInfo(call: TrunkCall, parsed: ParsedSip, reply: (msg: string) => void): Promise<void> {
    const viaBlock = formatMultiHeaders('Via', parsed.headerLines['via'] ?? []);
    const from = parsed.headers['from'] ?? '';
    const to = parsed.headers['to'] ?? '';
    const cid = parsed.headers['call-id'] ?? '';
    const cseqHdr = parsed.headers['cseq'] ?? '';

    if (call.state === 'ended') {
      reply(`SIP/2.0 481 Call/Transaction Does Not Exist\r\n${viaBlock}From: ${from}\r\nTo: ${to}\r\nCall-ID: ${cid}\r\nCSeq: ${cseqHdr}\r\nContent-Length: 0\r\n\r\n`);
      return;
    }

    const pbxCseq = ++this.pbxSeq;
    const pbxKey = `${call.pbxCid}:${pbxCseq}`;
    const contentType = parsed.headers['content-type'];
    const body = parsed.body ?? '';
    const imsSideTag = call.direction === 'mo' ? call.rtpFromTag : call.rtpToTag;

    const respondToIms = (code: number, reason: string) => {
      reply(`SIP/2.0 ${code} ${reason}\r\n${viaBlock}From: ${from}\r\nTo: ${to}\r\nCall-ID: ${cid}\r\nCSeq: ${cseqHdr}\r\nContent-Length: 0\r\n\r\n`);
    };

    const timer = setTimeout(() => {
      this.pendingPbxInfo.delete(pbxKey);
      respondToIms(408, 'Request Timeout');
    }, 5000);
    timer.unref?.();

    this.pendingPbxInfo.set(pbxKey, {
      timer,
      onResponse: async (code, reason) => {
        if ((code === 405 || code === 415 || code === 501) && (await this.tryRtpEnginePlayDtmf(call, imsSideTag, contentType, body))) {
          respondToIms(200, 'OK');
          return;
        }
        respondToIms(code, reason || (code === 200 ? 'OK' : ''));
      },
    });

    const pbxReqUri = call.pbxRemoteTarget ?? call.pbxTargetUri;
    const routeHdr = call.pbxRouteSet ? `Route: ${call.pbxRouteSet}\r\n` : '';
    const contentHdrs = body
      ? `${contentType ? `Content-Type: ${contentType}\r\n` : ''}Content-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`
      : 'Content-Length: 0\r\n\r\n';
    const infoPbx =
      `INFO ${pbxReqUri} SIP/2.0\r\n` +
      `Via: SIP/2.0/UDP ${this.config.localPubIp}:${this.config.localPubPort};branch=z9hG4bK${randHex(8)};rport\r\n` +
      `Max-Forwards: 70\r\n` +
      `From: ${call.direction === 'mo' ? call.pbxFromHdr : (call.pbxToFullHdr ?? call.pbxToBaseHdr)}\r\n` +
      `To: ${call.direction === 'mo' ? (call.pbxToFullHdr ?? call.pbxToBaseHdr) : call.pbxFromHdr}\r\n` +
      this.pubContactHeader() +
      routeHdr +
      `Call-ID: ${call.pbxCid}\r\n` +
      `CSeq: ${pbxCseq} INFO\r\n` +
      contentHdrs;
    this.sendPbx(infoPbx);
  }

  private async handleImsReinvite(call: TrunkCall, parsed: ParsedSip, reply: (msg: string) => void): Promise<void> {
    const viaBlock = formatMultiHeaders('Via', parsed.headerLines['via'] ?? []);
    const from = parsed.headers['from'] ?? '';
    const to = parsed.headers['to'] ?? '';
    const cid = parsed.headers['call-id'] ?? '';
    const cseqHdr = parsed.headers['cseq'] ?? '';
    if (parsed.body) {
      try {
        const res = await this.rtp.command({
          command: 'offer',
          'call-id': call.rtpCallId,
          'from-tag': call.rtpFromTag,
          'to-tag': call.rtpToTag,
          sdp: parsed.body,
          direction: ['ims', 'pub'],
          'transport-protocol': 'RTP/AVP',
          ICE: 'remove',
          flags: RTPENGINE_TRUNK_FLAGS,
          codec: this.audioCodecOpts('mo'),
        });
        const ans = await this.rtp.command({
          command: 'answer',
          'call-id': call.rtpCallId,
          'from-tag': call.rtpFromTag,
          'to-tag': call.rtpToTag,
          sdp: cleanSdpForPbx(res.sdp),
          direction: ['pub', 'ims'],
          'transport-protocol': 'RTP/AVP',
          ICE: 'remove',
          flags: RTPENGINE_TRUNK_FLAGS,
        });
        call.imsAnswerSdp = ans.sdp;
      } catch { /* fall back to cached SDP */ }
    }
    const sdp = call.imsAnswerSdp ?? parsed.body;
    reply(
      `SIP/2.0 200 OK\r\n${viaBlock}From: ${from}\r\nTo: ${to}\r\nCall-ID: ${cid}\r\nCSeq: ${cseqHdr}\r\n` +
      this.imsContactHeader(this.config.username, true) +
      (sdp ? `Content-Type: application/sdp\r\nContent-Length: ${Buffer.byteLength(sdp)}\r\n\r\n${sdp}` : 'Content-Length: 0\r\n\r\n'),
    );
  }

  // ── MO Call Setup: IMS UE -> S-CSCF -> Trunk -> FreePBX ─────────────────

  private async handleMoInvite(ruri: string, parsed: ParsedSip, peer: PeerAddress, reply: (msg: string) => void): Promise<void> {
    const cid = parsed.headers['call-id'] ?? '';
    const from = parsed.headers['from'] ?? '';
    const to = parsed.headers['to'] ?? '';
    const cseqHdr = parsed.headers['cseq'] ?? '1 INVITE';
    const viaLines = parsed.headerLines['via'] ?? [];
    const viaBlock = formatMultiHeaders('Via', viaLines);
    const rrLines = parsed.headerLines['record-route'] ?? [];

    reply(
      `SIP/2.0 100 Trying\r\n${viaBlock}From: ${from}\r\nTo: ${to}\r\nCall-ID: ${cid}\r\nCSeq: ${cseqHdr}\r\nContent-Length: 0\r\n\r\n`,
    );

    const targetNumber = extractUserFromUri(ruri) ?? extractUserFromUri(extractUriFromHeader(to)) ?? '';
    if (!targetNumber) {
      reply(`SIP/2.0 404 Not Found\r\n${viaBlock}From: ${from}\r\nTo: ${to};tag=${randHex(6)}\r\nCall-ID: ${cid}\r\nCSeq: ${cseqHdr}\r\nContent-Length: 0\r\n\r\n`);
      return;
    }

    const caller = extractCallerIdentity(parsed, this.config.username);
    const rtpCallId = `trunk-mo-${randHex(8)}`;
    const rtpFromTag = `ims-${randHex(6)}`;
    const rtpToTag = `pbx-${randHex(6)}`;

    let pbxOfferSdp = parsed.body;
    try {
      const offerRes = await this.rtp.command({
        command: 'offer',
        'call-id': rtpCallId,
        'from-tag': rtpFromTag,
        sdp: parsed.body,
        direction: ['ims', 'pub'],
        'transport-protocol': 'RTP/AVP',
        ICE: 'remove',
        flags: RTPENGINE_TRUNK_FLAGS,
        codec: this.audioCodecOpts('mo'),
      });
      pbxOfferSdp = cleanSdpForPbx(offerRes.sdp);
    } catch (err) {
      this.logger.warn({ err: String(err), trunk: this.config.id, targetNumber }, 'ims-sip-trunk: MO rtpengine offer failed');
      reply(`SIP/2.0 500 Server Internal Error\r\n${viaBlock}From: ${from}\r\nTo: ${to};tag=${randHex(6)}\r\nCall-ID: ${cid}\r\nCSeq: ${cseqHdr}\r\nContent-Length: 0\r\n\r\n`);
      return;
    }

    const pbxCid = `ims-trunk-${randHex(10)}`;
    const pbxFromTag = randHex(6);
    const pbxTargetUri = `sip:${targetNumber}@${this.config.remoteHost}:${this.config.remotePort}`;
    const pbxFromHdr = `"${caller.displayName}" <sip:${this.config.username}@${this.config.remoteHost}>;tag=${pbxFromTag}`;
    const pbxToBaseHdr = `<sip:${targetNumber}@${this.config.remoteHost}>`;

    const imsToTag = randHex(6);
    const imsToBaseHdr = stripTrailingTagParam(to);

    const call: TrunkCall = {
      direction: 'mo',
      rtpCallId,
      rtpFromTag,
      rtpToTag,
      state: 'early',
      imsCid: cid,
      imsFromTag: /tag=([^;\s]+)/i.exec(from)?.[1] ?? '',
      imsToTag,
      imsFromHdr: from,
      imsToBaseHdr,
      imsToFullHdr: `${imsToBaseHdr};tag=${imsToTag}`,
      imsCseqNum: Number(/(\d+)/.exec(cseqHdr)?.[1] ?? '1'),
      imsCseqHdr: cseqHdr,
      imsViaLines: viaLines,
      imsRecordRoutes: rrLines,
      imsRouteSet: forwardRecordRoutes(rrLines),
      imsRemoteTarget: extractUriFromHeader(parsed.headers['contact']),
      imsCallerUri: extractUriFromHeader(from) ?? '',
      imsPeer: peer,
      pbxCid,
      pbxFromTag,
      pbxToTag: '',
      pbxFromHdr,
      pbxToBaseHdr,
      pbxTargetUri,
      pbxCseqNum: ++this.pbxSeq,
      pbxCseqHdr: '',
      pbxViaLines: [],
      pbxRecordRoutes: [],
      pbxOfferSdp,
      pbxAuthAttempts: 0,
      pbxCallerDisplay: caller.displayName,
      pbxCallerNumber: caller.number,
    };
    call.pbxCseqHdr = `${call.pbxCseqNum} INVITE`;

    this.callsHandled++;
    this.callsByImsCid.set(cid, call);
    this.callsByPbxCid.set(pbxCid, call);
    this.logger.info(
      { trunk: this.config.id, direction: 'mo', caller: caller.number, target: targetNumber, pbxCid },
      'ims-sip-trunk: placing outbound call to PBX',
    );
    this.sendMoPbxInvite(call);
  }

  private buildCallerIdHeaders(callerDisplay: string, callerNumber: string): string {
    const uri = `<sip:${callerNumber}@${this.config.localPubIp}>`;
    let out = '';
    if (this.config.sendPai) {
      out += `P-Asserted-Identity: "${callerDisplay}" ${uri}\r\n`;
    }
    if (this.config.sendRpid) {
      out += `Remote-Party-ID: "${callerDisplay}" ${uri};party=calling;privacy=off;screen=yes\r\n`;
    }
    return out;
  }

  private sendMoPbxInvite(call: TrunkCall, authHeader = ''): void {
    const branch = `z9hG4bK${randHex(8)}`;
    call.pbxViaLines = [branch];
    const cidHdrs = this.buildCallerIdHeaders(call.pbxCallerDisplay, call.pbxCallerNumber);
    const sdp = call.pbxOfferSdp ?? '';
    const msg =
      `INVITE ${call.pbxTargetUri} SIP/2.0\r\n` +
      `Via: SIP/2.0/UDP ${this.config.localPubIp}:${this.config.localPubPort};branch=${branch};rport\r\n` +
      `Max-Forwards: 70\r\n` +
      `From: ${call.pbxFromHdr}\r\n` +
      `To: ${call.pbxToBaseHdr}\r\n` +
      `Call-ID: ${call.pbxCid}\r\n` +
      `CSeq: ${call.pbxCseqNum} INVITE\r\n` +
      this.pubContactHeader() +
      cidHdrs +
      authHeader +
      `Allow: ${ALLOW_SIP_METHODS}\r\n` +
      `Content-Type: application/sdp\r\nContent-Length: ${Buffer.byteLength(sdp)}\r\n\r\n${sdp}`;
    this.sendPbx(msg);
  }

  // ── PBX-side SIP Message Dispatcher ─────────────────────────────────────

  private async handlePbxMessage(raw: string, srcIp: string, srcPort: number): Promise<void> {
    if (!raw.trim()) return;
    const parsed = parseSipMessage(raw);
    const cid = parsed.headers['call-id'] ?? '';

    if (parsed.statusLine.startsWith('SIP/2.0 ')) {
      if (cid === this.regCallId && this.registerResolve) {
        this.registerResolve(parsed);
        return;
      }
      await this.handlePbxResponse(parsed);
      return;
    }

    const reqMatch = /^(\S+)\s+(\S+)\s+SIP\/2\.0/i.exec(parsed.statusLine);
    if (!reqMatch) return;
    const method = reqMatch[1].toUpperCase();
    const ruri = reqMatch[2];
    const from = parsed.headers['from'] ?? '';
    const to = parsed.headers['to'] ?? '';
    const cseqHdr = parsed.headers['cseq'] ?? '';
    const viaLines = parsed.headerLines['via'] ?? [];
    const viaBlock = formatMultiHeaders('Via', viaLines);
    const replyPbx = (msg: string) => this.sendPbx(msg, srcPort, srcIp);

    if (method === 'OPTIONS') {
      const toReply = /;tag=/i.test(to) ? to : `${to};tag=${randHex(6)}`;
      replyPbx(
        `SIP/2.0 200 OK\r\n${viaBlock}From: ${from}\r\nTo: ${toReply}\r\nCall-ID: ${cid}\r\nCSeq: ${cseqHdr}\r\n` +
        `Allow: ${ALLOW_SIP_METHODS}\r\nContent-Length: 0\r\n\r\n`,
      );
      return;
    }

    if (method === 'INVITE') {
      if (srcIp !== this.config.remoteHost) {
        this.logger.warn({ srcIp, expected: this.config.remoteHost, trunk: this.config.id }, 'ims-sip-trunk: rejected unsolicited INVITE');
        replyPbx(`SIP/2.0 403 Forbidden\r\n${viaBlock}From: ${from}\r\nTo: ${to};tag=${randHex(6)}\r\nCall-ID: ${cid}\r\nCSeq: ${cseqHdr}\r\nContent-Length: 0\r\n\r\n`);
        return;
      }
      const existing = this.callsByPbxCid.get(cid);
      if (existing && existing.state !== 'ended') {
        await this.handlePbxReinvite(existing, parsed, replyPbx);
        return;
      }
      await this.handleMtInvite(ruri, parsed, replyPbx);
      return;
    }

    const call = this.callsByPbxCid.get(cid);
    if (!call) {
      if (method === 'ACK') return;
      replyPbx(`SIP/2.0 481 Call/Transaction Does Not Exist\r\n${viaBlock}From: ${from}\r\nTo: ${to}\r\nCall-ID: ${cid}\r\nCSeq: ${cseqHdr}\r\nContent-Length: 0\r\n\r\n`);
      return;
    }

    if (method === 'ACK') return;

    if (method === 'CANCEL') {
      replyPbx(`SIP/2.0 200 OK\r\n${viaBlock}From: ${from}\r\nTo: ${to}\r\nCall-ID: ${cid}\r\nCSeq: ${cseqHdr}\r\nContent-Length: 0\r\n\r\n`);
      if (call.state === 'ended') return;
      this.logger.info({ trunk: this.config.id, direction: call.direction, pbxCid: cid }, 'ims-sip-trunk: PBX CANCEL received');
      replyPbx(
        `SIP/2.0 487 Request Terminated\r\n${formatMultiHeaders('Via', call.pbxViaLines)}From: ${call.pbxFromHdr}\r\n` +
        `To: ${call.pbxToBaseHdr};tag=${call.pbxToTag}\r\nCall-ID: ${call.pbxCid}\r\nCSeq: ${call.pbxCseqHdr}\r\nContent-Length: 0\r\n\r\n`,
      );
      if (call.direction === 'mt') {
        const branch = call.imsViaLines[0] ?? `z9hG4bK${randHex(8)}`;
        const cancelIms =
          `CANCEL ${call.imsCallerUri} SIP/2.0\r\n` +
          `Via: SIP/2.0/UDP ${this.imsBindIp}:${this.config.imsPort};branch=${branch};rport\r\n` +
          `Max-Forwards: 70\r\nFrom: ${call.imsFromHdr}\r\nTo: ${call.imsToBaseHdr}\r\n` +
          `Call-ID: ${call.imsCid}\r\nCSeq: ${call.imsCseqNum} CANCEL\r\nContent-Length: 0\r\n\r\n`;
        this.sendIms(cancelIms, this.icscfPort, this.icscfIp);
      }
      await this.cleanupCall(call);
      return;
    }

    if (method === 'BYE') {
      replyPbx(`SIP/2.0 200 OK\r\n${viaBlock}From: ${from}\r\nTo: ${to}\r\nCall-ID: ${cid}\r\nCSeq: ${cseqHdr}\r\nContent-Length: 0\r\n\r\n`);
      if (call.state === 'ended') return;
      this.logger.info({ trunk: this.config.id, direction: call.direction, pbxCid: cid, imsCid: call.imsCid }, 'ims-sip-trunk: PBX BYE received, tearing down IMS leg');
      const imsReqUri = call.imsRemoteTarget ?? call.imsCallerUri;
      const routeHdr = call.imsRouteSet ? `Route: ${call.imsRouteSet}\r\n` : '';
      const byeIms =
        `BYE ${imsReqUri} SIP/2.0\r\n` +
        `Via: SIP/2.0/UDP ${this.imsBindIp}:${this.config.imsPort};branch=z9hG4bK${randHex(8)};rport\r\n` +
        `Max-Forwards: 70\r\n` +
        `From: ${call.direction === 'mt' ? call.imsFromHdr : (call.imsToFullHdr ?? call.imsToBaseHdr)}\r\n` +
        `To: ${call.direction === 'mt' ? (call.imsToFullHdr ?? call.imsToBaseHdr) : call.imsFromHdr}\r\n` +
        routeHdr +
        `Call-ID: ${call.imsCid}\r\n` +
        `CSeq: ${++this.imsSeq} BYE\r\nContent-Length: 0\r\n\r\n`;
      this.sendImsByRoute(byeIms, call);
      await this.cleanupCall(call);
      return;
    }

    if (method === 'INFO') {
      await this.handlePbxInfo(call, parsed, replyPbx);
      return;
    }

    replyPbx(`SIP/2.0 405 Method Not Allowed\r\n${viaBlock}From: ${from}\r\nTo: ${to}\r\nCall-ID: ${cid}\r\nCSeq: ${cseqHdr}\r\nContent-Length: 0\r\n\r\n`);
  }

  private async handlePbxInfo(call: TrunkCall, parsed: ParsedSip, replyPbx: (msg: string) => void): Promise<void> {
    const viaBlock = formatMultiHeaders('Via', parsed.headerLines['via'] ?? []);
    const from = parsed.headers['from'] ?? '';
    const to = parsed.headers['to'] ?? '';
    const cid = parsed.headers['call-id'] ?? '';
    const cseqHdr = parsed.headers['cseq'] ?? '';

    if (call.state === 'ended') {
      replyPbx(`SIP/2.0 481 Call/Transaction Does Not Exist\r\n${viaBlock}From: ${from}\r\nTo: ${to}\r\nCall-ID: ${cid}\r\nCSeq: ${cseqHdr}\r\nContent-Length: 0\r\n\r\n`);
      return;
    }

    const imsCseq = ++this.imsSeq;
    const imsKey = `${call.imsCid}:${imsCseq}`;
    const contentType = parsed.headers['content-type'];
    const body = parsed.body ?? '';
    const pbxSideTag = call.direction === 'mo' ? call.rtpToTag : call.rtpFromTag;

    const respondToPbx = (code: number, reason: string) => {
      replyPbx(`SIP/2.0 ${code} ${reason}\r\n${viaBlock}From: ${from}\r\nTo: ${to}\r\nCall-ID: ${cid}\r\nCSeq: ${cseqHdr}\r\nContent-Length: 0\r\n\r\n`);
    };

    const timer = setTimeout(() => {
      this.pendingImsInfo.delete(imsKey);
      respondToPbx(408, 'Request Timeout');
    }, 5000);
    timer.unref?.();

    this.pendingImsInfo.set(imsKey, {
      timer,
      onResponse: async (code, reason) => {
        if ((code === 405 || code === 415 || code === 501) && (await this.tryRtpEnginePlayDtmf(call, pbxSideTag, contentType, body))) {
          respondToPbx(200, 'OK');
          return;
        }
        respondToPbx(code, reason || (code === 200 ? 'OK' : ''));
      },
    });

    const imsReqUri = call.imsRemoteTarget ?? call.imsCallerUri;
    const routeHdr = call.imsRouteSet ? `Route: ${call.imsRouteSet}\r\n` : '';
    const imsRemoteHdr = call.imsToFullHdr ?? (call.imsToTag ? `${call.imsToBaseHdr};tag=${call.imsToTag}` : call.imsToBaseHdr);
    const contentHdrs = body
      ? `${contentType ? `Content-Type: ${contentType}\r\n` : ''}Content-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`
      : 'Content-Length: 0\r\n\r\n';
    const infoIms =
      `INFO ${imsReqUri} SIP/2.0\r\n` +
      `Via: SIP/2.0/UDP ${this.imsBindIp}:${this.config.imsPort};branch=z9hG4bK${randHex(8)};rport\r\n` +
      `Max-Forwards: 70\r\n` +
      `From: ${call.direction === 'mt' ? call.imsFromHdr : imsRemoteHdr}\r\n` +
      `To: ${call.direction === 'mt' ? imsRemoteHdr : call.imsFromHdr}\r\n` +
      this.imsContactHeader(call.direction === 'mt' ? call.pbxCallerNumber : this.config.username, true) +
      routeHdr +
      `Call-ID: ${call.imsCid}\r\n` +
      `CSeq: ${imsCseq} INFO\r\n` +
      contentHdrs;
    this.sendImsByRoute(infoIms, call);
  }

  private async handlePbxReinvite(call: TrunkCall, parsed: ParsedSip, replyPbx: (msg: string) => void): Promise<void> {
    const viaBlock = formatMultiHeaders('Via', parsed.headerLines['via'] ?? []);
    const from = parsed.headers['from'] ?? '';
    const to = parsed.headers['to'] ?? '';
    const cid = parsed.headers['call-id'] ?? '';
    const cseqHdr = parsed.headers['cseq'] ?? '';
    if (parsed.body) {
      try {
        const res = await this.rtp.command({
          command: 'offer',
          'call-id': call.rtpCallId,
          'from-tag': call.rtpToTag,
          'to-tag': call.rtpFromTag,
          sdp: preferDtmfSafePbxSdp(parsed.body),
          direction: ['pub', 'ims'],
          'transport-protocol': 'RTP/AVP',
          ICE: 'remove',
          flags: RTPENGINE_TRUNK_FLAGS,
          codec: this.audioCodecOpts('mt'),
        });
        const ans = await this.rtp.command({
          command: 'answer',
          'call-id': call.rtpCallId,
          'from-tag': call.rtpToTag,
          'to-tag': call.rtpFromTag,
          sdp: res.sdp,
          direction: ['ims', 'pub'],
          'transport-protocol': 'RTP/AVP',
          ICE: 'remove',
          flags: RTPENGINE_TRUNK_FLAGS,
        });
        call.pbxOfferSdp = cleanSdpForPbx(ans.sdp);
      } catch { /* fallback */ }
    }
    const sdp = cleanSdpForPbx(call.pbxOfferSdp ?? parsed.body);
    replyPbx(
      `SIP/2.0 200 OK\r\n${viaBlock}From: ${from}\r\nTo: ${to}\r\nCall-ID: ${cid}\r\nCSeq: ${cseqHdr}\r\n` +
      this.pubContactHeader() +
      (sdp ? `Content-Type: application/sdp\r\nContent-Length: ${Buffer.byteLength(sdp)}\r\n\r\n${sdp}` : 'Content-Length: 0\r\n\r\n'),
    );
  }

  // ── MT Call Setup: FreePBX -> Trunk -> I-CSCF -> S-CSCF -> P-CSCF -> UE ─

  private async handleMtInvite(ruri: string, parsed: ParsedSip, replyPbx: (msg: string) => void): Promise<void> {
    const cid = parsed.headers['call-id'] ?? '';
    const from = parsed.headers['from'] ?? '';
    const to = parsed.headers['to'] ?? '';
    const cseqHdr = parsed.headers['cseq'] ?? '1 INVITE';
    const viaLines = parsed.headerLines['via'] ?? [];
    const viaBlock = formatMultiHeaders('Via', viaLines);
    const rrLines = parsed.headerLines['record-route'] ?? [];

    replyPbx(`SIP/2.0 100 Trying\r\n${viaBlock}From: ${from}\r\nTo: ${to}\r\nCall-ID: ${cid}\r\nCSeq: ${cseqHdr}\r\nContent-Length: 0\r\n\r\n`);

    const targetNumber = extractUserFromUri(ruri) ?? extractUserFromUri(extractUriFromHeader(to)) ?? '';
    if (!targetNumber || targetNumber === this.config.username) {
      replyPbx(`SIP/2.0 404 Not Found\r\n${viaBlock}From: ${from}\r\nTo: ${to};tag=${randHex(6)}\r\nCall-ID: ${cid}\r\nCSeq: ${cseqHdr}\r\nContent-Length: 0\r\n\r\n`);
      return;
    }

    const caller = extractCallerIdentity(parsed, 'unknown');
    const rtpCallId = `trunk-mt-${randHex(8)}`;
    const rtpFromTag = `pbx-${randHex(6)}`;
    const rtpToTag = `ims-${randHex(6)}`;

    let imsOfferSdp = parsed.body;
    try {
      const offerRes = await this.rtp.command({
        command: 'offer',
        'call-id': rtpCallId,
        'from-tag': rtpFromTag,
        sdp: preferDtmfSafePbxSdp(parsed.body),
        direction: ['pub', 'ims'],
        'transport-protocol': 'RTP/AVP',
        ICE: 'remove',
        flags: RTPENGINE_TRUNK_FLAGS,
        codec: this.audioCodecOpts('mt'),
      });
      imsOfferSdp = injectImsPreconditions(offerRes.sdp);
    } catch (err) {
      this.logger.warn({ err: String(err), trunk: this.config.id, targetNumber }, 'ims-sip-trunk: MT rtpengine offer failed');
      replyPbx(`SIP/2.0 500 Server Internal Error\r\n${viaBlock}From: ${from}\r\nTo: ${to};tag=${randHex(6)}\r\nCall-ID: ${cid}\r\nCSeq: ${cseqHdr}\r\nContent-Length: 0\r\n\r\n`);
      return;
    }

    const imsCid = `ims-mt-${randHex(10)}`;
    const imsFromTag = randHex(6);
    const branch = `z9hG4bK${randHex(8)}`;
    const imsFromHdr = `"${caller.displayName}" <sip:${caller.number}@${this.imsDomain}>;tag=${imsFromTag}`;
    const imsToBaseHdr = `<sip:${targetNumber}@${this.imsDomain}>`;
    const imsCseqNum = ++this.imsSeq;
    const pbxToTag = randHex(6);
    const pbxToBaseHdr = stripTrailingTagParam(to);

    const call: TrunkCall = {
      direction: 'mt',
      rtpCallId,
      rtpFromTag,
      rtpToTag,
      state: 'early',
      imsCid,
      imsFromTag,
      imsToTag: '',
      imsFromHdr,
      imsToBaseHdr,
      imsCseqNum,
      imsCseqHdr: `${imsCseqNum} INVITE`,
      imsViaLines: [branch],
      imsRecordRoutes: [],
      imsCallerUri: `sip:${targetNumber}@${this.imsDomain}`,
      imsOfferSdp,
      pbxCid: cid,
      pbxFromTag: /tag=([^;\s]+)/i.exec(from)?.[1] ?? '',
      pbxToTag,
      pbxFromHdr: from,
      pbxToBaseHdr,
      pbxToFullHdr: `${pbxToBaseHdr};tag=${pbxToTag}`,
      pbxTargetUri: extractUriFromHeader(parsed.headers['contact']) ?? `sip:${this.config.remoteHost}:${this.config.remotePort}`,
      pbxCseqNum: Number(/(\d+)/.exec(cseqHdr)?.[1] ?? '1'),
      pbxCseqHdr: cseqHdr,
      pbxViaLines: viaLines,
      pbxRecordRoutes: rrLines,
      pbxRouteSet: forwardRecordRoutes(rrLines),
      pbxAuthAttempts: 0,
      pbxCallerDisplay: caller.displayName,
      pbxCallerNumber: caller.number,
    };

    this.callsHandled++;
    this.callsByImsCid.set(imsCid, call);
    this.callsByPbxCid.set(cid, call);
    this.logger.info(
      { trunk: this.config.id, direction: 'mt', caller: caller.number, target: targetNumber, imsCid },
      'ims-sip-trunk: forwarding inbound PBX call to I-CSCF',
    );

    const invite =
      `INVITE sip:${targetNumber}@${this.imsDomain} SIP/2.0\r\n` +
      `Via: SIP/2.0/UDP ${this.imsBindIp}:${this.config.imsPort};branch=${branch};rport\r\n` +
      `Max-Forwards: 70\r\n` +
      `From: ${imsFromHdr}\r\n` +
      `To: ${imsToBaseHdr}\r\n` +
      `Call-ID: ${imsCid}\r\n` +
      `CSeq: ${imsCseqNum} INVITE\r\n` +
      this.imsContactHeader(caller.number, true) +
      `P-Asserted-Identity: "${caller.displayName}" <sip:${caller.number}@${this.imsDomain}>\r\n` +
      `Remote-Party-ID: "${caller.displayName}" <sip:${caller.number}@${this.imsDomain}>;party=calling;privacy=off;screen=yes\r\n` +
      `Supported: precondition, 100rel\r\n` +
      `Allow: ${ALLOW_SIP_METHODS}\r\n` +
      `Content-Type: application/sdp\r\nContent-Length: ${Buffer.byteLength(imsOfferSdp)}\r\n\r\n${imsOfferSdp}`;
    this.sendIms(invite, this.icscfPort, this.icscfIp);
  }

  // ── Response Relaying: PBX -> IMS (MO) and IMS -> PBX (MT) ──────────────

  private async handlePbxResponse(parsed: ParsedSip): Promise<void> {
    const cid = parsed.headers['call-id'] ?? '';
    const call = this.callsByPbxCid.get(cid);
    if (!call) return;

    const statusMatch = /^SIP\/2\.0\s+(\d{3})\s*(.*)$/.exec(parsed.statusLine);
    if (!statusMatch) return;
    const code = Number(statusMatch[1]);
    const reason = statusMatch[2] || '';
    const cseqMatch = /(\d+)\s+(\w+)/.exec(parsed.headers['cseq'] ?? '');
    const cseqMethod = (cseqMatch?.[2] ?? '').toUpperCase();
    const toHeader = parsed.headers['to'] ?? '';
    const toTagMatch = /;tag=([^;\s]+)/i.exec(toHeader);
    if (toTagMatch) call.pbxToTag = toTagMatch[1];
    call.pbxToFullHdr = toHeader;

    const contactUri = extractUriFromHeader(parsed.headers['contact']);
    if (contactUri) call.pbxRemoteTarget = contactUri;
    if (parsed.headerLines['record-route'] && !call.pbxRouteSet) {
      call.pbxRouteSet = reverseRecordRoutes(parsed.headerLines['record-route']);
    }

    if (cseqMethod === 'INFO' && code >= 200 && cseqMatch) {
      const key = `${cid}:${cseqMatch[1]}`;
      const pending = this.pendingPbxInfo.get(key);
      if (pending) {
        clearTimeout(pending.timer);
        this.pendingPbxInfo.delete(key);
        await pending.onResponse(code, reason);
      }
      return;
    }

    if (cseqMethod !== 'INVITE') return;
    if (code === 100) return;

    if (call.state === 'ended') {
      if (code >= 300) {
        const ackBranch = call.pbxViaLines[0] ?? `z9hG4bK${randHex(8)}`;
        const ackPbx =
          `ACK ${call.pbxTargetUri} SIP/2.0\r\n` +
          `Via: SIP/2.0/UDP ${this.config.localPubIp}:${this.config.localPubPort};branch=${ackBranch};rport\r\n` +
          `Max-Forwards: 70\r\nFrom: ${call.pbxFromHdr}\r\nTo: ${toHeader}\r\n` +
          `Call-ID: ${call.pbxCid}\r\nCSeq: ${call.pbxCseqNum} ACK\r\nContent-Length: 0\r\n\r\n`;
        this.sendPbx(ackPbx);
      }
      return;
    }

    if ((code === 401 || code === 407) && call.direction === 'mo') {
      const challengeHdr = code === 401 ? parsed.headers['www-authenticate'] : parsed.headers['proxy-authenticate'];
      const ackBranch = call.pbxViaLines[0] ?? `z9hG4bK${randHex(8)}`;
      const ack =
        `ACK ${call.pbxTargetUri} SIP/2.0\r\n` +
        `Via: SIP/2.0/UDP ${this.config.localPubIp}:${this.config.localPubPort};branch=${ackBranch};rport\r\n` +
        `Max-Forwards: 70\r\nFrom: ${call.pbxFromHdr}\r\nTo: ${toHeader}\r\n` +
        `Call-ID: ${call.pbxCid}\r\nCSeq: ${call.pbxCseqNum} ACK\r\nContent-Length: 0\r\n\r\n`;
      this.sendPbx(ack);

      if (challengeHdr && call.pbxAuthAttempts < 2) {
        call.pbxAuthAttempts++;
        call.pbxCseqNum = ++this.pbxSeq;
        call.pbxCseqHdr = `${call.pbxCseqNum} INVITE`;
        const authHdrName = code === 401 ? 'Authorization' : 'Proxy-Authorization';
        const authHdr = buildDigestHeader(authHdrName, 'INVITE', call.pbxTargetUri, this.config.username, this.config.password, challengeHdr);
        this.sendMoPbxInvite(call, authHdr);
        return;
      }
    }

    if (call.direction !== 'mo') return;

    const imsVia = formatMultiHeaders('Via', call.imsViaLines);
    const imsRr = formatMultiHeaders('Record-Route', call.imsRecordRoutes);
    const imsTo = `${call.imsToBaseHdr};tag=${call.imsToTag}`;

    let sdpForIms = '';
    if (parsed.body && (code === 180 || code === 183 || code === 200)) {
      try {
        const ansRes = await this.rtp.command({
          command: 'answer',
          'call-id': call.rtpCallId,
          'from-tag': call.rtpFromTag,
          'to-tag': call.rtpToTag,
          sdp: parsed.body,
          direction: ['pub', 'ims'],
          'transport-protocol': 'RTP/AVP',
          ICE: 'remove',
          flags: RTPENGINE_TRUNK_FLAGS,
        });
        sdpForIms = cleanSdpForPbx(ansRes.sdp);
        call.imsAnswerSdp = sdpForIms;
      } catch (err) {
        this.logger.warn({ err: String(err), trunk: this.config.id, cid: call.imsCid }, 'ims-sip-trunk: MO rtpengine answer failed');
      }
    } else if (code === 200 && call.imsAnswerSdp) {
      sdpForIms = call.imsAnswerSdp;
    }

    if (code >= 180 && code < 200) {
      const msg =
        `SIP/2.0 ${code} ${reason}\r\n${imsVia}${imsRr}From: ${call.imsFromHdr}\r\nTo: ${imsTo}\r\n` +
        `Call-ID: ${call.imsCid}\r\nCSeq: ${call.imsCseqHdr}\r\n` +
        this.imsContactHeader(this.config.username, true) +
        (sdpForIms ? `Content-Type: application/sdp\r\nContent-Length: ${Buffer.byteLength(sdpForIms)}\r\n\r\n${sdpForIms}` : 'Content-Length: 0\r\n\r\n');
      this.replyToImsPeer(call, msg);
      return;
    }

    if (code >= 200 && code < 300) {
      call.state = 'answered';
      this.logger.info({ trunk: this.config.id, direction: 'mo', imsCid: call.imsCid, pbxCid: call.pbxCid, hasSdp: Boolean(sdpForIms) }, 'ims-sip-trunk: MO call answered');
      const pbxAckUri = call.pbxRemoteTarget ?? call.pbxTargetUri;
      const pbxRoute = call.pbxRouteSet ? `Route: ${call.pbxRouteSet}\r\n` : '';
      const ackPbx =
        `ACK ${pbxAckUri} SIP/2.0\r\n` +
        `Via: SIP/2.0/UDP ${this.config.localPubIp}:${this.config.localPubPort};branch=z9hG4bK${randHex(8)};rport\r\n` +
        `Max-Forwards: 70\r\nFrom: ${call.pbxFromHdr}\r\nTo: ${toHeader}\r\n` +
        pbxRoute +
        `Call-ID: ${call.pbxCid}\r\nCSeq: ${call.pbxCseqNum} ACK\r\nContent-Length: 0\r\n\r\n`;
      this.sendPbx(ackPbx);

      const sdpSection = sdpForIms
        ? `Content-Type: application/sdp\r\nContent-Length: ${Buffer.byteLength(sdpForIms)}\r\n\r\n${sdpForIms}`
        : 'Content-Length: 0\r\n\r\n';
      const okMsg =
        `SIP/2.0 200 OK\r\n${imsVia}${imsRr}From: ${call.imsFromHdr}\r\nTo: ${imsTo}\r\n` +
        `Call-ID: ${call.imsCid}\r\nCSeq: ${call.imsCseqHdr}\r\n` +
        this.imsContactHeader(this.config.username, true) +
        `Allow: ${ALLOW_SIP_METHODS}\r\n` +
        sdpSection;
      this.replyToImsPeer(call, okMsg);
      return;
    }

    if (code >= 300) {
      const ackBranch = call.pbxViaLines[0] ?? `z9hG4bK${randHex(8)}`;
      const ackPbx =
        `ACK ${call.pbxTargetUri} SIP/2.0\r\n` +
        `Via: SIP/2.0/UDP ${this.config.localPubIp}:${this.config.localPubPort};branch=${ackBranch};rport\r\n` +
        `Max-Forwards: 70\r\nFrom: ${call.pbxFromHdr}\r\nTo: ${toHeader}\r\n` +
        `Call-ID: ${call.pbxCid}\r\nCSeq: ${call.pbxCseqNum} ACK\r\nContent-Length: 0\r\n\r\n`;
      this.sendPbx(ackPbx);

      const failMsg =
        `SIP/2.0 ${code} ${reason}\r\n${imsVia}${imsRr}From: ${call.imsFromHdr}\r\nTo: ${imsTo}\r\n` +
        `Call-ID: ${call.imsCid}\r\nCSeq: ${call.imsCseqHdr}\r\nContent-Length: 0\r\n\r\n`;
      this.replyToImsPeer(call, failMsg);
      await this.cleanupCall(call);
    }
  }

  private async handleImsResponse(parsed: ParsedSip): Promise<void> {
    const cid = parsed.headers['call-id'] ?? '';
    const call = this.callsByImsCid.get(cid);
    if (!call) return;

    const statusMatch = /^SIP\/2\.0\s+(\d{3})\s*(.*)$/.exec(parsed.statusLine);
    if (!statusMatch) return;
    const code = Number(statusMatch[1]);
    const reason = statusMatch[2] || '';
    const cseqMatch = /(\d+)\s+(\w+)/.exec(parsed.headers['cseq'] ?? '');
    const cseqMethod = (cseqMatch?.[2] ?? '').toUpperCase();
    const toHeader = parsed.headers['to'] ?? '';
    const toTagMatch = /;tag=([^;\s]+)/i.exec(toHeader);
    if (toTagMatch) call.imsToTag = toTagMatch[1];
    call.imsToFullHdr = toHeader;

    const contactUri = extractUriFromHeader(parsed.headers['contact']);
    if (contactUri) call.imsRemoteTarget = contactUri;
    if (parsed.headerLines['record-route'] && !call.imsRouteSet) {
      call.imsRouteSet = reverseRecordRoutes(parsed.headerLines['record-route']);
    }

    const computePbxAnswer = (sdpBody: string): Promise<string | undefined> => {
      const p = this.rtp.command({
        command: 'answer',
        'call-id': call.rtpCallId,
        'from-tag': call.rtpFromTag,
        'to-tag': call.rtpToTag,
        sdp: cleanSdpForPbx(sdpBody),
        direction: ['ims', 'pub'],
        'transport-protocol': 'RTP/AVP',
        ICE: 'remove',
        flags: RTPENGINE_TRUNK_FLAGS,
      }).then((ansRes) => {
        const cleaned = cleanSdpForPbx(ansRes.sdp);
        if (cleaned) call.pbxAnswerSdp = cleaned;
        return cleaned;
      }).catch((err) => {
        this.logger.warn({ err: String(err), trunk: this.config.id, cid: call.pbxCid }, 'ims-sip-trunk: MT rtpengine answer failed');
        return undefined;
      });
      call.pbxAnswerPromise = p;
      return p;
    };

    if (call.direction === 'mt' && cseqMethod === 'UPDATE' && code >= 200 && code < 300 && parsed.body && call.state !== 'ended') {
      await computePbxAnswer(parsed.body);
      return;
    }

    if (cseqMethod === 'INFO' && code >= 200 && cseqMatch) {
      const key = `${cid}:${cseqMatch[1]}`;
      const pending = this.pendingImsInfo.get(key);
      if (pending) {
        clearTimeout(pending.timer);
        this.pendingImsInfo.delete(key);
        await pending.onResponse(code, reason);
      }
      return;
    }

    if (cseqMethod !== 'INVITE' || call.direction !== 'mt') return;
    if (code === 100) return;

    if (call.state === 'ended') {
      if (code >= 300) {
        const ackBranch = call.imsViaLines[0] ?? `z9hG4bK${randHex(8)}`;
        const ackIms =
          `ACK ${call.imsCallerUri} SIP/2.0\r\n` +
          `Via: SIP/2.0/UDP ${this.imsBindIp}:${this.config.imsPort};branch=${ackBranch};rport\r\n` +
          `Max-Forwards: 70\r\nFrom: ${call.imsFromHdr}\r\nTo: ${toHeader}\r\n` +
          `Call-ID: ${call.imsCid}\r\nCSeq: ${call.imsCseqNum} ACK\r\nContent-Length: 0\r\n\r\n`;
        this.sendIms(ackIms, this.icscfPort, this.icscfIp);
      }
      return;
    }

    // RFC 3262 PRACK if the UE requires 100rel on provisional responses.
    if (code > 100 && code < 200 && /\b100rel\b/i.test(parsed.headers['require'] ?? '') && parsed.headers['rseq']) {
      const rseq = parsed.headers['rseq'].trim();
      const target = call.imsRemoteTarget ?? call.imsCallerUri;
      const routeHdr = call.imsRouteSet ? `Route: ${call.imsRouteSet}\r\n` : '';
      const prack =
        `PRACK ${target} SIP/2.0\r\n` +
        `Via: SIP/2.0/UDP ${this.imsBindIp}:${this.config.imsPort};branch=z9hG4bK${randHex(8)};rport\r\n` +
        `Max-Forwards: 70\r\nFrom: ${call.imsFromHdr}\r\nTo: ${toHeader}\r\n` +
        `Call-ID: ${call.imsCid}\r\nCSeq: ${++this.imsSeq} PRACK\r\n` +
        `RAck: ${rseq} ${call.imsCseqHdr}\r\n` +
        routeHdr +
        `Content-Length: 0\r\n\r\n`;
      this.sendImsByRoute(prack, call);
    }

    const peerUsesPreconditions =
      /a=(curr|des|conf):qos/i.test(parsed.body) ||
      /\bprecondition\b/i.test(parsed.headers['require'] ?? '');

    if ((code === 180 || code === 183 || code === 200) && peerUsesPreconditions && !call.imsUpdateSent && call.imsOfferSdp) {
      call.imsUpdateSent = true;
      const target = call.imsRemoteTarget ?? call.imsCallerUri;
      const routeHdr = call.imsRouteSet ? `Route: ${call.imsRouteSet}\r\n` : '';
      const updateSdp = injectImsPreconditions(call.imsOfferSdp)
        .replace(/^a=curr:qos local .*$/im, 'a=curr:qos local sendrecv');
      const update =
        `UPDATE ${target} SIP/2.0\r\n` +
        `Via: SIP/2.0/UDP ${this.imsBindIp}:${this.config.imsPort};branch=z9hG4bK${randHex(8)};rport\r\n` +
        `Max-Forwards: 70\r\nFrom: ${call.imsFromHdr}\r\nTo: ${toHeader}\r\n` +
        `Call-ID: ${call.imsCid}\r\nCSeq: ${++this.imsSeq} UPDATE\r\n` +
        this.imsContactHeader(call.pbxCallerNumber, true) +
        routeHdr +
        `Content-Type: application/sdp\r\nContent-Length: ${Buffer.byteLength(updateSdp)}\r\n\r\n${updateSdp}`;
      this.sendImsByRoute(update, call);
    }

    const pbxVia = formatMultiHeaders('Via', call.pbxViaLines);
    const pbxRr = formatMultiHeaders('Record-Route', call.pbxRecordRoutes);
    const pbxTo = `${call.pbxToBaseHdr};tag=${call.pbxToTag}`;

    // Pixel 9 Pro / VoLTE UEs send the SDP answer in 183 Session Progress and omit SDP in 200 OK.
    const answerPromise = parsed.body && (code === 180 || code === 183 || (code >= 200 && code < 300))
      ? computePbxAnswer(parsed.body)
      : undefined;

    if (code === 180 || code === 183) {
      const provisionalSdp = answerPromise ? ((await answerPromise) ?? '') : '';
      const sdpSection = provisionalSdp
        ? `Content-Type: application/sdp\r\nContent-Length: ${Buffer.byteLength(provisionalSdp)}\r\n\r\n${provisionalSdp}`
        : 'Content-Length: 0\r\n\r\n';
      const provMsg =
        `SIP/2.0 ${code} ${reason || (code === 180 ? 'Ringing' : 'Session Progress')}\r\n` +
        `${pbxVia}${pbxRr}From: ${call.pbxFromHdr}\r\nTo: ${pbxTo}\r\n` +
        `Call-ID: ${call.pbxCid}\r\nCSeq: ${call.pbxCseqHdr}\r\n` +
        this.pubContactHeader() +
        sdpSection;
      this.sendPbx(provMsg);
      return;
    }

    if (code >= 200 && code < 300) {
      call.state = 'answered';
      const imsAckUri = call.imsRemoteTarget ?? call.imsCallerUri;
      const routeHdr = call.imsRouteSet ? `Route: ${call.imsRouteSet}\r\n` : '';
      const ackIms =
        `ACK ${imsAckUri} SIP/2.0\r\n` +
        `Via: SIP/2.0/UDP ${this.imsBindIp}:${this.config.imsPort};branch=z9hG4bK${randHex(8)};rport\r\n` +
        `Max-Forwards: 70\r\nFrom: ${call.imsFromHdr}\r\nTo: ${toHeader}\r\n` +
        routeHdr +
        `Call-ID: ${call.imsCid}\r\nCSeq: ${call.imsCseqNum} ACK\r\nContent-Length: 0\r\n\r\n`;
      this.sendImsByRoute(ackIms, call);

      let pbxSdp = '';
      if (answerPromise) {
        pbxSdp = (await answerPromise) ?? '';
      } else if (call.pbxAnswerPromise) {
        pbxSdp = (await call.pbxAnswerPromise) ?? '';
      }
      if (!pbxSdp && call.pbxAnswerSdp) {
        pbxSdp = call.pbxAnswerSdp;
      }

      this.logger.info(
        { trunk: this.config.id, direction: 'mt', imsCid: call.imsCid, pbxCid: call.pbxCid, hasSdp: Boolean(pbxSdp) },
        'ims-sip-trunk: MT call answered',
      );
      const sdpSection = pbxSdp
        ? `Content-Type: application/sdp\r\nContent-Length: ${Buffer.byteLength(pbxSdp)}\r\n\r\n${pbxSdp}`
        : 'Content-Length: 0\r\n\r\n';
      const okPbx =
        `SIP/2.0 200 OK\r\n${pbxVia}${pbxRr}From: ${call.pbxFromHdr}\r\nTo: ${pbxTo}\r\n` +
        `Call-ID: ${call.pbxCid}\r\nCSeq: ${call.pbxCseqHdr}\r\n` +
        this.pubContactHeader() +
        `Allow: ${ALLOW_SIP_METHODS}\r\n` +
        sdpSection;
      this.sendPbx(okPbx);
      return;
    }

    if (code >= 300) {
      const ackBranch = call.imsViaLines[0] ?? `z9hG4bK${randHex(8)}`;
      const ackIms =
        `ACK ${call.imsCallerUri} SIP/2.0\r\n` +
        `Via: SIP/2.0/UDP ${this.imsBindIp}:${this.config.imsPort};branch=${ackBranch};rport\r\n` +
        `Max-Forwards: 70\r\nFrom: ${call.imsFromHdr}\r\nTo: ${toHeader}\r\n` +
        `Call-ID: ${call.imsCid}\r\nCSeq: ${call.imsCseqNum} ACK\r\nContent-Length: 0\r\n\r\n`;
      this.sendIms(ackIms, this.icscfPort, this.icscfIp);

      const failPbx =
        `SIP/2.0 ${code} ${reason}\r\n${pbxVia}${pbxRr}From: ${call.pbxFromHdr}\r\nTo: ${pbxTo}\r\n` +
        `Call-ID: ${call.pbxCid}\r\nCSeq: ${call.pbxCseqHdr}\r\nContent-Length: 0\r\n\r\n`;
      this.sendPbx(failPbx);
      await this.cleanupCall(call);
    }
  }

  private replyToImsPeer(call: TrunkCall, msg: string): void {
    const topVia = call.imsViaLines[0] ?? '';
    const m = /^SIP\/2\.0\/(\w+)\s+([^\s:;]+)(?::(\d+))?/i.exec(topVia);
    if (call.imsPeer?.replyFn) {
      call.imsPeer.replyFn(msg);
      return;
    }
    if (m) {
      this.sendIms(msg, Number(m[3] || 5060), m[2]);
    } else if (call.imsPeer) {
      this.sendIms(msg, call.imsPeer.port, call.imsPeer.address);
    }
  }

  private sendImsByRoute(msg: string, call: TrunkCall): void {
    const firstRoute = call.imsRouteSet?.split(',')[0]?.trim();
    const routeUri = extractUriFromHeader(firstRoute);
    const m = routeUri ? /^sips?:(?:[^@]+@)?([^:;>]+)(?::(\d+))?/i.exec(routeUri) : null;
    if (m) {
      this.sendIms(msg, Number(m[2] || 5060), m[1]);
      return;
    }
    this.sendIms(msg, this.icscfPort, this.icscfIp);
  }
}

// ── Manager & REST Controller ───────────────────────────────────────────────

function readSavedTrunks(): ImsSipTrunkConfig[] {
  for (const p of [DEFAULT_TRUNKS_FILE, HOST_TRUNKS_FALLBACK]) {
    if (fs.existsSync(p)) {
      try {
        const parsed = JSON.parse(fs.readFileSync(p, 'utf-8'));
        if (Array.isArray(parsed)) return parsed;
      } catch { /* ignore */ }
    }
  }
  return [];
}

function writeSavedTrunks(trunks: ImsSipTrunkConfig[]): void {
  const payload = JSON.stringify(trunks, null, 2);
  fs.mkdirSync(path.dirname(DEFAULT_TRUNKS_FILE), { recursive: true });
  fs.writeFileSync(DEFAULT_TRUNKS_FILE, payload, 'utf-8');
  if (fs.existsSync('/proc/1/root/etc/open5gs')) {
    fs.writeFileSync(HOST_TRUNKS_FALLBACK, payload, 'utf-8');
  }
}

export function formatImsSipTrunkDispatcherEntry(): string | null {
  const state = readImsState();
  if (!state) return null;
  const enabled = readSavedTrunks().filter((t) => t.enabled);
  if (enabled.length === 0) return null;
  const pcscfIp = state.config.pcscfIp;
  return enabled.map((t) => `1 sip:${pcscfIp}:${t.imsPort}`).join('\n') + '\n';
}

export function getImsSipTrunkPublicIps(): string[] {
  return [...new Set(readSavedTrunks().filter((t) => t.enabled).map((t) => t.localPubIp))];
}

export class ImsSipTrunkManager {
  private readonly instances = new Map<string, ImsSipTrunkInstance>();

  constructor(private readonly logger: pino.Logger) {}

  list(): ImsSipTrunkStatus[] {
    return [...this.instances.values()].map((i) => i.info());
  }

  has(id: string): boolean {
    return this.instances.has(id);
  }

  async createOrUpdate(input: {
    id?: string;
    name?: string;
    remoteHost: string;
    remotePort?: number;
    username: string;
    password?: string;
    localPubIp?: string;
    localPubPort?: number;
    imsPort?: number;
    sendRpid?: boolean;
    sendPai?: boolean;
    codecs?: string[];
    enabled?: boolean;
  }): Promise<ImsSipTrunkStatus> {
    const state = readImsState();
    if (!state) throw new Error('IMS is not configured yet — configure IMS first');
    const id = (input.id?.trim() || `${input.username}-${input.remoteHost}`).replace(/[^a-zA-Z0-9_.-]/g, '_');

    const prev = this.instances.get(id);
    const resolvedPassword = input.password ? input.password : prev?.config.password;
    if (!resolvedPassword) {
      throw new Error('password is required for a new SIP trunk');
    }
    if (prev) {
      await prev.stop();
      this.instances.delete(id);
    }

    const usedImsPorts = new Set([...this.instances.values()].map((i) => i.config.imsPort));
    let imsPort = Number(input.imsPort) || prev?.config.imsPort || DEFAULT_IMS_BIND_PORT;
    while (usedImsPorts.has(imsPort)) imsPort++;

    const cfg: ImsSipTrunkConfig = {
      id,
      name: input.name?.trim() || `FreePBX (${input.remoteHost})`,
      remoteHost: input.remoteHost.trim(),
      remotePort: Number(input.remotePort) || 5060,
      username: input.username.trim(),
      password: resolvedPassword,
      localPubIp: input.localPubIp?.trim() || prev?.config.localPubIp || detectFirstLanIp(),
      localPubPort: Number(input.localPubPort) || prev?.config.localPubPort || DEFAULT_PUB_PORT,
      imsPort,
      sendRpid: input.sendRpid !== false,
      sendPai: input.sendPai !== false,
      codecs: Array.isArray(input.codecs) && input.codecs.length > 0 ? input.codecs : [...DEFAULT_TRUNK_CODECS],
      enabled: input.enabled !== false,
      createdAt: prev?.config.createdAt ?? new Date().toISOString(),
    };

    const instance = await this.startInstance(cfg, state);
    this.persistAll();
    return instance.info();
  }

  private async startInstance(cfg: ImsSipTrunkConfig, state: NonNullable<ReturnType<typeof readImsState>>): Promise<ImsSipTrunkInstance> {
    const extCfg = state.config as { pcscfIp: string; icscfIp?: string; icscfPort?: number };
    const instance = new ImsSipTrunkInstance(
      cfg,
      state.imsDomain,
      extCfg.pcscfIp,
      extCfg.icscfIp ?? '127.0.1.1',
      extCfg.icscfPort ?? 4060,
      this.logger,
    );
    await instance.start();
    this.instances.set(cfg.id, instance);
    return instance;
  }

  async delete(id: string): Promise<void> {
    const inst = this.instances.get(id);
    if (!inst) throw new Error(`Unknown SIP trunk ${id}`);
    await inst.stop();
    this.instances.delete(id);
    this.persistAll();
  }

  async reregister(id: string): Promise<ImsSipTrunkStatus> {
    const inst = this.instances.get(id);
    if (!inst) throw new Error(`Unknown SIP trunk ${id}`);
    await inst.registerOnce();
    return inst.info();
  }

  private persistAll(): void {
    writeSavedTrunks([...this.instances.values()].map((i) => i.config));
  }

  async reconcile(): Promise<void> {
    const state = readImsState();
    if (!state) return;
    const saved = readSavedTrunks();
    for (const cfg of saved) {
      if (this.instances.has(cfg.id)) continue;
      try {
        await this.startInstance(cfg, state);
      } catch (err) {
        this.logger.warn({ err: String(err), trunk: cfg.id }, 'ims-sip-trunk: failed to start saved trunk');
      }
    }
  }

  async stopAll(): Promise<void> {
    for (const inst of this.instances.values()) {
      await inst.stop().catch(() => { /* best-effort shutdown */ });
    }
    this.instances.clear();
  }
}

export function createImsSipTrunkRouter(manager: ImsSipTrunkManager, auditLogger: IAuditLogger): Router {
  const router = Router();

  router.get('/', (_req: Request, res: Response) => {
    res.json({ success: true, trunks: manager.list() });
  });

  router.post('/', requireAdmin, async (req: Request, res: Response) => {
    const user = (req as any).user?.username ?? 'unknown';
    const { id, remoteHost, username, password } = req.body ?? {};
    const hasExisting = typeof id === 'string' && manager.has(id);
    if (!remoteHost || !username || (!password && !hasExisting)) {
      return res.status(400).json({ success: false, error: 'remoteHost, username, and password are required' });
    }
    try {
      const trunk = await manager.createOrUpdate(req.body);
      await auditLogger.log({
        action: 'ims_trunk_create',
        user,
        details: `id=${trunk.id} remote=${trunk.remoteHost}:${trunk.remotePort} user=${trunk.username} pub=${trunk.localPubIp}:${trunk.localPubPort}`,
        success: true,
      });
      res.json({ success: true, trunk });
    } catch (err) {
      await auditLogger.log({ action: 'ims_trunk_create', user, details: String(err), success: false });
      res.status(400).json({ success: false, error: (err as Error).message ?? String(err) });
    }
  });

  router.post('/:id/reregister', requireAdmin, async (req: Request, res: Response) => {
    const user = (req as any).user?.username ?? 'unknown';
    try {
      const trunk = await manager.reregister(req.params.id);
      await auditLogger.log({ action: 'ims_trunk_reregister', user, details: `id=${req.params.id}`, success: true });
      res.json({ success: true, trunk });
    } catch (err) {
      await auditLogger.log({ action: 'ims_trunk_reregister', user, details: String(err), success: false });
      res.status(400).json({ success: false, error: (err as Error).message ?? String(err) });
    }
  });

  router.delete('/:id', requireAdmin, async (req: Request, res: Response) => {
    const user = (req as any).user?.username ?? 'unknown';
    try {
      await manager.delete(req.params.id);
      await auditLogger.log({ action: 'ims_trunk_delete', user, details: `id=${req.params.id}`, success: true });
      res.json({ success: true });
    } catch (err) {
      await auditLogger.log({ action: 'ims_trunk_delete', user, details: String(err), success: false });
      res.status(400).json({ success: false, error: (err as Error).message ?? String(err) });
    }
  });

  return router;
}
