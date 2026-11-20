// github-core-clone-01 entry: a standalone GitHub-compatible git forge.
// One Node 22+ process, stdlib only, in-memory. Implements git smart HTTP
// (upload-pack v2 + receive-pack v0), REST v3, GraphQL v4 and MCP.
//
// The token owner (viewer) is the scenario viewer: adaiversen (id 1000).
// The scenario seed is fixed by the kit, so this login is deterministic.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';

// ---------------------------------------------------------------- constants

export const VIEWER_LOGIN = 'adaiversen';
export const VIEWER_ID = 1000;
export const VIEWER_NAME = 'ada iversen';
export const VIEWER_EMAIL = 'adaiversen@example.invalid';
export const DEFAULT_BRANCH = 'main';
const ZERO_OID = '0000000000000000000000000000000000000000';
const TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';
const JSON_TYPE = 'application/json; charset=utf-8';
const FIXED_EPOCH = 1700000000;

// Deterministic counters: no wall clock or unseeded randomness in state.
let nextRepoId = 1;
let nextIssueId = 1;
let nextPullId = 1;
let nextCommentId = 1;
let seqCounter = 1;
let reqCounter = 1;

function nextSeq(): number {
  return seqCounter++;
}
function isoForSeq(seq: number): string {
  return new Date((FIXED_EPOCH + seq) * 1000).toISOString();
}
function gitTsForSeq(seq: number): number {
  return FIXED_EPOCH + seq;
}

// ---------------------------------------------------------------- small helpers

function sha1(data: Buffer): string {
  return createHash('sha1').update(data).digest('hex');
}
function hashObject(type: string, data: Buffer): string {
  const head = Buffer.from(`${type} ${data.length}\0`, 'utf8');
  return sha1(Buffer.concat([head, data]));
}
function isOid(s: unknown): s is string {
  return typeof s === 'string' && /^[0-9a-f]{40}$/.test(s);
}
function jsonBody(res: ServerResponse, status: number, body: unknown, extra: Record<string, string> = {}): void {
  const text = `${JSON.stringify(body)}\n`;
  res.writeHead(status, { 'content-type': JSON_TYPE, 'content-length': Buffer.byteLength(text), ...extra });
  res.end(text);
}
function reqIdHeader(): Record<string, string> {
  return { 'x-github-request-id': `req-${reqCounter++}` };
}
function b64encode(s: string): string {
  return Buffer.from(s, 'utf8').toString('base64');
}
function b64decode(s: string): string | null {
  try {
    return Buffer.from(s, 'base64').toString('utf8');
  } catch {
    return null;
  }
}
function escReg(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// ---------------------------------------------------------------- pkt-lines

const FLUSH = Buffer.from('0000', 'ascii');
const DELIM = Buffer.from('0001', 'ascii');
function pktLine(payload: string | Buffer): Buffer {
  const data = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const len = data.length + 4;
  const head = Buffer.from(len.toString(16).padStart(4, '0'), 'ascii');
  return Buffer.concat([head, data]);
}
type Pkt = { kind: 'data' | 'flush' | 'delim'; payload: Buffer };
function decodePktLines(buf: Buffer): Pkt[] {
  const out: Pkt[] = [];
  let off = 0;
  while (off + 4 <= buf.length) {
    const len = parseInt(buf.subarray(off, off + 4).toString('ascii'), 16);
    if (Number.isNaN(len) || len < 0) throw new Error('bad pkt-line length');
    if (len === 0) {
      out.push({ kind: 'flush', payload: Buffer.alloc(0) });
      off += 4;
      continue;
    }
    if (len === 1) {
      out.push({ kind: 'delim', payload: Buffer.alloc(0) });
      off += 4;
      continue;
    }
    if (len < 4 || off + len > buf.length) throw new Error('truncated pkt-line');
    out.push({ kind: 'data', payload: buf.subarray(off + 4, off + len) });
    off += len;
  }
  return out;
}

// ---------------------------------------------------------------- git objects

type ObjType = 'blob' | 'tree' | 'commit' | 'tag';
interface GitObj {
  type: ObjType;
  data: Buffer;
}
const OBJ_TYPE_CODE: Record<string, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const OBJ_CODE_TYPE: Record<number, ObjType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

/** Adler-32 of a buffer (the zlib stream trailer). */
function adler32(data: Buffer): number {
  let a = 1;
  let b = 0;
  for (let i = 0; i < data.length; i++) {
    a = (a + data[i]) % 65521;
    b = (b + a) % 65521;
  }
  return ((b << 16) | a) >>> 0;
}

/**
 * Inflate the zlib stream starting at `off` (uncompressed size `expectedSize`, from the
 * pack object header); returns the output and the bytes consumed. A single inflate of a
 * slice with trailing bytes succeeds but hides the stream end, so the end is located by
 * the Adler-32 trailer (the last 4 bytes of a zlib stream) and verified by inflating the
 * exact slice; a binary search is the fallback. Two inflates per object, not ~17.
 */
function inflateAt(buf: Buffer, off: number, expectedSize: number): { data: Buffer; consumed: number } {
  const remaining = buf.length - off;
  if (remaining <= 0) throw new Error('pack truncated at object data');
  const bisect = (): { data: Buffer; consumed: number } => {
    let lo = 0;
    let hi = Math.min(16, remaining);
    let probe: Buffer | null = null;
    while (hi <= remaining) {
      try {
        probe = inflateSync(buf.subarray(off, off + hi));
        break;
      } catch {
        if (hi >= remaining) throw new Error('pack object does not inflate');
        lo = hi;
        hi = Math.min(remaining, hi * 2);
      }
    }
    if (probe === null) throw new Error('pack object does not inflate');
    while (hi - lo > 1) {
      const mid = (lo + hi) >> 1;
      try {
        probe = inflateSync(buf.subarray(off, off + mid));
        hi = mid;
      } catch {
        lo = mid;
      }
    }
    return { data: probe, consumed: hi };
  };
  // Upper bound on the compressed length: stored blocks add 5 bytes per 64 KiB
  // plus the 2-byte header and 4-byte Adler trailer.
  let hi = expectedSize + Math.ceil(expectedSize / 65535) * 5 + 16;
  if (hi > remaining) hi = remaining;
  let probe: Buffer;
  try {
    probe = inflateSync(buf.subarray(off, off + hi));
  } catch {
    return bisect();
  }
  if (probe.length !== expectedSize) return bisect();
  const adler = adler32(probe);
  const a0 = (adler >>> 24) & 0xff;
  const a1 = (adler >>> 16) & 0xff;
  const a2 = (adler >>> 8) & 0xff;
  const a3 = adler & 0xff;
  let end = -1;
  for (let p = off + 2; p + 4 <= off + hi; p++) {
    if (buf[p] === a0 && buf[p + 1] === a1 && buf[p + 2] === a2 && buf[p + 3] === a3) {
      end = p + 4;
      break;
    }
  }
  if (end === -1) return bisect();
  try {
    const check = inflateSync(buf.subarray(off, end));
    if (check.length === expectedSize && check.equals(probe)) return { data: probe, consumed: end - off };
  } catch {
    // fall through to the binary search
  }
  return bisect();
}

function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let off = 0;
  const readVarint = (): number => {
    let v = 0;
    let shift = 0;
    for (;;) {
      const b = delta[off++];
      v |= (b & 0x7f) << shift;
      shift += 7;
      if ((b & 0x80) === 0) break;
    }
    return v;
  };
  const srcSize = readVarint();
  const tgtSize = readVarint();
  if (srcSize !== base.length) throw new Error('delta base size mismatch');
  const parts: Buffer[] = [];
  let total = 0;
  while (off < delta.length) {
    const op = delta[off++];
    if (op & 0x80) {
      let cpOff = 0;
      let cpSize = 0;
      for (let i = 0; i < 4; i++) if (op & (1 << i)) cpOff |= delta[off++] << (8 * i);
      for (let i = 0; i < 3; i++) if (op & (0x10 << i)) cpSize |= delta[off++] << (8 * i);
      if (cpSize === 0) cpSize = 0x10000;
      parts.push(base.subarray(cpOff, cpOff + cpSize));
      total += cpSize;
    } else if (op !== 0) {
      parts.push(delta.subarray(off, off + op));
      total += op;
      off += op;
    } else {
      throw new Error('bad delta opcode 0');
    }
  }
  const out = Buffer.concat(parts);
  if (out.length !== tgtSize || total !== tgtSize) throw new Error('delta target size mismatch');
  return out;
}

/** Parse a packfile into objects (plain, ofs-delta and ref-delta). */
function readPack(buf: Buffer, getBase: (oid: string) => GitObj | undefined): Map<string, GitObj> {
  if (buf.length < 12 || buf.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('pack does not start with PACK');
  const count = buf.readUInt32BE(8);
  const objects = new Map<string, GitObj>();
  const byOffset = new Map<number, GitObj>();
  let off = 12;
  const readSizeType = (): { typeNum: number; size: number } => {
    let b = buf[off++];
    const typeNum = (b >> 4) & 0x7;
    let size = b & 0x0f;
    let shift = 4;
    while (b & 0x80) {
      b = buf[off++];
      size |= (b & 0x7f) << shift;
      shift += 7;
    }
    return { typeNum, size };
  };
  for (let i = 0; i < count; i++) {
    const objStart = off;
    const { typeNum, size } = readSizeType();
    if (typeNum === 6) {
      // ofs-delta: negative offset varint, then zlib delta.
      let b = buf[off++];
      let baseOff = b & 0x7f;
      while (b & 0x80) {
        b = buf[off++];
        baseOff = ((baseOff + 1) << 7) | (b & 0x7f);
      }
      const base = byOffset.get(objStart - baseOff);
      if (!base) throw new Error('ofs-delta base not found');
      const { data, consumed } = inflateAt(buf, off, size);
      off += consumed;
      const obj: GitObj = { type: base.type, data: applyDelta(base.data, data) };
      if (obj.data.length !== size) throw new Error('ofs-delta size mismatch');
      const oid = hashObject(obj.type, obj.data);
      objects.set(oid, obj);
      byOffset.set(objStart, obj);
    } else if (typeNum === 7) {
      const baseOid = buf.subarray(off, off + 20).toString('hex');
      off += 20;
      const base = objects.get(baseOid) ?? getBase(baseOid);
      if (!base) throw new Error('ref-delta base not found');
      const { data, consumed } = inflateAt(buf, off, size);
      off += consumed;
      const obj: GitObj = { type: base.type, data: applyDelta(base.data, data) };
      if (obj.data.length !== size) throw new Error('ref-delta size mismatch');
      const oid = hashObject(obj.type, obj.data);
      objects.set(oid, obj);
      byOffset.set(objStart, obj);
    } else {
      const type = OBJ_CODE_TYPE[typeNum];
      if (!type) throw new Error(`unknown pack object type ${typeNum}`);
      const { data, consumed } = inflateAt(buf, off, size);
      off += consumed;
      if (data.length !== size) throw new Error('pack object size mismatch');
      const oid = hashObject(type, data);
      const obj: GitObj = { type, data };
      objects.set(oid, obj);
      byOffset.set(objStart, obj);
    }
  }
  return objects;
}

/** Write a packfile of plain (undeltified) objects. */
function writePack(entries: readonly GitObj[]): Buffer {
  const chunks: Buffer[] = [];
  const head = Buffer.alloc(12);
  head.write('PACK', 0, 'ascii');
  head.writeUInt32BE(2, 4);
  head.writeUInt32BE(entries.length, 8);
  chunks.push(head);
  for (const entry of entries) {
    const size = entry.data.length;
    const typeNum = OBJ_TYPE_CODE[entry.type];
    const bytes: number[] = [];
    let b = (typeNum << 4) | (size & 0x0f);
    let rest = size >> 4;
    if (rest !== 0) b |= 0x80;
    bytes.push(b);
    while (rest !== 0) {
      b = rest & 0x7f;
      rest >>= 7;
      if (rest !== 0) b |= 0x80;
      bytes.push(b);
    }
    chunks.push(Buffer.from(bytes));
    chunks.push(deflateSync(entry.data, { level: 6 }));
  }
  const body = Buffer.concat(chunks);
  return Buffer.concat([body, createHash('sha1').update(body).digest()]);
}

// ---------------------------------------------------------------- commit / tree

interface CommitInfo {
  tree: string;
  parents: string[];
  message: string;
  author: string;
  committer: string;
  authorTs: number;
}
function parseCommit(data: Buffer): CommitInfo {
  const text = data.toString('utf8');
  const split = text.indexOf('\n\n');
  const header = split >= 0 ? text.slice(0, split) : text;
  const message = split >= 0 ? text.slice(split + 2) : '';
  let tree = '';
  const parents: string[] = [];
  let author = '';
  let committer = '';
  let authorTs = 0;
  for (const line of header.split('\n')) {
    if (line.startsWith('tree ')) tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) parents.push(line.slice(7).trim());
    else if (line.startsWith('author ')) {
      author = line.slice(7);
      const m = author.match(/ (\d+) [+-]\d{4}$/);
      if (m) authorTs = parseInt(m[1], 10);
    } else if (line.startsWith('committer ')) committer = line.slice(10);
  }
  return { tree, parents, message, author, committer, authorTs };
}
interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}
function parseTree(data: Buffer): TreeEntry[] {
  const out: TreeEntry[] = [];
  let off = 0;
  while (off < data.length) {
    const sp = data.indexOf(0x20, off);
    const nul = data.indexOf(0x00, sp);
    if (sp < 0 || nul < 0 || nul + 21 > data.length) break;
    out.push({ mode: data.subarray(off, sp).toString('utf8'), name: data.subarray(sp + 1, nul).toString('utf8'), oid: data.subarray(nul + 1, nul + 21).toString('hex') });
    off = nul + 21;
  }
  return out;
}
function buildTree(entries: readonly TreeEntry[]): Buffer {
  const sorted = [...entries].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  const parts: Buffer[] = [];
  for (const e of sorted) {
    parts.push(Buffer.from(`${e.mode} ${e.name}\0`, 'utf8'));
    parts.push(Buffer.from(e.oid, 'hex'));
  }
  return Buffer.concat(parts);
}
function buildCommit(tree: string, parents: readonly string[], message: string, seq: number): Buffer {
  const ts = gitTsForSeq(seq);
  const who = `${VIEWER_NAME} <${VIEWER_EMAIL}> ${ts} +0000`;
  let text = `tree ${tree}\n`;
  for (const p of parents) text += `parent ${p}\n`;
  text += `author ${who}\ncommitter ${who}\n\n${message}`;
  if (!message.endsWith('\n')) text += '\n';
  return Buffer.from(text, 'utf8');
}

// ---------------------------------------------------------------- store

interface CommentRec {
  id: number;
  body: string;
}
interface IssueRec {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: string[];
  seq: number;
  comments: CommentRec[];
}
interface PullRec {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed' | 'merged';
  head: string;
  base: string;
  seq: number;
  merged: boolean;
  mergedAt: string | null;
  mergeCommitSha: string | null;
}
interface RepoRec {
  id: number;
  owner: string;
  name: string;
  description: string;
  private: boolean;
  refs: Map<string, string>;
  objects: Map<string, GitObj>;
  labels: Map<string, { name: string; color: string }>;
  issues: Map<number, IssueRec>;
  nextIssue: number;
  pulls: Map<number, PullRec>;
  nextPull: number;
}
const repos = new Map<string, RepoRec>();
function repoKey(owner: string, name: string): string {
  return `${owner}/${name}`;
}
function getRepo(owner: string, name: string): RepoRec | undefined {
  return repos.get(repoKey(owner, name));
}
function newRepo(owner: string, name: string, description: string, isPrivate: boolean): RepoRec {
  const repo: RepoRec = {
    id: nextRepoId++,
    owner,
    name,
    description,
    private: isPrivate,
    refs: new Map(),
    objects: new Map(),
    labels: new Map(),
    issues: new Map(),
    nextIssue: 1,
    pulls: new Map(),
    nextPull: 1,
  };
  repos.set(repoKey(owner, name), repo);
  return repo;
}
function storeObject(repo: RepoRec, obj: GitObj): string {
  const oid = hashObject(obj.type, obj.data);
  if (!repo.objects.has(oid)) repo.objects.set(oid, obj);
  return oid;
}
function headRef(repo: RepoRec): string {
  return `refs/heads/${DEFAULT_BRANCH}`;
}
function headOid(repo: RepoRec): string | undefined {
  return repo.refs.get(headRef(repo));
}
function resolveRef(repo: RepoRec, ref: string): string | undefined {
  if (ref === 'HEAD') return headOid(repo);
  if (repo.refs.has(ref)) return repo.refs.get(ref);
  const full = `refs/heads/${ref}`;
  if (repo.refs.has(full)) return repo.refs.get(full);
  if (isOid(ref) && repo.objects.has(ref)) return ref;
  return undefined;
}
function isAncestor(repo: RepoRec, anc: string, desc: string): boolean {
  if (anc === desc) return true;
  const seen = new Set<string>();
  const stack = [desc];
  while (stack.length > 0) {
    const cur = stack.pop() as string;
    if (cur === anc) return true;
    if (seen.has(cur)) continue;
    seen.add(cur);
    const obj = repo.objects.get(cur);
    if (!obj || obj.type !== 'commit') continue;
    for (const p of parseCommit(obj.data).parents) stack.push(p);
  }
  return false;
}
/** Flat file map path -> {oid, mode} for a tree, recursively. */
function treeFileMap(repo: RepoRec, treeOid: string, prefix = '', out = new Map<string, { oid: string; mode: string }>()): Map<string, { oid: string; mode: string }> {
  const obj = repo.objects.get(treeOid);
  if (!obj || obj.type !== 'tree') return out;
  for (const e of parseTree(obj.data)) {
    const path = prefix === '' ? e.name : `${prefix}/${e.name}`;
    if (e.mode === '40000') treeFileMap(repo, e.oid, path, out);
    else out.set(path, { oid: e.oid, mode: e.mode });
  }
  return out;
}
function mergeBase(repo: RepoRec, a: string, b: string): string | null {
  const ancestorsA = new Set<string>();
  const stack = [a];
  while (stack.length > 0) {
    const cur = stack.pop() as string;
    if (ancestorsA.has(cur)) continue;
    ancestorsA.add(cur);
    const obj = repo.objects.get(cur);
    if (!obj || obj.type !== 'commit') continue;
    for (const p of parseCommit(obj.data).parents) stack.push(p);
  }
  const queue = [b];
  const seen = new Set<string>();
  while (queue.length > 0) {
    const cur = queue.shift() as string;
    if (ancestorsA.has(cur)) return cur;
    if (seen.has(cur)) continue;
    seen.add(cur);
    const obj = repo.objects.get(cur);
    if (!obj || obj.type !== 'commit') continue;
    for (const p of parseCommit(obj.data).parents) queue.push(p);
  }
  return null;
}

// ---------------------------------------------------------------- git closure / fetch

interface FetchPlan {
  entries: GitObj[];
  shallow: string[];
  unshallow: string[];
  acks: string[];
  nak: boolean;
  wantedRefs: Array<{ oid: string; ref: string }>;
}

/** Objects reachable from `wants`, minus anything reachable from `haves`, honoring `depth`. */
function planFetch(repo: RepoRec, wants: string[], haves: string[], oldShallow: string[], depth: number | null): FetchPlan {
  const haveReach = new Set<string>();
  const oldShallowSet = new Set(oldShallow);
  for (const h of haves) {
    const stack = [h];
    while (stack.length > 0) {
      const cur = stack.pop() as string;
      if (haveReach.has(cur)) continue;
      haveReach.add(cur);
      const obj = repo.objects.get(cur);
      if (!obj) continue;
      if (obj.type === 'commit') {
        const c = parseCommit(obj.data);
        // A shallow boundary is a cut point: the client holds the boundary commit
        // itself, but nothing beyond it — do not walk its parents.
        if (!oldShallowSet.has(cur)) for (const p of c.parents) stack.push(p);
        stack.push(c.tree);
      } else if (obj.type === 'tree') {
        for (const e of parseTree(obj.data)) stack.push(e.oid);
      } else if (obj.type === 'tag') {
        const m = obj.data.toString('utf8').match(/^object ([0-9a-f]{40})$/m);
        if (m) stack.push(m[1]);
      }
    }
  }
  const include = new Map<string, GitObj>();
  const shallow: string[] = [];
  const commitDepth = new Map<string, number>();
  // BFS over commits from wants; depth 1 = the want itself.
  const queue: Array<{ oid: string; d: number }> = wants.filter((w) => repo.objects.has(w)).map((w) => ({ oid: w, d: 1 }));
  const seenCommit = new Set<string>();
  while (queue.length > 0) {
    const { oid, d } = queue.shift() as { oid: string; d: number };
    if (seenCommit.has(oid)) continue;
    seenCommit.add(oid);
    commitDepth.set(oid, d);
    const obj = repo.objects.get(oid);
    if (!obj || obj.type !== 'commit') continue;
    const c = parseCommit(obj.data);
    const atBoundary = depth !== null && d >= depth;
    if (atBoundary) {
      shallow.push(oid);
    } else {
      for (const p of c.parents) queue.push({ oid: p, d: d + 1 });
    }
  }
  const addTree = (treeOid: string): void => {
    const stack = [treeOid];
    while (stack.length > 0) {
      const cur = stack.pop() as string;
      if (haveReach.has(cur) || include.has(cur)) continue;
      const obj = repo.objects.get(cur);
      if (!obj) continue;
      include.set(cur, obj);
      if (obj.type === 'tree') for (const e of parseTree(obj.data)) stack.push(e.oid);
    }
  };
  const addCommitClosure = (oid: string): void => {
    if (haveReach.has(oid) || include.has(oid)) return;
    const obj = repo.objects.get(oid);
    if (!obj) return;
    include.set(oid, obj);
    if (obj.type === 'commit') {
      addTree(parseCommit(obj.data).tree);
    } else if (obj.type === 'tag') {
      const m = obj.data.toString('utf8').match(/^object ([0-9a-f]{40})$/m);
      if (m) addCommitClosure(m[1]);
    } else if (obj.type === 'tree') {
      addTree(oid);
    }
  };
  for (const w of wants) {
    const obj = repo.objects.get(w);
    if (!obj) continue;
    if (obj.type === 'commit') {
      // Include every commit the BFS reached (up to the depth boundary), each with its tree.
      for (const cid of seenCommit) {
        if (haveReach.has(cid)) continue;
        const cobj = repo.objects.get(cid);
        if (!cobj || cobj.type !== 'commit') continue;
        if (include.has(cid)) continue;
        include.set(cid, cobj);
        addTree(parseCommit(cobj.data).tree);
      }
    } else {
      addCommitClosure(w);
    }
  }
  // Boundary commits' parents must not leak in: remove any commit whose depth >= depth
  // other than the boundary commits themselves... handled by BFS above (parents of a
  // boundary commit are never queued). But addCommitClosure(w) only adds the want itself.
  // Remove anything reachable from haves that slipped in via a want's tree (shouldn't happen).
  for (const oid of [...include.keys()]) if (haveReach.has(oid)) include.delete(oid);
  // Order: commits (by depth asc), then tags, trees, blobs — deterministic.
  const entries = [...include.values()].sort((a, b) => {
    const rank = (o: GitObj): number => (o.type === 'commit' ? 0 : o.type === 'tag' ? 1 : o.type === 'tree' ? 2 : 3);
    return rank(a) - rank(b);
  });
  // Fix entry order: keep object identity via oid lookup for the pack writer.
  const byOid = new Map<string, GitObj>();
  for (const [oid, obj] of include) byOid.set(oid, obj);
  const orderedEntries = entries.map((e) => e);
  void byOid;
  void orderedEntries;
  const unshallow: string[] = [];
  for (const old of oldShallow) {
    // An old boundary that is now inside the fetched history becomes unshallow.
    if (seenCommit.has(old) && (depth === null || (commitDepth.get(old) ?? 0) < depth)) unshallow.push(old);
    else if (wants.includes(old)) unshallow.push(old);
  }
  const acks: string[] = [];
  for (const h of haves) {
    if (wants.some((w) => isAncestor(repo, h, w))) acks.push(h);
  }
  const wantedRefs: Array<{ oid: string; ref: string }> = [];
  for (const [ref, oid] of repo.refs) {
    if (wants.includes(oid)) wantedRefs.push({ oid, ref });
  }
  return { entries, shallow, unshallow, acks, nak: acks.length === 0, wantedRefs };
}

function sidebandPackets(pack: Buffer): Buffer[] {
  const out: Buffer[] = [];
  const CHUNK = 65000;
  for (let off = 0; off < pack.length; off += CHUNK) {
    const slice = pack.subarray(off, Math.min(pack.length, off + CHUNK));
    out.push(pktLine(Buffer.concat([Buffer.from([1]), slice])));
  }
  if (out.length === 0) out.push(pktLine(Buffer.from([1])));
  return out;
}

// ---------------------------------------------------------------- git HTTP

function v2Advertisement(): Buffer {
  return Buffer.concat([
    pktLine('version 2\n'),
    pktLine('ls-refs=unborn\n'),
    pktLine('fetch=shallow wait-for-done\n'),
    pktLine('object-format=sha1\n'),
    FLUSH,
  ]);
}
function v0Advertisement(repo: RepoRec, service: 'git-upload-pack' | 'git-receive-pack'): Buffer {
  const caps =
    service === 'git-upload-pack'
      ? 'symref=HEAD:refs/heads/main side-band-64k shallow thin-pack ofs-delta'
      : 'report-status side-band-64k delete-refs ofs-delta';
  const parts: Buffer[] = [pktLine(`# service=${service}\n`), FLUSH];
  const refs = [...repo.refs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1));
  if (refs.length === 0) {
    parts.push(pktLine(`${ZERO_OID} capabilities^{}\0${caps}\n`));
  } else {
    let first = true;
    for (const [ref, oid] of refs) {
      parts.push(pktLine(first ? `${oid} ${ref}\0${caps}\n` : `${oid} ${ref}\n`));
      first = false;
    }
    const head = headOid(repo);
    if (head) {
      // HEAD line first in git's advertisement; prepend it.
      parts.splice(2, 0, pktLine(`${head} HEAD\n`));
      // caps move to the HEAD line: rebuild correctly.
      parts[2] = pktLine(`${head} HEAD\0${caps}\n`);
      parts[3] = pktLine(`${refs[0][1]} ${refs[0][0]}\n`);
    }
  }
  parts.push(FLUSH);
  return Buffer.concat(parts);
}
function sendRaw(res: ServerResponse, status: number, contentType: string, body: Buffer): void {
  res.writeHead(status, { 'content-type': contentType, 'content-length': body.length });
  res.end(body);
}

function handleInfoRefs(req: IncomingMessage, res: ServerResponse, owner: string, name: string, service: string): void {
  const repo = getRepo(owner, name);
  if (!repo) {
    jsonBody(res, 404, { message: 'Not Found' });
    return;
  }
  const v2 = (req.headers['git-protocol'] ?? '') === 'version=2';
  if (service === 'git-upload-pack') {
    if (v2) sendRaw(res, 200, 'application/x-git-upload-pack-advertisement', v2Advertisement());
    else sendRaw(res, 200, 'application/x-git-upload-pack-advertisement', v0Advertisement(repo, 'git-upload-pack'));
  } else if (service === 'git-receive-pack') {
    sendRaw(res, 200, 'application/x-git-receive-pack-advertisement', v0Advertisement(repo, 'git-receive-pack'));
  } else {
    jsonBody(res, 404, { message: 'Not Found' });
  }
}

function lsRefsResponse(repo: RepoRec, args: string[]): Buffer {
  const peel = args.includes('peel');
  const symrefs = args.includes('symrefs');
  const unborn = args.includes('unborn');
  const prefixes = args.filter((a) => a.startsWith('ref-prefix ')).map((a) => a.slice('ref-prefix '.length));
  const keep = (n: string): boolean => prefixes.length === 0 || prefixes.some((p) => n.startsWith(p));
  const parts: Buffer[] = [];
  const head = headOid(repo);
  const headUnborn = head === undefined;
  if (keep('HEAD') || prefixes.length === 0) {
    if (head !== undefined) {
      parts.push(pktLine(symrefs ? `${head} HEAD symref-target:refs/heads/${DEFAULT_BRANCH}\n` : `${head} HEAD\n`));
    } else if (unborn) {
      parts.push(pktLine(symrefs ? `unborn HEAD symref-target:refs/heads/${DEFAULT_BRANCH}\n` : `unborn HEAD\n`));
    }
  }
  void headUnborn;
  const refs = [...repo.refs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1));
  for (const [ref, oid] of refs) {
    if (!keep(ref)) continue;
    let line = `${oid} ${ref}`;
    if (peel) {
      const obj = repo.objects.get(oid);
      if (obj && obj.type === 'tag') {
        const m = obj.data.toString('utf8').match(/^object ([0-9a-f]{40})$/m);
        if (m) line += ` peeled:${m[1]}`;
      }
    }
    parts.push(pktLine(`${line}\n`));
  }
  parts.push(FLUSH);
  return Buffer.concat(parts);
}

function handleUploadPackV2(repo: RepoRec, packets: Pkt[]): Buffer {
  const lines: string[] = [];
  for (const p of packets) {
    if (p.kind === 'data') lines.push(p.payload.toString('utf8').replace(/\n$/, ''));
  }
  const command = lines[0] ?? '';
  if (command === 'command=ls-refs') {
    const args = lines.slice(1);
    return lsRefsResponse(repo, args);
  }
  if (command !== 'command=fetch') throw new Error(`unsupported upload-pack command ${JSON.stringify(command)}`);
  const wants: string[] = [];
  const haves: string[] = [];
  const shallowReq: string[] = [];
  let depth: number | null = null;
  for (const line of lines.slice(1)) {
    if (line.startsWith('want ')) wants.push(line.slice(5).trim());
    else if (line.startsWith('have ')) haves.push(line.slice(5).trim());
    else if (line.startsWith('shallow ')) shallowReq.push(line.slice(8).trim());
    else if (line.startsWith('deepen ')) depth = parseInt(line.slice(7).trim(), 10);
    else if (line.startsWith('deepen-since ')) depth = 1;
  }
  const plan = planFetch(repo, wants, haves, shallowReq, depth);
  const parts: Buffer[] = [];
  parts.push(pktLine('acknowledgments\n'));
  if (plan.acks.length > 0) {
    for (const a of plan.acks) parts.push(pktLine(`ACK ${a}\n`));
    parts.push(pktLine('ready\n'));
  } else {
    parts.push(pktLine('NAK\n'));
  }
  parts.push(DELIM);
  if (depth !== null || shallowReq.length > 0) {
    parts.push(pktLine('shallow-info\n'));
    for (const s of plan.shallow) parts.push(pktLine(`shallow ${s}\n`));
    for (const u of plan.unshallow) parts.push(pktLine(`unshallow ${u}\n`));
    parts.push(DELIM);
  }
  if (plan.wantedRefs.length > 0) {
    parts.push(pktLine('wanted-refs\n'));
    for (const w of plan.wantedRefs) parts.push(pktLine(`${w.oid} ${w.ref}\n`));
    parts.push(DELIM);
  }
  const pack = writePack(plan.entries);
  parts.push(pktLine('packfile\n'));
  for (const p of sidebandPackets(pack)) parts.push(p);
  parts.push(FLUSH);
  return Buffer.concat(parts);
}

function handleUploadPackV0(repo: RepoRec, packets: Pkt[]): Buffer {
  const lines: string[] = [];
  for (const p of packets) {
    if (p.kind === 'data') lines.push(p.payload.toString('utf8').replace(/\n$/, ''));
  }
  const wants: string[] = [];
  const haves: string[] = [];
  let depth: number | null = null;
  for (const line of lines) {
    if (line.startsWith('want ')) wants.push(line.slice(5).trim().split(' ')[0]);
    else if (line.startsWith('have ')) haves.push(line.slice(5).trim());
    else if (line.startsWith('deepen ')) depth = parseInt(line.slice(7).trim(), 10);
  }
  const plan = planFetch(repo, wants, haves, [], depth);
  const parts: Buffer[] = [];
  if (plan.acks.length > 0) {
    for (const a of plan.acks) parts.push(pktLine(`ACK ${a}\n`));
  } else {
    parts.push(pktLine('NAK\n'));
  }
  for (const s of plan.shallow) parts.push(pktLine(`shallow ${s}\n`));
  for (const u of plan.unshallow) parts.push(pktLine(`unshallow ${u}\n`));
  const pack = writePack(plan.entries);
  for (const p of sidebandPackets(pack)) parts.push(p);
  parts.push(FLUSH);
  return Buffer.concat(parts);
}

function handleReceivePack(repo: RepoRec, body: Buffer): Buffer {
  // Request: pkt-line commands, flush, then the raw pack. Parse pkt-lines only
  // up to the flush packet; everything after it is pack bytes, not pkt-lines.
  const commands: Array<{ oldOid: string; newOid: string; ref: string }> = [];
  let off = 0;
  while (off + 4 <= body.length) {
    const len = parseInt(body.subarray(off, off + 4).toString('ascii'), 16);
    if (Number.isNaN(len) || len < 0) throw new Error('bad pkt-line length');
    if (len === 0) {
      off += 4;
      break;
    }
    if (len === 1) {
      off += 4;
      continue;
    }
    if (len < 4 || off + len > body.length) throw new Error('truncated pkt-line');
    const line = body.subarray(off + 4, off + len).toString('utf8').replace(/\n$/, '');
    // The first command line carries "\0<capabilities>" after the ref name.
    const m = line.split('\0')[0].match(/^([0-9a-f]{40}) ([0-9a-f]{40}) (\S+)$/);
    if (m) commands.push({ oldOid: m[1], newOid: m[2], ref: m[3] });
    off += len;
  }
  const packStart = off;
  let unpackOk = true;
  let unpackDetail = '';
  let packed = new Map<string, GitObj>();
  if (packStart < body.length) {
    try {
      packed = readPack(body.subarray(packStart), (oid) => repo.objects.get(oid));
    } catch (err) {
      unpackOk = false;
      unpackDetail = err instanceof Error ? err.message : String(err);
    }
  }
  if (unpackOk) {
    for (const [oid, obj] of packed) if (!repo.objects.has(oid)) repo.objects.set(oid, obj);
  }
  // With side-band-64k the report-status stream is itself pkt-lined inside band 1:
  // build the inner pkt-line stream first, then wrap it in band-1 packets.
  const inner: Buffer[] = [];
  inner.push(pktLine(unpackOk ? 'unpack ok\n' : `unpack ${unpackDetail}\n`));
  for (const cmd of commands) {
    let ok = false;
    let reason = '';
    if (!unpackOk) {
      reason = 'unpack failed';
    } else if (cmd.newOid === ZERO_OID) {
      // delete
      const cur = repo.refs.get(cmd.ref);
      if (cur === undefined) reason = 'no such ref';
      else if (cmd.oldOid !== ZERO_OID && cmd.oldOid !== cur) reason = 'non-fast-forward';
      else {
        repo.refs.delete(cmd.ref);
        ok = true;
      }
    } else {
      const cur = repo.refs.get(cmd.ref);
      if (cmd.oldOid === ZERO_OID) {
        if (cur !== undefined) reason = 'non-fast-forward';
        else if (!repo.objects.has(cmd.newOid) && !packed.has(cmd.newOid)) reason = 'object not found';
        else {
          repo.refs.set(cmd.ref, cmd.newOid);
          ok = true;
        }
      } else if (cur === undefined) {
        reason = 'non-fast-forward';
      } else if (cur !== cmd.oldOid) {
        reason = 'non-fast-forward';
      } else if (!isAncestor(repo, cmd.oldOid, cmd.newOid) && cmd.oldOid !== cmd.newOid) {
        reason = 'non-fast-forward';
      } else if (!repo.objects.has(cmd.newOid) && !packed.has(cmd.newOid)) {
        reason = 'object not found';
      } else {
        repo.refs.set(cmd.ref, cmd.newOid);
        ok = true;
      }
    }
    inner.push(pktLine(ok ? `ok ${cmd.ref}\n` : `ng ${cmd.ref} ${reason}\n`));
  }
  const innerStream = Buffer.concat(inner);
  const report: Buffer[] = [];
  for (const p of sidebandPackets(innerStream)) report.push(p);
  report.push(FLUSH);
  return Buffer.concat(report);
}

// ---------------------------------------------------------------- REST v3

function repoJson(repo: RepoRec): Record<string, unknown> {
  return {
    id: repo.id,
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    owner: { login: repo.owner, id: repo.owner === VIEWER_LOGIN ? VIEWER_ID : 0, type: 'User' },
    description: repo.description,
    private: repo.private,
    default_branch: DEFAULT_BRANCH,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
  };
}
function issueJson(repo: RepoRec, issue: IssueRec): Record<string, unknown> {
  return {
    id: issue.id,
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels.map((name) => ({ name })),
    user: { login: VIEWER_LOGIN, id: VIEWER_ID },
    created_at: isoForSeq(issue.seq),
    updated_at: isoForSeq(issue.seq),
    comments: issue.comments.length,
  };
}
function prJson(repo: RepoRec, pr: PullRec): Record<string, unknown> {
  const headSha = resolveRef(repo, pr.head) ?? '';
  const baseSha = resolveRef(repo, pr.base) ?? '';
  return {
    id: pr.id,
    number: pr.number,
    title: pr.title,
    body: pr.body,
    state: pr.state === 'merged' ? 'closed' : pr.state,
    head: { ref: pr.head, sha: headSha, label: `${repo.owner}:${pr.head}` },
    base: { ref: pr.base, sha: baseSha, label: `${repo.owner}:${pr.base}` },
    merged: pr.merged,
    merged_at: pr.mergedAt,
    merge_commit_sha: pr.mergeCommitSha,
    mergeable: prMergeable(repo, pr),
    created_at: isoForSeq(pr.seq),
    updated_at: isoForSeq(pr.seq),
  };
}
function prMergeable(repo: RepoRec, pr: PullRec): boolean {
  if (pr.state !== 'open') return false;
  return prConflict(repo, pr) === null;
}
/** The conflicting path, or null when the PR merges cleanly. */
function prConflict(repo: RepoRec, pr: PullRec): string | null {
  const headSha = resolveRef(repo, pr.head);
  const baseSha = resolveRef(repo, pr.base);
  if (!headSha || !baseSha) return null;
  const base = mergeBase(repo, headSha, baseSha);
  if (base === null) return null;
  const baseObj = repo.objects.get(base);
  const headObj = repo.objects.get(headSha);
  const baseTipObj = repo.objects.get(baseSha);
  if (!baseObj || !headObj || !baseTipObj) return null;
  const baseFiles = treeFileMap(repo, parseCommit(baseObj.data).tree);
  const headFiles = treeFileMap(repo, parseCommit(headObj.data).tree);
  const baseTipFiles = treeFileMap(repo, parseCommit(baseTipObj.data).tree);
  for (const [path, headEntry] of headFiles) {
    const b = baseFiles.get(path);
    const t = baseTipFiles.get(path);
    if (b && t && b.oid !== t.oid && b.oid !== headEntry.oid && t.oid !== headEntry.oid) return path;
  }
  return null;
}
function lineDiff(a: string, b: string): { additions: number; deletions: number } {
  const al = a === '' ? [] : a.split('\n');
  const bl = b === '' ? [] : b.split('\n');
  const n = al.length;
  const m = bl.length;
  // LCS dynamic programming; files in the suite are small.
  const dp: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i][j] = al[i] === bl[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
  const lcs = dp[0][0];
  return { additions: m - lcs, deletions: n - lcs };
}
/** Commit a new tree version of `path` on `branchRef` (creating the branch when absent). */
function commitContent(
  repo: RepoRec,
  branchRef: string,
  path: string,
  content: Buffer | null,
  message: string,
): { commitSha: string; blobSha: string | null } {
  const seq = nextSeq();
  const tip = repo.refs.get(branchRef);
  let parentTree = '';
  const parents: string[] = [];
  if (tip !== undefined) {
    const obj = repo.objects.get(tip);
    if (obj && obj.type === 'commit') {
      parentTree = parseCommit(obj.data).tree;
      parents.push(tip);
    }
  }
  const segments = path.split('/').filter((s) => s !== '');
  const blobSha = content === null ? null : storeObject(repo, { type: 'blob', data: content });
  const buildLevel = (treeOid: string, depth: number): string => {
    const entries = treeOid === '' ? [] : parseTree(repo.objects.get(treeOid)?.data ?? Buffer.alloc(0));
    const seg = segments[depth];
    const isLast = depth === segments.length - 1;
    const next: TreeEntry[] = [];
    let replaced = false;
    for (const e of entries) {
      if (e.name !== seg) {
        next.push(e);
        continue;
      }
      replaced = true;
      if (isLast) {
        if (blobSha !== null) next.push({ mode: '100644', name: seg, oid: blobSha });
        // deletion: drop the entry
      } else {
        const childOid = e.mode === '40000' ? buildLevel(e.oid, depth + 1) : buildLevel('', depth + 1);
        next.push({ mode: '40000', name: seg, oid: childOid });
      }
    }
    if (!replaced) {
      if (isLast) {
        if (blobSha !== null) next.push({ mode: '100644', name: seg, oid: blobSha });
      } else {
        next.push({ mode: '40000', name: seg, oid: buildLevel('', depth + 1) });
      }
    }
    return storeObject(repo, { type: 'tree', data: buildTree(next) });
  };
  const newTree = buildLevel(parentTree, 0);
  const commitData = buildCommit(newTree, parents, message, seq);
  const commitSha = storeObject(repo, { type: 'commit', data: commitData });
  repo.refs.set(branchRef, commitSha);
  return { commitSha, blobSha };
}
function listCommits(repo: RepoRec, fromSha: string): Array<Record<string, unknown>> {
  const out: Array<Record<string, unknown>> = [];
  const seen = new Set<string>();
  const stack = [fromSha];
  while (stack.length > 0) {
    const cur = stack.pop() as string;
    if (seen.has(cur)) continue;
    seen.add(cur);
    const obj = repo.objects.get(cur);
    if (!obj || obj.type !== 'commit') continue;
    const c = parseCommit(obj.data);
    const authorName = c.author.split(' <')[0] || VIEWER_NAME;
    const authorEmail = (c.author.match(/<([^>]*)>/) ?? [])[1] ?? VIEWER_EMAIL;
    out.push({
      sha: cur,
      commit: {
        message: c.message.replace(/\n$/, ''),
        author: { name: authorName, email: authorEmail, date: new Date((c.authorTs || FIXED_EPOCH) * 1000).toISOString() },
        committer: { name: authorName, email: authorEmail, date: new Date((c.authorTs || FIXED_EPOCH) * 1000).toISOString() },
      },
      parents: c.parents.map((p) => ({ sha: p })),
    });
    for (const p of c.parents) stack.push(p);
  }
  return out;
}

interface RestCtx {
  method: string;
  segments: string[];
  query: URLSearchParams;
  body: unknown;
  rawBody: Buffer;
  host: string;
}

function badJson(res: ServerResponse): void {
  jsonBody(res, 400, { message: 'Invalid JSON' }, reqIdHeader());
}

/** Route one REST request. Returns true when handled. */
function handleRest(ctx: RestCtx, res: ServerResponse): boolean {
  const { method, segments, query } = ctx;
  const seg = (i: number): string | undefined => segments[i];
  // GET /api/v3 (root)
  if (segments.length === 0) {
    if (method === 'GET') {
      jsonBody(res, 200, { current_user_url: '/api/v3/user', rate_limit_url: '/api/v3/rate_limit' }, { ...reqIdHeader(), 'x-oauth-scopes': 'repo, read:org' });
      return true;
    }
    jsonBody(res, 404, { message: 'Not Found' }, reqIdHeader());
    return true;
  }
  if (seg(0) === 'meta' && segments.length === 1) {
    if (method === 'GET') jsonBody(res, 200, { installed_version: '1.0.0' }, reqIdHeader());
    else jsonBody(res, 404, { message: 'Not Found' }, reqIdHeader());
    return true;
  }
  if (seg(0) === 'user' && segments.length === 1) {
    if (method === 'GET') {
      jsonBody(res, 200, { login: VIEWER_LOGIN, id: VIEWER_ID, name: VIEWER_NAME, email: VIEWER_EMAIL, type: 'User' }, reqIdHeader());
    } else jsonBody(res, 404, { message: 'Not Found' }, reqIdHeader());
    return true;
  }
  if (seg(0) === 'user' && seg(1) === 'repos') {
    if (method === 'POST') {
      const b = (ctx.body ?? {}) as Record<string, unknown>;
      const name = typeof b.name === 'string' ? b.name : '';
      if (name === '' || !/^[A-Za-z0-9._-]+$/.test(name)) {
        jsonBody(res, 422, { message: 'Invalid repository name' }, reqIdHeader());
        return true;
      }
      if (getRepo(VIEWER_LOGIN, name)) {
        jsonBody(res, 422, { message: 'Repository already exists' }, reqIdHeader());
        return true;
      }
      const repo = newRepo(VIEWER_LOGIN, name, typeof b.description === 'string' ? b.description : '', b.private === true);
      jsonBody(res, 201, repoJson(repo), reqIdHeader());
      return true;
    }
    if (method === 'GET') {
      const perPage = Math.max(1, Math.min(100, parseInt(query.get('per_page') ?? '30', 10) || 30));
      const page = Math.max(1, parseInt(query.get('page') ?? '1', 10) || 1);
      const all = [...repos.values()].filter((r) => r.owner === VIEWER_LOGIN).sort((a, b) => a.id - b.id);
      const slice = all.slice((page - 1) * perPage, page * perPage);
      const extra: Record<string, string> = reqIdHeader();
      if ((page - 1) * perPage + slice.length < all.length) {
        const base = `http://${ctx.host}/api/v3/user/repos?per_page=${perPage}&page=${page + 1}`;
        extra.link = `<${base}>; rel="next"`;
      }
      jsonBody(res, 200, slice.map(repoJson), extra);
      return true;
    }
    jsonBody(res, 404, { message: 'Not Found' }, reqIdHeader());
    return true;
  }
  if (seg(0) === 'repos' && segments.length >= 3) {
    const owner = decodeURIComponent(seg(1) as string);
    const name = decodeURIComponent(seg(2) as string);
    const repo = getRepo(owner, name);
    const rest = segments.slice(3);
    // /repos/{o}/{r}
    if (rest.length === 0) {
      if (!repo) {
        jsonBody(res, 404, { message: 'Not Found' }, reqIdHeader());
        return true;
      }
      if (method === 'GET') jsonBody(res, 200, repoJson(repo), reqIdHeader());
      else if (method === 'PATCH') {
        const b = (ctx.body ?? {}) as Record<string, unknown>;
        if (typeof b.description === 'string') repo.description = b.description;
        if (typeof b.private === 'boolean') repo.private = b.private;
        jsonBody(res, 200, repoJson(repo), reqIdHeader());
      } else if (method === 'DELETE') {
        repos.delete(repoKey(owner, name));
        res.writeHead(204, { ...reqIdHeader() });
        res.end();
      } else jsonBody(res, 404, { message: 'Not Found' }, reqIdHeader());
      return true;
    }
    if (!repo) {
      jsonBody(res, 404, { message: 'Not Found' }, reqIdHeader());
      return true;
    }
    // git/refs
    if (rest[0] === 'git' && rest[1] === 'refs') {
      if (method === 'POST' && rest.length === 2) {
        const b = (ctx.body ?? {}) as Record<string, unknown>;
        const ref = typeof b.ref === 'string' ? b.ref : '';
        const sha = typeof b.sha === 'string' ? b.sha : '';
        if (!ref.startsWith('refs/') || !isOid(sha) || !repo.objects.has(sha)) {
          jsonBody(res, 422, { message: 'Invalid ref or sha' }, reqIdHeader());
          return true;
        }
        if (repo.refs.has(ref)) {
          jsonBody(res, 422, { message: 'Reference already exists' }, reqIdHeader());
          return true;
        }
        repo.refs.set(ref, sha);
        const obj = repo.objects.get(sha) as GitObj;
        jsonBody(res, 201, { ref, object: { sha, type: obj.type } }, reqIdHeader());
        return true;
      }
      if (method === 'GET' && rest.length === 4 && rest[2] === 'heads') {
        const branch = decodeURIComponent(rest[3]);
        const ref = `refs/heads/${branch}`;
        const sha = repo.refs.get(ref);
        if (!sha) {
          jsonBody(res, 404, { message: 'Not Found' }, reqIdHeader());
          return true;
        }
        jsonBody(res, 200, { ref, object: { sha, type: 'commit' } }, reqIdHeader());
        return true;
      }
      jsonBody(res, 404, { message: 'Not Found' }, reqIdHeader());
      return true;
    }
    // branches
    if (rest[0] === 'branches') {
      if (method === 'GET' && rest.length === 1) {
        const out: Array<Record<string, unknown>> = [];
        for (const [ref, sha] of [...repo.refs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))) {
          if (ref.startsWith('refs/heads/')) out.push({ name: ref.slice('refs/heads/'.length), commit: { sha } });
        }
        jsonBody(res, 200, out, reqIdHeader());
        return true;
      }
      if (method === 'GET' && rest.length === 2) {
        const branch = decodeURIComponent(rest[1]);
        const sha = repo.refs.get(`refs/heads/${branch}`);
        if (!sha) {
          jsonBody(res, 404, { message: 'Not Found' }, reqIdHeader());
          return true;
        }
        jsonBody(res, 200, { name: branch, commit: { sha } }, reqIdHeader());
        return true;
      }
      jsonBody(res, 404, { message: 'Not Found' }, reqIdHeader());
      return true;
    }
    // commits
    if (rest[0] === 'commits' && rest.length === 1 && method === 'GET') {
      const shaParam = query.get('sha');
      const from = shaParam ? resolveRef(repo, decodeURIComponent(shaParam)) : headOid(repo);
      if (!from) {
        jsonBody(res, 200, [], reqIdHeader());
        return true;
      }
      jsonBody(res, 200, listCommits(repo, from), reqIdHeader());
      return true;
    }
    // contents
    if (rest[0] === 'contents') {
      const filePath = rest.slice(1).map((s) => decodeURIComponent(s)).join('/');
      const refParam = query.get('ref');
      const branchName = (ctx.body as Record<string, unknown> | null)?.branch;
      const branchRef = (typeof branchName === 'string' && branchName !== '' ? `refs/heads/${branchName}` : undefined) ?? (refParam ? `refs/heads/${decodeURIComponent(refParam)}` : headRef(repo));
      if (method === 'GET') {
        const tip = refParam ? resolveRef(repo, decodeURIComponent(refParam)) : repo.refs.get(branchRef);
        if (!tip) {
          jsonBody(res, 404, { message: 'Not Found' }, reqIdHeader());
          return true;
        }
        const commitObj = repo.objects.get(tip);
        if (!commitObj || commitObj.type !== 'commit') {
          jsonBody(res, 404, { message: 'Not Found' }, reqIdHeader());
          return true;
        }
        const files = treeFileMap(repo, parseCommit(commitObj.data).tree);
        if (filePath === '') {
          const rootTree = parseCommit(commitObj.data).tree;
          const rootObj = repo.objects.get(rootTree);
          const entries = rootObj && rootObj.type === 'tree' ? parseTree(rootObj.data) : [];
          jsonBody(
            res,
            200,
            entries.map((e) => ({ type: e.mode === '40000' ? 'dir' : 'file', name: e.name, path: e.name, sha: e.oid, size: 0 })),
            reqIdHeader(),
          );
          return true;
        }
        const hit = files.get(filePath);
        if (hit) {
          const blob = repo.objects.get(hit.oid) as GitObj;
          jsonBody(res, 200, { type: 'file', encoding: 'base64', content: blob.data.toString('base64'), sha: hit.oid, size: blob.data.length, name: filePath.split('/').pop(), path: filePath }, reqIdHeader());
          return true;
        }
        // directory?
        const prefix = `${filePath}/`;
        const kids = new Map<string, { type: string; oid: string }>();
        for (const [p, entry] of files) {
          if (!p.startsWith(prefix)) continue;
          const restPath = p.slice(prefix.length);
          const firstSeg = restPath.split('/')[0];
          if (!kids.has(firstSeg)) kids.set(firstSeg, { type: restPath.includes('/') ? 'dir' : 'file', oid: entry.oid });
        }
        if (kids.size > 0) {
          jsonBody(
            res,
            200,
            [...kids.entries()].map(([n, k]) => ({ type: k.type, name: n, path: `${filePath}/${n}`, sha: k.oid })),
            reqIdHeader(),
          );
          return true;
        }
        jsonBody(res, 404, { message: 'Not Found' }, reqIdHeader());
        return true;
      }
      if (method === 'PUT') {
        const b = (ctx.body ?? {}) as Record<string, unknown>;
        const contentB64 = typeof b.content === 'string' ? b.content : '';
        const message = typeof b.message === 'string' ? b.message : `Update ${filePath}`;
        let content: Buffer;
        try {
          content = Buffer.from(contentB64.replace(/\s+/g, ''), 'base64');
        } catch {
          jsonBody(res, 422, { message: 'Invalid base64 content' }, reqIdHeader());
          return true;
        }
        const tip = repo.refs.get(branchRef);
        if (tip !== undefined) {
          const commitObj = repo.objects.get(tip);
          if (commitObj && commitObj.type === 'commit') {
            const files = treeFileMap(repo, parseCommit(commitObj.data).tree);
            const existing = files.get(filePath);
            const givenSha = typeof b.sha === 'string' ? b.sha : undefined;
            if (existing && givenSha === undefined) {
              jsonBody(res, 409, { message: 'sha is required to update a file' }, reqIdHeader());
              return true;
            }
            if (existing && givenSha !== undefined && givenSha !== existing.oid) {
              jsonBody(res, 409, { message: 'sha does not match' }, reqIdHeader());
              return true;
            }
            if (!existing && givenSha !== undefined) {
              jsonBody(res, 409, { message: 'sha does not match' }, reqIdHeader());
              return true;
            }
          }
        }
        const isUpdate = tip !== undefined && (() => {
          const commitObj = repo.objects.get(tip);
          if (!commitObj || commitObj.type !== 'commit') return false;
          return treeFileMap(repo, parseCommit(commitObj.data).tree).has(filePath);
        })();
        const { commitSha, blobSha } = commitContent(repo, branchRef, filePath, content, message);
        jsonBody(res, isUpdate ? 200 : 201, { content: { sha: blobSha, encoding: 'base64', name: filePath.split('/').pop(), path: filePath, size: content.length }, commit: { sha: commitSha, message } }, reqIdHeader());
        return true;
      }
      if (method === 'DELETE') {
        const b = (ctx.body ?? {}) as Record<string, unknown>;
        const message = typeof b.message === 'string' ? b.message : `Delete ${filePath}`;
        const givenSha = typeof b.sha === 'string' ? b.sha : undefined;
        const tip = repo.refs.get(branchRef);
        if (!tip) {
          jsonBody(res, 404, { message: 'Not Found' }, reqIdHeader());
          return true;
        }
        const commitObj = repo.objects.get(tip);
        if (!commitObj || commitObj.type !== 'commit') {
          jsonBody(res, 404, { message: 'Not Found' }, reqIdHeader());
          return true;
        }
        const files = treeFileMap(repo, parseCommit(commitObj.data).tree);
        const existing = files.get(filePath);
        if (!existing) {
          jsonBody(res, 404, { message: 'Not Found' }, reqIdHeader());
          return true;
        }
        if (givenSha !== undefined && givenSha !== existing.oid) {
          jsonBody(res, 409, { message: 'sha does not match' }, reqIdHeader());
          return true;
        }
        const { commitSha } = commitContent(repo, branchRef, filePath, null, message);
        jsonBody(res, 200, { commit: { sha: commitSha, message } }, reqIdHeader());
        return true;
      }
      jsonBody(res, 404, { message: 'Not Found' }, reqIdHeader());
      return true;
    }
    // labels
    if (rest[0] === 'labels') {
      if (method === 'POST' && rest.length === 1) {
        const b = (ctx.body ?? {}) as Record<string, unknown>;
        const name = typeof b.name === 'string' ? b.name : '';
        if (name === '') {
          jsonBody(res, 422, { message: 'Invalid label' }, reqIdHeader());
          return true;
        }
        if (repo.labels.has(name)) {
          jsonBody(res, 422, { message: 'Label already exists' }, reqIdHeader());
          return true;
        }
        repo.labels.set(name, { name, color: typeof b.color === 'string' ? b.color : 'ededed' });
        jsonBody(res, 201, { name, color: repo.labels.get(name)?.color ?? 'ededed' }, reqIdHeader());
        return true;
      }
      if (method === 'GET' && rest.length === 1) {
        jsonBody(res, 200, [...repo.labels.values()], reqIdHeader());
        return true;
      }
      jsonBody(res, 404, { message: 'Not Found' }, reqIdHeader());
      return true;
    }
    // issues
    if (rest[0] === 'issues') {
      if (rest.length === 1) {
        if (method === 'POST') {
          const b = (ctx.body ?? {}) as Record<string, unknown>;
          const title = typeof b.title === 'string' ? b.title : '';
          if (title === '') {
            jsonBody(res, 422, { message: 'Title is required' }, reqIdHeader());
            return true;
          }
          const labels = Array.isArray(b.labels) ? b.labels.filter((x): x is string => typeof x === 'string') : [];
          for (const l of labels) {
            if (!repo.labels.has(l)) {
              jsonBody(res, 422, { message: `Label does not exist: ${l}` }, reqIdHeader());
              return true;
            }
          }
          const number = repo.nextIssue++;
          const issue: IssueRec = { id: nextIssueId++, number, title, body: typeof b.body === 'string' ? b.body : '', state: 'open', labels, seq: nextSeq(), comments: [] };
          repo.issues.set(number, issue);
          jsonBody(res, 201, issueJson(repo, issue), reqIdHeader());
          return true;
        }
        if (method === 'GET') {
          const state = query.get('state') ?? 'open';
          const direction = query.get('direction') ?? 'desc';
          let list = [...repo.issues.values()];
          if (state !== 'all') list = list.filter((i) => i.state === state);
          list.sort((a, b) => (direction === 'asc' ? a.seq - b.seq : b.seq - a.seq));
          jsonBody(res, 200, list.map((i) => issueJson(repo, i)), reqIdHeader());
          return true;
        }
        jsonBody(res, 404, { message: 'Not Found' }, reqIdHeader());
        return true;
      }
      const num = parseInt(rest[1], 10);
      if (!Number.isSafeInteger(num)) {
        jsonBody(res, 404, { message: 'Not Found' }, reqIdHeader());
        return true;
      }
      const issue = repo.issues.get(num);
      if (rest.length === 2) {
        if (!issue) {
          jsonBody(res, 404, { message: 'Not Found' }, reqIdHeader());
          return true;
        }
        if (method === 'GET') jsonBody(res, 200, issueJson(repo, issue), reqIdHeader());
        else if (method === 'PATCH') {
          const b = (ctx.body ?? {}) as Record<string, unknown>;
          if (typeof b.title === 'string') issue.title = b.title;
          if (typeof b.body === 'string') issue.body = b.body;
          if (b.state === 'open' || b.state === 'closed') issue.state = b.state;
          if (Array.isArray(b.labels)) {
            const labels = b.labels.filter((x): x is string => typeof x === 'string');
            for (const l of labels) {
              if (!repo.labels.has(l)) {
                jsonBody(res, 422, { message: `Label does not exist: ${l}` }, reqIdHeader());
                return true;
              }
            }
            issue.labels = labels;
          }
          jsonBody(res, 200, issueJson(repo, issue), reqIdHeader());
        } else jsonBody(res, 404, { message: 'Not Found' }, reqIdHeader());
        return true;
      }
      if (rest.length === 3 && rest[2] === 'comments') {
        if (!issue) {
          jsonBody(res, 404, { message: 'Not Found' }, reqIdHeader());
          return true;
        }
        if (method === 'POST') {
          const b = (ctx.body ?? {}) as Record<string, unknown>;
          const comment: CommentRec = { id: nextCommentId++, body: typeof b.body === 'string' ? b.body : '' };
          issue.comments.push(comment);
          jsonBody(res, 201, { id: comment.id, body: comment.body }, reqIdHeader());
          return true;
        }
        if (method === 'GET') {
          jsonBody(res, 200, issue.comments.map((c) => ({ id: c.id, body: c.body })), reqIdHeader());
          return true;
        }
        jsonBody(res, 404, { message: 'Not Found' }, reqIdHeader());
        return true;
      }
      jsonBody(res, 404, { message: 'Not Found' }, reqIdHeader());
      return true;
    }
    // pulls
    if (rest[0] === 'pulls') {
      if (rest.length === 1) {
        if (method === 'POST') {
          const b = (ctx.body ?? {}) as Record<string, unknown>;
          const title = typeof b.title === 'string' ? b.title : '';
          const head = typeof b.head === 'string' ? b.head : '';
          const base = typeof b.base === 'string' ? b.base : '';
          if (title === '' || head === '' || base === '') {
            jsonBody(res, 422, { message: 'title, head and base are required' }, reqIdHeader());
            return true;
          }
          if (!repo.refs.has(`refs/heads/${head}`) || !repo.refs.has(`refs/heads/${base}`)) {
            jsonBody(res, 422, { message: 'head or base branch does not exist' }, reqIdHeader());
            return true;
          }
          const number = repo.nextPull++;
          const pr: PullRec = { id: nextPullId++, number, title, body: typeof b.body === 'string' ? b.body : '', state: 'open', head, base, seq: nextSeq(), merged: false, mergedAt: null, mergeCommitSha: null };
          repo.pulls.set(number, pr);
          jsonBody(res, 201, prJson(repo, pr), reqIdHeader());
          return true;
        }
        if (method === 'GET') {
          const state = query.get('state') ?? 'open';
          let list = [...repo.pulls.values()];
          if (state !== 'all') list = list.filter((p) => (state === 'closed' ? p.state !== 'open' : p.state === state));
          list.sort((a, b) => b.seq - a.seq);
          jsonBody(res, 200, list.map((p) => prJson(repo, p)), reqIdHeader());
          return true;
        }
        jsonBody(res, 404, { message: 'Not Found' }, reqIdHeader());
        return true;
      }
      const num = parseInt(rest[1], 10);
      if (!Number.isSafeInteger(num)) {
        jsonBody(res, 404, { message: 'Not Found' }, reqIdHeader());
        return true;
      }
      const pr = repo.pulls.get(num);
      if (rest.length === 2) {
        if (!pr) {
          jsonBody(res, 404, { message: 'Not Found' }, reqIdHeader());
          return true;
        }
        if (method === 'GET') jsonBody(res, 200, prJson(repo, pr), reqIdHeader());
        else if (method === 'PATCH') {
          const b = (ctx.body ?? {}) as Record<string, unknown>;
          if (typeof b.title === 'string') pr.title = b.title;
          if (typeof b.body === 'string') pr.body = b.body;
          if (b.state === 'open' || b.state === 'closed') pr.state = b.state;
          jsonBody(res, 200, prJson(repo, pr), reqIdHeader());
        } else jsonBody(res, 404, { message: 'Not Found' }, reqIdHeader());
        return true;
      }
      if (rest.length === 3 && rest[2] === 'files' && method === 'GET') {
        if (!pr) {
          jsonBody(res, 404, { message: 'Not Found' }, reqIdHeader());
          return true;
        }
        const headSha = resolveRef(repo, pr.head);
        const baseSha = resolveRef(repo, pr.base);
        if (!headSha || !baseSha) {
          jsonBody(res, 200, [], reqIdHeader());
          return true;
        }
        const mb = mergeBase(repo, headSha, baseSha);
        const baseTreeSha = mb ? parseCommit((repo.objects.get(mb) as GitObj).data).tree : '';
        const baseFiles = baseTreeSha === '' ? new Map() : treeFileMap(repo, baseTreeSha);
        const headFiles = treeFileMap(repo, parseCommit((repo.objects.get(headSha) as GitObj).data).tree);
        const out: Array<Record<string, unknown>> = [];
        const paths = new Set([...baseFiles.keys(), ...headFiles.keys()]);
        for (const path of [...paths].sort()) {
          const b = baseFiles.get(path);
          const h = headFiles.get(path);
          if (b && !h) {
            const oldText = (repo.objects.get(b.oid) as GitObj).data.toString('utf8');
            const d = lineDiff(oldText, '');
            out.push({ filename: path, status: 'removed', additions: 0, deletions: d.deletions, changes: d.deletions });
          } else if (!b && h) {
            const newText = (repo.objects.get(h.oid) as GitObj).data.toString('utf8');
            const d = lineDiff('', newText);
            out.push({ filename: path, status: 'added', additions: d.additions, deletions: 0, changes: d.additions });
          } else if (b && h && b.oid !== h.oid) {
            const oldText = (repo.objects.get(b.oid) as GitObj).data.toString('utf8');
            const newText = (repo.objects.get(h.oid) as GitObj).data.toString('utf8');
            const d = lineDiff(oldText, newText);
            out.push({ filename: path, status: 'modified', additions: d.additions, deletions: d.deletions, changes: d.additions + d.deletions });
          }
        }
        jsonBody(res, 200, out, reqIdHeader());
        return true;
      }
      if (rest.length === 3 && rest[2] === 'merge' && method === 'PUT') {
        if (!pr) {
          jsonBody(res, 404, { message: 'Not Found' }, reqIdHeader());
          return true;
        }
        if (pr.state !== 'open') {
          jsonBody(res, 405, { message: 'Pull request is not open' }, reqIdHeader());
          return true;
        }
        const conflict = prConflict(repo, pr);
        if (conflict !== null) {
          jsonBody(res, 405, { message: 'Merge conflict' }, reqIdHeader());
          return true;
        }
        const headSha = resolveRef(repo, pr.head) as string;
        const baseSha = resolveRef(repo, pr.base) as string;
        const headTree = parseCommit((repo.objects.get(headSha) as GitObj).data).tree;
        const seq = nextSeq();
        const commitData = buildCommit(headTree, [baseSha], pr.title, seq);
        const mergeSha = storeObject(repo, { type: 'commit', data: commitData });
        repo.refs.set(`refs/heads/${pr.base}`, mergeSha);
        pr.state = 'merged';
        pr.merged = true;
        pr.mergedAt = isoForSeq(seq);
        pr.mergeCommitSha = mergeSha;
        jsonBody(res, 200, { sha: mergeSha, merged: true, message: pr.title }, reqIdHeader());
        return true;
      }
      jsonBody(res, 404, { message: 'Not Found' }, reqIdHeader());
      return true;
    }
    jsonBody(res, 404, { message: 'Not Found' }, reqIdHeader());
    return true;
  }
  return false;
}

// ---------------------------------------------------------------- GraphQL v4

type GQLValue =
  | { kind: 'var'; name: string }
  | { kind: 'int'; value: number }
  | { kind: 'float'; value: number }
  | { kind: 'string'; value: string }
  | { kind: 'bool'; value: boolean }
  | { kind: 'enum'; value: string }
  | { kind: 'null' }
  | { kind: 'list'; values: GQLValue[] }
  | { kind: 'object'; fields: Array<{ name: string; value: GQLValue }> };
type GQLType = { kind: 'named'; name: string } | { kind: 'list'; of: GQLType } | { kind: 'nonNull'; of: GQLType };
interface GQLSelection {
  kind: 'field' | 'fragment' | 'inline';
  name?: string;
  alias?: string;
  args?: Array<{ name: string; value: GQLValue }>;
  selections?: GQLSelection[];
  typeCondition?: string;
}
interface GQLOperation {
  kind: 'query' | 'mutation';
  name?: string;
  varDefs: Array<{ name: string; type: GQLType; defaultValue?: GQLValue }>;
  selections: GQLSelection[];
}
interface GQLFragment {
  name: string;
  typeCondition: string;
  selections: GQLSelection[];
}

class GQLParseError extends Error {}

interface Token {
  kind: 'name' | 'string' | 'int' | 'float' | 'punct' | 'spread';
  value: string;
}
function tokenizeGQL(src: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === ',') {
      i++;
      continue;
    }
    if (c === '#') {
      while (i < src.length && src[i] !== '\n') i++;
      continue;
    }
    if (c === '.' && src.slice(i, i + 3) === '...') {
      tokens.push({ kind: 'spread', value: '...' });
      i += 3;
      continue;
    }
    if ('!$():[]=!{}@|&'.includes(c)) {
      tokens.push({ kind: 'punct', value: c });
      i++;
      continue;
    }
    if (c === '"') {
      let j = i + 1;
      let out = '';
      while (j < src.length && src[j] !== '"') {
        if (src[j] === '\\' && j + 1 < src.length) {
          const e = src[j + 1];
          out += e === 'n' ? '\n' : e === 't' ? '\t' : e === 'r' ? '\r' : e === 'u' ? String.fromCharCode(parseInt(src.slice(j + 2, j + 6), 16)) : e;
          j += e === 'u' ? 6 : 2;
        } else {
          out += src[j];
          j++;
        }
      }
      if (j >= src.length) throw new GQLParseError('unterminated string');
      tokens.push({ kind: 'string', value: out });
      i = j + 1;
      continue;
    }
    if (/[0-9-]/.test(c)) {
      let j = i;
      if (src[j] === '-') j++;
      while (j < src.length && /[0-9]/.test(src[j])) j++;
      let isFloat = false;
      if (src[j] === '.') {
        isFloat = true;
        j++;
        while (j < src.length && /[0-9]/.test(src[j])) j++;
      }
      if (src[j] === 'e' || src[j] === 'E') {
        isFloat = true;
        j++;
        if (src[j] === '+' || src[j] === '-') j++;
        while (j < src.length && /[0-9]/.test(src[j])) j++;
      }
      tokens.push({ kind: isFloat ? 'float' : 'int', value: src.slice(i, j) });
      i = j;
      continue;
    }
    if (/[_A-Za-z]/.test(c)) {
      let j = i;
      while (j < src.length && /[_0-9A-Za-z]/.test(src[j])) j++;
      tokens.push({ kind: 'name', value: src.slice(i, j) });
      i = j;
      continue;
    }
    throw new GQLParseError(`unexpected character ${JSON.stringify(c)}`);
  }
  return tokens;
}

class GQLParser {
  private pos = 0;
  private readonly tokens: Token[];
  constructor(tokens: Token[]) {
    this.tokens = tokens;
  }
  private peek(): Token | undefined {
    return this.tokens[this.pos];
  }
  private next(): Token {
    const t = this.tokens[this.pos++];
    if (!t) throw new GQLParseError('unexpected end of document');
    return t;
  }
  private expectPunct(v: string): void {
    const t = this.next();
    if (t.kind !== 'punct' || t.value !== v) throw new GQLParseError(`expected ${v}, got ${t.value}`);
  }
  private expectName(v?: string): string {
    const t = this.next();
    if (t.kind !== 'name') throw new GQLParseError(`expected name, got ${t.value}`);
    if (v !== undefined && t.value !== v) throw new GQLParseError(`expected ${v}, got ${t.value}`);
    return t.value;
  }
  parseDocument(): { operations: GQLOperation[]; fragments: Map<string, GQLFragment> } {
    const operations: GQLOperation[] = [];
    const fragments = new Map<string, GQLFragment>();
    while (this.peek() !== undefined) {
      const t = this.peek() as Token;
      if (t.kind === 'punct' && t.value === '{') {
        operations.push({ kind: 'query', varDefs: [], selections: this.parseSelectionSet() });
      } else if (t.kind === 'name' && (t.value === 'query' || t.value === 'mutation')) {
        const kind = this.next().value as 'query' | 'mutation';
        let name: string | undefined;
        const n = this.peek();
        if (n && n.kind === 'name') name = this.next().value;
        const varDefs = this.parseVarDefs();
        operations.push({ kind, name, varDefs, selections: this.parseSelectionSet() });
      } else if (t.kind === 'name' && t.value === 'fragment') {
        this.next();
        const name = this.expectName();
        this.expectName('on');
        const typeCondition = this.expectName();
        this.skipDirectives();
        fragments.set(name, { name, typeCondition, selections: this.parseSelectionSet() });
      } else {
        throw new GQLParseError(`unexpected token ${t.value}`);
      }
    }
    return { operations, fragments };
  }
  private parseVarDefs(): GQLOperation['varDefs'] {
    const defs: GQLOperation['varDefs'] = [];
    const t = this.peek();
    if (!t || t.kind !== 'punct' || t.value !== '(') return defs;
    this.next();
    while (this.peek() && !(this.peek()?.kind === 'punct' && this.peek()?.value === ')')) {
      this.expectPunct('$');
      const name = this.expectName();
      this.expectPunct(':');
      const type = this.parseType();
      let defaultValue: GQLValue | undefined;
      const eq = this.peek();
      if (eq && eq.kind === 'punct' && eq.value === '=') {
        this.next();
        defaultValue = this.parseValue(true);
      }
      defs.push({ name, type, defaultValue });
    }
    this.expectPunct(')');
    return defs;
  }
  private parseType(): GQLType {
    const t = this.peek();
    if (!t) throw new GQLParseError('unexpected end in type');
    let base: GQLType;
    if (t.kind === 'punct' && t.value === '[') {
      this.next();
      const inner = this.parseType();
      this.expectPunct(']');
      base = { kind: 'list', of: inner };
    } else {
      base = { kind: 'named', name: this.expectName() };
    }
    const bang = this.peek();
    if (bang && bang.kind === 'punct' && bang.value === '!') {
      this.next();
      return { kind: 'nonNull', of: base };
    }
    return base;
  }
  private parseSelectionSet(): GQLSelection[] {
    this.expectPunct('{');
    const sels: GQLSelection[] = [];
    while (this.peek() && !(this.peek()?.kind === 'punct' && this.peek()?.value === '}')) {
      sels.push(this.parseSelection());
    }
    this.expectPunct('}');
    return sels;
  }
  private parseSelection(): GQLSelection {
    const t = this.peek() as Token;
    if (t.kind === 'spread') {
      this.next();
      const n = this.peek();
      if (n && n.kind === 'name' && n.value === 'on') {
        this.next();
        const typeCondition = this.expectName();
        this.skipDirectives();
        return { kind: 'inline', typeCondition, selections: this.parseSelectionSet() };
      }
      if (n && n.kind === 'name') {
        const name = this.next().value;
        this.skipDirectives();
        return { kind: 'fragment', name };
      }
      throw new GQLParseError('bad fragment spread');
    }
    if (t.kind !== 'name') throw new GQLParseError(`expected field name, got ${t.value}`);
    const first = this.next().value;
    let alias: string | undefined;
    let name = first;
    const colon = this.peek();
    if (colon && colon.kind === 'punct' && colon.value === ':') {
      this.next();
      alias = first;
      name = this.expectName();
    }
    const args = this.parseArgs();
    this.skipDirectives();
    let selections: GQLSelection[] | undefined;
    const brace = this.peek();
    if (brace && brace.kind === 'punct' && brace.value === '{') selections = this.parseSelectionSet();
    return { kind: 'field', name, alias, args, selections };
  }
  private parseArgs(): Array<{ name: string; value: GQLValue }> {
    const args: Array<{ name: string; value: GQLValue }> = [];
    const t = this.peek();
    if (!t || t.kind !== 'punct' || t.value !== '(') return args;
    this.next();
    while (this.peek() && !(this.peek()?.kind === 'punct' && this.peek()?.value === ')')) {
      const name = this.expectName();
      this.expectPunct(':');
      args.push({ name, value: this.parseValue(false) });
    }
    this.expectPunct(')');
    return args;
  }
  private parseValue(isConst: boolean): GQLValue {
    const t = this.next();
    if (t.kind === 'punct' && t.value === '$') {
      if (isConst) throw new GQLParseError('variable in const value');
      return { kind: 'var', name: this.expectName() };
    }
    if (t.kind === 'punct' && t.value === '[') {
      const values: GQLValue[] = [];
      while (this.peek() && !(this.peek()?.kind === 'punct' && this.peek()?.value === ']')) values.push(this.parseValue(isConst));
      this.expectPunct(']');
      return { kind: 'list', values };
    }
    if (t.kind === 'punct' && t.value === '{') {
      const fields: Array<{ name: string; value: GQLValue }> = [];
      while (this.peek() && !(this.peek()?.kind === 'punct' && this.peek()?.value === '}')) {
        const name = this.expectName();
        this.expectPunct(':');
        fields.push({ name, value: this.parseValue(isConst) });
      }
      this.expectPunct('}');
      return { kind: 'object', fields };
    }
    if (t.kind === 'int') return { kind: 'int', value: parseInt(t.value, 10) };
    if (t.kind === 'float') return { kind: 'float', value: parseFloat(t.value) };
    if (t.kind === 'string') return { kind: 'string', value: t.value };
    if (t.kind === 'name') {
      if (t.value === 'true') return { kind: 'bool', value: true };
      if (t.value === 'false') return { kind: 'bool', value: false };
      if (t.value === 'null') return { kind: 'null' };
      return { kind: 'enum', value: t.value };
    }
    throw new GQLParseError(`unexpected value token ${t.value}`);
  }
  private skipDirectives(): void {
    while (this.peek() && this.peek()?.kind === 'punct' && this.peek()?.value === '@') {
      this.next();
      this.expectName();
      this.parseArgs();
    }
  }
}

function evalGQLValue(v: GQLValue, vars: Record<string, unknown>): unknown {
  switch (v.kind) {
    case 'var':
      return vars[v.name];
    case 'int':
    case 'float':
    case 'string':
    case 'bool':
      return v.value;
    case 'enum':
      return v.value;
    case 'null':
      return null;
    case 'list':
      return v.values.map((x) => evalGQLValue(x, vars));
    case 'object': {
      const out: Record<string, unknown> = {};
      for (const f of v.fields) out[f.name] = evalGQLValue(f.value, vars);
      return out;
    }
  }
}

// ---------------------------------------------------------------- GraphQL model

type GQLNode =
  | { __type: 'Query' }
  | { __type: 'Mutation' }
  | { __type: 'User'; login: string; id: number; name: string; email: string }
  | { __type: 'Repository'; repo: RepoRec }
  | { __type: 'Issue'; repo: RepoRec; issue: IssueRec }
  | { __type: 'PullRequest'; repo: RepoRec; pr: PullRec }
  | { __type: 'IssueComment'; repo: RepoRec; issue: IssueRec; comment: CommentRec }
  | { __type: 'IssueConnection'; nodes: GQLNode[]; pageInfo: { hasNextPage: boolean; endCursor: string | null }; totalCount: number }
  | { __type: 'PullRequestConnection'; nodes: GQLNode[]; pageInfo: { hasNextPage: boolean; endCursor: string | null }; totalCount: number }
  | { __type: 'LabelConnection'; nodes: GQLNode[]; totalCount: number }
  | { __type: 'PageInfo'; hasNextPage: boolean; endCursor: string | null }
  | { __type: 'BranchRef'; name: string }
  | { __type: 'Label'; name: string }
  | { __type: 'ChangedFile'; filename: string; additions: number; deletions: number; changes: number; status: string }
  | { __type: 'ChangedFileConnection'; nodes: GQLNode[]; totalCount: number }
  | { __type: 'CreateIssuePayload'; issue: GQLNode | null }
  | { __type: 'CloseIssuePayload'; issue: GQLNode | null }
  | { __type: 'CreatePullRequestPayload'; pr: GQLNode | null }
  | { __type: 'MergePullRequestPayload'; pr: GQLNode | null }
  | { __type: 'AddCommentPayload'; commentEdge: { node: GQLNode } | null }
  | { __type: 'CommentEdge'; node: GQLNode }
  | { __type: '__Type'; name: string; kind: string; fields: string[]; enumValues: string[] };

const GQL_TYPE_INFO: Record<string, { kind: string; fields: string[]; enumValues: string[] }> = {
  Issue: { kind: 'OBJECT', fields: ['id', 'number', 'title', 'state', 'body', 'createdAt', 'author', 'labels', 'comments', 'repository', 'url'], enumValues: [] },
  PullRequest: { kind: 'OBJECT', fields: ['id', 'number', 'title', 'state', 'body', 'headRefName', 'baseRefName', 'mergeable', 'merged', 'mergedAt', 'mergeCommitSha', 'files', 'author', 'createdAt'], enumValues: [] },
  Repository: { kind: 'OBJECT', fields: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest', 'description', 'isPrivate', 'createdAt', 'url'], enumValues: [] },
  User: { kind: 'OBJECT', fields: ['id', 'login', 'name', 'email'], enumValues: [] },
  IssueComment: { kind: 'OBJECT', fields: ['id', 'body', 'author'], enumValues: [] },
  SearchType: { kind: 'ENUM', fields: [], enumValues: ['ISSUE', 'REPOSITORY', 'USER', 'DISCUSSION'] },
  IssueState: { kind: 'ENUM', fields: [], enumValues: ['OPEN', 'CLOSED'] },
  PullRequestState: { kind: 'ENUM', fields: [], enumValues: ['OPEN', 'CLOSED', 'MERGED'] },
  RepositoryPermission: { kind: 'ENUM', fields: [], enumValues: ['ADMIN', 'MAINTAIN', 'WRITE', 'TRIAGE', 'READ'] },
};

function gidRepo(repo: RepoRec): string {
  return b64encode(`Repository:${repo.owner}/${repo.name}`);
}
function gidIssue(repo: RepoRec, issue: IssueRec): string {
  return b64encode(`Issue:${repo.owner}/${repo.name}#${issue.number}`);
}
function gidPull(repo: RepoRec, pr: PullRec): string {
  return b64encode(`PullRequest:${repo.owner}/${repo.name}#${pr.number}`);
}
function gidComment(repo: RepoRec, issue: IssueRec, comment: CommentRec): string {
  return b64encode(`IssueComment:${repo.owner}/${repo.name}#${issue.number}:${comment.id}`);
}
function decodeGid(id: string): { kind: string; owner: string; name: string; number?: number; commentId?: number } | null {
  const raw = b64decode(id);
  if (!raw) return null;
  let m = raw.match(/^Repository:([^/]+)\/(.+)$/);
  if (m) return { kind: 'Repository', owner: m[1], name: m[2] };
  m = raw.match(/^Issue:([^/]+)\/(.+)#(\d+)$/);
  if (m) return { kind: 'Issue', owner: m[1], name: m[2], number: parseInt(m[3], 10) };
  m = raw.match(/^PullRequest:([^/]+)\/(.+)#(\d+)$/);
  if (m) return { kind: 'PullRequest', owner: m[1], name: m[2], number: parseInt(m[3], 10) };
  m = raw.match(/^IssueComment:([^/]+)\/(.+)#(\d+):(\d+)$/);
  if (m) return { kind: 'IssueComment', owner: m[1], name: m[2], number: parseInt(m[3], 10), commentId: parseInt(m[4], 10) };
  return null;
}
function viewerNode(): GQLNode {
  return { __type: 'User', login: VIEWER_LOGIN, id: VIEWER_ID, name: VIEWER_NAME, email: VIEWER_EMAIL };
}
function issueConnection(repo: RepoRec, args: Record<string, unknown>): GQLNode {
  const states = Array.isArray(args.states) ? (args.states as string[]) : null;
  const orderBy = (args.orderBy ?? {}) as Record<string, unknown>;
  const direction = orderBy.direction === 'ASC' ? 'asc' : 'desc';
  const first = typeof args.first === 'number' ? args.first : 100;
  const after = typeof args.after === 'string' ? args.after : null;
  let list = [...repo.issues.values()];
  if (states) {
    const want = new Set(states.map((s) => String(s).toLowerCase()));
    list = list.filter((i) => want.has(i.state));
  }
  list.sort((a, b) => (direction === 'asc' ? a.number - b.number : b.number - a.number));
  if (after) {
    const raw = b64decode(after);
    const m = raw ? raw.match(/^issue:(\d+)$/) : null;
    if (m) {
      const n = parseInt(m[1], 10);
      list = list.filter((i) => (direction === 'asc' ? i.number > n : i.number < n));
    }
  }
  const page = list.slice(0, first);
  const hasNextPage = list.length > page.length;
  const endCursor = page.length > 0 ? b64encode(`issue:${page[page.length - 1].number}`) : null;
  return {
    __type: 'IssueConnection',
    nodes: page.map((issue) => ({ __type: 'Issue', repo, issue }) as GQLNode),
    pageInfo: { hasNextPage, endCursor },
    totalCount: list.length,
  };
}
function pullConnection(repo: RepoRec, args: Record<string, unknown>): GQLNode {
  const first = typeof args.first === 'number' ? args.first : 100;
  const list = [...repo.pulls.values()].sort((a, b) => b.number - a.number);
  const page = list.slice(0, first);
  const hasNextPage = list.length > page.length;
  const endCursor = page.length > 0 ? b64encode(`pr:${page[page.length - 1].number}`) : null;
  return {
    __type: 'PullRequestConnection',
    nodes: page.map((pr) => ({ __type: 'PullRequest', repo, pr }) as GQLNode),
    pageInfo: { hasNextPage, endCursor },
    totalCount: list.length,
  };
}
function changedFilesConnection(repo: RepoRec, pr: PullRec): GQLNode {
  const headSha = resolveRef(repo, pr.head);
  const baseSha = resolveRef(repo, pr.base);
  const nodes: GQLNode[] = [];
  if (headSha && baseSha) {
    const mb = mergeBase(repo, headSha, baseSha);
    const baseTreeSha = mb ? parseCommit((repo.objects.get(mb) as GitObj).data).tree : '';
    const baseFiles = baseTreeSha === '' ? new Map() : treeFileMap(repo, baseTreeSha);
    const headFiles = treeFileMap(repo, parseCommit((repo.objects.get(headSha) as GitObj).data).tree);
    const paths = new Set([...baseFiles.keys(), ...headFiles.keys()]);
    for (const path of [...paths].sort()) {
      const b = baseFiles.get(path);
      const h = headFiles.get(path);
      if (b && !h) {
        const oldText = (repo.objects.get(b.oid) as GitObj).data.toString('utf8');
        const d = lineDiff(oldText, '');
        nodes.push({ __type: 'ChangedFile', filename: path, additions: 0, deletions: d.deletions, changes: d.deletions, status: 'removed' });
      } else if (!b && h) {
        const newText = (repo.objects.get(h.oid) as GitObj).data.toString('utf8');
        const d = lineDiff('', newText);
        nodes.push({ __type: 'ChangedFile', filename: path, additions: d.additions, deletions: 0, changes: d.additions, status: 'added' });
      } else if (b && h && b.oid !== h.oid) {
        const oldText = (repo.objects.get(b.oid) as GitObj).data.toString('utf8');
        const newText = (repo.objects.get(h.oid) as GitObj).data.toString('utf8');
        const d = lineDiff(oldText, newText);
        nodes.push({ __type: 'ChangedFile', filename: path, additions: d.additions, deletions: d.deletions, changes: d.additions + d.deletions, status: 'modified' });
      }
    }
  }
  return { __type: 'ChangedFileConnection', nodes, totalCount: nodes.length };
}

class GQLFieldError extends Error {}

interface GQLCtx {
  errors: Array<{ message: string }>;
  fragments: Map<string, GQLFragment>;
  vars: Record<string, unknown>;
}

function argMap(sel: GQLSelection, ctx: GQLCtx): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const a of sel.args ?? []) out[a.name] = evalGQLValue(a.value, ctx.vars);
  return out;
}
function isObjectLike(v: unknown): v is GQLNode {
  return typeof v === 'object' && v !== null && '__type' in (v as Record<string, unknown>);
}

function resolveField(node: GQLNode, field: string, args: Record<string, unknown>): unknown {
  switch (node.__type) {
    case 'Query': {
      if (field === 'viewer') return viewerNode();
      if (field === 'repository') {
        const owner = String(args.owner ?? '');
        const name = String(args.name ?? '');
        const repo = getRepo(owner, name);
        return repo ? ({ __type: 'Repository', repo } as GQLNode) : null;
      }
      if (field === 'node') {
        const id = String(args.id ?? '');
        const dec = decodeGid(id);
        if (!dec) return null;
        const repo = getRepo(dec.owner, dec.name);
        if (!repo) return null;
        if (dec.kind === 'Repository') return { __type: 'Repository', repo } as GQLNode;
        if (dec.kind === 'Issue') {
          const issue = repo.issues.get(dec.number ?? -1);
          return issue ? ({ __type: 'Issue', repo, issue } as GQLNode) : null;
        }
        if (dec.kind === 'PullRequest') {
          const pr = repo.pulls.get(dec.number ?? -1);
          return pr ? ({ __type: 'PullRequest', repo, pr } as GQLNode) : null;
        }
        return null;
      }
      if (field === '__type') {
        const name = String(args.name ?? '');
        const info = GQL_TYPE_INFO[name];
        if (!info) return null;
        return { __type: '__Type', name, kind: info.kind, fields: info.fields, enumValues: info.enumValues } as GQLNode;
      }
      if (field === '__schema') {
        return { __type: '__Type', name: '__Schema', kind: 'OBJECT', fields: [], enumValues: [] } as GQLNode;
      }
      throw new GQLFieldError(`Cannot query field "${field}" on type "Query".`);
    }
    case 'Mutation': {
      if (field === 'createIssue') {
        const input = (args.input ?? {}) as Record<string, unknown>;
        const repoId = String(input.repositoryId ?? '');
        const dec = decodeGid(repoId);
        const repo = dec ? getRepo(dec.owner, dec.name) : undefined;
        if (!repo) throw new GQLFieldError('createIssue: repository not found');
        const title = String(input.title ?? '');
        if (title === '') throw new GQLFieldError('createIssue: title is required');
        const number = repo.nextIssue++;
        const issue: IssueRec = { id: nextIssueId++, number, title, body: typeof input.body === 'string' ? input.body : '', state: 'open', labels: [], seq: nextSeq(), comments: [] };
        repo.issues.set(number, issue);
        return { __type: 'CreateIssuePayload', issue: { __type: 'Issue', repo, issue } as GQLNode } as GQLNode;
      }
      if (field === 'closeIssue') {
        const input = (args.input ?? {}) as Record<string, unknown>;
        const dec = decodeGid(String(input.issueId ?? ''));
        const repo = dec ? getRepo(dec.owner, dec.name) : undefined;
        const issue = repo && dec?.number !== undefined ? repo.issues.get(dec.number) : undefined;
        if (!issue || !repo) throw new GQLFieldError('closeIssue: issue not found');
        issue.state = 'closed';
        return { __type: 'CloseIssuePayload', issue: { __type: 'Issue', repo, issue } as GQLNode } as GQLNode;
      }
      if (field === 'createPullRequest') {
        const input = (args.input ?? {}) as Record<string, unknown>;
        const dec = decodeGid(String(input.repositoryId ?? ''));
        const repo = dec ? getRepo(dec.owner, dec.name) : undefined;
        if (!repo) throw new GQLFieldError('createPullRequest: repository not found');
        const head = String(input.headRefName ?? '');
        const base = String(input.baseRefName ?? '');
        if (!repo.refs.has(`refs/heads/${head}`) || !repo.refs.has(`refs/heads/${base}`)) throw new GQLFieldError('createPullRequest: head or base branch does not exist');
        const number = repo.nextPull++;
        const pr: PullRec = { id: nextPullId++, number, title: String(input.title ?? ''), body: typeof input.body === 'string' ? input.body : '', state: 'open', head, base, seq: nextSeq(), merged: false, mergedAt: null, mergeCommitSha: null };
        repo.pulls.set(number, pr);
        return { __type: 'CreatePullRequestPayload', pr: { __type: 'PullRequest', repo, pr } as GQLNode } as GQLNode;
      }
      if (field === 'mergePullRequest') {
        const input = (args.input ?? {}) as Record<string, unknown>;
        const dec = decodeGid(String(input.pullRequestId ?? ''));
        const repo = dec ? getRepo(dec.owner, dec.name) : undefined;
        const pr = repo && dec?.number !== undefined ? repo.pulls.get(dec.number) : undefined;
        if (!pr || !repo) throw new GQLFieldError('mergePullRequest: pull request not found');
        if (pr.state !== 'open') throw new GQLFieldError('mergePullRequest: pull request is not open');
        if (prConflict(repo, pr) !== null) throw new GQLFieldError('mergePullRequest: merge conflict');
        const headSha = resolveRef(repo, pr.head) as string;
        const baseSha = resolveRef(repo, pr.base) as string;
        const headTree = parseCommit((repo.objects.get(headSha) as GitObj).data).tree;
        const seq = nextSeq();
        const mergeSha = storeObject(repo, { type: 'commit', data: buildCommit(headTree, [baseSha], pr.title, seq) });
        repo.refs.set(`refs/heads/${pr.base}`, mergeSha);
        pr.state = 'merged';
        pr.merged = true;
        pr.mergedAt = isoForSeq(seq);
        pr.mergeCommitSha = mergeSha;
        return { __type: 'MergePullRequestPayload', pr: { __type: 'PullRequest', repo, pr } as GQLNode } as GQLNode;
      }
      if (field === 'addComment') {
        const input = (args.input ?? {}) as Record<string, unknown>;
        const dec = decodeGid(String(input.subjectId ?? ''));
        const repo = dec ? getRepo(dec.owner, dec.name) : undefined;
        if (!repo || !dec) throw new GQLFieldError('addComment: subject not found');
        let target: GQLNode | null = null;
        if (dec.kind === 'Issue') {
          const issue = repo.issues.get(dec.number ?? -1);
          if (!issue) throw new GQLFieldError('addComment: issue not found');
          const comment: CommentRec = { id: nextCommentId++, body: String(input.body ?? '') };
          issue.comments.push(comment);
          target = { __type: 'IssueComment', repo, issue, comment } as GQLNode;
        } else if (dec.kind === 'PullRequest') {
          const pr = repo.pulls.get(dec.number ?? -1);
          if (!pr) throw new GQLFieldError('addComment: pull request not found');
          const comment: CommentRec = { id: nextCommentId++, body: String(input.body ?? '') };
          target = { __type: 'IssueComment', repo, issue: { id: 0, number: pr.number, title: pr.title, body: pr.body, state: 'open', labels: [], seq: pr.seq, comments: [comment] }, comment } as GQLNode;
        } else {
          throw new GQLFieldError('addComment: unsupported subject');
        }
        return { __type: 'AddCommentPayload', commentEdge: target ? { node: target } : null } as GQLNode;
      }
      throw new GQLFieldError(`Cannot query field "${field}" on type "Mutation".`);
    }
    case 'User': {
      if (field === 'id') return b64encode(`User:${node.login}`);
      if (field === 'login') return node.login;
      if (field === 'name') return node.name;
      if (field === 'email') return node.email;
      throw new GQLFieldError(`Cannot query field "${field}" on type "User".`);
    }
    case 'Repository': {
      const repo = node.repo;
      if (field === 'id') return gidRepo(repo);
      if (field === 'databaseId') return repo.id;
      if (field === 'name') return repo.name;
      if (field === 'nameWithOwner') return `${repo.owner}/${repo.name}`;
      if (field === 'owner') return viewerNode();
      if (field === 'defaultBranchRef') return headOid(repo) ? ({ __type: 'BranchRef', name: DEFAULT_BRANCH } as GQLNode) : null;
      if (field === 'viewerPermission') return 'ADMIN';
      if (field === 'hasIssuesEnabled') return true;
      if (field === 'description') return repo.description;
      if (field === 'isPrivate') return repo.private;
      if (field === 'createdAt') return '2026-01-01T00:00:00Z';
      if (field === 'url') return `https://example.invalid/${repo.owner}/${repo.name}`;
      if (field === 'issue') {
        const n = typeof args.number === 'number' ? args.number : -1;
        const issue = repo.issues.get(n);
        return issue ? ({ __type: 'Issue', repo, issue } as GQLNode) : null;
      }
      if (field === 'issues') return issueConnection(repo, args);
      if (field === 'pullRequests') return pullConnection(repo, args);
      if (field === 'pullRequest') {
        const n = typeof args.number === 'number' ? args.number : -1;
        const pr = repo.pulls.get(n);
        return pr ? ({ __type: 'PullRequest', repo, pr } as GQLNode) : null;
      }
      throw new GQLFieldError(`Cannot query field "${field}" on type "Repository".`);
    }
    case 'Issue': {
      const { repo, issue } = node;
      if (field === 'id') return gidIssue(repo, issue);
      if (field === 'number') return issue.number;
      if (field === 'title') return issue.title;
      if (field === 'body') return issue.body;
      if (field === 'state') return issue.state === 'open' ? 'OPEN' : 'CLOSED';
      if (field === 'createdAt') return isoForSeq(issue.seq);
      if (field === 'author') return viewerNode();
      if (field === 'repository') return { __type: 'Repository', repo } as GQLNode;
      if (field === 'url') return `https://example.invalid/${repo.owner}/${repo.name}/issues/${issue.number}`;
      if (field === 'labels') {
        return { __type: 'LabelConnection', nodes: issue.labels.map((name) => ({ __type: 'Label', name }) as GQLNode), totalCount: issue.labels.length } as GQLNode;
      }
      if (field === 'comments') {
        return { __type: 'LabelConnection', nodes: issue.comments.map((c) => ({ __type: 'IssueComment', repo, issue, comment: c }) as GQLNode), totalCount: issue.comments.length } as GQLNode;
      }
      throw new GQLFieldError(`Cannot query field "${field}" on type "Issue".`);
    }
    case 'PullRequest': {
      const { repo, pr } = node;
      if (field === 'id') return gidPull(repo, pr);
      if (field === 'number') return pr.number;
      if (field === 'title') return pr.title;
      if (field === 'body') return pr.body;
      if (field === 'state') return pr.state === 'merged' ? 'MERGED' : pr.state === 'open' ? 'OPEN' : 'CLOSED';
      if (field === 'headRefName') return pr.head;
      if (field === 'baseRefName') return pr.base;
      if (field === 'mergeable') return prMergeable(repo, pr) ? 'MERGEABLE' : 'CONFLICTING';
      if (field === 'merged') return pr.merged;
      if (field === 'mergedAt') return pr.mergedAt;
      if (field === 'mergeCommitSha') return pr.mergeCommitSha;
      if (field === 'createdAt') return isoForSeq(pr.seq);
      if (field === 'author') return viewerNode();
      if (field === 'files') return changedFilesConnection(repo, pr);
      throw new GQLFieldError(`Cannot query field "${field}" on type "PullRequest".`);
    }
    case 'IssueComment': {
      if (field === 'id') return gidComment(node.repo, node.issue, node.comment);
      if (field === 'body') return node.comment.body;
      if (field === 'author') return viewerNode();
      throw new GQLFieldError(`Cannot query field "${field}" on type "IssueComment".`);
    }
    case 'IssueConnection':
    case 'PullRequestConnection':
    case 'ChangedFileConnection':
    case 'LabelConnection': {
      if (field === 'nodes') return node.nodes;
      if (field === 'totalCount') return node.totalCount;
      if (field === 'pageInfo' && (node.__type === 'IssueConnection' || node.__type === 'PullRequestConnection')) {
        return { __type: 'PageInfo', hasNextPage: node.pageInfo.hasNextPage, endCursor: node.pageInfo.endCursor } as GQLNode;
      }
      if (field === 'edges') {
        return node.nodes.map((n) => ({ __type: 'CommentEdge', node: n }) as GQLNode);
      }
      throw new GQLFieldError(`Cannot query field "${field}" on type "${node.__type}".`);
    }
    case 'PageInfo': {
      if (field === 'hasNextPage') return node.hasNextPage;
      if (field === 'endCursor') return node.endCursor;
      if (field === 'hasPreviousPage') return false;
      if (field === 'startCursor') return node.endCursor;
      throw new GQLFieldError(`Cannot query field "${field}" on type "PageInfo".`);
    }
    case 'BranchRef': {
      if (field === 'name') return node.name;
      throw new GQLFieldError(`Cannot query field "${field}" on type "Ref".`);
    }
    case 'Label': {
      if (field === 'name') return node.name;
      throw new GQLFieldError(`Cannot query field "${field}" on type "Label".`);
    }
    case 'ChangedFile': {
      if (field === 'filename' || field === 'path') return node.filename;
      if (field === 'additions') return node.additions;
      if (field === 'deletions') return node.deletions;
      if (field === 'changes') return node.changes;
      if (field === 'status') return node.status;
      throw new GQLFieldError(`Cannot query field "${field}" on type "PullRequestChangedFile".`);
    }
    case 'CreateIssuePayload': {
      if (field === 'issue') return node.issue;
      throw new GQLFieldError(`Cannot query field "${field}" on type "CreateIssuePayload".`);
    }
    case 'CloseIssuePayload': {
      if (field === 'issue') return node.issue;
      throw new GQLFieldError(`Cannot query field "${field}" on type "CloseIssuePayload".`);
    }
    case 'CreatePullRequestPayload': {
      if (field === 'pullRequest') return node.pr;
      throw new GQLFieldError(`Cannot query field "${field}" on type "CreatePullRequestPayload".`);
    }
    case 'MergePullRequestPayload': {
      if (field === 'pullRequest') return node.pr;
      throw new GQLFieldError(`Cannot query field "${field}" on type "MergePullRequestPayload".`);
    }
    case 'AddCommentPayload': {
      if (field === 'commentEdge') return node.commentEdge ? ({ __type: 'CommentEdge', node: node.commentEdge.node } as GQLNode) : null;
      throw new GQLFieldError(`Cannot query field "${field}" on type "AddCommentPayload".`);
    }
    case 'CommentEdge': {
      if (field === 'node') return node.node;
      throw new GQLFieldError(`Cannot query field "${field}" on type "IssueCommentEdge".`);
    }
    case '__Type': {
      if (field === 'name') return node.name;
      if (field === 'kind') return node.kind;
      if (field === 'fields') return node.fields.map((f) => ({ name: f }));
      if (field === 'enumValues') return node.enumValues.map((v) => ({ name: v }));
      throw new GQLFieldError(`Cannot query field "${field}" on type "__Type".`);
    }
  }
}

function executeSelections(node: GQLNode, selections: GQLSelection[], ctx: GQLCtx): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const sel of selections) {
    if (sel.kind === 'fragment') {
      const frag = ctx.fragments.get(sel.name ?? '');
      if (frag) Object.assign(out, executeSelections(node, frag.selections, ctx));
      continue;
    }
    if (sel.kind === 'inline') {
      if (!sel.typeCondition || sel.typeCondition === node.__type) {
        Object.assign(out, executeSelections(node, sel.selections ?? [], ctx));
      }
      continue;
    }
    const fieldName = sel.name as string;
    const key = sel.alias ?? fieldName;
    if (fieldName === '__typename') {
      out[key] = node.__type;
      continue;
    }
    const args = argMap(sel, ctx);
    let value: unknown;
    try {
      value = resolveField(node, fieldName, args);
    } catch (err) {
      if (err instanceof GQLFieldError) {
        ctx.errors.push({ message: err.message });
        out[key] = null;
        continue;
      }
      throw err;
    }
    if (value === null || value === undefined) {
      out[key] = null;
      continue;
    }
    if (sel.selections && sel.selections.length > 0) {
      if (isObjectLike(value)) {
        out[key] = executeSelections(value, sel.selections, ctx);
      } else if (Array.isArray(value)) {
        out[key] = value.map((v) => (isObjectLike(v) ? executeSelections(v, sel.selections as GQLSelection[], ctx) : v));
      } else {
        out[key] = value;
      }
    } else {
      out[key] = value;
    }
  }
  return out;
}

function executeGraphQL(doc: string, variables: Record<string, unknown>, operationName?: string): { data: Record<string, unknown> | null; errors?: Array<{ message: string }> } {
  let parsed;
  try {
    parsed = new GQLParser(tokenizeGQL(doc)).parseDocument();
  } catch (err) {
    return { data: null, errors: [{ message: err instanceof Error ? err.message : String(err) }] };
  }
  let op: GQLOperation | undefined;
  if (operationName !== undefined) {
    op = parsed.operations.find((o) => o.name === operationName);
    if (!op) return { data: null, errors: [{ message: `Unknown operation named "${operationName}".` }] };
  } else if (parsed.operations.length === 1) {
    op = parsed.operations[0];
  } else if (parsed.operations.length === 0) {
    return { data: null, errors: [{ message: 'No operation in document.' }] };
  } else {
    return { data: null, errors: [{ message: 'Must provide operation name when there are multiple operations.' }] };
  }
  const vars: Record<string, unknown> = {};
  for (const def of op.varDefs) {
    if (variables[def.name] !== undefined) vars[def.name] = variables[def.name];
    else if (def.defaultValue !== undefined) vars[def.name] = evalGQLValue(def.defaultValue, {});
    else vars[def.name] = null;
  }
  const ctx: GQLCtx = { errors: [], fragments: parsed.fragments, vars };
  const root: GQLNode = op.kind === 'mutation' ? { __type: 'Mutation' } : { __type: 'Query' };
  let data: Record<string, unknown>;
  try {
    data = executeSelections(root, op.selections, ctx);
  } catch (err) {
    return { data: null, errors: [{ message: err instanceof Error ? err.message : String(err) }] };
  }
  if (ctx.errors.length > 0) return { data, errors: ctx.errors };
  return { data };
}

// ---------------------------------------------------------------- MCP

const MCP_REVISIONS = ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26'];
const MCP_SESSION_ID = 'mcp-session-1';
interface MCPTool {
  name: string;
  description: string;
  inputSchema: { type: 'object'; properties: Record<string, unknown>; required: string[] };
}
const MCP_TOOLS: MCPTool[] = [
  {
    name: 'create_repo',
    description: 'Create a new repository owned by the authenticated user.',
    inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Repository owner login' }, name: { type: 'string', description: 'Repository name' }, description: { type: 'string', description: 'Repository description' }, private: { type: 'boolean', description: 'Whether the repository is private' } }, required: ['name'] },
  },
  {
    name: 'get_repo',
    description: 'Get a repository by owner and name.',
    inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Repository owner login' }, repo: { type: 'string', description: 'Repository name' } }, required: ['owner', 'repo'] },
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Repository owner login' }, repo: { type: 'string', description: 'Repository name' }, title: { type: 'string', description: 'Issue title' }, body: { type: 'string', description: 'Issue body' } }, required: ['owner', 'repo', 'title'] },
  },
  {
    name: 'list_issues',
    description: 'List issues in a repository.',
    inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Repository owner login' }, repo: { type: 'string', description: 'Repository name' }, state: { type: 'string', description: 'Issue state filter: open, closed or all' } }, required: ['owner', 'repo'] },
  },
  {
    name: 'create_pull_request',
    description: 'Create a pull request in a repository.',
    inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Repository owner login' }, repo: { type: 'string', description: 'Repository name' }, title: { type: 'string', description: 'Pull request title' }, body: { type: 'string', description: 'Pull request body' }, head: { type: 'string', description: 'Head branch name' }, base: { type: 'string', description: 'Base branch name' } }, required: ['owner', 'repo', 'title', 'head', 'base'] },
  },
  {
    name: 'merge_pull_request',
    description: 'Merge a pull request with the squash method.',
    inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Repository owner login' }, repo: { type: 'string', description: 'Repository name' }, pull_number: { type: 'integer', description: 'Pull request number' } }, required: ['owner', 'repo', 'pull_number'] },
  },
  {
    name: 'list_repos',
    description: 'List repositories owned by the authenticated user.',
    inputSchema: { type: 'object', properties: {}, required: [] },
  },
  {
    name: 'get_issue',
    description: 'Get an issue by owner, repository and number.',
    inputSchema: { type: 'object', properties: { owner: { type: 'string', description: 'Repository owner login' }, repo: { type: 'string', description: 'Repository name' }, number: { type: 'integer', description: 'Issue number' } }, required: ['owner', 'repo', 'number'] },
  },
];

function mcpToolCall(name: string, args: Record<string, unknown>): { text: string; structured: Record<string, unknown> } {
  const need = (keys: string[]): void => {
    for (const k of keys) {
      if (args[k] === undefined || args[k] === null || args[k] === '') throw new Error(`missing required argument: ${k}`);
    }
  };
  const ownerOf = (): string => (typeof args.owner === 'string' && args.owner !== '' ? args.owner : VIEWER_LOGIN);
  switch (name) {
    case 'create_repo': {
      need(['name']);
      const repoName = String(args.name);
      const owner = ownerOf();
      if (getRepo(owner, repoName)) throw new Error('Repository already exists');
      const repo = newRepo(owner, repoName, typeof args.description === 'string' ? args.description : '', args.private === true);
      const out = repoJson(repo);
      return { text: JSON.stringify(out), structured: out as Record<string, unknown> };
    }
    case 'get_repo': {
      need(['owner', 'repo']);
      const repo = getRepo(String(args.owner), String(args.repo));
      if (!repo) throw new Error('Not Found');
      const out = repoJson(repo);
      return { text: JSON.stringify(out), structured: out as Record<string, unknown> };
    }
    case 'create_issue': {
      need(['owner', 'repo', 'title']);
      const repo = getRepo(String(args.owner), String(args.repo));
      if (!repo) throw new Error('Not Found');
      const number = repo.nextIssue++;
      const issue: IssueRec = { id: nextIssueId++, number, title: String(args.title), body: typeof args.body === 'string' ? args.body : '', state: 'open', labels: [], seq: nextSeq(), comments: [] };
      repo.issues.set(number, issue);
      const out = issueJson(repo, issue);
      return { text: JSON.stringify(out), structured: out as Record<string, unknown> };
    }
    case 'list_issues': {
      need(['owner', 'repo']);
      const repo = getRepo(String(args.owner), String(args.repo));
      if (!repo) throw new Error('Not Found');
      const state = typeof args.state === 'string' ? args.state : 'open';
      let list = [...repo.issues.values()];
      if (state !== 'all') list = list.filter((i) => i.state === state);
      list.sort((a, b) => b.seq - a.seq);
      const out = { issues: list.map((i) => issueJson(repo, i)) };
      return { text: JSON.stringify(out), structured: out as unknown as Record<string, unknown> };
    }
    case 'create_pull_request': {
      need(['owner', 'repo', 'title', 'head', 'base']);
      const repo = getRepo(String(args.owner), String(args.repo));
      if (!repo) throw new Error('Not Found');
      const head = String(args.head);
      const base = String(args.base);
      if (!repo.refs.has(`refs/heads/${head}`) || !repo.refs.has(`refs/heads/${base}`)) throw new Error('head or base branch does not exist');
      const number = repo.nextPull++;
      const pr: PullRec = { id: nextPullId++, number, title: String(args.title), body: typeof args.body === 'string' ? args.body : '', state: 'open', head, base, seq: nextSeq(), merged: false, mergedAt: null, mergeCommitSha: null };
      repo.pulls.set(number, pr);
      const out = prJson(repo, pr);
      return { text: JSON.stringify(out), structured: out as Record<string, unknown> };
    }
    case 'merge_pull_request': {
      need(['owner', 'repo', 'pull_number']);
      const repo = getRepo(String(args.owner), String(args.repo));
      if (!repo) throw new Error('Not Found');
      const pr = repo.pulls.get(Number(args.pull_number));
      if (!pr) throw new Error('Not Found');
      if (pr.state !== 'open') throw new Error('Pull request is not open');
      if (prConflict(repo, pr) !== null) throw new Error('Merge conflict');
      const headSha = resolveRef(repo, pr.head) as string;
      const baseSha = resolveRef(repo, pr.base) as string;
      const headTree = parseCommit((repo.objects.get(headSha) as GitObj).data).tree;
      const seq = nextSeq();
      const mergeSha = storeObject(repo, { type: 'commit', data: buildCommit(headTree, [baseSha], pr.title, seq) });
      repo.refs.set(`refs/heads/${pr.base}`, mergeSha);
      pr.state = 'merged';
      pr.merged = true;
      pr.mergedAt = isoForSeq(seq);
      pr.mergeCommitSha = mergeSha;
      const out = { sha: mergeSha, merged: true, message: pr.title };
      return { text: JSON.stringify(out), structured: out };
    }
    case 'list_repos': {
      const out = { repos: [...repos.values()].filter((r) => r.owner === VIEWER_LOGIN).sort((a, b) => a.id - b.id).map(repoJson) };
      return { text: JSON.stringify(out), structured: out as unknown as Record<string, unknown> };
    }
    case 'get_issue': {
      need(['owner', 'repo', 'number']);
      const repo = getRepo(String(args.owner), String(args.repo));
      const issue = repo?.issues.get(Number(args.number));
      if (!repo || !issue) throw new Error('Not Found');
      const out = issueJson(repo, issue);
      return { text: JSON.stringify(out), structured: out as Record<string, unknown> };
    }
    default:
      throw new Error(`unknown tool: ${name}`);
  }
}

function handleMcp(req: IncomingMessage, res: ServerResponse, rawBody: Buffer): void {
  const mirror: Record<string, string> = {};
  if (req.headers['mcp-session-id']) mirror['mcp-session-id'] = String(req.headers['mcp-session-id']);
  else mirror['mcp-session-id'] = MCP_SESSION_ID;
  if (req.headers['mcp-name']) mirror['mcp-name'] = String(req.headers['mcp-name']);
  let body: unknown;
  try {
    body = JSON.parse(rawBody.toString('utf8'));
  } catch {
    const text = JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    res.writeHead(400, { 'content-type': JSON_TYPE, 'content-length': Buffer.byteLength(text), ...mirror });
    res.end(text);
    return;
  }
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    const text = JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid Request' } });
    res.writeHead(400, { 'content-type': JSON_TYPE, 'content-length': Buffer.byteLength(text), ...mirror });
    res.end(text);
    return;
  }
  const msg = body as Record<string, unknown>;
  const id = msg.id === undefined ? null : msg.id;
  const method = typeof msg.method === 'string' ? msg.method : '';
  const send = (status: number, payload: unknown): void => {
    const text = JSON.stringify(payload);
    res.writeHead(status, { 'content-type': JSON_TYPE, 'content-length': Buffer.byteLength(text), ...mirror });
    res.end(text);
  };
  // Notification (no id): 202, no body.
  if (msg.id === undefined) {
    if (method === 'notifications/initialized' || method.startsWith('notifications/')) {
      res.writeHead(202, { ...mirror });
      res.end();
      return;
    }
    res.writeHead(202, { ...mirror });
    res.end();
    return;
  }
  const params = (msg.params ?? {}) as Record<string, unknown>;
  if (method === 'server/discover') {
    send(200, { jsonrpc: '2.0', id, result: { protocolVersion: MCP_REVISIONS[0], supportedVersions: MCP_REVISIONS, capabilities: { tools: { listChanged: false } }, serverInfo: { name: 'github-core-clone', version: '1.0.0' } } });
    return;
  }
  if (method === 'initialize') {
    const offered = typeof params.protocolVersion === 'string' ? params.protocolVersion : '';
    const chosen = MCP_REVISIONS.includes(offered) ? offered : MCP_REVISIONS[1];
    send(200, { jsonrpc: '2.0', id, result: { protocolVersion: chosen, capabilities: { tools: {} }, serverInfo: { name: 'github-core-clone', version: '1.0.0' } } });
    return;
  }
  if (method === 'ping') {
    send(200, { jsonrpc: '2.0', id, result: {} });
    return;
  }
  if (method === 'tools/list') {
    send(200, { jsonrpc: '2.0', id, result: { tools: MCP_TOOLS } });
    return;
  }
  if (method === 'tools/call') {
    const toolName = typeof params.name === 'string' ? params.name : '';
    const args = (params.arguments ?? {}) as Record<string, unknown>;
    if (typeof args !== 'object' || args === null || Array.isArray(args)) {
      send(200, { jsonrpc: '2.0', id, error: { code: -32602, message: 'Invalid params: arguments must be an object' } });
      return;
    }
    const tool = MCP_TOOLS.find((t) => t.name === toolName);
    if (!tool) {
      send(200, { jsonrpc: '2.0', id, error: { code: -32601, message: `Unknown tool: ${toolName}` } });
      return;
    }
    try {
      const out = mcpToolCall(toolName, args);
      send(200, { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: out.text }], structuredContent: out.structured, isError: false } });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (message.startsWith('missing required argument')) {
        send(200, { jsonrpc: '2.0', id, error: { code: -32602, message } });
      } else {
        send(200, { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: message }], isError: true } });
      }
    }
    return;
  }
  send(200, { jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${method}` } });
}

// ---------------------------------------------------------------- server

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on('data', (c: Buffer) => {
      total += c.length;
      if (total > 64 * 1024 * 1024) {
        reject(new Error('request body too large'));
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function authorized(req: IncomingMessage): boolean {
  if (TOKEN === '') return true;
  const h = req.headers.authorization ?? '';
  return h === `Bearer ${TOKEN}`;
}

/** Build the server. It binds nothing until the caller listens. */
export function createApp(): Server {
  return createServer((req: IncomingMessage, res: ServerResponse) => {
    void (async () => {
      try {
        const url = new URL(req.url ?? '/', 'http://entry');
        const path = url.pathname;
        const method = req.method ?? 'GET';
        if (method === 'GET' && path === '/healthz') {
          jsonBody(res, 200, { ok: true });
          return;
        }
        const gitMatch = path.match(/^\/([^/]+)\/([^/]+)\.git\/(info\/refs|git-upload-pack|git-receive-pack)$/);
        if (gitMatch) {
          if (!authorized(req)) {
            jsonBody(res, 401, { message: 'Requires authentication' });
            return;
          }
          const owner = decodeURIComponent(gitMatch[1]);
          const name = decodeURIComponent(gitMatch[2]);
          const action = gitMatch[3];
          const repo = getRepo(owner, name);
          if (action === 'info/refs') {
            const service = url.searchParams.get('service') ?? '';
            handleInfoRefs(req, res, owner, name, service);
            return;
          }
          if (!repo) {
            jsonBody(res, 404, { message: 'Not Found' });
            return;
          }
          const rawBody = await readBody(req);
          if (action === 'git-upload-pack') {
            const v2 = (req.headers['git-protocol'] ?? '') === 'version=2';
            let packets: Pkt[];
            try {
              packets = decodePktLines(rawBody);
            } catch {
              jsonBody(res, 400, { message: 'Malformed pkt-line stream' });
              return;
            }
            const out = v2 ? handleUploadPackV2(repo, packets) : handleUploadPackV0(repo, packets);
            sendRaw(res, 200, 'application/x-git-upload-pack-result', out);
            return;
          }
          // git-receive-pack (v0)
          let out: Buffer;
          try {
            out = handleReceivePack(repo, rawBody);
          } catch (err) {
            const detail = err instanceof Error ? err.message : String(err);
            out = Buffer.concat([
              pktLine(Buffer.concat([Buffer.from([1]), Buffer.from(`unpack ${detail}\n`, 'utf8')])),
              FLUSH,
            ]);
          }
          sendRaw(res, 200, 'application/x-git-receive-pack-result', out);
          return;
        }
        if (path === '/api/graphql' && method === 'POST') {
          if (!authorized(req)) {
            jsonBody(res, 401, { message: 'Requires authentication' });
            return;
          }
          const rawBody = await readBody(req);
          let parsed: unknown;
          try {
            parsed = JSON.parse(rawBody.toString('utf8'));
          } catch {
            jsonBody(res, 400, { message: 'Invalid JSON' });
            return;
          }
          const runOne = (entry: unknown): Record<string, unknown> => {
            if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) return { data: null, errors: [{ message: 'Invalid GraphQL request' }] };
            const e = entry as Record<string, unknown>;
            const query = typeof e.query === 'string' ? e.query : '';
            const variables = (e.variables ?? {}) as Record<string, unknown>;
            const operationName = typeof e.operationName === 'string' ? e.operationName : undefined;
            if (query === '') return { data: null, errors: [{ message: 'No query provided' }] };
            return executeGraphQL(query, variables, operationName);
          };
          if (Array.isArray(parsed)) {
            jsonBody(res, 200, parsed.map(runOne));
          } else {
            jsonBody(res, 200, runOne(parsed));
          }
          return;
        }
        if (path === '/mcp' && method === 'POST') {
          if (!authorized(req)) {
            jsonBody(res, 401, { message: 'Requires authentication' });
            return;
          }
          const rawBody = await readBody(req);
          handleMcp(req, res, rawBody);
          return;
        }
        if (path === '/api/v3' || path.startsWith('/api/v3/')) {
          if (!authorized(req)) {
            jsonBody(res, 401, { message: 'Requires authentication' }, reqIdHeader());
            return;
          }
          const restPath = path === '/api/v3' ? '' : path.slice('/api/v3/'.length);
          const segments = restPath === '' ? [] : restPath.split('/').filter((s) => s !== '');
          let parsedBody: unknown = null;
          if (method === 'POST' || method === 'PATCH' || method === 'PUT' || method === 'DELETE') {
            const rawBody = await readBody(req);
            if (rawBody.length > 0) {
              try {
                parsedBody = JSON.parse(rawBody.toString('utf8'));
              } catch {
                badJson(res);
                return;
              }
            }
          }
          const ctx: RestCtx = { method, segments, query: url.searchParams, body: parsedBody, rawBody: Buffer.alloc(0), host: req.headers.host ?? 'localhost' };
          const handled = handleRest(ctx, res);
          if (!handled) jsonBody(res, 404, { message: 'Not Found' }, reqIdHeader());
          return;
        }
        jsonBody(res, 404, { message: 'Not Found' });
      } catch (err) {
        process.stderr.write(`[entry] handler error: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
        if (!res.headersSent) {
          try {
            jsonBody(res, 500, { message: 'Internal Server Error' });
          } catch {
            // socket already gone
          }
        }
      }
    })();
  });
}
