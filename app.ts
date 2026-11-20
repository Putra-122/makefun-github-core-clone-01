// github-core-clone-01 entry: a standalone GitHub-compatible git forge.
// Node 22 stdlib only. One process, in-memory store, no git binary, no UI.
// Serves: git smart HTTP (upload-pack v2, receive-pack v0), REST v3, GraphQL v4, MCP.
//
// Determinism: no wall clock, no Math.random in any response. Fixed timestamps for
// commits the forge creates (1700000000, +0000); ids from counters, not random.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';

// ---------------------------------------------------------------------------
// identity & constants

const VIEWER_LOGIN = 'adaiversen';
const VIEWER_ID = 1000;
const VIEWER_NAME = 'ada iversen';
const VIEWER_EMAIL = 'adaiversen@example.invalid';
const FIXED_TS = 1700000000;
const FIXED_IDENT = `${VIEWER_NAME} <${VIEWER_EMAIL}> ${FIXED_TS} +0000`;
const ZERO_OID = '0000000000000000000000000000000000000000';
const FORGE_VERSION = '1.0.0';
const AGENT_NAME = 'github-core-clone/1.0.0';
const JSON_TYPE = 'application/json; charset=utf-8';
const MAX_BODY_BYTES = 128 * 1024 * 1024;

let reqSeq = 0;
let nextRepoId = 5000; // scenario repos[0].id is 5000; ids are read back from creation responses
let nextIssueId = 1;
let nextCommentId = 1;
let nextPullId = 1;

// ---------------------------------------------------------------------------
// git primitives

type GitObjectType = 'commit' | 'tree' | 'blob' | 'tag';
interface GitObject { type: GitObjectType; data: Buffer; }

function sha1Hex(data: Buffer): string {
  return createHash('sha1').update(data).digest('hex');
}

function hashObject(type: GitObjectType, data: Buffer): string {
  const header = Buffer.from(`${type} ${data.length}\0`, 'utf8');
  return sha1Hex(Buffer.concat([header, data]));
}

function isObjectId(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{40}$/.test(value);
}

interface TreeEntry { mode: string; name: string; oid: string; }

function treeSortKey(entry: TreeEntry): string {
  return entry.mode === '40000' ? `${entry.name}/` : entry.name;
}

function buildTree(entries: readonly TreeEntry[]): Buffer {
  const sorted = [...entries].sort((a, b) => {
    const ka = treeSortKey(a);
    const kb = treeSortKey(b);
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  });
  const parts: Buffer[] = [];
  for (const entry of sorted) {
    parts.push(Buffer.from(`${entry.mode} ${entry.name}\0`, 'utf8'));
    parts.push(Buffer.from(entry.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let offset = 0;
  while (offset < data.length) {
    const space = data.indexOf(0x20, offset);
    const nul = data.indexOf(0x00, space);
    if (space < 0 || nul < 0 || nul + 21 > data.length) throw new Error('corrupt tree object');
    const mode = data.subarray(offset, space).toString('utf8');
    const name = data.subarray(space + 1, nul).toString('utf8');
    const oid = data.subarray(nul + 1, nul + 21).toString('hex');
    entries.push({ mode, name, oid });
    offset = nul + 21;
  }
  return entries;
}

interface ParsedCommit {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
}

function parseCommit(data: Buffer): ParsedCommit {
  const text = data.toString('utf8');
  const blank = text.indexOf('\n\n');
  const header = blank < 0 ? text : text.slice(0, blank);
  const message = blank < 0 ? '' : text.slice(blank + 2);
  const out: ParsedCommit = { tree: '', parents: [], author: '', committer: '', message };
  for (const line of header.split('\n')) {
    if (line.startsWith('tree ')) out.tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) out.parents.push(line.slice(7).trim());
    else if (line.startsWith('author ')) out.author = line.slice(7);
    else if (line.startsWith('committer ')) out.committer = line.slice(10);
  }
  return out;
}

interface ParsedTag { object: string; type: string; tag: string; tagger: string; message: string; }

function parseTag(data: Buffer): ParsedTag {
  const text = data.toString('utf8');
  const blank = text.indexOf('\n\n');
  const header = blank < 0 ? text : text.slice(0, blank);
  const message = blank < 0 ? '' : text.slice(blank + 2);
  const out: ParsedTag = { object: '', type: '', tag: '', tagger: '', message };
  for (const line of header.split('\n')) {
    if (line.startsWith('object ')) out.object = line.slice(7).trim();
    else if (line.startsWith('type ')) out.type = line.slice(5).trim();
    else if (line.startsWith('tag ')) out.tag = line.slice(4);
    else if (line.startsWith('tagger ')) out.tagger = line.slice(7);
  }
  return out;
}

function buildCommit(tree: string, parents: readonly string[], message: string, author: string, committer: string): Buffer {
  const msg = message.endsWith('\n') ? message : `${message}\n`;
  let text = `tree ${tree}\n`;
  for (const parent of parents) text += `parent ${parent}\n`;
  text += `author ${author}\ncommitter ${committer}\n\n${msg}`;
  return Buffer.from(text, 'utf8');
}

/** Reachable object ids from `tips`, following commits -> tree -> entries, tags -> target. */
function collectReachable(
  tips: Iterable<string>,
  lookup: (oid: string) => GitObject | undefined,
  options: { maxDepth?: number; stopAt?: ReadonlySet<string> } = {},
): Map<string, number> {
  // returns oid -> commit depth (1 for a tip commit; trees/blobs/tags get depth of their commit)
  const seen = new Map<string, number>();
  const queue: Array<{ oid: string; depth: number }> = [];
  for (const tip of tips) queue.push({ oid: tip, depth: 1 });
  while (queue.length > 0) {
    const item = queue.shift()!;
    if (seen.has(item.oid)) continue;
    const object = lookup(item.oid);
    if (!object) continue;
    seen.set(item.oid, item.depth);
    if (options.stopAt !== undefined && options.stopAt.has(item.oid)) continue;
    if (object.type === 'commit') {
      if (options.maxDepth !== undefined && item.depth >= options.maxDepth) {
        // boundary commit: include its tree, not its parents
        const parsed = parseCommit(object.data);
        const tree = lookup(parsed.tree);
        if (tree && !seen.has(parsed.tree)) {
          seen.set(parsed.tree, item.depth);
          queue.push({ oid: parsed.tree, depth: item.depth });
        }
        continue;
      }
      const parsed = parseCommit(object.data);
      for (const parent of parsed.parents) {
        if (!seen.has(parent)) queue.push({ oid: parent, depth: item.depth + 1 });
      }
      if (!seen.has(parsed.tree)) queue.push({ oid: parsed.tree, depth: item.depth });
    } else if (object.type === 'tree') {
      for (const entry of parseTree(object.data)) {
        if (!seen.has(entry.oid)) queue.push({ oid: entry.oid, depth: item.depth });
      }
    } else if (object.type === 'tag') {
      const parsed = parseTag(object.data);
      if (!seen.has(parsed.object)) queue.push({ oid: parsed.object, depth: item.depth });
    }
  }
  return seen;
}

// ---------------------------------------------------------------------------
// pkt-line codec

/** A flush packet: the four-byte length "0000" with no payload. */
const FLUSH_PKT = Buffer.from('0000', 'utf8');
/** A delimiter packet: "0001". */
const DELIM_PKT = Buffer.from('0001', 'utf8');
/** A response-end packet: "0002". */
const RESPONSE_END_PKT = Buffer.from('0002', 'utf8');

function pktLine(payload: string | Buffer): Buffer {
  const body = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const length = body.length + 4;
  const header = Buffer.from(length.toString(16).padStart(4, '0'), 'ascii');
  return Buffer.concat([header, body]);
}

const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');

type PktLine = { kind: 'data'; payload: Buffer } | { kind: 'flush' } | { kind: 'delim' } | { kind: 'response-end' };

function decodePktLines(buffer: Buffer): PktLine[] {
  const lines: PktLine[] = [];
  let offset = 0;
  while (offset < buffer.length) {
    if (offset + 4 > buffer.length) throw new Error('truncated pkt-line');
    const header = buffer.subarray(offset, offset + 4).toString('ascii');
    if (header === '0000') { lines.push({ kind: 'flush' }); offset += 4; continue; }
    if (header === '0001') { lines.push({ kind: 'delim' }); offset += 4; continue; }
    if (header === '0002') { lines.push({ kind: 'response-end' }); offset += 4; continue; }
    const length = parseInt(header, 16);
    if (!Number.isFinite(length) || length < 4 || length > 65520 || offset + length > buffer.length) {
      throw new Error(`malformed pkt-line length ${JSON.stringify(header)}`);
    }
    lines.push({ kind: 'data', payload: buffer.subarray(offset + 4, offset + length) });
    offset += length;
  }
  return lines;
}

function encodePktLines(lines: readonly (string | Buffer | 'flush' | 'delim')[]): Buffer {
  const parts: Buffer[] = [];
  for (const line of lines) {
    if (line === 'flush') parts.push(PKT_FLUSH);
    else if (line === 'delim') parts.push(PKT_DELIM);
    else parts.push(pktLine(line));
  }
  return Buffer.concat(parts);
}

/** One sideband packet: [band][data...], chunked so no pkt-line exceeds the limit. */
function sidebandPackets(band: number, data: Buffer): Buffer[] {
  const out: Buffer[] = [];
  const CHUNK = 65500;
  if (data.length === 0) return out;
  for (let offset = 0; offset < data.length; offset += CHUNK) {
    const piece = data.subarray(offset, Math.min(data.length, offset + CHUNK));
    const payload = Buffer.concat([Buffer.from([band]), piece]);
    out.push(pktLine(payload));
  }
  return out;
}

// ---------------------------------------------------------------------------
// packfile codec (plain objects only; no deltas)

const PACK_TYPE_CODE: Record<GitObjectType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };

function writePackObjectHeader(type: GitObjectType, size: number): Buffer {
  const code = PACK_TYPE_CODE[type];
  const bytes: number[] = [];
  let remaining = size;
  let first = (code << 4) | (remaining & 0x0f);
  remaining = Math.floor(remaining / 16);
  while (remaining > 0) {
    bytes.push(first | 0x80);
    first = remaining & 0x7f;
    remaining = Math.floor(remaining / 128);
  }
  bytes.push(first);
  return Buffer.from(bytes);
}

function writePack(objects: readonly GitObject[]): Buffer {
  const parts: Buffer[] = [];
  const header = Buffer.allocUnsafe(12);
  header.write('PACK', 0, 4, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(objects.length, 8);
  parts.push(header);
  for (const object of objects) {
    parts.push(writePackObjectHeader(object.type, object.data.length));
    parts.push(deflateSync(object.data));
  }
  const body = Buffer.concat(parts);
  return Buffer.concat([body, createHash('sha1').update(body).digest()]);
}

function readVarintSize(buffer: Buffer, start: number): { size: number; next: number; first: number } {
  if (start >= buffer.length) throw new Error('pack entry has no size header');
  let byte = buffer[start];
  const first = byte;
  let size = byte & 0x0f;
  let shift = 4;
  let offset = start + 1;
  while (byte & 0x80) {
    if (offset >= buffer.length) throw new Error('pack entry size varint is truncated');
    byte = buffer[offset++];
    size += (byte & 0x7f) * 2 ** shift;
    shift += 7;
    if (shift > 63) throw new Error('pack entry size varint is too long');
  }
  return { size, next: offset, first };
}

const PACK_CODE_TYPE: Record<number, GitObjectType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

function inflateAt(buffer: Buffer, offset: number, limit: number): { data: Buffer; next: number } {
  const view = buffer.subarray(offset, limit);
  const result = inflateSync(view, { info: true }) as unknown as { buffer: Buffer; engine: { bytesWritten: number } };
  const written = result.engine.bytesWritten;
  if (!written || written <= 0) throw new Error(`zlib stream at offset ${offset} consumed no bytes`);
  return { data: result.buffer, next: offset + written };
}

/** Parse a packfile; returns the objects keyed by recomputed oid. Throws on any corruption. */
function readPack(pack: Buffer): Map<string, GitObject> {
  if (pack.length < 32) throw new Error(`pack is ${pack.length} bytes, too short`);
  if (pack.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('pack does not start with PACK');
  const version = pack.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error(`unsupported pack version ${version}`);
  const declaredCount = pack.readUInt32BE(8);
  const trailerStart = pack.length - 20;
  const trailer = pack.subarray(trailerStart).toString('hex');
  const computed = createHash('sha1').update(pack.subarray(0, trailerStart)).digest('hex');
  if (trailer !== computed) throw new Error('pack trailer checksum mismatch');
  const objects = new Map<string, GitObject>();
  let offset = 12;
  for (let index = 0; index < declaredCount; index += 1) {
    const header = readVarintSize(pack, offset);
    offset = header.next;
    const typeCode = (header.first >> 4) & 0x07;
    if (typeCode === 6 || typeCode === 7) throw new Error('delta pack entries are not accepted');
    const type = PACK_CODE_TYPE[typeCode];
    if (!type) throw new Error(`pack entry ${index} has unknown type code ${typeCode}`);
    const inflated = inflateAt(pack, offset, trailerStart);
    if (inflated.data.length !== header.size) {
      throw new Error(`pack entry declares ${header.size} bytes but inflated to ${inflated.data.length}`);
    }
    offset = inflated.next;
    const oid = hashObject(type, inflated.data);
    if (!objects.has(oid)) objects.set(oid, { type, data: inflated.data });
  }
  if (offset !== trailerStart) throw new Error(`pack has ${trailerStart - offset} stray bytes before its trailer`);
  return objects;
}

// ---------------------------------------------------------------------------
// pkt-line / packfile adapters used by the git smart-HTTP handlers

/** Data payloads of a pkt-line stream (flush/delim/response-end dropped). */
function parsePktLines(buffer: Buffer): Buffer[] {
  const out: Buffer[] = [];
  for (const line of decodePktLines(buffer)) {
    if (line.kind === 'data') out.push(line.payload);
  }
  return out;
}

/** Parse pkt-lines until the first flush; everything after it is returned raw (a pack). */
function parsePktLinesUntilFlush(buffer: Buffer): { lines: Buffer[]; rest: Buffer } {
  const lines: Buffer[] = [];
  let offset = 0;
  while (offset + 4 <= buffer.length) {
    const header = buffer.subarray(offset, offset + 4).toString('ascii');
    if (header === '0000') {
      return { lines, rest: buffer.subarray(offset + 4) };
    }
    if (header === '0001' || header === '0002') {
      offset += 4;
      continue;
    }
    const length = parseInt(header, 16);
    if (!Number.isFinite(length) || length < 4 || offset + length > buffer.length) break;
    lines.push(buffer.subarray(offset + 4, offset + length));
    offset += length;
  }
  return { lines, rest: buffer.subarray(offset) };
}

/** One sideband packet (or several, concatenated); an empty payload still yields one packet. */
function sidebandPacket(band: number, data: Buffer): Buffer {
  const packets = sidebandPackets(band, data);
  if (packets.length === 0) {
    return pktLine(Buffer.concat([Buffer.from([band]), Buffer.alloc(0)]));
  }
  return Buffer.concat(packets);
}

/** Build a packfile holding the given objects from the repo. */
function buildPackfile(repo: Repo, oids: readonly string[]): Buffer {
  const objects: GitObject[] = [];
  for (const oid of oids) {
    const object = repo.objects.get(oid);
    if (object !== undefined) objects.push(object);
  }
  return writePack(objects);
}

/** Parse a packfile and store its objects in the repo. */
function parsePackfile(repo: Repo, pack: Buffer): Map<string, GitObject> {
  const objects = readPack(pack);
  for (const [oid, object] of objects) {
    if (!repo.objects.has(oid)) repo.objects.set(oid, object);
  }
  return objects;
}

// ---------------------------------------------------------------------------
// store

interface Label { name: string; color: string; }
interface Comment { id: number; body: string; user: string; }
interface Issue {
  id: number; number: number; title: string; body: string;
  state: 'open' | 'closed'; labels: string[]; comments: Comment[]; seq: number;
}
interface Pull {
  id: number; number: number; title: string; body: string;
  state: 'open' | 'closed'; headRef: string; baseRef: string;
  headSha: string; baseSha: string; merged: boolean;
  mergedAt: string | null; mergeCommitSha: string | null; seq: number;
}
interface Repo {
  id: number; owner: string; name: string; description: string; isPrivate: boolean;
  defaultBranch: string; createdSeq: number;
  objects: Map<string, GitObject>;
  refs: Map<string, string>;
  labels: Map<string, Label>;
  issues: Issue[]; pulls: Pull[];
  nextIssueNumber: number; nextPullNumber: number;
}

const repos = new Map<string, Repo>();
let repoSeq = 0;

function repoKey(owner: string, name: string): string {
  return `${owner}/${name}`;
}

function createRepoRecord(name: string, isPrivate: boolean, description: string): Repo {
  const repo: Repo = {
    id: nextRepoId++, owner: VIEWER_LOGIN, name, description, isPrivate,
    defaultBranch: 'main', createdSeq: ++repoSeq,
    objects: new Map(), refs: new Map(), labels: new Map(),
    issues: [], pulls: [], nextIssueNumber: 1, nextPullNumber: 1,
  };
  repos.set(repoKey(VIEWER_LOGIN, name), repo);
  return repo;
}

function findRepo(owner: string, name: string): Repo | undefined {
  if (owner !== VIEWER_LOGIN) return undefined;
  return repos.get(repoKey(owner, name));
}

function viewerRepos(): Repo[] {
  return [...repos.values()].sort((a, b) => a.createdSeq - b.createdSeq);
}

// ---------------------------------------------------------------------------
// tree helpers (flat path maps)

interface FileEntry { oid: string; mode: string; }

function treeToFiles(repo: Repo, treeOid: string): Map<string, FileEntry> {
  const out = new Map<string, FileEntry>();
  const walk = (oid: string, prefix: string): void => {
    const object = repo.objects.get(oid);
    if (!object || object.type !== 'tree') return;
    for (const entry of parseTree(object.data)) {
      const path = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
      if (entry.mode === '40000') walk(entry.oid, path);
      else out.set(path, { oid: entry.oid, mode: entry.mode });
    }
  };
  walk(treeOid, '');
  return out;
}

function treeFromFiles(repo: Repo, files: ReadonlyMap<string, FileEntry>): string {
  interface Node { files: Map<string, FileEntry>; dirs: Map<string, Node>; }
  const make = (): Node => ({ files: new Map(), dirs: new Map() });
  const root = make();
  for (const [path, entry] of files) {
    const segments = path.split('/');
    let node = root;
    for (let i = 0; i < segments.length - 1; i += 1) {
      const name = segments[i]!;
      if (!node.dirs.has(name)) node.dirs.set(name, make());
      node = node.dirs.get(name)!;
    }
    node.files.set(segments[segments.length - 1]!, entry);
  }
  const build = (node: Node): string => {
    const entries: TreeEntry[] = [];
    for (const [name, entry] of node.files) entries.push({ mode: entry.mode, name, oid: entry.oid });
    for (const [name, child] of node.dirs) entries.push({ mode: '40000', name, oid: build(child) });
    const data = buildTree(entries);
    const oid = hashObject('tree', data);
    if (!repo.objects.has(oid)) repo.objects.set(oid, { type: 'tree', data });
    return oid;
  };
  return build(root);
}

function storeObject(repo: Repo, type: GitObjectType, data: Buffer): string {
  const oid = hashObject(type, data);
  if (!repo.objects.has(oid)) repo.objects.set(oid, { type, data });
  return oid;
}

function refTip(repo: Repo, ref: string): string | undefined {
  return repo.refs.get(ref);
}

function resolveBranchTip(repo: Repo, name: string): string | undefined {
  if (name.startsWith('refs/')) return repo.refs.get(name);
  return repo.refs.get(`refs/heads/${name}`);
}

function resolveToCommit(repo: Repo, oid: string): string | undefined {
  const object = repo.objects.get(oid);
  if (!object) return undefined;
  if (object.type === 'commit') return oid;
  if (object.type === 'tag') {
    const parsed = parseTag(object.data);
    return resolveToCommit(repo, parsed.object);
  }
  return undefined;
}

function peelToCommit(repo: Repo, oid: string): string | undefined {
  return resolveToCommit(repo, oid);
}

function commitTreeOid(repo: Repo, commitOid: string): string | undefined {
  const object = repo.objects.get(commitOid);
  if (!object || object.type !== 'commit') return undefined;
  return parseCommit(object.data).tree;
}

/** Ancestors of a commit (the commit itself first), in BFS order. */
function ancestors(repo: Repo, tip: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const queue = [tip];
  while (queue.length > 0) {
    const oid = queue.shift()!;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const object = repo.objects.get(oid);
    if (!object || object.type !== 'commit') continue;
    out.push(oid);
    for (const parent of parseCommit(object.data).parents) queue.push(parent);
  }
  return out;
}

function mergeBase(repo: Repo, a: string, b: string): string | undefined {
  const aAncestors = new Set(ancestors(repo, a));
  for (const oid of ancestors(repo, b)) {
    if (aAncestors.has(oid)) return oid;
  }
  return undefined;
}

function isAncestor(repo: Repo, ancestor: string, tip: string): boolean {
  if (ancestor === tip) return true;
  return ancestors(repo, tip).includes(ancestor);
}

interface DiffEntry { path: string; status: 'added' | 'removed' | 'modified'; oldOid: string | null; newOid: string | null; }

function diffFileMaps(oldFiles: ReadonlyMap<string, FileEntry>, newFiles: ReadonlyMap<string, FileEntry>): DiffEntry[] {
  const out: DiffEntry[] = [];
  for (const [path, entry] of newFiles) {
    const old = oldFiles.get(path);
    if (!old) out.push({ path, status: 'added', oldOid: null, newOid: entry.oid });
    else if (old.oid !== entry.oid) out.push({ path, status: 'modified', oldOid: old.oid, newOid: entry.oid });
  }
  for (const [path, entry] of oldFiles) {
    if (!newFiles.has(path)) out.push({ path, status: 'removed', oldOid: entry.oid, newOid: null });
  }
  out.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return out;
}

/** Line additions/deletions between two blobs (LCS on lines, capped). */
function lineDiff(oldData: Buffer | null, newData: Buffer | null): { additions: number; deletions: number } {
  if (oldData === null && newData === null) return { additions: 0, deletions: 0 };
  if (oldData === null) {
    const lines = newData!.toString('utf8').split('\n');
    return { additions: lines.length, deletions: 0 };
  }
  if (newData === null) {
    const lines = oldData.toString('utf8').split('\n');
    return { additions: 0, deletions: lines.length };
  }
  const a = oldData.toString('utf8').split('\n');
  const b = newData.toString('utf8').split('\n');
  if (a.length > 2000 || b.length > 2000) return { additions: b.length, deletions: a.length };
  // LCS length via two rows.
  let prev = new Array<number>(b.length + 1).fill(0);
  let curr = new Array<number>(b.length + 1).fill(0);
  for (let i = 1; i <= a.length; i += 1) {
    curr[0] = 0;
    for (let j = 1; j <= b.length; j += 1) {
      curr[j] = a[i - 1] === b[j - 1] ? prev[j - 1] + 1 : Math.max(prev[j], curr[j - 1]);
    }
    const tmp = prev; prev = curr; curr = tmp;
  }
  const lcs = prev[b.length];
  return { additions: b.length - lcs, deletions: a.length - lcs };
}

/** Three-way merge check: apply head's changes (vs base) onto the current tip tree. */
function tryMergeTrees(
  repo: Repo, baseOid: string, headOid: string, tipOid: string,
): { conflict: false; treeOid: string } | { conflict: true } {
  const baseTree = commitTreeOid(repo, baseOid);
  const headTree = commitTreeOid(repo, headOid);
  const tipTree = commitTreeOid(repo, tipOid);
  if (!baseTree || !headTree || !tipTree) return { conflict: true };
  const baseFiles = treeToFiles(repo, baseTree);
  const headFiles = treeToFiles(repo, headTree);
  const tipFiles = treeToFiles(repo, tipTree);
  const headChanges = diffFileMaps(baseFiles, headFiles);
  const tipChanges = diffFileMaps(baseFiles, tipFiles);
  const tipChanged = new Map(tipChanges.map((c) => [c.path, c]));
  for (const change of headChanges) {
    const other = tipChanged.get(change.path);
    if (!other) continue;
    // Both sides changed this path: conflict unless they agree.
    if (change.newOid !== other.newOid) return { conflict: true };
  }
  const result = new Map(tipFiles);
  for (const change of headChanges) {
    if (change.status === 'removed') result.delete(change.path);
    else if (change.newOid !== null) result.set(change.path, { oid: change.newOid, mode: '100644' });
  }
  return { conflict: false, treeOid: treeFromFiles(repo, result) };
}

function mergeableState(repo: Repo, headSha: string, baseTipSha: string): 'MERGEABLE' | 'CONFLICTING' | 'UNKNOWN' {
  const base = mergeBase(repo, headSha, baseTipSha);
  if (base === undefined) return 'UNKNOWN';
  const merged = tryMergeTrees(repo, base, headSha, baseTipSha);
  return merged.conflict ? 'CONFLICTING' : 'MERGEABLE';
}

function stripMessage(message: string): string {
  return message.replace(/\n+$/, '');
}

// ---------------------------------------------------------------------------
// HTTP helpers

function requestId(): string {
  reqSeq += 1;
  return `gh-${String(reqSeq).padStart(8, '0')}`;
}

function sendJson(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  const text = `${JSON.stringify(body)}\n`;
  res.writeHead(status, {
    'content-type': JSON_TYPE,
    'content-length': Buffer.byteLength(text),
    'x-github-request-id': requestId(),
    ...headers,
  });
  res.end(text);
}

function sendNoContent(res: ServerResponse, status = 204): void {
  res.writeHead(status, { 'x-github-request-id': requestId() });
  res.end();
}

function sendError(res: ServerResponse, status: number, message: string): void {
  sendJson(res, status, { message });
}

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let failed = false;
    req.on('data', (chunk: Buffer) => {
      if (failed) return;
      total += chunk.length;
      if (total > MAX_BODY_BYTES) {
        failed = true;
        reject(new Error('request body too large'));
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function expectedToken(): string | null {
  const token = process.env.MAKEFUN_SHOP_TOKEN ?? '';
  return token === '' ? null : token;
}

function isAuthorized(req: IncomingMessage): boolean {
  const header = req.headers.authorization ?? '';
  if (!header.startsWith('Bearer ')) return false;
  const token = header.slice('Bearer '.length).trim();
  if (token === '') return false;
  const expected = expectedToken();
  if (expected !== null) return token === expected;
  return true;
}

function parseJsonBody(buffer: Buffer): { ok: true; value: unknown } | { ok: false; error: string } {
  const text = buffer.toString('utf8').trim();
  if (text === '') return { ok: true, value: {} };
  try {
    return { ok: true, value: JSON.parse(text) as unknown };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : 'invalid JSON' };
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function b64decodeToBuffer(content: string): Buffer {
  return Buffer.from(content.replace(/[\r\n\t ]+/g, ''), 'base64');
}

function pathOf(req: IncomingMessage): { pathname: string; query: URLSearchParams } {
  try {
    const url = new URL(req.url ?? '/', 'http://entry');
    let pathname = url.pathname;
    if (pathname.length > 1 && pathname.endsWith('/')) pathname = pathname.slice(0, -1);
    return { pathname, query: url.searchParams };
  } catch {
    return { pathname: '/', query: new URLSearchParams() };
  }
}

function decodeSegment(segment: string): string {
  try {
    return decodeURIComponent(segment);
  } catch {
    return segment;
  }
}

function splitPath(pathname: string): string[] {
  return pathname.split('/').filter((s) => s !== '').map(decodeSegment);
}

/** Build a pagination Link header (next only when more pages remain). */
function paginationLink(req: IncomingMessage, page: number, perPage: number, total: number): string | null {
  const totalPages = Math.max(1, Math.ceil(total / perPage));
  if (page >= totalPages) return null;
  const host = req.headers.host ?? 'entry';
  const base = `http://${host}`;
  const url = new URL(req.url ?? '/', base);
  url.searchParams.set('page', String(page + 1));
  url.searchParams.set('per_page', String(perPage));
  return `<${url.toString()}>; rel="next"`;
}

function pageParams(query: URLSearchParams): { page: number; perPage: number } {
  const page = Math.max(1, Number.parseInt(query.get('page') ?? '1', 10) || 1);
  const perPageRaw = Number.parseInt(query.get('per_page') ?? '30', 10);
  const perPage = Number.isFinite(perPageRaw) ? Math.min(100, Math.max(1, perPageRaw)) : 30;
  return { page, perPage };
}

function paginate<T>(items: readonly T[], page: number, perPage: number): T[] {
  const start = (page - 1) * perPage;
  return items.slice(start, start + perPage);
}

// ---------------------------------------------------------------------------
// REST serializers

function repoJson(repo: Repo): Record<string, unknown> {
  return {
    id: repo.id,
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    owner: { login: repo.owner, id: VIEWER_ID, type: 'User' },
    private: repo.isPrivate,
    description: repo.description,
    default_branch: repo.defaultBranch,
    created_at: '2025-01-01T00:00:00Z',
    updated_at: '2025-01-01T00:00:00Z',
    has_issues: true,
    has_projects: false,
    has_wiki: false,
    fork: false,
    archived: false,
    disabled: false,
    visibility: repo.isPrivate ? 'private' : 'public',
  };
}

function issueJson(repo: Repo, issue: Issue): Record<string, unknown> {
  return {
    id: issue.id,
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels.map((name) => {
      const label = repo.labels.get(name);
      return { name, color: label?.color ?? 'ededed' };
    }),
    user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    created_at: '2025-01-01T00:00:00Z',
    updated_at: '2025-01-01T00:00:00Z',
    comments: issue.comments.length,
  };
}

function commentJson(comment: Comment): Record<string, unknown> {
  return {
    id: comment.id,
    body: comment.body,
    user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    created_at: '2025-01-01T00:00:00Z',
    updated_at: '2025-01-01T00:00:00Z',
  };
}

function pullFilesOf(repo: Repo, pull: Pull): Array<Record<string, unknown>> {
  const baseTree = commitTreeOid(repo, pull.baseSha);
  const headTree = commitTreeOid(repo, pull.headSha);
  if (!baseTree || !headTree) return [];
  const baseFiles = treeToFiles(repo, baseTree);
  const headFiles = treeToFiles(repo, headTree);
  const diffs = diffFileMaps(baseFiles, headFiles);
  return diffs.map((diff) => {
    const oldData = diff.oldOid !== null ? repo.objects.get(diff.oldOid)?.data ?? null : null;
    const newData = diff.newOid !== null ? repo.objects.get(diff.newOid)?.data ?? null : null;
    const counts = lineDiff(oldData, newData);
    return {
      filename: diff.path,
      status: diff.status,
      additions: counts.additions,
      deletions: counts.deletions,
      changes: counts.additions + counts.deletions,
    };
  });
}

function pullJson(repo: Repo, pull: Pull): Record<string, unknown> {
  const baseTip = resolveBranchTip(repo, pull.baseRef);
  const mergeable = baseTip !== undefined ? mergeableState(repo, pull.headSha, baseTip) : 'UNKNOWN';
  return {
    id: pull.id,
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state: pull.state,
    head: {
      ref: pull.headRef,
      sha: pull.headSha,
      label: `${repo.owner}:${pull.headRef}`,
      user: { login: repo.owner, id: VIEWER_ID, type: 'User' },
    },
    base: {
      ref: pull.baseRef,
      sha: pull.baseSha,
      label: `${repo.owner}:${pull.baseRef}`,
      user: { login: repo.owner, id: VIEWER_ID, type: 'User' },
    },
    merged: pull.merged,
    merged_at: pull.mergedAt,
    merge_commit_sha: pull.mergeCommitSha,
    mergeable,
    created_at: '2025-01-01T00:00:00Z',
    updated_at: '2025-01-01T00:00:00Z',
  };
}

function commitJson(repo: Repo, commitOid: string): Record<string, unknown> | null {
  const object = repo.objects.get(commitOid);
  if (!object || object.type !== 'commit') return null;
  const parsed = parseCommit(object.data);
  const ident = (line: string): { name: string; email: string; date: string } => {
    const match = /^(.*) <(.*)> (\d+) \+0000$/.exec(line);
    if (!match) return { name: line, email: '', date: '2025-01-01T00:00:00Z' };
    const ts = Number(match[3]);
    return { name: match[1] ?? '', email: match[2] ?? '', date: new Date(ts * 1000).toISOString() };
  };
  return {
    sha: commitOid,
    commit: {
      message: stripMessage(parsed.message),
      author: ident(parsed.author),
      committer: ident(parsed.committer),
    },
    author: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    committer: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    parents: parsed.parents.map((sha) => ({ sha })),
  };
}

/** Create a commit on `branch` (creating the branch from the default tip when needed). */
function commitFile(
  repo: Repo, branch: string, path: string, content: Buffer, message: string,
): { commitSha: string; contentSha: string; branchCreated: boolean } {
  let tip = resolveBranchTip(repo, branch);
  let branchCreated = false;
  if (tip === undefined) {
    // New branch: fork from the default branch tip (or start unborn).
    const defaultTip = resolveBranchTip(repo, repo.defaultBranch);
    if (defaultTip !== undefined) {
      repo.refs.set(`refs/heads/${branch}`, defaultTip);
      tip = defaultTip;
    }
    branchCreated = true;
  }
  const parentTree = tip !== undefined ? commitTreeOid(repo, tip) : undefined;
  const baseFiles = parentTree !== undefined ? treeToFiles(repo, parentTree) : new Map<string, FileEntry>();
  const contentSha = storeObject(repo, 'blob', content);
  const nextFiles = new Map(baseFiles);
  nextFiles.set(path, { oid: contentSha, mode: '100644' });
  const treeOid = treeFromFiles(repo, nextFiles);
  const commitData = buildCommit(treeOid, tip !== undefined ? [tip] : [], message, FIXED_IDENT, FIXED_IDENT);
  const commitSha = storeObject(repo, 'commit', commitData);
  repo.refs.set(`refs/heads/${branch}`, commitSha);
  return { commitSha, contentSha, branchCreated };
}

function deleteFile(
  repo: Repo, branch: string, path: string, message: string,
): { commitSha: string } | null {
  const tip = resolveBranchTip(repo, branch);
  if (tip === undefined) return null;
  const parentTree = commitTreeOid(repo, tip);
  if (parentTree === undefined) return null;
  const baseFiles = treeToFiles(repo, parentTree);
  if (!baseFiles.has(path)) return null;
  const nextFiles = new Map(baseFiles);
  nextFiles.delete(path);
  const treeOid = treeFromFiles(repo, nextFiles);
  const commitData = buildCommit(treeOid, [tip], message, FIXED_IDENT, FIXED_IDENT);
  const commitSha = storeObject(repo, 'commit', commitData);
  repo.refs.set(`refs/heads/${branch}`, commitSha);
  return { commitSha };
}

function squashMerge(repo: Repo, pull: Pull): { ok: true; sha: string } | { ok: false; reason: string } {
  const baseTip = resolveBranchTip(repo, pull.baseRef);
  if (baseTip === undefined) return { ok: false, reason: 'base branch not found' };
  const base = mergeBase(repo, pull.headSha, baseTip);
  if (base === undefined) return { ok: false, reason: 'no merge base' };
  const merged = tryMergeTrees(repo, base, pull.headSha, baseTip);
  if (merged.conflict) return { ok: false, reason: 'merge conflict' };
  const message = `${pull.title} (#${pull.number})`;
  const commitData = buildCommit(merged.treeOid, [baseTip], message, FIXED_IDENT, FIXED_IDENT);
  const sha = storeObject(repo, 'commit', commitData);
  repo.refs.set(`refs/heads/${pull.baseRef}`, sha);
  pull.state = 'closed';
  pull.merged = true;
  pull.mergedAt = '2025-01-01T00:00:00Z';
  pull.mergeCommitSha = sha;
  return { ok: true, sha };
}

// ---------------------------------------------------------------------------
// REST handlers

type Handler = (req: IncomingMessage, res: ServerResponse, segments: string[], query: URLSearchParams) => Promise<boolean>;

async function handleRest(req: IncomingMessage, res: ServerResponse, segments: string[], query: URLSearchParams): Promise<boolean> {
  const method = req.method ?? 'GET';
  // segments[0..1] are ['api','v3']; the rest is the route.
  const route = segments.slice(2);

  const needBody = method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE';
  let body: unknown = {};
  if (needBody) {
    const raw = await readBody(req);
    const parsed = parseJsonBody(raw);
    if (!parsed.ok) {
      sendError(res, 400, `malformed JSON body: ${parsed.error}`);
      return true;
    }
    body = parsed.value;
  }
  const bodyObj: Record<string, unknown> = isRecord(body) ? body : {};

  // GET /api/v3/ (root) and /api/v3/meta
  if (route.length === 0 && method === 'GET') {
    sendJson(res, 200, { current_user_url: '/api/v3/user', rate_limit_url: '/api/v3/rate_limit' }, { 'x-oauth-scopes': 'repo, read:org' });
    return true;
  }
  if (route.length === 1 && route[0] === 'meta' && method === 'GET') {
    sendJson(res, 200, { installed_version: FORGE_VERSION });
    return true;
  }
  // GET /api/v3/user
  if (route.length === 1 && route[0] === 'user' && method === 'GET') {
    sendJson(res, 200, {
      login: VIEWER_LOGIN, id: VIEWER_ID, name: VIEWER_NAME, email: VIEWER_EMAIL,
      type: 'User', site_admin: false,
    });
    return true;
  }
  // POST /api/v3/user/repos
  if (route.length === 2 && route[0] === 'user' && route[1] === 'repos' && method === 'POST') {
    const name = typeof bodyObj.name === 'string' ? bodyObj.name : '';
    if (name === '' || name.length > 100 || name.includes('/')) {
      sendError(res, 422, 'Repository name is invalid');
      return true;
    }
    if (findRepo(VIEWER_LOGIN, name) !== undefined) {
      sendError(res, 422, `Repository ${VIEWER_LOGIN}/${name} already exists`);
      return true;
    }
    const isPrivate = bodyObj.private === true;
    const description = typeof bodyObj.description === 'string' ? bodyObj.description : '';
    const repo = createRepoRecord(name, isPrivate, description);
    sendJson(res, 201, repoJson(repo));
    return true;
  }
  // GET /api/v3/user/repos (paginated)
  if (route.length === 2 && route[0] === 'user' && route[1] === 'repos' && method === 'GET') {
    const { page, perPage } = pageParams(query);
    const all = viewerRepos();
    const items = paginate(all, page, perPage);
    const headers: Record<string, string> = {};
    const link = paginationLink(req, page, perPage, all.length);
    if (link !== null) headers.link = link;
    sendJson(res, 200, items.map(repoJson), headers);
    return true;
  }

  // /api/v3/repos/{owner}/{name}/...
  if (route.length >= 3 && route[0] === 'repos') {
    const owner = route[1]!;
    const name = route[2]!;
    const repo = findRepo(owner, name);
    if (repo === undefined) {
      sendError(res, 404, 'Not Found');
      return true;
    }
    const rest = route.slice(3);

    // GET/PATCH/DELETE /repos/{o}/{r}
    if (rest.length === 0) {
      if (method === 'GET') { sendJson(res, 200, repoJson(repo)); return true; }
      if (method === 'PATCH') {
        if (typeof bodyObj.description === 'string') repo.description = bodyObj.description;
        if (typeof bodyObj.name === 'string' && bodyObj.name !== '' && bodyObj.name !== repo.name) {
          if (findRepo(owner, bodyObj.name) !== undefined) { sendError(res, 422, 'Repository already exists'); return true; }
          repos.delete(repoKey(owner, repo.name));
          repo.name = bodyObj.name;
          repos.set(repoKey(owner, repo.name), repo);
        }
        sendJson(res, 200, repoJson(repo));
        return true;
      }
      if (method === 'DELETE') {
        repos.delete(repoKey(owner, repo.name));
        sendNoContent(res, 204);
        return true;
      }
      return false;
    }

    // git refs: POST /git/refs, GET /git/refs/heads/{branch}
    if (rest[0] === 'git' && rest[1] === 'refs') {
      if (method === 'POST' && rest.length === 2) {
        const ref = typeof bodyObj.ref === 'string' ? bodyObj.ref : '';
        const sha = typeof bodyObj.sha === 'string' ? bodyObj.sha : '';
        if (!ref.startsWith('refs/') || !isObjectId(sha) || repo.objects.get(sha) === undefined) {
          sendError(res, 422, 'Invalid ref or sha');
          return true;
        }
        if (repo.refs.has(ref)) {
          sendError(res, 422, 'Reference already exists');
          return true;
        }
        repo.refs.set(ref, sha);
        const object = repo.objects.get(sha)!;
        sendJson(res, 201, { ref, object: { sha, type: object.type } });
        return true;
      }
      if (method === 'GET' && rest.length >= 3) {
        const refName = rest.slice(2).join('/');
        const sha = repo.refs.get(refName);
        if (sha === undefined) { sendError(res, 404, 'Not Found'); return true; }
        const object = repo.objects.get(sha);
        sendJson(res, 200, { ref: refName, object: { sha, type: object?.type ?? 'commit' } });
        return true;
      }
      return false;
    }

    // GET /branches and GET /branches/{branch}
    if (rest[0] === 'branches') {
      if (method === 'GET' && rest.length === 1) {
        const list: Array<Record<string, unknown>> = [];
        for (const [ref, sha] of repo.refs) {
          if (ref.startsWith('refs/heads/')) {
            list.push({ name: ref.slice('refs/heads/'.length), commit: { sha }, protected: false });
          }
        }
        sendJson(res, 200, list);
        return true;
      }
      if (method === 'GET' && rest.length >= 2) {
        const branch = rest.slice(1).join('/');
        const sha = resolveBranchTip(repo, branch);
        if (sha === undefined) { sendError(res, 404, 'Not Found'); return true; }
        sendJson(res, 200, { name: branch, commit: { sha }, protected: false });
        return true;
      }
      return false;
    }

    // GET /commits[?sha=]
    if (rest[0] === 'commits' && rest.length === 1 && method === 'GET') {
      const shaParam = query.get('sha') ?? '';
      let tip: string | undefined;
      if (shaParam === '') tip = resolveBranchTip(repo, repo.defaultBranch);
      else if (isObjectId(shaParam)) tip = shaParam;
      else tip = resolveBranchTip(repo, shaParam);
      if (tip === undefined || repo.objects.get(tip) === undefined) {
        sendJson(res, 200, []);
        return true;
      }
      const list: Array<Record<string, unknown>> = [];
      for (const oid of ancestors(repo, tip)) {
        const entry = commitJson(repo, oid);
        if (entry !== null) list.push(entry);
      }
      sendJson(res, 200, list);
      return true;
    }

    // contents: PUT/GET/DELETE /contents/{path...}
    if (rest[0] === 'contents') {
      const filePath = rest.slice(1).join('/');
      if (method === 'PUT') {
        const message = typeof bodyObj.message === 'string' ? bodyObj.message : `Update ${filePath}`;
        const contentB64 = typeof bodyObj.content === 'string' ? bodyObj.content : '';
        const branch = typeof bodyObj.branch === 'string' && bodyObj.branch !== '' ? bodyObj.branch : repo.defaultBranch;
        const content = b64decodeToBuffer(contentB64);
        const shaParam = typeof bodyObj.sha === 'string' ? bodyObj.sha : undefined;
        const tip = resolveBranchTip(repo, branch);
        const isUpdate = tip !== undefined && (() => {
          const tree = commitTreeOid(repo, tip);
          if (tree === undefined) return false;
          return treeToFiles(repo, tree).has(filePath);
        })();
        if (shaParam !== undefined) {
          const currentSha = (() => {
            if (tip === undefined) return undefined;
            const tree = commitTreeOid(repo, tip);
            if (tree === undefined) return undefined;
            return treeToFiles(repo, tree).get(filePath)?.oid;
          })();
          if (currentSha === undefined || currentSha.toLowerCase() !== shaParam.toLowerCase()) {
            sendError(res, 409, 'sha does not match the current blob');
            return true;
          }
        }
        const made = commitFile(repo, branch, filePath, content, message);
        sendJson(res, isUpdate ? 200 : 201, {
          content: { name: filePath.split('/').pop() ?? filePath, path: filePath, sha: made.contentSha, size: content.length, encoding: 'base64', type: 'file' },
          commit: { sha: made.commitSha, message },
        });
        return true;
      }
      if (method === 'GET') {
        const refParam = query.get('ref') ?? '';
        let tip: string | undefined;
        if (refParam === '') tip = resolveBranchTip(repo, repo.defaultBranch);
        else if (isObjectId(refParam)) tip = refParam;
        else tip = resolveBranchTip(repo, refParam);
        if (tip === undefined) { sendError(res, 404, 'Not Found'); return true; }
        const treeOid = commitTreeOid(repo, tip);
        if (treeOid === undefined) { sendError(res, 404, 'Not Found'); return true; }
        if (filePath === '') {
          const files = treeToFiles(repo, treeOid);
          const names = new Set<string>();
          for (const path of files.keys()) names.add(path.split('/')[0]!);
          const entries: Array<Record<string, unknown>> = [];
          const root = repo.objects.get(treeOid);
          if (root) {
            for (const entry of parseTree(root.data)) {
              entries.push({ type: entry.mode === '40000' ? 'dir' : 'file', name: entry.name, path: entry.name, sha: entry.oid });
            }
          }
          sendJson(res, 200, entries);
          return true;
        }
        const files = treeToFiles(repo, treeOid);
        const file = files.get(filePath);
        if (file !== undefined) {
          const blob = repo.objects.get(file.oid);
          const data = blob?.data ?? Buffer.alloc(0);
          sendJson(res, 200, {
            type: 'file', encoding: 'base64', content: data.toString('base64'),
            sha: file.oid, size: data.length, name: filePath.split('/').pop() ?? filePath, path: filePath,
          });
          return true;
        }
        // directory?
        const prefix = `${filePath}/`;
        const children = new Map<string, { type: string; oid: string }>();
        for (const [path, entry] of files) {
          if (!path.startsWith(prefix)) continue;
          const rest2 = path.slice(prefix.length);
          const first = rest2.split('/')[0]!;
          if (!children.has(first)) {
            children.set(first, { type: rest2.includes('/') ? 'dir' : 'file', oid: entry.oid });
          }
        }
        if (children.size > 0) {
          const entries: Array<Record<string, unknown>> = [];
          // resolve dir shas from the tree itself for correctness
          const dirTree = findSubtree(repo, treeOid, filePath.split('/'));
          if (dirTree !== undefined) {
            const object = repo.objects.get(dirTree);
            if (object) {
              for (const entry of parseTree(object.data)) {
                entries.push({ type: entry.mode === '40000' ? 'dir' : 'file', name: entry.name, path: `${filePath}/${entry.name}`, sha: entry.oid });
              }
            }
          } else {
            for (const [name, child] of children) {
              entries.push({ type: child.type, name, path: `${filePath}/${name}`, sha: child.oid });
            }
          }
          sendJson(res, 200, entries);
          return true;
        }
        sendError(res, 404, 'Not Found');
        return true;
      }
      if (method === 'DELETE') {
        const message = typeof bodyObj.message === 'string' ? bodyObj.message : `Delete ${filePath}`;
        const branch = typeof bodyObj.branch === 'string' && bodyObj.branch !== '' ? bodyObj.branch : repo.defaultBranch;
        const shaParam = typeof bodyObj.sha === 'string' ? bodyObj.sha : undefined;
        const tip = resolveBranchTip(repo, branch);
        if (tip !== undefined && shaParam !== undefined) {
          const tree = commitTreeOid(repo, tip);
          const currentSha = tree !== undefined ? treeToFiles(repo, tree).get(filePath)?.oid : undefined;
          if (currentSha === undefined || currentSha.toLowerCase() !== shaParam.toLowerCase()) {
            sendError(res, 409, 'sha does not match the current blob');
            return true;
          }
        }
        const made = deleteFile(repo, branch, filePath, message);
        if (made === null) { sendError(res, 404, 'Not Found'); return true; }
        sendJson(res, 200, { commit: { sha: made.commitSha, message } });
        return true;
      }
      return false;
    }

    // labels: POST /labels, GET /labels
    if (rest[0] === 'labels') {
      if (method === 'POST' && rest.length === 1) {
        const name = typeof bodyObj.name === 'string' ? bodyObj.name : '';
        const color = typeof bodyObj.color === 'string' ? bodyObj.color : 'ededed';
        if (name === '') { sendError(res, 422, 'Label name is required'); return true; }
        if (repo.labels.has(name)) { sendError(res, 422, 'Label already exists'); return true; }
        repo.labels.set(name, { name, color });
        sendJson(res, 201, { name, color });
        return true;
      }
      if (method === 'GET' && rest.length === 1) {
        sendJson(res, 200, [...repo.labels.values()].map((l) => ({ name: l.name, color: l.color })));
        return true;
      }
      return false;
    }

    // issues
    if (rest[0] === 'issues') {
      // POST /issues
      if (method === 'POST' && rest.length === 1) {
        const title = typeof bodyObj.title === 'string' ? bodyObj.title : '';
        const bodyText = typeof bodyObj.body === 'string' ? bodyObj.body : '';
        const labels = Array.isArray(bodyObj.labels) ? bodyObj.labels.filter((l): l is string => typeof l === 'string') : [];
        for (const label of labels) {
          if (!repo.labels.has(label)) { sendError(res, 422, `Label ${label} does not exist`); return true; }
        }
        const number = repo.nextIssueNumber++;
        const issue: Issue = {
          id: nextIssueId++, number, title, body: bodyText, state: 'open',
          labels: [...labels], comments: [], seq: number,
        };
        repo.issues.push(issue);
        sendJson(res, 201, issueJson(repo, issue));
        return true;
      }
      // GET /issues (list)
      if (method === 'GET' && rest.length === 1) {
        const state = query.get('state') ?? 'open';
        const sort = query.get('sort') ?? 'created';
        const direction = query.get('direction') ?? 'desc';
        let list = [...repo.issues];
        if (state === 'open') list = list.filter((i) => i.state === 'open');
        else if (state === 'closed') list = list.filter((i) => i.state === 'closed');
        if (sort === 'created') {
          list.sort((a, b) => (direction === 'asc' ? a.seq - b.seq : b.seq - a.seq));
        }
        const { page, perPage } = pageParams(query);
        const items = paginate(list, page, perPage);
        const headers: Record<string, string> = {};
        const link = paginationLink(req, page, perPage, list.length);
        if (link !== null) headers.link = link;
        sendJson(res, 200, items.map((i) => issueJson(repo, i)), headers);
        return true;
      }
      // /issues/{n}...
      const num = Number.parseInt(rest[1] ?? '', 10);
      if (rest.length >= 2 && Number.isInteger(num) && num > 0) {
        const issue = repo.issues.find((i) => i.number === num);
        if (issue === undefined) { sendError(res, 404, 'Not Found'); return true; }
        // comments
        if (rest.length === 3 && rest[2] === 'comments') {
          if (method === 'POST') {
            const text = typeof bodyObj.body === 'string' ? bodyObj.body : '';
            const comment: Comment = { id: nextCommentId++, body: text, user: VIEWER_LOGIN };
            issue.comments.push(comment);
            sendJson(res, 201, commentJson(comment));
            return true;
          }
          if (method === 'GET') {
            sendJson(res, 200, issue.comments.map(commentJson));
            return true;
          }
          return false;
        }
        if (rest.length === 2) {
          if (method === 'GET') { sendJson(res, 200, issueJson(repo, issue)); return true; }
          if (method === 'PATCH') {
            if (bodyObj.state === 'open' || bodyObj.state === 'closed') issue.state = bodyObj.state;
            if (typeof bodyObj.title === 'string') issue.title = bodyObj.title;
            if (typeof bodyObj.body === 'string') issue.body = bodyObj.body;
            sendJson(res, 200, issueJson(repo, issue));
            return true;
          }
          return false;
        }
        return false;
      }
      return false;
    }

    // pulls
    if (rest[0] === 'pulls') {
      // POST /pulls
      if (method === 'POST' && rest.length === 1) {
        const title = typeof bodyObj.title === 'string' ? bodyObj.title : '';
        const bodyText = typeof bodyObj.body === 'string' ? bodyObj.body : '';
        const head = typeof bodyObj.head === 'string' ? bodyObj.head : '';
        const base = typeof bodyObj.base === 'string' ? bodyObj.base : '';
        const headSha = resolveBranchTip(repo, head);
        const baseSha = resolveBranchTip(repo, base);
        if (headSha === undefined || baseSha === undefined) {
          sendError(res, 422, 'head or base branch not found');
          return true;
        }
        if (headSha === baseSha) {
          sendError(res, 422, 'No commits between head and base');
          return true;
        }
        const existing = repo.pulls.find((p) => p.headRef === head && p.baseRef === base && p.state === 'open');
        if (existing !== undefined) {
          sendError(res, 422, 'A pull request already exists for this head and base');
          return true;
        }
        const number = repo.nextPullNumber++;
        const pull: Pull = {
          id: nextPullId++, number, title, body: bodyText, state: 'open',
          headRef: head, baseRef: base, headSha, baseSha,
          merged: false, mergedAt: null, mergeCommitSha: null, seq: number,
        };
        repo.pulls.push(pull);
        sendJson(res, 201, pullJson(repo, pull));
        return true;
      }
      // GET /pulls (list)
      if (method === 'GET' && rest.length === 1) {
        const state = query.get('state') ?? 'open';
        let list = [...repo.pulls];
        if (state === 'open') list = list.filter((p) => p.state === 'open');
        else if (state === 'closed') list = list.filter((p) => p.state === 'closed');
        list.sort((a, b) => b.seq - a.seq);
        const { page, perPage } = pageParams(query);
        const items = paginate(list, page, perPage);
        const headers: Record<string, string> = {};
        const link = paginationLink(req, page, perPage, list.length);
        if (link !== null) headers.link = link;
        sendJson(res, 200, items.map((p) => pullJson(repo, p)), headers);
        return true;
      }
      const num = Number.parseInt(rest[1] ?? '', 10);
      if (rest.length >= 2 && Number.isInteger(num) && num > 0) {
        const pull = repo.pulls.find((p) => p.number === num);
        if (pull === undefined) { sendError(res, 404, 'Not Found'); return true; }
        // GET /pulls/{n}/files
        if (rest.length === 3 && rest[2] === 'files' && method === 'GET') {
          sendJson(res, 200, pullFilesOf(repo, pull));
          return true;
        }
        // PUT /pulls/{n}/merge
        if (rest.length === 3 && rest[2] === 'merge' && method === 'PUT') {
          if (pull.merged) { sendError(res, 405, 'Pull request already merged'); return true; }
          if (pull.state === 'closed') { sendError(res, 405, 'Pull request is closed'); return true; }
          const merged = squashMerge(repo, pull);
          if (!merged.ok) { sendError(res, 405, merged.reason); return true; }
          sendJson(res, 200, { sha: merged.sha, merged: true, message: 'Pull request successfully merged' });
          return true;
        }
        if (rest.length === 2 && method === 'GET') {
          sendJson(res, 200, pullJson(repo, pull));
          return true;
        }
        return false;
      }
      return false;
    }

    return false;
  }

  return false;
}

/** Find a subtree oid by walking path segments from a tree. */
function findSubtree(repo: Repo, treeOid: string, segments: readonly string[]): string | undefined {
  let current: string | undefined = treeOid;
  for (const segment of segments) {
    if (current === undefined) return undefined;
    const object = repo.objects.get(current);
    if (!object || object.type !== 'tree') return undefined;
    const entry = parseTree(object.data).find((e) => e.name === segment);
    if (!entry || entry.mode !== '40000') return undefined;
    current = entry.oid;
  }
  return current;
}

// ---------------------------------------------------------------------------
// Git smart HTTP

function sendGitAdvert(res: ServerResponse, service: string, body: Buffer): void {
  const header = `# service=git-${service}\n`;
  const headerFrame = pktLine(Buffer.from(header, 'utf8'));
  const payload = Buffer.concat([headerFrame, FLUSH_PKT, body]);
  res.writeHead(200, {
    'content-type': `application/x-git-${service}-advertisement`,
    'content-length': payload.length,
    'x-github-request-id': requestId(),
  });
  res.end(payload);
}

function sendGitResult(res: ServerResponse, service: string, body: Buffer): void {
  res.writeHead(200, {
    'content-type': `application/x-git-${service}-result`,
    'content-length': body.length,
    'x-github-request-id': requestId(),
  });
  res.end(body);
}

function v2AdvertCaps(repo: Repo): Buffer {
  const chunks: Buffer[] = [];
  chunks.push(pktLine(Buffer.from('version 2\n', 'utf8')));
  chunks.push(pktLine(Buffer.from('ls-refs=unborn\n', 'utf8')));
  chunks.push(pktLine(Buffer.from('fetch=shallow filter\n', 'utf8')));
  chunks.push(pktLine(Buffer.from('object-format=sha1\n', 'utf8')));
  chunks.push(pktLine(Buffer.from('agent=forge/1.0.0\n', 'utf8')));
  chunks.push(FLUSH_PKT);
  return Buffer.concat(chunks);
}

function v0AdvertRefs(repo: Repo, service: 'upload-pack' | 'receive-pack'): Buffer {
  const chunks: Buffer[] = [];
  const caps = service === 'upload-pack'
    ? ['side-band-64k', 'thin-pack', 'shallow', 'ofs-delta', 'agent=forge/1.0.0', 'object-format=sha1', `symref=HEAD:refs/heads/${repo.defaultBranch}`]
    : ['report-status', 'side-band-64k', 'delete-refs', 'ofs-delta', 'agent=forge/1.0.0', 'object-format=sha1', `symref=HEAD:refs/heads/${repo.defaultBranch}`];
  const refs = [...repo.refs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  const headSha = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
  if (refs.length === 0) {
    const line = Buffer.from(`${ZERO_OID} capabilities^{}\0${caps.join(' ')}\n`, 'utf8');
    chunks.push(pktLine(line));
  } else {
    let first = true;
    if (headSha !== undefined) {
      chunks.push(pktLine(Buffer.from(`${headSha} HEAD\0${caps.join(' ')}\n`, 'utf8')));
      first = false;
    }
    for (const [refName, sha] of refs) {
      if (first) {
        chunks.push(pktLine(Buffer.from(`${sha} ${refName}\0${caps.join(' ')}\n`, 'utf8')));
        first = false;
      } else {
        chunks.push(pktLine(Buffer.from(`${sha} ${refName}\n`, 'utf8')));
      }
    }
    // Peeled annotated tags, as "<commit> <ref>^{}" lines.
    for (const [refName, sha] of refs) {
      if (!refName.startsWith('refs/tags/')) continue;
      const peeled = peelToCommit(repo, sha);
      if (peeled !== undefined && peeled !== sha) {
        chunks.push(pktLine(Buffer.from(`${peeled} ${refName}^{}\n`, 'utf8')));
      }
    }
  }
  chunks.push(FLUSH_PKT);
  return Buffer.concat(chunks);
}

/** Collect the objects a fetch must send, honouring haves, depth and shallow boundaries.
 * Rules (git upload-pack semantics): a have is never re-sent and its history is not walked,
 * except when deepening (depth set + the have is a request shallow line) where the walk continues
 * below it. A sent commit whose parent would exceed the depth is a shallow boundary; a request
 * shallow line whose parent is now sent becomes unshallow. Objects reachable from a have are
 * never re-sent (the client already holds them). */
function collectForFetch(
  repo: Repo, wants: readonly string[], haves: ReadonlySet<string>,
  depth: number | undefined, requestShallow: readonly string[],
): { objectOids: string[]; shallow: string[]; unshallow: string[]; wantedRefs: string[] } {
  const wantedRefs: string[] = [];
  const wantCommits: string[] = [];
  const wantTags: string[] = [];
  for (const want of wants) {
    const commitOid = resolveToCommit(repo, want);
    if (commitOid === undefined) continue;
    wantedRefs.push(want);
    wantCommits.push(commitOid);
    const object = repo.objects.get(want);
    if (object !== undefined && object.type === 'tag') wantTags.push(want);
  }

  const shallowLines = new Set(requestShallow);
  const sent = new Set<string>();
  const traversed = new Set<string>();
  const shallow = new Set<string>();
  const queue: Array<{ oid: string; distance: number }> = wantCommits.map((oid) => ({ oid, distance: 1 }));
  while (queue.length > 0) {
    const { oid, distance } = queue.shift()!;
    if (traversed.has(oid)) continue;
    traversed.add(oid);
    const object = repo.objects.get(oid);
    if (!object || object.type !== 'commit') continue;
    const isHave = haves.has(oid);
    if (!isHave) sent.add(oid);
    // A have is a boundary: everything below it is already on the client, so do not walk
    // its parents — unless deepening (depth set + this commit is a request shallow line).
    if (isHave && !(depth !== undefined && shallowLines.has(oid))) continue;
    const parsed = parseCommit(object.data);
    for (const parent of parsed.parents) {
      const parentDistance = distance + 1;
      if (depth !== undefined && parentDistance > depth) {
        if (!isHave) shallow.add(oid);
        continue;
      }
      queue.push({ oid: parent, distance: parentDistance });
    }
  }

  const unshallow = new Set<string>();
  for (const line of requestShallow) {
    if (!traversed.has(line)) continue;
    const object = repo.objects.get(line);
    if (!object || object.type !== 'commit') continue;
    if (parseCommit(object.data).parents.some((parent) => sent.has(parent))) unshallow.add(line);
  }

  // Objects the client already holds: the full closure of every have commit — but never
  // below a request shallow line (a shallow clone does not hold its boundary's parents).
  const held = new Set<string>();
  const heldQueue: string[] = [...haves];
  while (heldQueue.length > 0) {
    const oid = heldQueue.pop()!;
    if (held.has(oid)) continue;
    const object = repo.objects.get(oid);
    if (!object) continue;
    held.add(oid);
    if (object.type === 'commit') {
      const parsed = parseCommit(object.data);
      heldQueue.push(parsed.tree);
      if (!shallowLines.has(oid)) {
        for (const parent of parsed.parents) heldQueue.push(parent);
      }
    } else if (object.type === 'tag') {
      heldQueue.push(parseTag(object.data).object);
    } else if (object.type === 'tree') {
      for (const entry of parseTree(object.data)) heldQueue.push(entry.oid);
    }
  }

  // Pack contents: sent commits + wanted tags + the trees/blobs under sent commits.
  const objectOids: string[] = [];
  const seen = new Set<string>();
  const addObject = (oid: string): void => {
    if (seen.has(oid) || held.has(oid)) return;
    if (repo.objects.get(oid) === undefined) return;
    seen.add(oid);
    objectOids.push(oid);
  };
  for (const oid of wantTags) addObject(oid);
  const treeQueue: string[] = [];
  for (const oid of sent) {
    addObject(oid);
    const parsed = parseCommit(repo.objects.get(oid)!.data);
    treeQueue.push(parsed.tree);
  }
  while (treeQueue.length > 0) {
    const oid = treeQueue.pop()!;
    if (seen.has(oid) || held.has(oid)) continue;
    const object = repo.objects.get(oid);
    if (!object || object.type !== 'tree') continue;
    seen.add(oid);
    objectOids.push(oid);
    for (const entry of parseTree(object.data)) {
      if (entry.mode === '40000') treeQueue.push(entry.oid);
      else addObject(entry.oid);
    }
  }

  return {
    objectOids,
    shallow: [...shallow].filter((oid) => !held.has(oid)),
    unshallow: [...unshallow],
    wantedRefs,
  };
}

function sidebandPack(pack: Buffer, progress: string | null): Buffer {
  const chunks: Buffer[] = [];
  const MAX_CHUNK = 65500;
  if (pack.length === 0) {
    chunks.push(sidebandPacket(1, Buffer.alloc(0)));
  } else {
    for (let offset = 0; offset < pack.length; offset += MAX_CHUNK) {
      chunks.push(sidebandPacket(1, pack.subarray(offset, Math.min(pack.length, offset + MAX_CHUNK))));
    }
  }
  if (progress !== null) chunks.push(sidebandPacket(2, Buffer.from(progress, 'utf8')));
  return Buffer.concat(chunks);
}

function handleUploadPackV2(repo: Repo, body: Buffer): Buffer {
  const lines = parsePktLines(body);
  let command: string | null = null;
  const wants: string[] = [];
  const haves: string[] = [];
  const shallowLines: string[] = [];
  let deepen: number | undefined;
  let peel = false;
  let refPrefix: string | undefined;
  for (const line of lines) {
    const text = line.toString('utf8').trimEnd();
    if (text.startsWith('command=ls-refs')) {
      command = 'ls-refs';
      continue;
    }
    if (text.startsWith('command=fetch')) {
      command = 'fetch';
      continue;
    }
    // v0: the first want line carries capabilities after a space.
    if (text.startsWith('want ')) { wants.push(text.slice(5).trim().split(' ')[0]!); continue; }
    if (text.startsWith('have ')) { haves.push(text.slice(5).trim()); continue; }
    if (text.startsWith('shallow ')) { shallowLines.push(text.slice(8).trim()); continue; }
    if (text.startsWith('deepen ')) { deepen = Number.parseInt(text.slice(7).trim(), 10) || undefined; continue; }
    if (text === 'peel') { peel = true; continue; }
    if (text.startsWith('ref-prefix ')) { refPrefix = text.slice(11).trim(); continue; }
  }
  // No command line means a v0 fetch request (want lines, flush, have lines, done).
  if (command === null && wants.length > 0) command = 'fetch-v0';

  if (command === 'ls-refs') {
    const chunks: Buffer[] = [];
    const defaultHead = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
    const refs = [...repo.refs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
    const prefix = refPrefix ?? '';
    const filtered = refs.filter(([name]) => name.startsWith(prefix));
    if (prefix === '' || prefix === 'HEAD') {
      if (defaultHead !== undefined) {
        chunks.push(pktLine(Buffer.from(`${defaultHead} HEAD symref-target:refs/heads/${repo.defaultBranch}\n`, 'utf8')));
      } else {
        chunks.push(pktLine(Buffer.from(`unborn HEAD symref-target:refs/heads/${repo.defaultBranch}\n`, 'utf8')));
      }
    }
    for (const [name, sha] of filtered) {
      let line = `${sha} ${name}`;
      if (peel) {
        const peeled = peelToCommit(repo, sha);
        if (peeled !== undefined && peeled !== sha) line += ` peeled:${peeled}`;
      }
      chunks.push(pktLine(Buffer.from(`${line}\n`, 'utf8')));
    }
    chunks.push(RESPONSE_END_PKT);
    return Buffer.concat(chunks);
  }

  // fetch (v2 or v0)
  const haveSet = new Set(haves);
  for (const shallowOid of shallowLines) haveSet.add(shallowOid);
  const resolvedWants = wants.filter((w) => repo.objects.get(w) !== undefined);
  const { objectOids, shallow, unshallow } = collectForFetch(repo, resolvedWants, haveSet, deepen, shallowLines);
  const pack = buildPackfile(repo, objectOids);

  if (command === 'fetch-v0') {
    const chunks: Buffer[] = [];
    let acked = false;
    for (const have of haves) {
      if (repo.objects.get(have) !== undefined) {
        chunks.push(pktLine(Buffer.from(`ACK ${have}\n`, 'utf8')));
        acked = true;
      }
    }
    if (!acked) chunks.push(pktLine(Buffer.from('NAK\n', 'utf8')));
    for (const oid of shallow) chunks.push(pktLine(Buffer.from(`shallow ${oid}\n`, 'utf8')));
    for (const oid of unshallow) chunks.push(pktLine(Buffer.from(`unshallow ${oid}\n`, 'utf8')));
    chunks.push(sidebandPack(pack, null));
    return Buffer.concat(chunks);
  }

  const chunks: Buffer[] = [];
  // acknowledgments section
  chunks.push(pktLine(Buffer.from('acknowledgments\n', 'utf8')));
  for (const have of haves) {
    if (repo.objects.get(have) !== undefined) {
      chunks.push(pktLine(Buffer.from(`ACK ${have}\n`, 'utf8')));
    }
  }
  chunks.push(pktLine(Buffer.from('ready\n', 'utf8')));
  chunks.push(DELIM_PKT);
  // shallow-info section
  if (shallow.length > 0 || unshallow.length > 0) {
    chunks.push(pktLine(Buffer.from('shallow-info\n', 'utf8')));
    for (const oid of shallow) chunks.push(pktLine(Buffer.from(`shallow ${oid}\n`, 'utf8')));
    for (const oid of unshallow) chunks.push(pktLine(Buffer.from(`unshallow ${oid}\n`, 'utf8')));
    chunks.push(DELIM_PKT);
  }
  // wanted-refs section: "<oid> <ref>" per want.
  chunks.push(pktLine(Buffer.from('wanted-refs\n', 'utf8')));
  for (const want of resolvedWants) {
    const refName = [...repo.refs.entries()].find(([, sha]) => sha === want)?.[0] ?? want;
    chunks.push(pktLine(Buffer.from(`${want} ${refName}\n`, 'utf8')));
  }
  chunks.push(DELIM_PKT);
  // packfile section
  chunks.push(pktLine(Buffer.from('packfile\n', 'utf8')));
  chunks.push(sidebandPack(pack, null));
  return Buffer.concat(chunks);
}

function handleReceivePack(repo: Repo, body: Buffer): Buffer {
  // Command list is pkt-lines up to the first flush; the pack follows raw.
  const { lines, rest } = parsePktLinesUntilFlush(body);
  const commands: Array<{ oldOid: string; newOid: string; ref: string }> = [];
  for (const line of lines) {
    const text = line.toString('utf8');
    const trimmed = text.trimEnd();
    const parts = trimmed.split(' ');
    if (parts.length >= 3 && isObjectId(parts[0]!) && isObjectId(parts[1]!)) {
      let refName = parts.slice(2).join(' ');
      const nul = refName.indexOf('\0');
      if (nul >= 0) refName = refName.slice(0, nul);
      commands.push({ oldOid: parts[0]!, newOid: parts[1]!, ref: refName });
    }
  }
  const hasPack = rest.length > 0 && rest.subarray(0, 4).toString('ascii') === 'PACK';

  const report: string[] = [];
  let unpackOk = true;
  if (hasPack) {
    try {
      parsePackfile(repo, rest);
    } catch (err) {
      unpackOk = false;
      report.push(`unpack ${err instanceof Error ? err.message : 'failed'}`);
    }
  }

  if (!unpackOk) {
    const payload = Buffer.concat([
      pktLine(Buffer.from('unpack failed\n', 'utf8')),
      ...commands.map((c) => pktLine(Buffer.from(`ng ${c.ref} unpacker error\n`, 'utf8'))),
    ]);
    return sidebandReport(payload);
  }

  for (const cmd of commands) {
    const current = repo.refs.get(cmd.ref);
    if (cmd.newOid === ZERO_OID) {
      if (cmd.oldOid === ZERO_OID || current === undefined) {
        report.push(`ng ${cmd.ref} invalid delete`);
        continue;
      }
      repo.refs.delete(cmd.ref);
      report.push(`ok ${cmd.ref}`);
      continue;
    }
    const object = repo.objects.get(cmd.newOid);
    if (object === undefined || object.type === 'blob') {
      report.push(`ng ${cmd.ref} invalid object`);
      continue;
    }
    if (current === undefined) {
      if (cmd.oldOid !== ZERO_OID) {
        report.push(`ng ${cmd.ref} invalid old oid`);
        continue;
      }
      repo.refs.set(cmd.ref, cmd.newOid);
      report.push(`ok ${cmd.ref}`);
      continue;
    }
    if (cmd.oldOid !== current) {
      report.push(`ng ${cmd.ref} non-fast-forward`);
      continue;
    }
    // Fast-forward: new tip must descend from the current tip.
    const tipCommit = resolveToCommit(repo, cmd.newOid);
    if (tipCommit === undefined || !isAncestor(repo, current, tipCommit)) {
      report.push(`ng ${cmd.ref} non-fast-forward`);
      continue;
    }
    repo.refs.set(cmd.ref, cmd.newOid);
    report.push(`ok ${cmd.ref}`);
  }

  const payload = Buffer.concat([
    pktLine(Buffer.from('unpack ok\n', 'utf8')),
    ...report.map((line) => pktLine(Buffer.from(`${line}\n`, 'utf8'))),
  ]);
  return sidebandReport(payload);
}

function sidebandReport(payload: Buffer): Buffer {
  // Report lines go in band 1 packets.
  const chunks: Buffer[] = [];
  for (let offset = 0; offset < payload.length; offset += 65500) {
    chunks.push(sidebandPacket(1, payload.subarray(offset, Math.min(payload.length, offset + 65500))));
  }
  chunks.push(FLUSH_PKT);
  return Buffer.concat(chunks);
}

function handleGitHttp(req: IncomingMessage, res: ServerResponse, owner: string, name: string, segments: string[]): Promise<boolean> {
  return (async (): Promise<boolean> => {
    const repo = findRepo(owner, name);
    const method = req.method ?? 'GET';
    const tail = segments.slice(4); // after ['api','v3'? no — git route handled below]
    void tail;

    // Route shapes:
    //  /{owner}/{repo}.git/info/refs?service=git-upload-pack
    //  /{owner}/{repo}.git/git-upload-pack
    //  /{owner}/{repo}.git/git-receive-pack
    //  /{owner}/{repo}/info/refs?service=...
    //  /{owner}/{repo}/git-upload-pack
    //  /{owner}/{repo}/git-receive-pack
    if (repo === undefined) {
      sendError(res, 404, 'Not Found');
      return true;
    }
    if (method === 'GET' && segments.length >= 4 && segments[2] === 'info' && segments[3] === 'refs') {
      const service = new URL(req.url ?? '/', 'http://entry').searchParams.get('service') ?? '';
      const wantsV2 = (req.headers['git-protocol'] ?? '') === 'version=2';
      if (service === 'git-upload-pack') {
        if (wantsV2) {
          sendGitAdvert(res, 'upload-pack', v2AdvertCaps(repo));
        } else {
          sendGitAdvert(res, 'upload-pack', v0AdvertRefs(repo, 'upload-pack'));
        }
        return true;
      }
      if (service === 'git-receive-pack') {
        sendGitAdvert(res, 'receive-pack', v0AdvertRefs(repo, 'receive-pack'));
        return true;
      }
      sendError(res, 400, 'unknown service');
      return true;
    }
    if (method === 'POST' && segments.length >= 3) {
      const action = segments[segments.length - 1];
      if (action === 'git-upload-pack') {
        const raw = await readBody(req);
        const out = handleUploadPackV2(repo, raw);
        sendGitResult(res, 'upload-pack', out);
        return true;
      }
      if (action === 'git-receive-pack') {
        const raw = await readBody(req);
        const out = handleReceivePack(repo, raw);
        sendGitResult(res, 'receive-pack', out);
        return true;
      }
    }
    return false;
  })();
}

// ---------------------------------------------------------------------------
// GraphQL

type GqlValue =
  | { kind: 'variable'; name: string }
  | { kind: 'string'; value: string }
  | { kind: 'int'; value: number }
  | { kind: 'float'; value: number }
  | { kind: 'boolean'; value: boolean }
  | { kind: 'null' }
  | { kind: 'enum'; value: string }
  | { kind: 'list'; values: GqlValue[] }
  | { kind: 'object'; fields: Array<{ name: string; value: GqlValue }> };

interface GqlField {
  kind: 'field';
  name: string;
  alias: string | null;
  args: Array<{ name: string; value: GqlValue }>;
  selections: GqlSelection[] | null;
}
interface GqlFragmentSpread { kind: 'fragmentSpread'; name: string; }
interface GqlInlineFragment { kind: 'inlineFragment'; typeCondition: string | null; selections: GqlSelection[]; }
type GqlSelection = GqlField | GqlFragmentSpread | GqlInlineFragment;

interface GqlOperation {
  kind: 'query' | 'mutation';
  name: string | null;
  variableDefinitions: Array<{ name: string; defaultValue: GqlValue | null }>;
  selections: GqlSelection[];
}
interface GqlFragmentDef { name: string; typeCondition: string; selections: GqlSelection[]; }
interface GqlDocument { operations: GqlOperation[]; fragments: Map<string, GqlFragmentDef>; }

interface GqlToken { type: 'name' | 'string' | 'number' | 'punct' | 'spread'; value: string; }

function gqlLex(input: string): GqlToken[] {
  const tokens: GqlToken[] = [];
  let i = 0;
  while (i < input.length) {
    const ch = input[i]!;
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r' || ch === ',') { i += 1; continue; }
    if (ch === '#') { while (i < input.length && input[i] !== '\n') i += 1; continue; }
    if (ch === '.' && input[i + 1] === '.' && input[i + 2] === '.') { tokens.push({ type: 'spread', value: '...' }); i += 3; continue; }
    if ('{}()[]:!=$@'.includes(ch)) { tokens.push({ type: 'punct', value: ch }); i += 1; continue; }
    if (ch === '"') {
      let j = i + 1;
      let out = '';
      while (j < input.length && input[j] !== '"') {
        if (input[j] === '\\' && j + 1 < input.length) {
          const esc = input[j + 1]!;
          if (esc === 'n') out += '\n';
          else if (esc === 't') out += '\t';
          else if (esc === 'r') out += '\r';
          else if (esc === '"') out += '"';
          else if (esc === '\\') out += '\\';
          else if (esc === '/') out += '/';
          else if (esc === 'u' && j + 5 < input.length) { out += String.fromCharCode(Number.parseInt(input.slice(j + 2, j + 6), 16)); j += 4; }
          else out += esc;
          j += 2;
        } else {
          out += input[j]!;
          j += 1;
        }
      }
      tokens.push({ type: 'string', value: out });
      i = j + 1;
      continue;
    }
    if (/[0-9-]/.test(ch)) {
      let j = i;
      while (j < input.length && /[0-9.eE+-]/.test(input[j]!)) j += 1;
      tokens.push({ type: 'number', value: input.slice(i, j) });
      i = j;
      continue;
    }
    if (/[A-Za-z_]/.test(ch)) {
      let j = i;
      while (j < input.length && /[A-Za-z0-9_]/.test(input[j]!)) j += 1;
      tokens.push({ type: 'name', value: input.slice(i, j) });
      i = j;
      continue;
    }
    i += 1;
  }
  return tokens;
}

class GqlParser {
  private pos = 0;
  private readonly tokens: GqlToken[];
  constructor(tokens: GqlToken[]) {
    this.tokens = tokens;
  }

  private peek(): GqlToken | undefined { return this.tokens[this.pos]; }
  private next(): GqlToken {
    const token = this.tokens[this.pos];
    if (token === undefined) throw new Error('unexpected end of document');
    this.pos += 1;
    return token;
  }
  private expectPunct(value: string): void {
    const token = this.next();
    if (token.type !== 'punct' || token.value !== value) throw new Error(`expected ${value}, got ${token.value}`);
  }
  private expectName(value?: string): string {
    const token = this.next();
    if (token.type !== 'name') throw new Error(`expected name, got ${token.value}`);
    if (value !== undefined && token.value !== value) throw new Error(`expected ${value}, got ${token.value}`);
    return token.value;
  }
  private atPunct(value: string): boolean {
    const token = this.peek();
    return token !== undefined && token.type === 'punct' && token.value === value;
  }
  private atName(value: string): boolean {
    const token = this.peek();
    return token !== undefined && token.type === 'name' && token.value === value;
  }

  parseDocument(): GqlDocument {
    const operations: GqlOperation[] = [];
    const fragments = new Map<string, GqlFragmentDef>();
    while (this.pos < this.tokens.length) {
      if (this.atName('fragment')) {
        this.next();
        const name = this.expectName();
        this.expectName('on');
        const typeCondition = this.expectName();
        this.skipDirectives();
        const selections = this.parseSelectionSet();
        fragments.set(name, { name, typeCondition, selections });
        continue;
      }
      operations.push(this.parseOperation());
    }
    return { operations, fragments };
  }

  private parseOperation(): GqlOperation {
    let kind: 'query' | 'mutation' = 'query';
    let name: string | null = null;
    if (this.atName('query')) { this.next(); kind = 'query'; }
    else if (this.atName('mutation')) { this.next(); kind = 'mutation'; }
    const token = this.peek();
    if (token !== undefined && token.type === 'name') name = this.next().value;
    const variableDefinitions = this.parseVariableDefinitions();
    this.skipDirectives();
    const selections = this.parseSelectionSet();
    return { kind, name, variableDefinitions, selections };
  }

  private parseVariableDefinitions(): Array<{ name: string; defaultValue: GqlValue | null }> {
    const defs: Array<{ name: string; defaultValue: GqlValue | null }> = [];
    if (!this.atPunct('(')) return defs;
    this.next();
    while (!this.atPunct(')')) {
      this.expectPunct('$');
      const name = this.expectName();
      this.expectPunct(':');
      this.parseType();
      let defaultValue: GqlValue | null = null;
      if (this.atPunct('=')) { this.next(); defaultValue = this.parseValue(); }
      this.skipDirectives();
      defs.push({ name, defaultValue });
    }
    this.expectPunct(')');
    return defs;
  }

  private parseType(): void {
    if (this.atPunct('[')) {
      this.next();
      this.parseType();
      this.expectPunct(']');
    } else {
      this.expectName();
    }
    if (this.atPunct('!')) this.next();
  }

  private skipDirectives(): void {
    while (this.atPunct('@')) {
      this.next();
      this.expectName();
      if (this.atPunct('(')) this.parseArguments();
    }
  }

  private parseSelectionSet(): GqlSelection[] {
    this.expectPunct('{');
    const selections: GqlSelection[] = [];
    while (!this.atPunct('}')) {
      selections.push(this.parseSelection());
    }
    this.expectPunct('}');
    return selections;
  }

  private parseSelection(): GqlSelection {
    if (this.peek()?.type === 'spread') {
      this.next();
      const token = this.peek();
      if (token !== undefined && token.type === 'name' && token.value === 'on') {
        this.next();
        const typeCondition = this.expectName();
        this.skipDirectives();
        return { kind: 'inlineFragment', typeCondition, selections: this.parseSelectionSet() };
      }
      if (token !== undefined && token.type === 'name') {
        const name = this.next().value;
        this.skipDirectives();
        return { kind: 'fragmentSpread', name };
      }
      this.skipDirectives();
      return { kind: 'inlineFragment', typeCondition: null, selections: this.parseSelectionSet() };
    }
    const first = this.expectName();
    let alias: string | null = null;
    let name = first;
    if (this.atPunct(':')) {
      this.next();
      alias = first;
      name = this.expectName();
    }
    const args = this.atPunct('(') ? this.parseArguments() : [];
    this.skipDirectives();
    const selections = this.atPunct('{') ? this.parseSelectionSet() : null;
    return { kind: 'field', name, alias, args, selections };
  }

  private parseArguments(): Array<{ name: string; value: GqlValue }> {
    const args: Array<{ name: string; value: GqlValue }> = [];
    this.expectPunct('(');
    while (!this.atPunct(')')) {
      const name = this.expectName();
      this.expectPunct(':');
      args.push({ name, value: this.parseValue() });
    }
    this.expectPunct(')');
    return args;
  }

  private parseValue(): GqlValue {
    const token = this.next();
    if (token.type === 'punct' && token.value === '$') {
      return { kind: 'variable', name: this.expectName() };
    }
    if (token.type === 'string') return { kind: 'string', value: token.value };
    if (token.type === 'number') {
      return token.value.includes('.') || token.value.includes('e') || token.value.includes('E')
        ? { kind: 'float', value: Number(token.value) }
        : { kind: 'int', value: Number(token.value) };
    }
    if (token.type === 'punct' && token.value === '[') {
      const values: GqlValue[] = [];
      while (!this.atPunct(']')) values.push(this.parseValue());
      this.expectPunct(']');
      return { kind: 'list', values };
    }
    if (token.type === 'punct' && token.value === '{') {
      const fields: Array<{ name: string; value: GqlValue }> = [];
      while (!this.atPunct('}')) {
        const name = this.expectName();
        this.expectPunct(':');
        fields.push({ name, value: this.parseValue() });
      }
      this.expectPunct('}');
      return { kind: 'object', fields };
    }
    if (token.type === 'name') {
      if (token.value === 'true') return { kind: 'boolean', value: true };
      if (token.value === 'false') return { kind: 'boolean', value: false };
      if (token.value === 'null') return { kind: 'null' };
      return { kind: 'enum', value: token.value };
    }
    throw new Error(`unexpected token ${token.value}`);
  }
}

function resolveGqlValue(value: GqlValue, variables: Record<string, unknown>): unknown {
  switch (value.kind) {
    case 'variable': return variables[value.name] ?? null;
    case 'string': return value.value;
    case 'int': case 'float': return value.value;
    case 'boolean': return value.value;
    case 'null': return null;
    case 'enum': return value.value;
    case 'list': return value.values.map((v) => resolveGqlValue(v, variables));
    case 'object': {
      const out: Record<string, unknown> = {};
      for (const field of value.fields) out[field.name] = resolveGqlValue(field.value, variables);
      return out;
    }
  }
}

interface GqlNode { __type: string; [key: string]: unknown; }

function globalId(kind: string, id: number): string {
  return Buffer.from(`${kind}:${id}`).toString('base64');
}

function parseGlobalId(id: string): { kind: string; num: number } | null {
  try {
    const decoded = Buffer.from(id, 'base64').toString('utf8');
    const match = /^([A-Za-z]+):(\d+)$/.exec(decoded);
    if (!match) return null;
    return { kind: match[1]!, num: Number(match[2]) };
  } catch {
    return null;
  }
}

function repoNode(repo: Repo): GqlNode {
  return { __type: 'Repository', repo };
}
function issueNode(repo: Repo, issue: Issue): GqlNode {
  return { __type: 'Issue', repo, issue };
}
function pullNode(repo: Repo, pull: Pull): GqlNode {
  return { __type: 'PullRequest', repo, pull };
}
function userNode(login: string): GqlNode {
  return { __type: 'User', login };
}

function cursorFor(index: number): string {
  return Buffer.from(`cursor:${index}`).toString('base64');
}
function indexFromCursor(cursor: string): number {
  try {
    const decoded = Buffer.from(cursor, 'base64').toString('utf8');
    const match = /^cursor:(\d+)$/.exec(decoded);
    return match ? Number(match[1]) : -1;
  } catch {
    return -1;
  }
}

const TYPE_FIELDS: Record<string, string[]> = {
  Query: ['viewer', 'repository', 'node', '__type', '__schema'],
  Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest'],
  Issue: ['id', 'number', 'title', 'state', 'body'],
  PullRequest: ['id', 'number', 'state', 'merged', 'headRefName', 'baseRefName', 'mergeable', 'files'],
  User: ['id', 'login', 'name', 'email'],
  IssueConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  IssueEdge: ['node', 'cursor'],
  PageInfo: ['hasNextPage', 'endCursor', 'hasPreviousPage', 'startCursor'],
  PullRequestConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PullRequestEdge: ['node', 'cursor'],
  FileConnection: ['nodes', 'edges', 'pageInfo'],
  FileNode: ['path'],
  BranchRef: ['name'],
  Comment: ['id', 'body'],
  CommentEdge: ['node', 'cursor'],
  AddCommentPayload: ['commentEdge'],
  CreateIssuePayload: ['issue'],
  CloseIssuePayload: ['issue'],
  CreatePullRequestPayload: ['pullRequest'],
  MergePullRequestPayload: ['pullRequest'],
  __Type: ['name', 'kind', 'fields', 'enumValues', 'description'],
  __Field: ['name', 'description', 'args'],
  __EnumValue: ['name', 'description'],
  __Schema: ['queryType', 'mutationType', 'types'],
};
const TYPE_ENUMS: Record<string, string[]> = {
  SearchType: ['ISSUE', 'REPOSITORY', 'USER', 'DISCUSSION', 'CODE', 'COMMIT', 'LABEL', 'MILESTONE'],
  IssueState: ['OPEN', 'CLOSED'],
  PullRequestState: ['OPEN', 'CLOSED', 'MERGED'],
  MergeableState: ['CONFLICTING', 'MERGEABLE', 'UNKNOWN'],
  OrderDirection: ['ASC', 'DESC'],
  IssueOrderField: ['CREATED_AT', 'UPDATED_AT', 'COMMENTS'],
  RepositoryPermission: ['ADMIN', 'MAINTAIN', 'WRITE', 'TRIAGE', 'READ'],
};
const TYPE_KINDS: Record<string, string> = {
  Query: 'OBJECT', Repository: 'OBJECT', Issue: 'OBJECT', PullRequest: 'OBJECT',
  User: 'OBJECT', IssueConnection: 'OBJECT', IssueEdge: 'OBJECT', PageInfo: 'OBJECT',
  PullRequestConnection: 'OBJECT', FileConnection: 'OBJECT', FileNode: 'OBJECT',
  BranchRef: 'OBJECT', Comment: 'OBJECT', __Type: 'OBJECT', __Field: 'OBJECT',
  __EnumValue: 'OBJECT', __Schema: 'OBJECT',
  SearchType: 'ENUM', IssueState: 'ENUM', PullRequestState: 'ENUM',
  MergeableState: 'ENUM', OrderDirection: 'ENUM', IssueOrderField: 'ENUM',
  RepositoryPermission: 'ENUM',
};

interface GqlContext {
  doc: GqlDocument;
  variables: Record<string, unknown>;
  errors: Array<{ message: string }>;
}

function resolveField(
  ctx: GqlContext, parent: GqlNode | null, typeName: string, field: GqlField,
): unknown {
  const args: Record<string, unknown> = {};
  for (const arg of field.args) args[arg.name] = resolveGqlValue(arg.value, ctx.variables);

  if (field.name === '__typename') return typeName;

  // __type / __schema are available on any type (introspection).
  if (field.name === '__type') {
    const name = String(args.name ?? '');
    if (TYPE_FIELDS[name] === undefined && TYPE_ENUMS[name] === undefined && TYPE_KINDS[name] === undefined) return null;
    return { __type: '__Type', typeName: name };
  }
  if (field.name === '__schema') {
    return { __type: '__Schema' };
  }

  if (parent === null) {
    // Root Query
    if (field.name === 'viewer') return userNode(VIEWER_LOGIN);
    if (field.name === 'repository') {
      const owner = String(args.owner ?? '');
      const name = String(args.name ?? '');
      const repo = findRepo(owner, name);
      return repo === undefined ? null : repoNode(repo);
    }
    if (field.name === 'node') {
      const parsed = parseGlobalId(String(args.id ?? ''));
      if (parsed === null) return null;
      if (parsed.kind === 'Repository') {
        const repo = [...repos.values()].find((r) => r.id === parsed.num);
        return repo === undefined ? null : repoNode(repo);
      }
      if (parsed.kind === 'Issue') {
        for (const repo of repos.values()) {
          const issue = repo.issues.find((i) => i.id === parsed.num);
          if (issue !== undefined) return issueNode(repo, issue);
        }
        return null;
      }
      if (parsed.kind === 'PullRequest') {
        for (const repo of repos.values()) {
          const pull = repo.pulls.find((p) => p.id === parsed.num);
          if (pull !== undefined) return pullNode(repo, pull);
        }
        return null;
      }
      return null;
    }
    ctx.errors.push({ message: `Cannot query field "${field.name}" on type "Query".` });
    return null;
  }

  switch (typeName) {
    case 'Repository': {
      const repo = parent.repo as Repo;
      switch (field.name) {
        case 'id': return globalId('Repository', repo.id);
        case 'databaseId': return repo.id;
        case 'name': return repo.name;
        case 'nameWithOwner': return `${repo.owner}/${repo.name}`;
        case 'owner': return userNode(repo.owner);
        case 'defaultBranchRef': return { __type: 'BranchRef', name: repo.defaultBranch };
        case 'viewerPermission': return 'ADMIN';
        case 'hasIssuesEnabled': return true;
        case 'issue': {
          const number = Number(args.number ?? 0);
          const issue = repo.issues.find((i) => i.number === number);
          return issue === undefined ? null : issueNode(repo, issue);
        }
        case 'issues': {
          let list = [...repo.issues];
          const states = Array.isArray(args.states) ? args.states.map(String) : null;
          if (states !== null) {
            list = list.filter((i) => states.includes(i.state === 'open' ? 'OPEN' : 'CLOSED'));
          }
          const orderBy = isRecord(args.orderBy) ? args.orderBy : null;
          const direction = orderBy !== null ? String(orderBy.direction ?? 'DESC') : 'DESC';
          list.sort((a, b) => (direction === 'ASC' ? a.seq - b.seq : b.seq - a.seq));
          return { __type: 'IssueConnection', repo, items: list, first: args.first, after: args.after };
        }
        case 'pullRequests': {
          const list = [...repo.pulls].sort((a, b) => b.seq - a.seq);
          return { __type: 'PullRequestConnection', repo, items: list, first: args.first, after: args.after };
        }
        case 'pullRequest': {
          const number = Number(args.number ?? 0);
          const pull = repo.pulls.find((p) => p.number === number);
          return pull === undefined ? null : pullNode(repo, pull);
        }
        default:
          ctx.errors.push({ message: `Cannot query field "${field.name}" on type "Repository".` });
          return null;
      }
    }
    case 'Issue': {
      const issue = parent.issue as Issue;
      const repo = parent.repo as Repo;
      switch (field.name) {
        case 'id': return globalId('Issue', issue.id);
        case 'number': return issue.number;
        case 'title': return issue.title;
        case 'state': return issue.state === 'open' ? 'OPEN' : 'CLOSED';
        case 'body': return issue.body;
        default:
          ctx.errors.push({ message: `Cannot query field "${field.name}" on type "Issue".` });
          return null;
      }
    }
    case 'PullRequest': {
      const pull = parent.pull as Pull;
      const repo = parent.repo as Repo;
      switch (field.name) {
        case 'id': return globalId('PullRequest', pull.id);
        case 'number': return pull.number;
        case 'state': return pull.merged ? 'MERGED' : pull.state === 'open' ? 'OPEN' : 'CLOSED';
        case 'merged': return pull.merged;
        case 'headRefName': return pull.headRef;
        case 'baseRefName': return pull.baseRef;
        case 'mergeable': {
          const baseTip = resolveBranchTip(repo, pull.baseRef);
          if (baseTip === undefined) return 'UNKNOWN';
          return mergeableState(repo, pull.headSha, baseTip);
        }
        case 'files': {
          const files = pullFilesOf(repo, pull);
          return { __type: 'FileConnection', files, first: args.first };
        }
        default:
          ctx.errors.push({ message: `Cannot query field "${field.name}" on type "PullRequest".` });
          return null;
      }
    }
    case 'User': {
      switch (field.name) {
        case 'login': return parent.login as string;
        case 'id': return globalId('User', parent.login === VIEWER_LOGIN ? VIEWER_ID : 0);
        case 'name': return parent.login === VIEWER_LOGIN ? VIEWER_NAME : (parent.login as string);
        case 'email': return parent.login === VIEWER_LOGIN ? VIEWER_EMAIL : null;
        default:
          ctx.errors.push({ message: `Cannot query field "${field.name}" on type "User".` });
          return null;
      }
    }
    case 'IssueConnection':
    case 'PullRequestConnection': {
      const items = parent.items as Array<Issue | Pull>;
      const first = typeof parent.first === 'number' ? parent.first : undefined;
      const after = typeof parent.after === 'string' ? parent.after : undefined;
      const start = after !== undefined ? indexFromCursor(after) + 1 : 0;
      const sliced = first !== undefined ? items.slice(start, start + first) : items.slice(start);
      const endIndex = start + sliced.length - 1;
      const hasNext = start + sliced.length < items.length;
      const repo = parent.repo as Repo;
      switch (field.name) {
        case 'nodes':
          return sliced.map((item) => (typeName === 'IssueConnection'
            ? issueNode(repo, item as Issue)
            : pullNode(repo, item as Pull)));
        case 'edges':
          return sliced.map((item, idx) => ({
            __type: typeName === 'IssueConnection' ? 'IssueEdge' : 'PullRequestEdge',
            node: typeName === 'IssueConnection' ? issueNode(repo, item as Issue) : pullNode(repo, item as Pull),
            cursor: cursorFor(start + idx),
          }));
        case 'pageInfo':
          return {
            __type: 'PageInfo',
            hasNextPage: hasNext,
            endCursor: sliced.length > 0 ? cursorFor(endIndex) : null,
            hasPreviousPage: start > 0,
            startCursor: sliced.length > 0 ? cursorFor(start) : null,
          };
        case 'totalCount': return items.length;
        default:
          ctx.errors.push({ message: `Cannot query field "${field.name}" on type "${typeName}".` });
          return null;
      }
    }
    case 'IssueEdge':
    case 'PullRequestEdge': {
      switch (field.name) {
        case 'node': return parent.node as GqlNode;
        case 'cursor': return parent.cursor as string;
        default:
          ctx.errors.push({ message: `Cannot query field "${field.name}" on type "${typeName}".` });
          return null;
      }
    }
    case 'PageInfo': {
      switch (field.name) {
        case 'hasNextPage': return parent.hasNextPage as boolean;
        case 'endCursor': return parent.endCursor as string | null;
        case 'hasPreviousPage': return parent.hasPreviousPage as boolean;
        case 'startCursor': return parent.startCursor as string | null;
        default:
          ctx.errors.push({ message: `Cannot query field "${field.name}" on type "${typeName}".` });
          return null;
      }
    }
    case 'FileConnection': {
      const files = parent.files as Array<Record<string, unknown>>;
      const first = typeof parent.first === 'number' ? parent.first : undefined;
      const sliced = first !== undefined ? files.slice(0, first) : files;
      switch (field.name) {
        case 'nodes': return sliced.map((f) => ({ __type: 'FileNode', path: String(f.filename ?? '') }));
        case 'edges': return sliced.map((f, idx) => ({ __type: 'FileEdge', node: { __type: 'FileNode', path: String(f.filename ?? '') }, cursor: cursorFor(idx) }));
        case 'pageInfo': return { __type: 'PageInfo', hasNextPage: first !== undefined && files.length > first, endCursor: null, hasPreviousPage: false, startCursor: null };
        default:
          ctx.errors.push({ message: `Cannot query field "${field.name}" on type "FileConnection".` });
          return null;
      }
    }
    case 'FileNode': {
      if (field.name === 'path') return parent.path as string;
      ctx.errors.push({ message: `Cannot query field "${field.name}" on type "FileNode".` });
      return null;
    }
    case 'BranchRef': {
      if (field.name === 'name') return parent.name as string;
      ctx.errors.push({ message: `Cannot query field "${field.name}" on type "BranchRef".` });
      return null;
    }
    case '__Type': {
      const name = parent.typeName as string;
      switch (field.name) {
        case 'name': return name;
        case 'kind': return TYPE_KINDS[name] ?? 'OBJECT';
        case 'description': return null;
        case 'fields': {
          const list = TYPE_FIELDS[name] ?? [];
          return list.map((fieldName) => ({ __type: '__Field', name: fieldName }));
        }
        case 'enumValues': {
          const list = TYPE_ENUMS[name] ?? [];
          return list.map((enumName) => ({ __type: '__EnumValue', name: enumName }));
        }
        default:
          ctx.errors.push({ message: `Cannot query field "${field.name}" on type "__Type".` });
          return null;
      }
    }
    case '__Field': {
      switch (field.name) {
        case 'name': return parent.name as string;
        case 'description': return null;
        case 'args': return [];
        default:
          ctx.errors.push({ message: `Cannot query field "${field.name}" on type "__Field".` });
          return null;
      }
    }
    case '__EnumValue': {
      switch (field.name) {
        case 'name': return parent.name as string;
        case 'description': return null;
        default:
          ctx.errors.push({ message: `Cannot query field "${field.name}" on type "__EnumValue".` });
          return null;
      }
    }
    case '__Schema': {
      switch (field.name) {
        case 'queryType': return { __type: '__Type', typeName: 'Query' };
        case 'mutationType': return { __type: '__Type', typeName: 'Mutation' };
        case 'types': return Object.keys(TYPE_FIELDS).map((n) => ({ __type: '__Type', typeName: n }));
        default:
          ctx.errors.push({ message: `Cannot query field "${field.name}" on type "__Schema".` });
          return null;
      }
    }
    case 'CreateIssuePayload':
    case 'CloseIssuePayload': {
      if (field.name === 'issue') return parent.issue as GqlNode;
      ctx.errors.push({ message: `Cannot query field "${field.name}" on type "${typeName}".` });
      return null;
    }
    case 'CreatePullRequestPayload':
    case 'MergePullRequestPayload': {
      if (field.name === 'pullRequest') return parent.pullRequest as GqlNode;
      ctx.errors.push({ message: `Cannot query field "${field.name}" on type "${typeName}".` });
      return null;
    }
    case 'AddCommentPayload': {
      if (field.name === 'commentEdge') return parent.commentEdge as GqlNode;
      ctx.errors.push({ message: `Cannot query field "${field.name}" on type "AddCommentPayload".` });
      return null;
    }
    case 'CommentEdge': {
      if (field.name === 'node') return parent.node as GqlNode;
      if (field.name === 'cursor') return parent.cursor as string;
      ctx.errors.push({ message: `Cannot query field "${field.name}" on type "CommentEdge".` });
      return null;
    }
    case 'Comment': {
      if (field.name === 'id') return globalId('Comment', parent.commentId as number);
      if (field.name === 'body') return parent.body as string;
      ctx.errors.push({ message: `Cannot query field "${field.name}" on type "Comment".` });
      return null;
    }
    default:
      ctx.errors.push({ message: `Cannot query field "${field.name}" on type "${typeName}".` });
      return null;
  }
}

function executeSelections(
  ctx: GqlContext, parent: GqlNode | null, typeName: string, selections: readonly GqlSelection[],
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const selection of selections) {
    if (selection.kind === 'fragmentSpread') {
      const fragment = ctx.doc.fragments.get(selection.name);
      if (fragment !== undefined) {
        const merged = executeSelections(ctx, parent, typeName, fragment.selections);
        Object.assign(out, merged);
      }
      continue;
    }
    if (selection.kind === 'inlineFragment') {
      if (selection.typeCondition === null || selection.typeCondition === typeName) {
        const merged = executeSelections(ctx, parent, typeName, selection.selections);
        Object.assign(out, merged);
      }
      continue;
    }
    const key = selection.alias ?? selection.name;
    const value = resolveField(ctx, parent, typeName, selection);
    if (value === null || value === undefined) {
      out[key] = null;
      continue;
    }
    if (Array.isArray(value)) {
      out[key] = value.map((item) => {
        if (item !== null && typeof item === 'object' && '__type' in item && selection.selections !== null) {
          const node = item as GqlNode;
          return executeSelections(ctx, node, node.__type, selection.selections);
        }
        return item;
      });
      continue;
    }
    if (typeof value === 'object' && '__type' in value) {
      const node = value as GqlNode;
      out[key] = selection.selections !== null
        ? executeSelections(ctx, node, node.__type, selection.selections)
        : {};
      continue;
    }
    out[key] = value;
  }
  return out;
}

function executeMutation(ctx: GqlContext, field: GqlField): unknown {
  const args: Record<string, unknown> = {};
  for (const arg of field.args) args[arg.name] = resolveGqlValue(arg.value, ctx.variables);
  const input = isRecord(args.input) ? args.input : {};

  if (field.name === 'createIssue') {
    const repo = [...repos.values()].find((r) => r.id === Number(input.repositoryId) || globalId('Repository', r.id) === String(input.repositoryId));
    if (repo === undefined) return null;
    const number = repo.nextIssueNumber++;
    const issue: Issue = {
      id: nextIssueId++, number,
      title: String(input.title ?? ''), body: String(input.body ?? ''),
      state: 'open', labels: [], comments: [], seq: number,
    };
    repo.issues.push(issue);
    return { __type: 'CreateIssuePayload', issue: issueNode(repo, issue) };
  }
  if (field.name === 'closeIssue') {
    const parsed = parseGlobalId(String(input.issueId ?? ''));
    for (const repo of repos.values()) {
      const issue = repo.issues.find((i) => i.id === (parsed?.num ?? -1) || i.number === Number(input.issueId));
      if (issue !== undefined) {
        issue.state = 'closed';
        return { __type: 'CloseIssuePayload', issue: issueNode(repo, issue) };
      }
    }
    return null;
  }
  if (field.name === 'createPullRequest') {
    const repo = [...repos.values()].find((r) => r.id === Number(input.repositoryId) || globalId('Repository', r.id) === String(input.repositoryId));
    if (repo === undefined) return null;
    const head = String(input.headRefName ?? '');
    const base = String(input.baseRefName ?? '');
    const headSha = resolveBranchTip(repo, head);
    const baseSha = resolveBranchTip(repo, base);
    if (headSha === undefined || baseSha === undefined) return null;
    const number = repo.nextPullNumber++;
    const pull: Pull = {
      id: nextPullId++, number, title: String(input.title ?? ''), body: String(input.body ?? ''),
      state: 'open', headRef: head, baseRef: base, headSha, baseSha,
      merged: false, mergedAt: null, mergeCommitSha: null, seq: number,
    };
    repo.pulls.push(pull);
    return { __type: 'CreatePullRequestPayload', pullRequest: pullNode(repo, pull) };
  }
  if (field.name === 'mergePullRequest') {
    const parsed = parseGlobalId(String(input.pullRequestId ?? ''));
    for (const repo of repos.values()) {
      const pull = repo.pulls.find((p) => p.id === (parsed?.num ?? -1) || p.number === Number(input.pullRequestId));
      if (pull !== undefined) {
        if (pull.merged || pull.state === 'closed') return { __type: 'MergePullRequestPayload', pullRequest: pullNode(repo, pull) };
        squashMerge(repo, pull);
        return { __type: 'MergePullRequestPayload', pullRequest: pullNode(repo, pull) };
      }
    }
    return null;
  }
  if (field.name === 'addComment') {
    const parsed = parseGlobalId(String(input.subjectId ?? ''));
    for (const repo of repos.values()) {
      const issue = repo.issues.find((i) => i.id === (parsed?.num ?? -1));
      if (issue !== undefined) {
        const comment: Comment = { id: nextCommentId++, body: String(input.body ?? ''), user: VIEWER_LOGIN };
        issue.comments.push(comment);
        return {
          __type: 'AddCommentPayload',
          commentEdge: {
            __type: 'CommentEdge',
            node: { __type: 'Comment', commentId: comment.id, body: comment.body },
            cursor: cursorFor(issue.comments.length - 1),
          },
        };
      }
    }
    return null;
  }
  ctx.errors.push({ message: `Cannot query field "${field.name}" on type "Mutation".` });
  return null;
}

function executeOperation(doc: GqlDocument, op: GqlOperation, variables: Record<string, unknown>): { data: Record<string, unknown> | null; errors: Array<{ message: string }> } {
  const ctx: GqlContext = { doc, variables, errors: [] };
  for (const def of op.variableDefinitions) {
    if (ctx.variables[def.name] === undefined && def.defaultValue !== null) {
      ctx.variables[def.name] = resolveGqlValue(def.defaultValue, ctx.variables);
    }
  }
  const data: Record<string, unknown> = {};
  for (const selection of op.selections) {
    if (selection.kind === 'fragmentSpread') {
      const fragment = doc.fragments.get(selection.name);
      if (fragment !== undefined) Object.assign(data, executeSelections(ctx, null, 'Query', fragment.selections));
      continue;
    }
    if (selection.kind === 'inlineFragment') {
      if (selection.typeCondition === null || selection.typeCondition === 'Query') {
        Object.assign(data, executeSelections(ctx, null, 'Query', selection.selections));
      }
      continue;
    }
    const key = selection.alias ?? selection.name;
    if (op.kind === 'mutation') {
      const value = executeMutation(ctx, selection);
      if (value === null || value === undefined) {
        data[key] = null;
        continue;
      }
      if (typeof value === 'object' && '__type' in value) {
        const node = value as GqlNode;
        data[key] = selection.selections !== null
          ? executeSelections(ctx, node, node.__type, selection.selections)
          : {};
        continue;
      }
      data[key] = value;
      continue;
    }
    const value = resolveField(ctx, null, 'Query', selection);
    if (value === null || value === undefined) {
      data[key] = null;
      continue;
    }
    if (typeof value === 'object' && '__type' in value) {
      const node = value as GqlNode;
      data[key] = selection.selections !== null
        ? executeSelections(ctx, node, node.__type, selection.selections)
        : {};
      continue;
    }
    data[key] = value;
  }
  return { data, errors: ctx.errors };
}

function runGraphQL(body: unknown): Array<Record<string, unknown>> | Record<string, unknown> {
  const requests = Array.isArray(body) ? body : [body];
  const results = requests.map((request) => {
    const query = isRecord(request) ? String(request.query ?? '') : '';
    const variables = isRecord(request) && isRecord(request.variables) ? (request.variables as Record<string, unknown>) : {};
    const operationName = isRecord(request) ? (typeof request.operationName === 'string' ? request.operationName : null) : null;
    try {
      const doc = new GqlParser(gqlLex(query)).parseDocument();
      let op: GqlOperation | undefined;
      if (operationName !== null) op = doc.operations.find((o) => o.name === operationName);
      else op = doc.operations[0];
      if (op === undefined) return { data: null, errors: [{ message: 'No operation found in document.' }] };
      // Multiple operations in one document: execute all in order, merge data.
      if (doc.operations.length > 1 && operationName === null) {
        const mergedData: Record<string, unknown> = {};
        const mergedErrors: Array<{ message: string }> = [];
        for (const operation of doc.operations) {
          const result = executeOperation(doc, operation, { ...variables });
          Object.assign(mergedData, result.data ?? {});
          mergedErrors.push(...result.errors);
        }
        const out: Record<string, unknown> = { data: mergedData };
        if (mergedErrors.length > 0) out.errors = mergedErrors;
        return out;
      }
      const result = executeOperation(doc, op, { ...variables });
      const out: Record<string, unknown> = { data: result.data };
      if (result.errors.length > 0) out.errors = result.errors;
      return out;
    } catch (err) {
      return { data: null, errors: [{ message: err instanceof Error ? err.message : 'GraphQL parse error' }] };
    }
  });
  return Array.isArray(body) ? results : results[0]!;
}

async function handleGraphQL(req: IncomingMessage, res: ServerResponse): Promise<boolean> {
  const raw = await readBody(req);
  const parsed = parseJsonBody(raw);
  if (!parsed.ok) {
    sendError(res, 400, `malformed JSON body: ${parsed.error}`);
    return true;
  }
  const result = runGraphQL(parsed.value);
  sendJson(res, 200, result);
  return true;
}

// ---------------------------------------------------------------------------
// MCP (JSON-RPC 2.0 Streamable HTTP)

interface McpTool {
  name: string;
  description: string;
  inputSchema: { type: 'object'; properties: Record<string, unknown>; required: string[] };
  run: (args: Record<string, unknown>) => { ok: boolean; text: string };
}

function argString(args: Record<string, unknown>, ...keys: string[]): string {
  for (const key of keys) {
    const value = args[key];
    if (typeof value === 'string' && value !== '') return value;
  }
  return '';
}

function argBool(args: Record<string, unknown>, ...keys: string[]): boolean {
  for (const key of keys) {
    const value = args[key];
    if (typeof value === 'boolean') return value;
  }
  return false;
}

function argInt(args: Record<string, unknown>, ...keys: string[]): number {
  for (const key of keys) {
    const value = args[key];
    if (typeof value === 'number' && Number.isFinite(value)) return Math.trunc(value);
    if (typeof value === 'string' && /^\d+$/.test(value)) return Number(value);
  }
  return 0;
}

function mcpRepo(args: Record<string, unknown>): { repo: Repo | null; owner: string; name: string } {
  const owner = argString(args, 'owner', 'owner_login', 'org', 'user', 'login') || VIEWER_LOGIN;
  const name = argString(args, 'repo', 'repository', 'repo_name', 'name');
  return { repo: findRepo(owner, name) ?? null, owner, name };
}

const MCP_TOOLS: McpTool[] = [
  {
    name: 'create_repo',
    description: 'Create a new repository owned by the authenticated user.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Repository name' },
        description: { type: 'string', description: 'Repository description' },
        private: { type: 'boolean', description: 'Whether the repository is private' },
      },
      required: ['name'],
    },
    run: (args) => {
      const name = argString(args, 'name');
      if (name === '') return { ok: false, text: 'name is required' };
      if (findRepo(VIEWER_LOGIN, name) !== undefined) return { ok: false, text: `Repository ${VIEWER_LOGIN}/${name} already exists` };
      const repo = createRepoRecord(name, argBool(args, 'private', 'is_private'), argString(args, 'description'));
      return { ok: true, text: JSON.stringify(repoJson(repo)) };
    },
  },
  {
    name: 'get_repo',
    description: 'Get a repository by owner and name.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
      },
      required: ['owner', 'repo'],
    },
    run: (args) => {
      const { repo, name } = mcpRepo(args);
      if (repo === null) return { ok: false, text: `Repository ${name} not found` };
      return { ok: true, text: JSON.stringify(repoJson(repo)) };
    },
  },
  {
    name: 'list_repos',
    description: 'List repositories owned by the authenticated user.',
    inputSchema: {
      type: 'object',
      properties: {
        page: { type: 'integer', description: 'Page number' },
        per_page: { type: 'integer', description: 'Results per page' },
      },
      required: [],
    },
    run: (args) => {
      const page = argInt(args, 'page') || 1;
      const perPage = argInt(args, 'per_page') || 30;
      const items = paginate(viewerRepos(), page, perPage);
      return { ok: true, text: JSON.stringify(items.map(repoJson)) };
    },
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        title: { type: 'string', description: 'Issue title' },
        body: { type: 'string', description: 'Issue body' },
        labels: { type: 'array', items: { type: 'string' }, description: 'Issue labels' },
      },
      required: ['owner', 'repo', 'title'],
    },
    run: (args) => {
      const { repo } = mcpRepo(args);
      if (repo === null) return { ok: false, text: 'Repository not found' };
      const title = argString(args, 'title');
      if (title === '') return { ok: false, text: 'title is required' };
      const labels = Array.isArray(args.labels) ? args.labels.filter((l): l is string => typeof l === 'string') : [];
      for (const label of labels) {
        if (!repo.labels.has(label)) return { ok: false, text: `Label ${label} does not exist` };
      }
      const number = repo.nextIssueNumber++;
      const issue: Issue = {
        id: nextIssueId++, number, title, body: argString(args, 'body', 'description', 'content'),
        state: 'open', labels: [...labels], comments: [], seq: number,
      };
      repo.issues.push(issue);
      return { ok: true, text: JSON.stringify(issueJson(repo, issue)) };
    },
  },
  {
    name: 'list_issues',
    description: 'List issues in a repository, optionally filtered by state.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        state: { type: 'string', description: 'Issue state filter: open, closed, or all' },
      },
      required: ['owner', 'repo'],
    },
    run: (args) => {
      const { repo } = mcpRepo(args);
      if (repo === null) return { ok: false, text: 'Repository not found' };
      const state = argString(args, 'state') || 'open';
      let list = [...repo.issues];
      if (state === 'open') list = list.filter((i) => i.state === 'open');
      else if (state === 'closed') list = list.filter((i) => i.state === 'closed');
      list.sort((a, b) => b.seq - a.seq);
      return { ok: true, text: JSON.stringify(list.map((i) => issueJson(repo, i))) };
    },
  },
  {
    name: 'get_issue',
    description: 'Get a single issue by number.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        number: { type: 'integer', description: 'Issue number' },
      },
      required: ['owner', 'repo', 'number'],
    },
    run: (args) => {
      const { repo } = mcpRepo(args);
      if (repo === null) return { ok: false, text: 'Repository not found' };
      const issue = repo.issues.find((i) => i.number === argInt(args, 'number', 'issue_number'));
      if (issue === undefined) return { ok: false, text: 'Issue not found' };
      return { ok: true, text: JSON.stringify(issueJson(repo, issue)) };
    },
  },
  {
    name: 'close_issue',
    description: 'Close an issue by number.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        number: { type: 'integer', description: 'Issue number' },
      },
      required: ['owner', 'repo', 'number'],
    },
    run: (args) => {
      const { repo } = mcpRepo(args);
      if (repo === null) return { ok: false, text: 'Repository not found' };
      const issue = repo.issues.find((i) => i.number === argInt(args, 'number', 'issue_number'));
      if (issue === undefined) return { ok: false, text: 'Issue not found' };
      issue.state = 'closed';
      return { ok: true, text: JSON.stringify(issueJson(repo, issue)) };
    },
  },
  {
    name: 'create_pull_request',
    description: 'Create a pull request from a head branch into a base branch.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        title: { type: 'string', description: 'Pull request title' },
        body: { type: 'string', description: 'Pull request body' },
        head: { type: 'string', description: 'Head branch name' },
        base: { type: 'string', description: 'Base branch name' },
      },
      required: ['owner', 'repo', 'title', 'head', 'base'],
    },
    run: (args) => {
      const { repo } = mcpRepo(args);
      if (repo === null) return { ok: false, text: 'Repository not found' };
      const head = argString(args, 'head', 'head_ref', 'source', 'from', 'branch');
      const base = argString(args, 'base', 'base_ref', 'target', 'into');
      const headSha = resolveBranchTip(repo, head);
      const baseSha = resolveBranchTip(repo, base);
      if (headSha === undefined || baseSha === undefined) return { ok: false, text: 'head or base branch not found' };
      const number = repo.nextPullNumber++;
      const pull: Pull = {
        id: nextPullId++, number, title: argString(args, 'title'), body: argString(args, 'body', 'description', 'content'),
        state: 'open', headRef: head, baseRef: base, headSha, baseSha,
        merged: false, mergedAt: null, mergeCommitSha: null, seq: number,
      };
      repo.pulls.push(pull);
      return { ok: true, text: JSON.stringify(pullJson(repo, pull)) };
    },
  },
  {
    name: 'list_pull_requests',
    description: 'List pull requests in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        state: { type: 'string', description: 'Pull request state filter: open, closed, or all' },
      },
      required: ['owner', 'repo'],
    },
    run: (args) => {
      const { repo } = mcpRepo(args);
      if (repo === null) return { ok: false, text: 'Repository not found' };
      const state = argString(args, 'state') || 'open';
      let list = [...repo.pulls];
      if (state === 'open') list = list.filter((p) => p.state === 'open');
      else if (state === 'closed') list = list.filter((p) => p.state === 'closed');
      list.sort((a, b) => b.seq - a.seq);
      return { ok: true, text: JSON.stringify(list.map((p) => pullJson(repo, p))) };
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Merge a pull request with a squash merge.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        pull_number: { type: 'integer', description: 'Pull request number' },
        merge_method: { type: 'string', description: 'Merge method: squash' },
      },
      required: ['owner', 'repo', 'pull_number'],
    },
    run: (args) => {
      const { repo } = mcpRepo(args);
      if (repo === null) return { ok: false, text: 'Repository not found' };
      const pull = repo.pulls.find((p) => p.number === argInt(args, 'pull_number', 'number', 'pr_number'));
      if (pull === undefined) return { ok: false, text: 'Pull request not found' };
      if (pull.merged || pull.state === 'closed') return { ok: false, text: 'Pull request already merged or closed' };
      const merged = squashMerge(repo, pull);
      if (!merged.ok) return { ok: false, text: merged.reason };
      return { ok: true, text: JSON.stringify({ sha: merged.sha, merged: true, message: 'Pull request successfully merged' }) };
    },
  },
];

function mcpJsonRpcResult(id: unknown, result: unknown): Record<string, unknown> {
  return { jsonrpc: '2.0', id: id ?? null, result };
}
function mcpJsonRpcError(id: unknown, code: number, message: string): Record<string, unknown> {
  return { jsonrpc: '2.0', id: id ?? null, error: { code, message } };
}

async function handleMcp(req: IncomingMessage, res: ServerResponse): Promise<boolean> {
  const raw = await readBody(req);
  const text = raw.toString('utf8').trim();
  const sessionId = req.headers['mcp-session-id'];
  const sessionHeader = typeof sessionId === 'string' && sessionId !== '' ? sessionId : 'forge-session-1';
  const baseHeaders: Record<string, string> = {
    'x-github-request-id': requestId(),
    'mcp-session-id': sessionHeader,
  };
  if (text === '') {
    sendJson(res, 400, mcpJsonRpcError(null, -32700, 'Parse error'), baseHeaders);
    return true;
  }
  let request: unknown;
  try {
    request = JSON.parse(text) as unknown;
  } catch {
    sendJson(res, 400, mcpJsonRpcError(null, -32700, 'Parse error'), baseHeaders);
    return true;
  }
  if (!isRecord(request) || request.jsonrpc !== '2.0' || typeof request.method !== 'string') {
    sendJson(res, 400, mcpJsonRpcError(isRecord(request) ? request.id ?? null : null, -32600, 'Invalid Request'), baseHeaders);
    return true;
  }
  const id = request.id ?? null;
  const method = request.method as string;
  const params = isRecord(request.params) ? (request.params as Record<string, unknown>) : {};

  // Notifications (no id): 202 with no body.
  if (id === null) {
    res.writeHead(202, { ...baseHeaders });
    res.end();
    return true;
  }

  if (method === 'ping') {
    sendJson(res, 200, mcpJsonRpcResult(id, {}), baseHeaders);
    return true;
  }
  if (method === 'server/discover') {
    sendJson(res, 200, mcpJsonRpcResult(id, {
      protocolVersion: '2026-07-28',
      supportedVersions: ['2026-07-28', '2025-11-25'],
      serverInfo: { name: 'forge', version: FORGE_VERSION },
      capabilities: { tools: {} },
    }), baseHeaders);
    return true;
  }
  if (method === 'initialize') {
    sendJson(res, 200, mcpJsonRpcResult(id, {
      protocolVersion: '2026-07-28',
      capabilities: { tools: {} },
      serverInfo: { name: 'forge', version: FORGE_VERSION },
    }), baseHeaders);
    return true;
  }
  if (method === 'tools/list') {
    sendJson(res, 200, mcpJsonRpcResult(id, {
      tools: MCP_TOOLS.map((tool) => ({
        name: tool.name,
        description: tool.description,
        inputSchema: tool.inputSchema,
      })),
    }), baseHeaders);
    return true;
  }
  if (method === 'tools/call') {
    const name = typeof params.name === 'string' ? params.name : '';
    const args = isRecord(params.arguments) ? (params.arguments as Record<string, unknown>) : {};
    const tool = MCP_TOOLS.find((t) => t.name === name);
    if (tool === undefined) {
      sendJson(res, 200, mcpJsonRpcError(id, -32602, `Unknown tool: ${name}`), baseHeaders);
      return true;
    }
    for (const required of tool.inputSchema.required) {
      if (args[required] === undefined || args[required] === null || args[required] === '') {
        sendJson(res, 200, mcpJsonRpcResult(id, {
          content: [{ type: 'text', text: `Missing required argument: ${required}` }],
          isError: true,
        }), baseHeaders);
        return true;
      }
    }
    const outcome = tool.run(args);
    sendJson(res, 200, mcpJsonRpcResult(id, {
      content: [{ type: 'text', text: outcome.text }],
      isError: !outcome.ok,
    }), baseHeaders);
    return true;
  }
  sendJson(res, 200, mcpJsonRpcError(id, -32601, `Method not found: ${method}`), baseHeaders);
  return true;
}

// ---------------------------------------------------------------------------
// Main router + server bootstrap

async function handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
  try {
    const method = req.method ?? 'GET';
    const { pathname, query } = pathOf(req);
    const segments = splitPath(pathname);

    // Health probe (no auth).
    if (pathname === '/healthz' && method === 'GET') {
      sendJson(res, 200, { ok: true });
      return;
    }

    // MCP endpoint.
    if (pathname === '/mcp') {
      if (!isAuthorized(req)) { sendError(res, 401, 'Requires authentication'); return; }
      await handleMcp(req, res);
      return;
    }

    // GraphQL endpoint.
    if (pathname === '/api/graphql') {
      if (!isAuthorized(req)) { sendError(res, 401, 'Requires authentication'); return; }
      await handleGraphQL(req, res);
      return;
    }

    // REST v3.
    if (segments.length >= 2 && segments[0] === 'api' && segments[1] === 'v3') {
      if (!isAuthorized(req)) { sendError(res, 401, 'Requires authentication'); return; }
      const handled = await handleRest(req, res, segments, query);
      if (!handled) sendError(res, 404, 'Not Found');
      return;
    }

    // Git smart HTTP: /{owner}/{repo}[.git]/{info/refs|git-upload-pack|git-receive-pack}
    if (segments.length >= 3 && (segments[2] === 'info' || segments[2] === 'git-upload-pack' || segments[2] === 'git-receive-pack')) {
      const owner = segments[0]!;
      const repoName = segments[1]!.replace(/\.git$/, '');
      const handled = await handleGitHttp(req, res, owner, repoName, segments);
      if (!handled) sendError(res, 404, 'Not Found');
      return;
    }

    sendError(res, 404, 'Not Found');
  } catch (err) {
    if (!res.headersSent) {
      sendError(res, 500, err instanceof Error ? err.message : 'Internal server error');
    } else {
      res.end();
    }
  }
}

/** Build the server. It binds nothing until the caller listens; the entry listens on an ephemeral port. */
export function createApp(): Server {
  const server = createServer((req, res) => {
    void handleRequest(req, res);
  });
  server.on('clientError', (_err, socket) => {
    socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
  });
  return server;
}
