'use strict';

const DEFAULT_FEDERATION_DOMAIN = 'localhost';

const VALID_MEMO_TYPES = ['text', 'id', 'hash'];
const MEMO_ID_RE = /^\d+$/;
const MEMO_HASH_RE = /^[0-9a-fA-F]{64}$/;

const RESERVED_NAMES = ['admin', 'root', 'support', 'system', 'stellar', 'api', 'help'];

const RESERVED_USERNAMES = [
  'admin',
  'root',
  'stellar',
  'system',
  'superuser',
  'administrator',
  'support',
];

// #613 — an address may carry at most this many federation usernames
// (one primary plus up to four aliases).
const MAX_USERNAMES_PER_ADDRESS = 5;

// #613 — Prisma orderBy that resolves an address to its primary username:
// the row flagged primary wins, with oldest-registered as the tiebreak so
// the result stays stable if no row is flagged (e.g. legacy data).
const PRIMARY_USERNAME_ORDER = [{ isPrimary: 'desc' }, { createdAt: 'asc' }];

function normalizeNameTag(value) {
  const trimmed = typeof value === 'string' ? value.trim() : '';
  if (!trimmed) return '';
  return trimmed.includes('*') ? trimmed : `${trimmed}*${DEFAULT_FEDERATION_DOMAIN}`;
}

function validateMemo(memoType, memo) {
  if (!memoType && !memo) return null;
  if (memoType && !memo) return 'memo is required when memo_type is provided.';
  if (!memoType && memo) return 'memo_type is required when memo is provided.';
  if (!VALID_MEMO_TYPES.includes(memoType)) {
    return `memo_type must be one of: ${VALID_MEMO_TYPES.join(', ')}.`;
  }
  if (memoType === 'text' && Buffer.byteLength(memo, 'utf8') > 28) {
    return 'memo of type text must not exceed 28 bytes.';
  }
  if (memoType === 'id') {
    if (!MEMO_ID_RE.test(memo) || BigInt(memo) > 18446744073709551615n) {
      return 'memo of type id must be a valid 64-bit unsigned integer.';
    }
  }
  if (memoType === 'hash' && !MEMO_HASH_RE.test(memo)) {
    return 'memo of type hash must be a 64-character hex string (32 bytes).';
  }
  return null;
}

const USER_DATABASE = {
  'client*localhost': 'GAPUQZH3WZUXHEMUGZN5ZYU4D4GHCFEMOGUINU6MF345GBD2QXNYYIEQ',
  'lekan*localhost': 'GAPUQZH3WZUXHEMUGZN5ZYU4D4GHCFEMOGUINU6MF345GBD2QXNYYIEQ',
};

const shouldFallbackToLocalRegistry = (error) => {
  const code = typeof error?.code === 'string' ? error.code : '';
  const message = typeof error?.message === 'string' ? error.message : '';
  return (
    code.startsWith('P10') ||
    ['P2021', 'P2023', 'P2028', 'P2001'].includes(code) ||
    /DATABASE_URL|connect|relation|table|timeout/i.test(message)
  );
};

module.exports = {
  normalizeNameTag,
  validateMemo,
  RESERVED_NAMES,
  RESERVED_USERNAMES,
  MAX_USERNAMES_PER_ADDRESS,
  PRIMARY_USERNAME_ORDER,
  VALID_MEMO_TYPES,
  USER_DATABASE,
  shouldFallbackToLocalRegistry,
};
