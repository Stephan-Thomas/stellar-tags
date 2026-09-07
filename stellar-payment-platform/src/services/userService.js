'use strict';

const { poolGet, poolAll } = require('../db');
const { paginateByKeyset, cursorPaginatedResponse, paginatedResponse, parseCursorQuery, parsePagination, keysetWhereDesc } = require('../pagination');
const { prisma } = require('../../prismaClient');
const { shouldFallbackToLocalRegistry, PRIMARY_USERNAME_ORDER } = require('../utils');

const getLocalUserByAddress = async (address) =>
  poolGet(
    'SELECT username, address FROM username_registry WHERE address = ? LIMIT 1',
    [address],
  );

const getLocalUserByUsername = async (username) =>
  poolGet(
    'SELECT username, address FROM username_registry WHERE username = ? LIMIT 1',
    [username],
  );

const listLocalUsers = async (search, page, limit, cursorPoint = null) => {
  const searchPattern = `%${search}%`;
  const LIKE_FILTER =
    'WHERE (username LIKE ? COLLATE NOCASE OR address LIKE ? COLLATE NOCASE)';

  if (cursorPoint) {
    const rows = await poolAll(
      `SELECT username, address, created_at
      FROM username_registry
      ${LIKE_FILTER}
      AND (created_at < ? OR (created_at = ? AND username < ?))
      ORDER BY created_at DESC, username DESC
      LIMIT ?`,
      [searchPattern, searchPattern, String(cursorPoint.createdAt), String(cursorPoint.createdAt), String(cursorPoint.username), limit + 1],
    );
    const normalized = rows.map((row) => ({
      username: row.username,
      address: row.address,
      createdAt: row.created_at,
    }));
    const { rows: pageRows, hasMore, nextCursor } = paginateByKeyset(normalized, limit);
    return cursorPaginatedResponse(
      pageRows.map((user) => ({
        username: user.username,
        address: user.address,
        created_at: user.createdAt,
      })),
      { limit, nextCursor, hasMore },
    );
  }

  const skip = (page - 1) * limit;
  const rows = await poolAll(
    `SELECT username, address, created_at
     FROM username_registry
     ${LIKE_FILTER}
     ORDER BY created_at DESC
     LIMIT ? OFFSET ?`,
    [searchPattern, searchPattern, limit, skip],
  );

  const countRow = await poolGet(
    `SELECT COUNT(*) AS totalCount
     FROM username_registry
     ${LIKE_FILTER}`,
    [searchPattern, searchPattern],
  );

  const totalCount = Number(countRow?.totalCount || 0);
  return paginatedResponse(
    rows.map((user) => ({
      username: user.username,
      address: user.address,
      created_at: user.created_at,
    })),
    totalCount,
    { page, limit },
  );
};

const lookupUser = async (address, search, query) => {
  if (address) {
    let row;
    try {
      row = await prisma.user.findFirst({
        where: { address, deletedAt: null },
        select: { username: true },
        orderBy: PRIMARY_USERNAME_ORDER,
      });
    } catch (error) {
      if (!shouldFallbackToLocalRegistry(error)) throw error;
      row = await getLocalUserByAddress(address);
    }
    
    if (!row) {
      const notFoundError = new Error('Username not found for this address');
      notFoundError.statusCode = 404;
      throw notFoundError;
    }
    return { username: row.username, address };
  }

  const { limit: cursorLimit, cursor, invalid: invalidCursor } = parseCursorQuery(query);
  const { page, limit, skip } = parsePagination(query);
  if (invalidCursor) {
    const error = new Error('Invalid cursor parameter');
    error.statusCode = 400;
    error.code = 'INVALID_INPUT';
    throw error;
  }

  const where = {
    deletedAt: null,
    OR: [
      { username: { contains: search, mode: 'insensitive' } },
      { address: { contains: search, mode: 'insensitive' } },
    ],
  };

  if (cursor) {
    const candidates = await prisma.user.findMany({
      where: { AND: [where, keysetWhereDesc(cursor)] },
      orderBy: [{ createdAt: 'desc' }, { username: 'desc' }],
      take: cursorLimit + 1,
    });
    const { rows, hasMore, nextCursor } = paginateByKeyset(candidates, cursorLimit);
    return cursorPaginatedResponse(
      rows.map((user) => ({
        username: user.username,
        address: user.address,
        created_at: user.createdAt.toISOString(),
      })),
      { limit: cursorLimit, nextCursor, hasMore },
    );
  } else {
    const [totalCount, rows] = await prisma.$transaction([
      prisma.user.count({ where }),
      prisma.user.findMany({
        where,
        orderBy: [{ createdAt: 'desc' }, { username: 'desc' }],
        skip,
        take: limit,
      }),
    ]);

    return paginatedResponse(
      rows.map((user) => ({
        username: user.username,
        address: user.address,
        created_at: user.createdAt.toISOString(),
      })),
      totalCount,
      { page, limit },
    );
  }
};

const listUsers = async (query) => {
  const { limit: cursorLimit, cursor, invalid: invalidCursor } = parseCursorQuery(query);
  const { page, limit, skip } = parsePagination(query);
  if (invalidCursor) {
    const error = new Error('Invalid cursor parameter');
    error.statusCode = 400;
    error.code = 'INVALID_INPUT';
    throw error;
  }
  const search = query.search ?? null;

  const where = search
    ? {
        deletedAt: null,
        OR: [
          { username: { contains: search, mode: 'insensitive' } },
          { address: { contains: search, mode: 'insensitive' } },
        ],
      }
    : { deletedAt: null };

  if (cursor) {
    const candidates = await prisma.user.findMany({
      where: { AND: [where, keysetWhereDesc(cursor)] },
      orderBy: [{ createdAt: 'desc' }, { username: 'desc' }],
      take: cursorLimit + 1,
    });
    const { rows, hasMore, nextCursor } = paginateByKeyset(candidates, cursorLimit);
    const data = rows.map((user) => ({
      username: user.username,
      address: user.address,
      created_at: user.createdAt ? user.createdAt.toISOString() : undefined,
    }));
    return cursorPaginatedResponse(data, { limit: cursorLimit, nextCursor, hasMore });
  }

  const [totalCount, rows] = await prisma.$transaction([
    prisma.user.count({ where }),
    prisma.user.findMany({
      where,
      orderBy: [{ createdAt: 'desc' }, { username: 'desc' }],
      skip,
      take: limit,
    }),
  ]);

  const totalPages = Math.ceil(totalCount / limit);
  const data = rows.map((user) => ({
    username: user.username,
    address: user.address,
    created_at: user.createdAt ? user.createdAt.toISOString() : undefined,
  }));

  return {
    data,
    meta: {
      total: totalCount,
      totalCount,
      page,
      currentPage: page,
      limit,
      totalPages,
    },
    totalCount,
    totalPages,
    currentPage: page,
  };
};

module.exports = {
  getLocalUserByAddress,
  getLocalUserByUsername,
  listLocalUsers,
  lookupUser,
  listUsers,
};
