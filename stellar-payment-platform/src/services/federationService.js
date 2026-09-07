'use strict';

const { prisma } = require('../../prismaClient');
const { USER_DATABASE, PRIMARY_USERNAME_ORDER } = require('../utils');

const resolveFederationId = async (queryValue) => {
  const row = await prisma.user.findFirst({
    where: { address: { equals: queryValue, mode: 'insensitive' }, deletedAt: null },
    select: { username: true, address: true, memoType: true, memo: true, flaggedAt: true },
    orderBy: PRIMARY_USERNAME_ORDER,
  });

  if (!row) return null;
  if (row.flaggedAt) {
    const forbiddenError = new Error('Address is blocked');
    forbiddenError.statusCode = 403;
    throw forbiddenError;
  }

  const response = {
    stellar_address: `${row.username}*${process.env.DOMAIN || 'localhost'}`,
    account_id: row.address,
  };
  if (row.memoType) {
    response.memo_type = row.memoType;
    response.memo = row.memo;
  }
  return response;
};

const resolveFederationName = async (queryName) => {
  const row = await prisma.user.findFirst({
    where: { username: queryName, deletedAt: null },
    select: { address: true, memoType: true, memo: true, flaggedAt: true },
  });

  if (row && row.flaggedAt) {
    const forbiddenError = new Error('Address is blocked');
    forbiddenError.statusCode = 403;
    throw forbiddenError;
  }

  const address = row?.address || USER_DATABASE[queryName];
  if (!address) return null;

  const response = {
    stellar_address: address,
    account_id: address,
  };
  if (row?.memoType) {
    response.memo_type = row.memoType;
    response.memo = row.memo;
  }
  return response;
};

module.exports = {
  resolveFederationId,
  resolveFederationName,
};
