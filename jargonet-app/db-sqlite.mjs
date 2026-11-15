// SQLite adapter exposing the same small query-builder surface the router was
// written against, so functions/router.mjs runs unchanged outside the original
// managed-runtime. Uses the built-in node:sqlite driver: no native build, no
// external database, no connection string.
//
// Supported chain: from(t).select(cols).eq(col, val).order(col, opts).limit(n)
//                  from(t).insertIfAbsent(row, {onConflict}).select(cols)
//                  from(t).update(patch).eq(col, val).select(cols)
//                  from(t).delete().eq(col, val)
// Every stage is awaitable and resolves to { data: rows }.

import { DatabaseSync } from 'node:sqlite';

import { AppError } from './functions/http.mjs';

const IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/;

function identifier(name) {
  if (typeof name !== 'string' || !IDENTIFIER.test(name)) {
    throw new AppError('database_unavailable', 503);
  }
  return `"${name}"`;
}

function columnList(text) {
  if (typeof text !== 'string') return '*';
  const trimmed = text.trim();
  if (trimmed === '' || trimmed === '*') return '*';
  return trimmed.split(',').map((part) => identifier(part.trim())).join(', ');
}

function conflictTarget(text) {
  if (typeof text !== 'string' || text.trim() === '') {
    throw new AppError('database_unavailable', 503);
  }
  return text.split(',').map((part) => identifier(part.trim())).join(', ');
}

// node:sqlite binds null/number/string/bigint/Uint8Array. Booleans are coerced
// because the schema stores them as INTEGER.
function bindable(value) {
  if (value === undefined) return null;
  if (typeof value === 'boolean') return value ? 1 : 0;
  return value;
}

class Query {
  constructor(connection, table) {
    this.connection = connection;
    this.table = identifier(table);
    this.kind = 'select';
    this.columns = '*';
    this.filters = [];
    this.orderClause = '';
    this.limitValue = null;
    this.record = null;
    this.conflict = null;
  }

  select(columns) {
    this.columns = columnList(columns);
    return this;
  }

  eq(column, value) {
    this.filters.push([identifier(column), bindable(value)]);
    return this;
  }

  order(column, options = {}) {
    const direction = options.ascending === false ? 'DESC' : 'ASC';
    this.orderClause = `${identifier(column)} ${direction}`;
    return this;
  }

  limit(count) {
    const value = Number(count);
    if (!Number.isInteger(value) || value < 0) {
      throw new AppError('database_unavailable', 503);
    }
    this.limitValue = value;
    return this;
  }

  insertIfAbsent(record, options = {}) {
    if (!record || typeof record !== 'object') {
      throw new AppError('database_unavailable', 503);
    }
    this.kind = 'insert';
    this.record = record;
    this.conflict = options.onConflict ?? null;
    return this;
  }

  update(patch) {
    if (!patch || typeof patch !== 'object') {
      throw new AppError('database_unavailable', 503);
    }
    this.kind = 'update';
    this.record = patch;
    return this;
  }

  delete() {
    this.kind = 'delete';
    return this;
  }

  whereClause() {
    if (this.filters.length === 0) return { sql: '', params: [] };
    const sql = ` WHERE ${this.filters.map(([column]) => `${column} = ?`).join(' AND ')}`;
    return { sql, params: this.filters.map(([, value]) => value) };
  }

  build() {
    const where = this.whereClause();

    if (this.kind === 'insert') {
      const columns = Object.keys(this.record);
      if (columns.length === 0) throw new AppError('database_unavailable', 503);
      const names = columns.map(identifier).join(', ');
      const placeholders = columns.map(() => '?').join(', ');
      const conflict = this.conflict
        ? ` ON CONFLICT(${conflictTarget(this.conflict)}) DO NOTHING`
        : '';
      return {
        sql: `INSERT INTO ${this.table} (${names}) VALUES (${placeholders})${conflict} RETURNING ${this.columns}`,
        params: columns.map((column) => bindable(this.record[column])),
      };
    }

    if (this.kind === 'update') {
      const columns = Object.keys(this.record);
      if (columns.length === 0) throw new AppError('database_unavailable', 503);
      const assignments = columns.map((column) => `${identifier(column)} = ?`).join(', ');
      return {
        sql: `UPDATE ${this.table} SET ${assignments}${where.sql} RETURNING ${this.columns}`,
        params: [...columns.map((column) => bindable(this.record[column])), ...where.params],
      };
    }

    if (this.kind === 'delete') {
      return { sql: `DELETE FROM ${this.table}${where.sql}`, params: where.params };
    }

    let sql = `SELECT ${this.columns} FROM ${this.table}${where.sql}`;
    if (this.orderClause) sql += ` ORDER BY ${this.orderClause}`;
    if (this.limitValue !== null) sql += ` LIMIT ${this.limitValue}`;
    return { sql, params: where.params };
  }

  execute() {
    let statement;
    try {
      const { sql, params } = this.build();
      statement = this.connection.prepare(sql);
      if (this.kind === 'delete') {
        statement.run(...params);
        return { data: [] };
      }
      return { data: statement.all(...params) };
    } catch (error) {
      if (error instanceof AppError) throw error;
      throw new AppError('database_unavailable', 503);
    }
  }

  then(onFulfilled, onRejected) {
    try {
      return Promise.resolve(this.execute()).then(onFulfilled, onRejected);
    } catch (error) {
      return Promise.reject(error);
    }
  }
}

export function createSqliteClient(filePath) {
  const connection = new DatabaseSync(filePath);
  connection.exec('PRAGMA journal_mode = WAL');
  connection.exec('PRAGMA busy_timeout = 5000');
  connection.exec('PRAGMA synchronous = NORMAL');

  return {
    from: (table) => new Query(connection, table),
    exec: (sql) => connection.exec(sql),
    close: () => connection.close(),
  };
}
