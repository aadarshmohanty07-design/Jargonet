// In-memory stand-in for the Function database client. Mirrors the chainable
// select/insertIfAbsent/update/order/limit shape used by functions/router.mjs.
// Test-only; never package this directory as the Function.

export function createFakeDb(control = { mode: 'ok', writes: [] }) {
  if (!Array.isArray(control.writes)) control.writes = [];
  const tables = new Map();
  const rows = (table) => {
    if (!tables.has(table)) tables.set(table, []);
    return tables.get(table);
  };
  const pick = (row, columns) => (columns === '*' || columns === null
    ? { ...row }
    : Object.fromEntries(columns.split(',').map((c) => [c.trim(), row[c.trim()]])));

  function builder(table, mode, values) {
    const filters = [];
    let columns = '*';
    let orderBy = null;
    let descending = false;
    let maxRows = Infinity;
    let execution;

    const run = () => {
      const list = rows(table);
      const match = (row) => filters.every(([key, value]) => row[key] === value);
      if (mode === 'read') {
        const selected = list.filter(match);
        if (orderBy) {
          selected.sort((a, b) => {
            const order = String(a[orderBy] ?? '').localeCompare(String(b[orderBy] ?? ''));
            return descending ? -order : order;
          });
        }
        return { data: selected.slice(0, maxRows).map((row) => pick(row, columns)), error: null };
      }

      control.writes.push(table);

      if (mode === 'insert') {
        const unique = (values.onConflict ?? '').split(',').map((c) => c.trim()).filter(Boolean);
        if (unique.length && list.some((row) => unique.every((key) => row[key] === values.row[key]))) {
          return { data: [], error: null };
        }
        list.push({ ...values.row });
        return { data: [pick(values.row, columns)], error: null };
      }

      if (mode === 'delete') {
        const remaining = list.filter((row) => !match(row));
        const deleted = list.filter(match);
        list.length = 0;
        list.push(...remaining);
        return { data: deleted.map((row) => pick(row, columns)), error: null };
      }

      const matched = list.filter(match);
      for (const row of matched) Object.assign(row, values.row);
      return { data: matched.map((row) => pick(row, columns)), error: null };
    };

    const chain = {
      eq(key, value) { filters.push([key, value]); return chain; },
      limit(count) { maxRows = count; return chain; },
      order(name, options) { orderBy = String(name); descending = options?.ascending === false; return chain; },
      select(names) { if (typeof names === 'string') columns = names; return chain; },
      then(resolve, reject) { execution ??= Promise.resolve().then(run); return execution.then(resolve, reject); },
    };
    return chain;
  }

  return {
    from(table) {
      return {
        select: (columns) => builder(table, 'read', null).select(columns),
        insertIfAbsent: (row, options) => builder(table, 'insert', { row, onConflict: options?.onConflict }),
        update: (row) => builder(table, 'update', { row }),
        delete: () => builder(table, 'delete', null),
      };
    },
    dump: (table) => rows(table).map((row) => ({ ...row })),
  };
}
