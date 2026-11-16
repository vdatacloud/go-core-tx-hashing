// Checks the vectors in testdata/upstream against the upstream TypeScript
// package installed in node_modules (CI installs exactly UpstreamVersion),
// and writes the upstream protobuf field numbers of every message a prepared
// transaction holds, for TestFieldsMatchUpstream.
//
//   node scripts/upstream-check.mjs <fields-out.json>
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const { computePreparedTransactionHash } = await import("@canton-network/core-tx-hashing");
const { PreparedTransaction } = await import("@canton-network/core-ledger-proto");

let failed = 0, n = 0;
for (const dir of readdirSync("testdata/upstream", { withFileTypes: true }).filter((d) => d.isDirectory())) {
  const path = join("testdata/upstream", dir.name);
  for (const f of readdirSync(path).filter((f) => f.endsWith(".json"))) {
    const v = JSON.parse(readFileSync(join(path, f), "utf8"));
    n++;
    let got;
    try {
      const h = await computePreparedTransactionHash(v.preparedTransaction, v.scheme, v.limits ? { limits: v.limits } : undefined);
      got = { hash: Buffer.from(h).toString("hex") };
    } catch (e) {
      got = { error: e.code ?? String(e) };
    }
    if (JSON.stringify(got) !== JSON.stringify(v.expected)) {
      console.error(`MISMATCH ${dir.name}/${f}: upstream gives ${JSON.stringify(got)}, the vector says ${JSON.stringify(v.expected)}`);
      failed++;
    }
  }
}
console.log(`${n - failed}/${n} vectors agree with the installed upstream package`);

const fields = {};
(function walk(t) {
  const name = t.typeName.replace(/^com\.daml\.ledger\.api\.v2\.(interactive\.)?(transaction\.v1\.)?/, "").replaceAll(".", "_");
  if (name in fields) return;
  fields[name] = t.fields.map((f) => f.no).sort((a, b) => a - b);
  for (const f of t.fields) if (f.kind === "message") walk(f.T());
})(PreparedTransaction);
if (process.argv[2]) writeFileSync(process.argv[2], JSON.stringify(fields, null, 2) + "\n");
process.exit(failed ? 1 : 0);
