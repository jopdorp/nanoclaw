/// <reference lib="dom" />
/// <reference lib="dom.iterable" />
/**
 * Durable crypto store for the Matrix bot. The rust crypto engine keeps the
 * device keys and the Olm/Megolm sessions only in IndexedDB, which Node lacks,
 * and its in-memory fallback mints a new identity for the same device on every
 * restart. So it runs on fake-indexeddb, every committed write is snapshotted
 * to a file, and the snapshot is restored before crypto starts. The SDK
 * encrypts the store contents with the recovery key. Also home to attachment
 * encryption, which the adapter does not do.
 */
import 'fake-indexeddb/auto';
import { IDBFactory } from 'fake-indexeddb';
import { createHash, randomUUID, webcrypto } from 'crypto';
import fs from 'fs';
import v8 from 'v8';

import { log } from '../log.js';

interface StoreDump {
  name: string;
  keyPath: string | string[] | null;
  autoIncrement: boolean;
  indexes: { name: string; keyPath: string | string[]; unique: boolean; multiEntry: boolean }[];
  keys: IDBValidKey[];
  values: unknown[];
}
interface DatabaseDump {
  name: string;
  version: number;
  stores: StoreDump[];
}

const result = <T>(request: IDBRequest<T>) =>
  new Promise<T>((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });

async function dump(): Promise<DatabaseDump[]> {
  const databases: DatabaseDump[] = [];
  for (const { name, version } of await indexedDB.databases()) {
    const db = await result(indexedDB.open(name!));
    const names = [...db.objectStoreNames];
    const tx = names.length > 0 ? db.transaction(names) : undefined;
    const stores: StoreDump[] = [];
    for (const storeName of names) {
      const store = tx!.objectStore(storeName);
      stores.push({
        name: storeName,
        keyPath: store.keyPath,
        autoIncrement: store.autoIncrement,
        indexes: [...store.indexNames].map((indexName) => {
          const { keyPath, unique, multiEntry } = store.index(indexName);
          return { name: indexName, keyPath, unique, multiEntry };
        }),
        keys: await result(store.getAllKeys()),
        values: await result(store.getAll()),
      });
    }
    db.close();
    databases.push({ name: name!, version: version!, stores });
  }
  return databases;
}

async function restore(databases: DatabaseDump[]): Promise<void> {
  for (const { name, version, stores } of databases) {
    const request = indexedDB.open(name, version);
    request.onupgradeneeded = () => {
      for (const s of stores) {
        const store = request.result.createObjectStore(s.name, { keyPath: s.keyPath, autoIncrement: s.autoIncrement });
        for (const index of s.indexes) store.createIndex(index.name, index.keyPath, index);
      }
    };
    const db = await result(request);
    if (stores.length > 0) {
      const tx = db.transaction(
        stores.map((s) => s.name),
        'readwrite',
      );
      for (const s of stores) {
        const store = tx.objectStore(s.name);
        s.values.forEach((value, i) => (s.keyPath === null ? store.put(value, s.keys[i]) : store.put(value)));
      }
      await new Promise((resolve, reject) => {
        tx.oncomplete = resolve;
        tx.onerror = () => reject(tx.error);
      });
    }
    db.close();
  }
}

/** Keeps an unusable snapshot aside and starts crypto over on an empty IndexedDB, so Matrix still comes up. */
export function discardCryptoStore(file: string, err: unknown): void {
  log.error('Matrix crypto store unusable, starting with an empty one', { err });
  if (fs.existsSync(file)) fs.renameSync(file, `${file}.corrupt-${Date.now()}`);
  globalThis.indexedDB = new IDBFactory();
}

/** Restore the snapshot, then re-snapshot a second after every committed write. Returns a flush for shutdown. */
export async function useDurableCryptoStore(file: string): Promise<() => Promise<void>> {
  try {
    if (fs.existsSync(file)) await restore(v8.deserialize(fs.readFileSync(file)) as DatabaseDump[]);
  } catch (err) {
    discardCryptoStore(file, err);
  }
  let pending: NodeJS.Timeout | undefined;
  const save = async () => {
    pending = undefined;
    fs.writeFileSync(`${file}.tmp`, v8.serialize(await dump()), { mode: 0o600 });
    fs.renameSync(`${file}.tmp`, file);
  };
  const transaction = IDBDatabase.prototype.transaction;
  IDBDatabase.prototype.transaction = function (this: IDBDatabase, ...args: Parameters<typeof transaction>) {
    const tx = transaction.apply(this, args);
    if (tx.mode === 'readwrite')
      tx.addEventListener('complete', () => {
        pending ??= setTimeout(
          () => void save().catch((err) => log.error('Matrix crypto store snapshot failed', { err })),
          1000,
        );
      });
    return tx;
  };
  return async () => {
    if (!pending) return;
    clearTimeout(pending);
    await save();
  };
}

/** Matrix encrypted attachment (spec "Sending encrypted attachments"): AES-256-CTR, v2. */
async function encryptAttachment(data: Uint8Array) {
  const key = await webcrypto.subtle.generateKey({ name: 'AES-CTR', length: 256 }, true, ['encrypt', 'decrypt']);
  const iv = new Uint8Array(16);
  webcrypto.getRandomValues(iv.subarray(0, 8));
  const ciphertext = new Uint8Array(
    await webcrypto.subtle.encrypt({ name: 'AES-CTR', counter: iv, length: 64 }, key, data),
  );
  const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64').replace(/=+$/, '');
  const hash = createHash('sha256').update(ciphertext).digest();
  return {
    ciphertext,
    file: { v: 'v2', key: await webcrypto.subtle.exportKey('jwk', key), iv: b64(iv), hashes: { sha256: b64(hash) } },
  };
}

interface UploadingClient {
  uploadContent(data: Blob, opts: { name?: string; type?: string }): Promise<{ content_uri: string }>;
  getCrypto(): { isEncryptionEnabledInRoom(roomId: string): Promise<boolean> } | undefined;
}
type Send = (roomId: string, rootEventId: string | undefined, content: Record<string, unknown>) => Promise<unknown>;

/**
 * Uploads are held until the message is sent, where the room is known, so a
 * file for an encrypted room is encrypted before it leaves the host.
 */
export function encryptUploads(client: UploadingClient, send: Send): Send {
  const upload = client.uploadContent.bind(client);
  const held = new Map<string, { data: Blob; opts: { name?: string; type?: string } }>();
  client.uploadContent = async (data, opts) => {
    const contentUri = `held:${randomUUID()}`;
    held.set(contentUri, { data, opts });
    return { content_uri: contentUri };
  };
  return async (roomId, rootEventId, content) => {
    const file = held.get(content.url as string);
    if (!file) return send(roomId, rootEventId, content);
    held.delete(content.url as string);
    if (!(await client.getCrypto()?.isEncryptionEnabledInRoom(roomId))) {
      const { content_uri } = await upload(file.data, file.opts);
      return send(roomId, rootEventId, { ...content, url: content_uri });
    }
    const encrypted = await encryptAttachment(new Uint8Array(await file.data.arrayBuffer()));
    const { content_uri } = await upload(new Blob([encrypted.ciphertext]), { type: 'application/octet-stream' });
    const { url: _plain, ...rest } = content;
    return send(roomId, rootEventId, { ...rest, file: { ...encrypted.file, url: content_uri } });
  };
}
