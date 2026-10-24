/**
 * Email channel: one adapter per mailbox named in EMAIL_INSTANCES, keyed `email-<name>`.
 * Inbound polls INBOX every minute for unseen mail; the platform id is the sender address
 * and a reply threads onto that sender's latest mail. `ncl email send|list|read` give agents
 * wired to an instance its mailbox without the credentials ever leaving the host.
 *
 * .env per mailbox: EMAIL_<NAME>_ADDRESS, EMAIL_<NAME>_PASSWORD, EMAIL_<NAME>_IMAP_HOST,
 * EMAIL_<NAME>_SMTP_HOST, optional EMAIL_<NAME>_IMAP_PORT (993, TLS) and _SMTP_PORT (587, STARTTLS).
 * A mailbox without SMTP_HOST is read-only: nothing is ever sent from it.
 */
import { ImapFlow, type MessageStructureObject } from 'imapflow';
import nodemailer from 'nodemailer';
import MailComposer from 'nodemailer/lib/mail-composer/index.js';

import { normalizeArgs } from '../cli/args.js';
import type { CallerContext } from '../cli/frame.js';
import { register } from '../cli/registry.js';
import { getDb } from '../db/connection.js';
import { readEnvFile } from '../env.js';
import { log } from '../log.js';
import type { ChannelAdapter, ChannelDefaults } from './adapter.js';
import { registerChannelAdapter } from './channel-registry.js';

const POLL_MS = 60_000;

// Unknown senders never get a messaging group (no mention), so only wired addresses reach an agent.
const EMAIL_DEFAULTS: ChannelDefaults = {
  dm: { engageMode: 'pattern', engagePattern: '.', threads: false, unknownSenderPolicy: 'public' },
  group: { engageMode: 'pattern', engagePattern: '.', threads: false, unknownSenderPolicy: 'public' },
  mentions: 'never',
};

interface Mailbox {
  address: string;
  password: string;
  imapHost: string;
  imapPort: number;
  smtpHost?: string;
  smtpPort: number;
}

interface Mail {
  to: string;
  cc?: string;
  subject: string;
  text: string;
  inReplyTo?: string;
}

const mailboxes = new Map<string, Mailbox>();

function readMailbox(name: string): Mailbox | null {
  const prefix = `EMAIL_${name.toUpperCase().replace(/-/g, '_')}_`;
  const env = readEnvFile(
    ['ADDRESS', 'PASSWORD', 'IMAP_HOST', 'IMAP_PORT', 'SMTP_HOST', 'SMTP_PORT'].map((k) => prefix + k),
  );
  const get = (k: string) => env[prefix + k];
  if (!get('ADDRESS') || !get('PASSWORD') || !get('IMAP_HOST')) return null;
  return {
    address: get('ADDRESS')!,
    password: get('PASSWORD')!,
    imapHost: get('IMAP_HOST')!,
    imapPort: Number(get('IMAP_PORT') ?? 993),
    smtpHost: get('SMTP_HOST'),
    smtpPort: Number(get('SMTP_PORT') ?? 587),
  };
}

async function withImap<T>(box: Mailbox, fn: (client: ImapFlow) => Promise<T>): Promise<T> {
  const client = new ImapFlow({
    host: box.imapHost,
    port: box.imapPort,
    secure: true,
    auth: { user: box.address, pass: box.password },
    logger: false,
  });
  await client.connect();
  try {
    return await fn(client);
  } finally {
    await client.logout();
  }
}

function findPart(node: MessageStructureObject, type: string): string | undefined {
  if (node.type === type && node.disposition !== 'attachment') return node.part ?? '1';
  for (const child of node.childNodes ?? []) {
    const part = findPart(child, type);
    if (part) return part;
  }
  return undefined;
}

async function bodyText(client: ImapFlow, uid: number, structure?: MessageStructureObject): Promise<string> {
  const part = structure && (findPart(structure, 'text/plain') ?? findPart(structure, 'text/html'));
  if (!part) return '';
  const { meta, content } = await client.download(String(uid), part, { uid: true });
  if (!content) return '';
  const chunks: Buffer[] = [];
  for await (const chunk of content) chunks.push(chunk as Buffer);
  const text = Buffer.concat(chunks).toString('utf8');
  return (meta?.contentType === 'text/html' ? text.replace(/<[^>]+>/g, '') : text).trim();
}

async function sendMail(box: Mailbox, mail: Mail): Promise<string> {
  if (!box.smtpHost) throw new Error(`${box.address} is read-only`);
  const compiled = new MailComposer({ from: box.address, ...mail, references: mail.inReplyTo }).compile();
  const raw = await compiled.build();
  await nodemailer
    .createTransport({
      host: box.smtpHost,
      port: box.smtpPort,
      requireTLS: true,
      auth: { user: box.address, pass: box.password },
    })
    .sendMail({ envelope: { from: box.address, to: [mail.to, mail.cc].filter(Boolean).join(',') }, raw });
  await withImap(box, async (client) => {
    const sent = (await client.list()).find((b) => b.specialUse === '\\Sent')?.path ?? 'Sent';
    await client.append(sent, raw, ['\\Seen']);
  });
  return compiled.messageId();
}

function createEmailAdapter(instance: string, box: Mailbox): ChannelAdapter {
  let timer: NodeJS.Timeout | undefined;
  let connected = false;
  return {
    name: instance,
    channelType: 'email',
    instance,
    supportsThreads: false,
    textOnly: true,
    defaults: EMAIL_DEFAULTS,
    async setup(config) {
      const poll = () =>
        withImap(box, async (client) => {
          await client.mailboxOpen('INBOX');
          const uids = await client.search({ seen: false }, { uid: true });
          if (!uids || uids.length === 0) return;
          const messages = await client.fetchAll(
            uids,
            { uid: true, envelope: true, bodyStructure: true },
            { uid: true },
          );
          for (const msg of messages) {
            const from = msg.envelope?.from?.[0];
            if (from?.address) {
              const sender = from.address.toLowerCase();
              const text = await bodyText(client, msg.uid, msg.bodyStructure);
              await config.onInbound(sender, null, {
                id: msg.envelope?.messageId ?? `${box.address}:${msg.uid}`,
                kind: 'chat',
                content: {
                  text: `To: ${box.address}\nSubject: ${msg.envelope?.subject ?? ''}\n\n${text}`,
                  sender: from.name || sender,
                  senderId: sender,
                },
                timestamp: new Date(msg.envelope?.date ?? Date.now()).toISOString(),
              });
            }
            await client.messageFlagsAdd(String(msg.uid), ['\\Seen'], { uid: true });
          }
        });
      const loop = () => {
        poll()
          .catch((err) => log.warn('Email poll failed', { instance, err: err instanceof Error ? err.message : err }))
          .finally(() => {
            if (connected) timer = setTimeout(loop, POLL_MS);
          });
      };
      await withImap(box, async () => undefined);
      connected = true;
      loop();
    },
    async teardown() {
      connected = false;
      clearTimeout(timer);
    },
    isConnected: () => connected,
    async deliver(platformId, _threadId, message) {
      const content = message.content as { text?: string; markdown?: string };
      const last = await withImap(box, async (client) => {
        await client.mailboxOpen('INBOX');
        const uids = await client.search({ from: platformId }, { uid: true });
        const uid = uids ? uids.at(-1) : undefined;
        const msg = uid && (await client.fetchOne(String(uid), { envelope: true }, { uid: true }));
        return msg ? msg.envelope : undefined;
      });
      const subject = last?.subject ?? '';
      return sendMail(box, {
        to: platformId,
        subject: !subject || /^re:/i.test(subject) ? subject : `Re: ${subject}`,
        text: content.text ?? content.markdown ?? '',
        inReplyTo: last?.messageId,
      });
    },
  };
}

for (const raw of (readEnvFile(['EMAIL_INSTANCES']).EMAIL_INSTANCES ?? '').split(',')) {
  const name = raw.trim();
  if (!name) continue;
  const instance = `email-${name}`;
  registerChannelAdapter(instance, {
    factory: () => {
      const box = readMailbox(name);
      if (!box) return null;
      mailboxes.set(instance, box);
      return createEmailAdapter(instance, box);
    },
    defaults: EMAIL_DEFAULTS,
  });
}

async function mailboxFor(args: Record<string, unknown>, ctx: CallerContext): Promise<Mailbox> {
  const instance = String(args.instance);
  const box = mailboxes.get(instance);
  if (!box) throw new Error(`unknown email instance "${instance}" (live: ${[...mailboxes.keys()].join(', ')})`);
  if (
    ctx.caller === 'agent' &&
    !(await getDb().get(
      `SELECT 1 FROM messaging_group_agents a JOIN messaging_groups m ON m.id = a.messaging_group_id
       WHERE a.agent_group_id = ? AND m.channel_type = 'email' AND m.instance = ? LIMIT 1`,
      ctx.agentGroupId,
      instance,
    ))
  ) {
    throw new Error(`this agent group is not wired to ${instance}`);
  }
  return box;
}

function requireArgs(...keys: string[]) {
  return (raw: Record<string, unknown>) => {
    const args = normalizeArgs(raw);
    const missing = keys.filter((k) => typeof args[k] !== 'string' || !args[k]);
    if (missing.length) throw new Error(`missing --${missing.join(', --')}`);
    return args;
  };
}

const optional = (v: unknown) => (typeof v === 'string' && v ? v : undefined);

register({
  name: 'email-send',
  action: 'email.send',
  resource: 'email',
  access: 'open',
  description:
    'Send a mail from an email instance: --instance email-<name> --to <addr[,addr]> [--cc <addr[,addr]>] --subject <s> --body <text> [--in-reply-to <Message-ID>]. Returns the Message-ID.',
  parseArgs: requireArgs('instance', 'to', 'subject', 'body'),
  handler: async (args, ctx) => ({
    messageId: await sendMail(await mailboxFor(args, ctx), {
      to: args.to as string,
      cc: optional(args.cc),
      subject: args.subject as string,
      text: args.body as string,
      inReplyTo: optional(args.in_reply_to),
    }),
  }),
});

register({
  name: 'email-list',
  action: 'email.list',
  resource: 'email',
  access: 'open',
  description:
    'List the newest mails of an email instance: --instance email-<name> [--folder INBOX|Sent] [--limit 20]. Rows: id, date, from, to, subject, messageId.',
  parseArgs: requireArgs('instance'),
  handler: async (args, ctx) =>
    withImap(await mailboxFor(args, ctx), async (client) => {
      const box = await client.mailboxOpen(optional(args.folder) ?? 'INBOX');
      const limit = Number(args.limit ?? 20);
      if (box.exists === 0) return [];
      const messages = await client.fetchAll(`${Math.max(1, box.exists - limit + 1)}:*`, { uid: true, envelope: true });
      return messages.reverse().map((m) => ({
        id: m.uid,
        date: m.envelope?.date && new Date(m.envelope.date).toISOString(),
        from: m.envelope?.from?.map((a) => a.address).join(', '),
        to: m.envelope?.to?.map((a) => a.address).join(', '),
        subject: m.envelope?.subject,
        messageId: m.envelope?.messageId,
      }));
    }),
});

register({
  name: 'email-read',
  action: 'email.read',
  resource: 'email',
  access: 'open',
  description:
    'Read one mail by the id from `ncl email list`: --instance email-<name> --id <id> [--folder INBOX|Sent].',
  parseArgs: requireArgs('instance', 'id'),
  handler: async (args, ctx) =>
    withImap(await mailboxFor(args, ctx), async (client) => {
      await client.mailboxOpen(optional(args.folder) ?? 'INBOX');
      const msg = await client.fetchOne(
        args.id as string,
        { uid: true, envelope: true, bodyStructure: true },
        { uid: true },
      );
      if (!msg) throw new Error(`no mail with id ${args.id}`);
      const e = msg.envelope;
      return {
        from: e?.from?.map((a) => a.address).join(', '),
        to: e?.to?.map((a) => a.address).join(', '),
        cc: e?.cc?.map((a) => a.address).join(', '),
        date: e?.date && new Date(e.date).toISOString(),
        subject: e?.subject,
        messageId: e?.messageId,
        inReplyTo: e?.inReplyTo,
        text: await bodyText(client, msg.uid, msg.bodyStructure),
      };
    }),
});
