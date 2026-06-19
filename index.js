import { Client, GatewayIntentBits, EmbedBuilder } from 'discord.js';
import express from 'express';
import dotenv from 'dotenv';
import crypto from 'crypto';

// Load environment variables
dotenv.config();

// Create Discord client with required intents
const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
  ],
});

let discordReady = false;

client.once('ready', () => {
  console.log(`[Discord] Bot is ready and logged in as: ${client.user.tag}`);
  discordReady = true;
});

// Login to Discord if token is provided
if (process.env.DISCORD_TOKEN) {
  console.log('[Discord] Attempting to connect to Discord...');
  client.login(process.env.DISCORD_TOKEN).catch((err) => {
    console.error('[Discord] Failed to log in:', err.message);
  });
} else {
  console.warn('[Discord] DISCORD_TOKEN is missing in .env. Bot will not login.');
}

// Create Express server
const app = express();

// Parse json body and preserve raw body for GitHub signature verification
app.use(
  express.json({
    verify: (req, res, buf) => {
      req.rawBody = buf;
    },
  })
);

// Middleware to verify GitHub webhook signatures
function verifyGithubSignature(req, res, next) {
  const secret = process.env.GITHUB_WEBHOOK_SECRET;

  // If no secret is configured, skip verification with a warning
  if (!secret) {
    console.warn('[Security Warning] GITHUB_WEBHOOK_SECRET is not set in .env. Webhook signature verification is disabled.');
    return next();
  }

  const signature = req.headers['x-hub-signature-256'];
  if (!signature) {
    console.warn('[Webhook] Missing "x-hub-signature-256" header. Request rejected.');
    return res.status(401).send('Signature verification failed: missing signature header');
  }

  const hmac = crypto.createHmac('sha256', secret);
  const digest = 'sha256=' + hmac.update(req.rawBody || '').digest('hex');

  const sigBuffer = Buffer.from(signature);
  const digestBuffer = Buffer.from(digest);

  // Timing safe comparison to prevent timing attacks
  if (sigBuffer.length !== digestBuffer.length) {
    console.warn('[Webhook] Signature verification failed (length mismatch). Request rejected.');
    return res.status(401).send('Signature verification failed: length mismatch');
  }

  if (crypto.timingSafeEqual(sigBuffer, digestBuffer)) {
    return next();
  } else {
    console.warn('[Webhook] Signature verification failed (signature mismatch). Request rejected.');
    return res.status(401).send('Signature verification failed: mismatch');
  }
}

// Webhook listener endpoint
app.post('/webhook', verifyGithubSignature, async (req, res) => {
  const event = req.headers['x-github-event'];

  // Handle GitHub Ping event
  if (event === 'ping') {
    console.log('[Webhook] Received ping event from GitHub.');
    return res.status(200).send('pong');
  }

  // We only respond to push events
  if (event !== 'push') {
    console.log(`[Webhook] Received unhandled event: "${event}". Ignored.`);
    return res.status(200).send(`Event "${event}" ignored`);
  }

  const payload = req.body;

  // Validate request structure
  if (!payload || !payload.commits || payload.commits.length === 0) {
    console.log('[Webhook] Received push event with empty payload or no commits.');
    return res.status(200).send('No commits found in payload');
  }

  const repoName = payload.repository?.full_name || 'unknown-repository';
  const branch = payload.ref ? payload.ref.replace('refs/heads/', '') : 'unknown-branch';
  const pusherName = payload.pusher?.name || 'unknown-pusher';
  const compareUrl = payload.compare || payload.repository?.html_url || '';
  const commitsCount = payload.commits.length;

  console.log(`[Webhook] Push detected: ${repoName} (Branch: ${branch}) by ${pusherName}. Commits count: ${commitsCount}`);

  // Ensure Discord Bot is ready
  if (!discordReady) {
    console.error('[Discord] Cannot process push event: Discord bot is not logged in or not ready.');
    return res.status(503).send('Discord bot is not ready');
  }

  const channelId = process.env.DISCORD_CHANNEL_ID;
  if (!channelId) {
    console.error('[Discord] Cannot process push event: DISCORD_CHANNEL_ID is not configured in .env');
    return res.status(500).send('Discord channel ID is not configured');
  }

  try {
    const channel = await client.channels.fetch(channelId);
    if (!channel || !channel.isTextBased()) {
      console.error(`[Discord] Channel with ID "${channelId}" not found or is not text-based.`);
      return res.status(500).send('Target discord channel is invalid or inaccessible');
    }

    // 1. Build a beautiful Embed with commit details
    const embed = new EmbedBuilder()
      .setTitle(`Push to ${repoName}`)
      .setURL(compareUrl)
      .setColor(0x2f3136) // Sleek dark/grey aesthetic
      .setAuthor({
        name: pusherName,
        iconURL: payload.sender?.avatar_url || undefined,
        url: payload.sender?.html_url || undefined,
      })
      .setDescription(`Pushed **${commitsCount}** commit${commitsCount > 1 ? 's' : ''} to branch \`${branch}\``)
      .setTimestamp();

    // Limit commit list in the embed to max 5 commits to prevent UI clutter
    const maxCommitsToShow = 5;
    const commitsToShow = payload.commits.slice(0, maxCommitsToShow);
    
    const commitLines = commitsToShow.map((commit) => {
      const shortSha = commit.id ? commit.id.substring(0, 7) : 'xxxxxxx';
      const cleanMessage = commit.message ? commit.message.split('\n')[0] : 'No commit message';
      const authorName = commit.author?.username || commit.author?.name || 'Unknown';
      const commitUrl = commit.url || '';

      return commitUrl 
        ? `[\`${shortSha}\`](${commitUrl}) - ${cleanMessage} (${authorName})`
        : `\`${shortSha}\` - ${cleanMessage} (${authorName})`;
    }).join('\n');

    embed.addFields({
      name: 'Commits',
      value: commitLines || 'No details available',
    });

    if (commitsCount > maxCommitsToShow) {
      embed.setFooter({ text: `... and ${commitsCount - maxCommitsToShow} more commit(s)` });
    }

    // 2. Prep notification content (e.g., tags)
    const tagContent = process.env.ROLE_TO_TAG ? `${process.env.ROLE_TO_TAG}` : '';

    // 3. Send message to Discord
    await channel.send({
      content: tagContent,
      embeds: [embed],
    });

    console.log(`[Discord] Push notification successfully posted to channel ${channelId}.`);
    return res.status(200).send('Notification sent successfully');
  } catch (error) {
    console.error('[Discord] Error sending message to Discord channel:', error);
    return res.status(500).send('Failed to post message to Discord');
  }
});

// Start listening
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`[Server] Webhook server running on port ${PORT}`);
});
