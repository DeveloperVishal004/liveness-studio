package io.mosip.liveness.session;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/**
 * Persistent, tamper-evident {@link AttemptLedger} (reference implementation for U5 / D-MOS-7; the Registration Client
 * would back this by its encrypted database). Properties:
 * <ul>
 *   <li><b>write-through:</b> {@code recordAttempt}/{@code recordAttackEvent} return only after the new counts are on
 *       disk (temp file, fsync, atomic move), so a crash cannot undo a recorded attempt;</li>
 *   <li><b>tamper-evident:</b> the file is authenticated with HMAC-SHA256 under a caller-held key; editing counts,
 *       truncating or swapping in another file is detected;</li>
 *   <li><b>no plaintext subject keys:</b> keys are stored as HMAC-SHA256(key, subjectKey);</li>
 *   <li><b>fail-closed:</b> an unreadable or unauthenticated file puts the ledger in a LOCKED state in which every subject
 *       reads as over any limit (sessions end FAILED_MAX_RETRIES) and nothing is written; it is never silently reset.
 *       A missing file is a fresh ledger.</li>
 * </ul>
 * Single-process: methods are synchronized; concurrent processes sharing one file are not supported.
 */
public final class FileAttemptLedger implements AttemptLedger {
    private static final String MAGIC = "phase0-attempt-ledger/1";
    private final Path file;
    private final byte[] hmacKey;
    private final Map<String, int[]> counts = new TreeMap<>();
    /** channel id -> {count, lastEventEpochMs}; reasons kept separately (base64url text). */
    private final Map<String, long[]> channels = new TreeMap<>();
    private final Map<String, String> channelReasons = new TreeMap<>();
    private final java.util.List<String> audit = new java.util.ArrayList<>();
    private final boolean locked;
    private final String lockReason;

    public FileAttemptLedger(Path file, byte[] hmacKey) {
        this.file = Objects.requireNonNull(file);
        if (hmacKey == null || hmacKey.length < 32) {
            throw new IllegalArgumentException("HMAC key must be at least 32 bytes");
        }
        this.hmacKey = hmacKey.clone();
        String reason = null;
        try {
            if (Files.exists(file)) {
                load(Files.readAllBytes(file));
            }
        } catch (IOException | RuntimeException | GeneralSecurityException e) {
            counts.clear();
            channels.clear();
            channelReasons.clear();
            audit.clear();
            reason = e.getClass().getSimpleName() + ": " + e.getMessage();
        }
        this.locked = reason != null;
        this.lockReason = reason;
    }

    /** True if the file could not be authenticated; every subject is then treated as over-limit. */
    public boolean locked() { return locked; }

    public String lockReason() { return lockReason; }

    @Override
    public boolean trustworthy() { return !locked; }

    @Override
    public synchronized int attempts(String key) {
        return locked ? Integer.MAX_VALUE : c(key)[0];
    }

    @Override
    public synchronized int attackEvents(String key) {
        return locked ? Integer.MAX_VALUE : c(key)[1];
    }

    @Override
    public synchronized int deviceFaults(String key) {
        return locked ? Integer.MAX_VALUE : c(key)[2];
    }

    @Override
    public synchronized int recordDeviceFault(String key) {
        return record(key, 2);
    }

    @Override
    public synchronized int recordAttempt(String key) {
        return record(key, 0);
    }

    @Override
    public synchronized int recordAttackEvent(String key) {
        return record(key, 1);
    }

    private int record(String key, int idx) {
        if (locked) {
            return Integer.MAX_VALUE;
        }
        int[] c = c(key);
        int[] next = {c[0], c[1], c[2]};
        next[idx] = AttemptLedger.inc(next[idx]);              // saturating: never wraps to a negative count
        String id = id(key);
        int[] previous = counts.put(id, next);
        try {
            persist();
        } catch (IOException | GeneralSecurityException e) {
            if (previous == null) {
                counts.remove(id);
            } else {
                counts.put(id, previous);
            }
            throw new IllegalStateException("attempt ledger not persisted (fail closed): " + e.getMessage(), e);
        }
        return next[idx];
    }

    @Override
    public synchronized int channelEvents(String channelKey) {
        if (locked) {
            return Integer.MAX_VALUE;
        }
        long[] v = channels.get(cid(channelKey));
        return v == null ? 0 : (int) v[0];
    }

    @Override
    public synchronized int recordChannelEvent(String channelKey, String reason) {
        if (locked) {
            return Integer.MAX_VALUE;
        }
        String id = cid(channelKey);
        long[] prev = channels.get(id);
        String prevReason = channelReasons.get(id);
        int n = AttemptLedger.inc(prev == null ? 0 : (int) prev[0]);
        channels.put(id, new long[] {n, System.currentTimeMillis()});
        channelReasons.put(id, b64(String.valueOf(reason)));
        try {
            persist();
        } catch (IOException | GeneralSecurityException e) {
            if (prev == null) {
                channels.remove(id);
                channelReasons.remove(id);
            } else {
                channels.put(id, prev);
                channelReasons.put(id, prevReason);
            }
            throw new IllegalStateException("attempt ledger not persisted (fail closed): " + e.getMessage(), e);
        }
        return n;
    }

    @Override
    public synchronized String lastChannelReason(String channelKey) {
        String r = channelReasons.get(cid(channelKey));
        return r == null ? null : new String(Base64.getUrlDecoder().decode(r), StandardCharsets.UTF_8);
    }

    @Override
    public synchronized void resetChannel(String channelKey, String authorizedBy, String justification) {
        AttemptLedger.requireResetAuthorization(authorizedBy, justification);
        if (locked) {
            throw new IllegalStateException("ledger is locked (tampered or unreadable): an administrative reset cannot "
                    + "repair it; restore the file from a trusted backup or re-provision the ledger");
        }
        String id = cid(channelKey);
        long[] prev = channels.remove(id);
        String prevReason = channelReasons.remove(id);
        String entry = "r " + id + " " + System.currentTimeMillis() + " " + (prev == null ? 0 : prev[0]) + " "
                + b64(authorizedBy) + " " + b64(justification);
        audit.add(entry);
        try {
            persist();
        } catch (IOException | GeneralSecurityException e) {
            audit.remove(audit.size() - 1);
            if (prev != null) {
                channels.put(id, prev);
                channelReasons.put(id, prevReason);
            }
            throw new IllegalStateException("reset not persisted: " + e.getMessage(), e);
        }
    }

    @Override
    public synchronized java.util.List<String> resetAudit() {
        java.util.List<String> out = new java.util.ArrayList<>();
        for (String a : audit) {
            String[] f = a.split(" ");
            out.add("reset channel=" + f[1] + " at=" + f[2] + " previous=" + f[3] + " by="
                    + new String(Base64.getUrlDecoder().decode(f[4]), StandardCharsets.UTF_8) + " why="
                    + new String(Base64.getUrlDecoder().decode(f[5]), StandardCharsets.UTF_8));
        }
        return java.util.Collections.unmodifiableList(out);
    }

    private String cid(String channelKey) {
        try {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hmac(("channel:" + channelKey).getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String b64(String s) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    private int[] c(String key) {
        int[] v = counts.get(id(key));
        return v == null ? new int[3] : v;
    }

    private String id(String key) {
        try {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hmac(("subject:" + key).getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private byte[] hmac(byte[] data) throws GeneralSecurityException {
        Mac m = Mac.getInstance("HmacSHA256");
        m.init(new SecretKeySpec(hmacKey, "HmacSHA256"));
        return m.doFinal(data);
    }

    private byte[] body() {
        StringBuilder sb = new StringBuilder(MAGIC).append('\n');
        for (Map.Entry<String, int[]> e : counts.entrySet()) {
            sb.append(e.getKey()).append(' ').append(e.getValue()[0]).append(' ').append(e.getValue()[1]).append(' ')
                    .append(e.getValue()[2]).append('\n');
        }
        for (Map.Entry<String, long[]> e : channels.entrySet()) {
            String r = channelReasons.get(e.getKey());
            sb.append("c ").append(e.getKey()).append(' ').append(e.getValue()[0]).append(' ').append(e.getValue()[1])
                    .append(' ').append(r == null || r.isEmpty() ? "-" : r).append('\n');
        }
        for (String a : audit) {
            sb.append(a).append('\n');
        }
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    private void persist() throws IOException, GeneralSecurityException {
        byte[] body = body();
        byte[] mac = hmac(body);
        Path tmp = file.resolveSibling(file.getFileName() + ".tmp");
        try (FileChannel ch = FileChannel.open(tmp, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.WRITE)) {
            ch.write(ByteBuffer.wrap(body));
            ch.write(ByteBuffer.wrap(("mac " + Base64.getEncoder().encodeToString(mac) + "\n").getBytes(StandardCharsets.US_ASCII)));
            ch.force(true);
        }
        try {
            Files.move(tmp, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private void load(byte[] all) throws GeneralSecurityException {
        String text = new String(all, StandardCharsets.UTF_8);
        int macAt = text.lastIndexOf("mac ");
        if (macAt <= 0 || !text.endsWith("\n")) {
            throw new IllegalArgumentException("truncated or not a ledger");
        }
        byte[] body = text.substring(0, macAt).getBytes(StandardCharsets.UTF_8);
        byte[] mac = Base64.getDecoder().decode(text.substring(macAt + 4).trim());
        if (!MessageDigest.isEqual(mac, hmac(body))) {
            throw new IllegalArgumentException("ledger authentication failed (tampered or wrong key)");
        }
        String[] lines = new String(body, StandardCharsets.UTF_8).split("\n");
        if (!MAGIC.equals(lines[0])) {
            throw new IllegalArgumentException("unknown ledger format");
        }
        for (String l : Arrays.copyOfRange(lines, 1, lines.length)) {
            String[] f = l.split(" ");
            if (f.length == 5 && "c".equals(f[0])) {                  // channel: c <id> <count> <lastMs> <reason>
                long n = Long.parseLong(f[2]), t = Long.parseLong(f[3]);
                if (n < 0 || n > Integer.MAX_VALUE) {
                    throw new IllegalArgumentException("channel count out of range");
                }
                channels.put(f[1], new long[] {n, t});
                if (!"-".equals(f[4])) {
                    channelReasons.put(f[1], f[4]);
                }
                continue;
            }
            if (f.length == 6 && "r".equals(f[0])) {                  // reset audit: r <id> <ms> <prev> <by> <why>
                audit.add(l);
                continue;
            }
            if (f.length != 3 && f.length != 4) {                     // 3 fields: written before device faults existed
                throw new IllegalArgumentException("malformed ledger line");
            }
            int a = Integer.parseInt(f[1]), b = Integer.parseInt(f[2]), d = f.length == 4 ? Integer.parseInt(f[3]) : 0;
            if (a < 0 || b < 0 || d < 0) {
                throw new IllegalArgumentException("negative count");
            }
            counts.put(f[0], new int[] {a, b, d});
        }
    }
}
