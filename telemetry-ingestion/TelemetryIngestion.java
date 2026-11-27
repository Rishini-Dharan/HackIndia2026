import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Random;

/**
 * Q-Guardian OS telemetry ingestion service.
 *
 * Parses pipe-delimited packet records (ts|src_ip|dst_ip|protocol|port|bytes|flags)
 * with a single charAt pass (no regex, no split) and turns them into JSON events.
 *
 * Modes:
 *   java TelemetryIngestion                       stdin lines -> JSON lines on stdout
 *   java TelemetryIngestion --simulate 500        generated lines -> JSON lines on stdout
 *   java TelemetryIngestion --bench 2000000       measure parse+serialize throughput
 *   java TelemetryIngestion --emit URL [--rate N] [--attack]
 *                                                 stream generated traffic to the backend's
 *                                                 POST /ingest endpoint in batches
 */
public class TelemetryIngestion {

    static final String[] SRC_POOL = {
        "10.0.1.21", "10.0.1.34", "10.0.2.15", "172.16.5.10", "172.16.5.11",
        "192.168.1.100", "192.168.1.101", "192.168.1.57", "203.0.113.50"
    };
    static final String[] DST_POOL = {
        "192.168.1.1", "192.168.1.10", "10.10.10.1", "10.10.10.2", "172.16.0.1"
    };
    static final String[] PROTOCOLS = {"TCP", "TCP", "TCP", "UDP", "UDP", "ICMP"};
    static final String[] FLAGS = {"SYN", "ACK", "SYN-ACK", "FIN", "RST", "PSH-ACK"};
    static final int[] PORTS = {80, 443, 443, 443, 22, 53, 53, 8080, 3306, 5432};

    static final String ATTACKER_IP = "45.33.12.99";

    /** Parsed record. Fields are kept as index ranges into the raw line until serialization. */
    static final class Record {
        final int[] starts = new int[7];
        final int[] ends = new int[7];
        String raw;
    }

    /** Splits a line on '|' into 7 fields. Returns false for malformed lines. */
    static boolean parse(String raw, Record r) {
        int field = 0;
        int start = 0;
        int len = raw.length();
        for (int i = 0; i < len; i++) {
            if (raw.charAt(i) == '|') {
                if (field >= 6) return false;
                r.starts[field] = start;
                r.ends[field] = i;
                field++;
                start = i + 1;
            }
        }
        if (field != 6) return false;
        r.starts[6] = start;
        r.ends[6] = len;
        r.raw = raw;
        // port and bytes must be numeric
        return isDigits(raw, r.starts[4], r.ends[4]) && isDigits(raw, r.starts[5], r.ends[5]);
    }

    static boolean isDigits(String s, int from, int to) {
        if (from >= to) return false;
        for (int i = from; i < to; i++) {
            char c = s.charAt(i);
            if (c < '0' || c > '9') return false;
        }
        return true;
    }

    /** Appends the record as a JSON object matching the backend's /ingest event schema. */
    static void toJson(Record r, StringBuilder out) {
        String s = r.raw;
        out.append("{\"ts\":\"").append(s, r.starts[0], r.ends[0]);
        out.append("\",\"src_ip\":\"").append(s, r.starts[1], r.ends[1]);
        out.append("\",\"dst_ip\":\"").append(s, r.starts[2], r.ends[2]);
        out.append("\",\"protocol\":\"").append(s, r.starts[3], r.ends[3]);
        out.append("\",\"port\":").append(s, r.starts[4], r.ends[4]);
        out.append(",\"bytes\":").append(s, r.starts[5], r.ends[5]);
        out.append(",\"flags\":\"").append(s, r.starts[6], r.ends[6]);
        out.append("\"}");
    }

    static String generateLine(Random rng, long ts, boolean attack) {
        StringBuilder line = new StringBuilder(96);
        if (attack) {
            line.append(ts).append('|').append(ATTACKER_IP).append("|192.168.1.10|TCP|445|")
                .append(30000 + rng.nextInt(35535)).append("|PSH-ACK");
        } else {
            line.append(ts).append('|')
                .append(SRC_POOL[rng.nextInt(SRC_POOL.length)]).append('|')
                .append(DST_POOL[rng.nextInt(DST_POOL.length)]).append('|')
                .append(PROTOCOLS[rng.nextInt(PROTOCOLS.length)]).append('|')
                .append(PORTS[rng.nextInt(PORTS.length)]).append('|')
                .append(64 + rng.nextInt(4000)).append('|')
                .append(FLAGS[rng.nextInt(FLAGS.length)]);
        }
        return line.toString();
    }

    static String argValue(String[] args, String name, String fallback) {
        for (int i = 0; i < args.length - 1; i++) {
            if (name.equals(args[i])) return args[i + 1];
        }
        return fallback;
    }

    static boolean hasFlag(String[] args, String name) {
        for (String a : args) if (name.equals(a)) return true;
        return false;
    }

    public static void main(String[] args) throws Exception {
        if (hasFlag(args, "--bench")) {
            bench(Integer.parseInt(argValue(args, "--bench", "2000000")));
        } else if (hasFlag(args, "--emit")) {
            emit(argValue(args, "--emit", "http://localhost:8000/ingest"),
                 Integer.parseInt(argValue(args, "--rate", "6")),
                 hasFlag(args, "--attack"));
        } else if (hasFlag(args, "--simulate")) {
            int n = Integer.parseInt(argValue(args, "--simulate", "1000"));
            Random rng = new Random(42);
            Record r = new Record();
            StringBuilder sb = new StringBuilder(256);
            for (int i = 0; i < n; i++) {
                if (!parse(generateLine(rng, 1720000000L + i, false), r)) continue;
                sb.setLength(0);
                toJson(r, sb);
                System.out.println(sb);
            }
        } else {
            stdin();
        }
    }

    static void stdin() throws IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        Record r = new Record();
        StringBuilder sb = new StringBuilder(256);
        String raw;
        long ok = 0, bad = 0;
        while ((raw = reader.readLine()) != null) {
            if (raw.isEmpty()) continue;
            if (!parse(raw, r)) { bad++; continue; }
            sb.setLength(0);
            toJson(r, sb);
            System.out.println(sb);
            ok++;
        }
        System.err.println("[INGESTION] parsed=" + ok + " malformed=" + bad);
    }

    /** Parse + serialize throughput on pre-generated lines (generation is excluded from timing). */
    static void bench(int n) {
        Random rng = new Random(7);
        String[] lines = new String[n];
        for (int i = 0; i < n; i++) lines[i] = generateLine(rng, 1720000000L + i, i % 50 == 0);
        Record r = new Record();
        StringBuilder sb = new StringBuilder(256);
        long sink = 0;
        // warm-up so the JIT has compiled the hot path before timing
        for (int round = 0; round < 3; round++) {
            for (int i = 0; i < Math.min(n, 200000); i++) {
                parse(lines[i], r); sb.setLength(0); toJson(r, sb); sink += sb.length();
            }
        }
        long t0 = System.nanoTime();
        for (int i = 0; i < n; i++) {
            parse(lines[i], r); sb.setLength(0); toJson(r, sb); sink += sb.length();
        }
        long elapsed = System.nanoTime() - t0;
        double perSec = n / (elapsed / 1e9);
        System.out.printf("records=%d elapsed_ms=%.1f throughput=%.0f records/s ns_per_record=%.0f (sink=%d)%n",
            n, elapsed / 1e6, perSec, (double) elapsed / n, sink);
    }

    /** Streams generated traffic to the backend in ~1 batch per 500 ms. */
    static void emit(String url, int perTick, boolean attack) throws Exception {
        // HTTP/1.1: the default h2c upgrade attempt on plain http is rejected by uvicorn
        HttpClient client = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .connectTimeout(Duration.ofSeconds(3))
            .build();
        Random rng = new Random();
        Record r = new Record();
        System.err.println("[INGESTION] Emitting to " + url + " (" + perTick + " events/tick, attack=" + attack + ")");
        long seq = 0;
        while (true) {
            StringBuilder body = new StringBuilder(perTick * 160 + 16).append("{\"events\":[");
            int count = 0;
            for (int i = 0; i < perTick; i++) {
                boolean isAttack = attack && i == 0;
                if (!parse(generateLine(rng, System.currentTimeMillis() / 1000, isAttack), r)) continue;
                if (count++ > 0) body.append(',');
                toJson(r, body);
            }
            body.append("]}");
            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                .header("Content-Type", "application/json")
                .timeout(Duration.ofSeconds(5))
                .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
                .build();
            try {
                HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
                if (resp.statusCode() != 200) System.err.println("[INGESTION] HTTP " + resp.statusCode() + ": " + resp.body());
                else if (++seq % 20 == 0) System.err.println("[INGESTION] batch " + seq + " -> HTTP " + resp.statusCode());
            } catch (IOException e) {
                System.err.println("[INGESTION] backend unreachable (" + e.getMessage() + "), retrying");
                Thread.sleep(2000);
            }
            Thread.sleep(500);
        }
    }
}
