import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;
import java.util.Random;

/**
 * Q-Guardian OS — High-Speed Telemetry Ingestion Microservice
 *
 * Reads DDoS telemetry lines from stdin (format: timestamp|src_ip|dst_ip|protocol|port|bytes|flags)
 * and emits parsed JSON to stdout.
 *
 * CONSTRAINTS ENFORCED:
 *   - All logic in a single main() function.
 *   - Input via BufferedReader only.
 *   - Manual character parsing via charAt/indexOf — NO split(), NO StringTokenizer.
 *
 * Usage:
 *   echo "1720000000|10.0.0.1|192.168.1.1|TCP|443|1024|SYN" | java TelemetryIngestion
 *   java TelemetryIngestion --simulate 500
 */
public class TelemetryIngestion {

    public static void main(String[] args) throws IOException {
        // ── Check for --simulate mode ──────────────────────────────
        boolean simulate = false;
        int simCount = 1000;
        for (int i = 0; i < args.length; i++) {
            if ("--simulate".equals(args[i])) {
                simulate = true;
                if (i + 1 < args.length) {
                    // Manual integer parse from the next argument
                    String numStr = args[i + 1];
                    int val = 0;
                    for (int c = 0; c < numStr.length(); c++) {
                        char ch = numStr.charAt(c);
                        if (ch >= '0' && ch <= '9') {
                            val = val * 10 + (ch - '0');
                        }
                    }
                    if (val > 0) {
                        simCount = val;
                    }
                }
                break;
            }
        }

        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));

        if (simulate) {
            // ── Simulation mode: generate fake packet lines, pipe them through our own parser ──
            Random rng = new Random(42);
            String[] srcPool = {
                "10.0.0.1", "10.0.0.2", "10.0.0.3", "172.16.5.10", "172.16.5.11",
                "192.168.1.100", "192.168.1.101", "45.33.32.156", "203.0.113.50"
            };
            String[] dstPool = {
                "192.168.1.1", "192.168.1.2", "10.10.10.1", "10.10.10.2", "172.16.0.1"
            };
            String[] protocols = {"TCP", "UDP", "ICMP", "TCP", "TCP", "UDP"};
            String[] flagSets = {"SYN", "ACK", "SYN-ACK", "FIN", "RST", "PSH-ACK", "URG"};
            int[] commonPorts = {80, 443, 22, 53, 8080, 3306, 5432, 8443, 25, 110};

            long baseTs = 1720000000L;

            System.err.println("[INGESTION] Simulation mode: generating " + simCount + " packets...");

            for (int n = 0; n < simCount; n++) {
                long ts = baseTs + n;
                String src = srcPool[rng.nextInt(srcPool.length)];
                String dst = dstPool[rng.nextInt(dstPool.length)];
                String proto = protocols[rng.nextInt(protocols.length)];
                int port = commonPorts[rng.nextInt(commonPorts.length)];
                int bytes = 64 + rng.nextInt(65000);
                String flags = flagSets[rng.nextInt(flagSets.length)];

                // Build the pipe-delimited line manually (no split, no StringTokenizer)
                StringBuilder line = new StringBuilder(128);
                line.append(ts);
                line.append('|');
                line.append(src);
                line.append('|');
                line.append(dst);
                line.append('|');
                line.append(proto);
                line.append('|');
                line.append(port);
                line.append('|');
                line.append(bytes);
                line.append('|');
                line.append(flags);

                String raw = line.toString();

                // ── Parse using charAt / indexOf only ──────────────────
                // Field positions: 0=timestamp, 1=src_ip, 2=dst_ip, 3=protocol, 4=port, 5=bytes, 6=flags
                String fTimestamp = null;
                String fSrc = null;
                String fDst = null;
                String fProto = null;
                String fPort = null;
                String fBytes = null;
                String fFlags = null;

                int fieldIndex = 0;
                int start = 0;
                int len = raw.length();

                for (int i = 0; i <= len; i++) {
                    char c;
                    if (i < len) {
                        c = raw.charAt(i);
                    } else {
                        c = '|'; // sentinel to flush last field
                    }

                    if (c == '|') {
                        String field = raw.substring(start, i);
                        if (fieldIndex == 0) fTimestamp = field;
                        else if (fieldIndex == 1) fSrc = field;
                        else if (fieldIndex == 2) fDst = field;
                        else if (fieldIndex == 3) fProto = field;
                        else if (fieldIndex == 4) fPort = field;
                        else if (fieldIndex == 5) fBytes = field;
                        else if (fieldIndex == 6) fFlags = field;
                        fieldIndex++;
                        start = i + 1;
                    }
                }

                if (fieldIndex < 7) {
                    System.err.println("[WARN] Malformed line (only " + fieldIndex + " fields): " + raw);
                    continue;
                }

                // ── Emit JSON to stdout ────────────────────────────────
                StringBuilder json = new StringBuilder(256);
                json.append("{\"ts\":\"");
                json.append(fTimestamp);
                json.append("\",\"src\":\"");
                json.append(fSrc);
                json.append("\",\"dst\":\"");
                json.append(fDst);
                json.append("\",\"proto\":\"");
                json.append(fProto);
                json.append("\",\"port\":");
                json.append(fPort);
                json.append(",\"bytes\":");
                json.append(fBytes);
                json.append(",\"flags\":\"");
                json.append(fFlags);
                json.append("\"}");

                System.out.println(json.toString());
            }

            System.err.println("[INGESTION] Simulation complete. " + simCount + " packets emitted.");
            return;
        }

        // ── Stdin streaming mode ──────────────────────────────────
        System.err.println("[INGESTION] Reading telemetry from stdin...");
        String raw;
        long count = 0;

        while ((raw = reader.readLine()) != null) {
            int len = raw.length();
            if (len == 0) continue;

            // ── Parse using charAt / indexOf only ──────────────────
            String fTimestamp = null;
            String fSrc = null;
            String fDst = null;
            String fProto = null;
            String fPort = null;
            String fBytes = null;
            String fFlags = null;

            int fieldIndex = 0;
            int start = 0;

            for (int i = 0; i <= len; i++) {
                char c;
                if (i < len) {
                    c = raw.charAt(i);
                } else {
                    c = '|'; // sentinel
                }

                if (c == '|') {
                    String field = raw.substring(start, i);
                    if (fieldIndex == 0) fTimestamp = field;
                    else if (fieldIndex == 1) fSrc = field;
                    else if (fieldIndex == 2) fDst = field;
                    else if (fieldIndex == 3) fProto = field;
                    else if (fieldIndex == 4) fPort = field;
                    else if (fieldIndex == 5) fBytes = field;
                    else if (fieldIndex == 6) fFlags = field;
                    fieldIndex++;
                    start = i + 1;
                }
            }

            if (fieldIndex < 7) {
                System.err.println("[WARN] Malformed line (only " + fieldIndex + " fields): " + raw);
                continue;
            }

            // ── Emit JSON ──────────────────────────────────────────
            StringBuilder json = new StringBuilder(256);
            json.append("{\"ts\":\"");
            json.append(fTimestamp);
            json.append("\",\"src\":\"");
            json.append(fSrc);
            json.append("\",\"dst\":\"");
            json.append(fDst);
            json.append("\",\"proto\":\"");
            json.append(fProto);
            json.append("\",\"port\":");
            json.append(fPort);
            json.append(",\"bytes\":");
            json.append(fBytes);
            json.append(",\"flags\":\"");
            json.append(fFlags);
            json.append("\"}");

            System.out.println(json.toString());
            count++;

            if (count % 10000 == 0) {
                System.err.println("[INGESTION] Processed " + count + " packets...");
            }
        }

        System.err.println("[INGESTION] Done. Total packets processed: " + count);
    }
}
