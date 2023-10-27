package org.exemple;

import io.javalin.Javalin;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.FileWriter;
import java.io.IOException;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Main {

    public static void main(String[] args) {

        Security.addProvider(new BouncyCastleProvider());

        Javalin app = Javalin.create().start(8081);

        app.get("/", ctx -> {
            ctx.html("<html><body>" +
                    "<h1>IP Scanner</h1>" +
                    "<form action='/scan' method='post'>" +
                    "<label for='ipRange'>IP Range:</label>" +
                    "<input type='text' id='ipRange' name='ipRange' required><br>" +
                    "<label for='numThreads'>Number of Threads:</label>" +
                    "<input type='number' id='numThreads' name='numThreads' required><br>" +
                    "<input type='submit' value='Start Scanning'>" +
                    "</form>" +
                    "</body></html>");
        });

        app.post("/scan", ctx -> {
            String ipAddressRange = ctx.formParam("ipRange");
            int numThreads = Integer.parseInt(Objects.requireNonNull(ctx.formParam("numThreads")));
            String outPutFile = "found_domains.txt";

            assert ipAddressRange != null;
            System.out.println("ipAddressRange: " + ipAddressRange);
            if (isValidIpAddressRange(ipAddressRange)) {
                String[] ipAddresses = ipAddressRange.split("-");

                String startIp = ipAddresses[0];
                String endIp = ipAddresses[1];

                try (FileWriter writer = new FileWriter(outPutFile)) {
                    for (int i = 0; i < numThreads; i++) {
                        int finalI = i;
                        new Thread(() -> {
                            for (int j = finalI; j < endIp.length(); j += numThreads) {
                                String ipAddress = startIp + j;
                                String domain = scanIpAddress(ipAddress);
                                if (domain != null) {
                                    try {
                                        writer.write(domain + "\n");
                                    } catch (IOException e) {
                                        e.printStackTrace();
                                    }
                                }
                            }
                        }).start();
                    }
                    ctx.result("The results are saved in a file.");
                } catch (IOException e) {
                    e.printStackTrace();
                    ctx.result("An error occurred while saving results.");
                }
            } else {
                ctx.result("Invalid IP Address Range format.");
            }
        });
    }

    private static String scanIpAddress(String ipAddress) {
        try {
            if (!ipAddress.startsWith("https://")) {
                ipAddress = "https://" + ipAddress;
            }

            SSLContext sslContext = SSLContext.getInstance("TLS", "SunJSSE");
            sslContext.init(null, null, null);

            CloseableHttpClient httpClient = HttpClients.custom()
                    .setSslcontext(sslContext)
                    .build();

            HttpGet httpGet = new HttpGet(ipAddress);

            HttpResponse response = httpClient.execute(httpGet);
            int statusCode = response.getStatusLine().getStatusCode();

            if (statusCode == 200) {
                SSLSocketFactory socketFactory = sslContext.getSocketFactory();
                SSLSocket socket = (SSLSocket) socketFactory.createSocket(ipAddress, 443);

                SSLSession sslSession = socket.getSession();
                X509Certificate[] certificates = (X509Certificate[]) sslSession.getPeerCertificates();
                String domain = extractDomainFromCertificate(certificates[0]);

                if (domain != null) {
                    return domain;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static String extractDomainFromCertificate(X509Certificate certificate) {
        String subjectDN = certificate.getSubjectX500Principal().getName();
        Pattern domainPattern = Pattern.compile("CN=([\\w.-]+)");
        Matcher matcher = domainPattern.matcher(subjectDN);

        if (matcher.find()) {
            return matcher.group(1);
        } else {
            return null;
        }
    }
    private static boolean isValidIpAddressRange(String ipAddressRange) {
        String pattern = "\\d+\\.\\d+\\.\\d+\\.\\d+-\\d+\\.\\d+\\.\\d+\\.\\d+";
        if (!ipAddressRange.matches(pattern)) {
            return false;
        }

        String[] parts = ipAddressRange.split("-");
        String startIp = parts[0];
        String endIp = parts[1];

        String[] startIpParts = startIp.split("\\.");
        String[] endIpParts = endIp.split("\\.");

        for (int i = 0; i < 4; i++) {
            int startIpPart = Integer.parseInt(startIpParts[i]);
            int endIpPart = Integer.parseInt(endIpParts[i]);
            if (startIpPart < 0 || startIpPart > 255 || endIpPart < 0 || endIpPart > 255) {
                return false;
            }
        }

        return true;
    }


}