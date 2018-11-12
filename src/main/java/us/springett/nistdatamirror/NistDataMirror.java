/*
 * This file is part of nist-data-mirror.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package us.springett.nistdatamirror;

import com.github.bordertech.config.Config;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.zip.GZIPInputStream;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import org.apache.commons.configuration.Configuration;

/**
 * This self-contained class can be called from the command-line. It downloads the contents of NVD CPE/CVE XML and JSON
 * data to the specified output path.
 *
 * @author Steve Springett (steve.springett@owasp.org)
 */
public class NistDataMirror {

    private static final String CVE_XML_12_MODIFIED_URL = "https://nvd.nist.gov/feeds/xml/cve/1.2/nvdcve-modified.xml.gz";
    private static final String CVE_XML_20_MODIFIED_URL = "https://nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-modified.xml.gz";
    private static final String CVE_XML_12_BASE_URL = "https://nvd.nist.gov/feeds/xml/cve/1.2/nvdcve-%d.xml.gz";
    private static final String CVE_XML_20_BASE_URL = "https://nvd.nist.gov/feeds/xml/cve/2.0/nvdcve-2.0-%d.xml.gz";
    private static final String CVE_JSON_10_MODIFIED_URL = "https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-modified.json.gz";
    private static final String CVE_JSON_10_BASE_URL = "https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-%d.json.gz";
    private static final int START_YEAR = 2002;
    private static final int END_YEAR = Calendar.getInstance().get(Calendar.YEAR);
    private final File outputDir;
    private boolean downloadFailed = false;
    private boolean json = true;
    private boolean xml = true;

    private static final Proxy PROXY;

    private static final String PARAM_OUTPUT_PATH = "nist.mirror.output.path";
    private static final String PARAM_OUTPUT_TYPE = "nist.mirror.output.type";
    private static final String PARAM_PROXY_ENABLED = "nist.mirror.proxy.enabled";
    private static final String PARAM_PROXY_HOST = "nist.mirror.proxy.host";
    private static final String PARAM_PROXY_PORT = "nist.mirror.proxy.port";
    private static final String PARAM_PROXY_USER = "nist.mirror.proxy.user";
    private static final String PARAM_PROXY_PWD = "nist.mirror.proxy.password";
    private static final String PARAM_PROXY_CUSTOM_SSL = "nist.mirror.proxy.custom.ssl.enabled";

    static {
        PROXY = createProxy();
        if (PROXY != null) {
            setupAuthentication();
            setupCustomSSL();
        }
    }

    public static void main(String[] args) {
        final String outputFile;
        final String type;
        switch (args.length) {
            case 0:
                // Use config file
                outputFile = Config.getInstance().getString(PARAM_OUTPUT_PATH, "nist");
                type = Config.getInstance().getString(PARAM_OUTPUT_TYPE, "json");
                break;
            case 2:
                outputFile = args[0];
                type = args[1];
                break;
            default:
                System.out.println("Usage: java NistDataMirror outputDir [xml|json]");
                return;
        }
        // Do mirror
        NistDataMirror nvd = new NistDataMirror(outputFile, type);
        nvd.mirror();
        if (nvd.downloadFailed) {
            System.exit(1);
        }
    }

    public NistDataMirror(final String outputDirPath, final String type) {
        outputDir = new File(outputDirPath);
        if (!outputDir.exists()) {
            outputDir.mkdirs();
        }
        if (type != null) {
            if (type.equals("xml")) {
                json = false;
            } else if (type.equals("json")) {
                xml = false;
            } else {
                throw new IllegalArgumentException(String.format("Invalid type parameter '%s'. Usage: java NistDataMirror outputDir [xml|json]", type));
            }
        }
    }

    public void mirror() {
        Date currentDate = new Date();
        System.out.println("Downloading files at " + currentDate);
        if (xml) {
            doDownload(CVE_XML_12_MODIFIED_URL);
            doDownload(CVE_XML_20_MODIFIED_URL);
        }
        if (json) {
            doDownload(CVE_JSON_10_MODIFIED_URL);
        }
        for (int i = START_YEAR; i <= END_YEAR; i++) {
            if (xml) {
                String cve12BaseUrl = CVE_XML_12_BASE_URL.replace("%d", String.valueOf(i));
                String cve20BaseUrl = CVE_XML_20_BASE_URL.replace("%d", String.valueOf(i));
                doDownload(cve12BaseUrl);
                doDownload(cve20BaseUrl);
            }
            if (json) {
                String cveJsonBaseUrl = CVE_JSON_10_BASE_URL.replace("%d", String.valueOf(i));
                doDownload(cveJsonBaseUrl);
            }
        }
    }

    private long checkHead(String cveUrl) {
        try {
            URL url = new URL(cveUrl);
            HttpURLConnection connection = (HttpURLConnection) handleOpenConnection(url);
            connection.setRequestMethod("HEAD");
            connection.connect();
            connection.getInputStream();
            return connection.getContentLengthLong();
        } catch (IOException e) {
            System.out.println("Failed to determine content length. " + e.getMessage());
        }
        return 0;
    }

    private void doDownload(String cveUrl) {
        BufferedInputStream bis = null;
        BufferedOutputStream bos = null;
        File file = null;
        boolean success = false;
        try {
            URL url = new URL(cveUrl);
            String filename = url.getFile();
            filename = filename.substring(filename.lastIndexOf('/') + 1);
            file = new File(outputDir, filename).getAbsoluteFile();

            if (file.exists()) {
                long fileSize = checkHead(cveUrl);
                if (file.length() == fileSize) {
                    System.out.println("Using cached version of " + filename);
                    return;
                }
            }

            URLConnection connection = handleOpenConnection(url);
            System.out.println("Downloading " + url.toExternalForm());
            bis = new BufferedInputStream(connection.getInputStream());
            file = new File(outputDir, filename);
            bos = new BufferedOutputStream(new FileOutputStream(file));

            int i;
            while ((i = bis.read()) != -1) {
                bos.write(i);
            }
            success = true;
        } catch (IOException e) {
            String msg = "Download failed [" + e.getClass().getName() + "]: " + e.getMessage();
            System.out.println(msg);
            downloadFailed = true;
            throw new IllegalStateException(msg);
        } finally {
            close(bis);
            close(bos);
        }
        if (file != null && success) {
            uncompress(file);
        }
    }

    private void uncompress(File file) {
        byte[] buffer = new byte[1024];
        GZIPInputStream gzis = null;
        FileOutputStream out = null;
        try {
            System.out.println("Uncompressing " + file.getName());
            gzis = new GZIPInputStream(new FileInputStream(file));
            out = new FileOutputStream(new File(file.getAbsolutePath().replaceAll(".gz", "")));
            int len;
            while ((len = gzis.read(buffer)) > 0) {
                out.write(buffer, 0, len);
            }
        } catch (IOException ex) {
            ex.printStackTrace();
        } finally {
            close(gzis);
            close(out);
        }
    }

    private void close(Closeable object) {
        if (object != null) {
            try {
                object.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * @param url the URL to open
     * @return the URL Connection
     * @throws IOException an IO exception occurred
     */
    private URLConnection handleOpenConnection(final URL url) throws IOException {
        if (PROXY == null) {
            return url.openConnection();
        } else {
            return url.openConnection(PROXY);
        }
    }

    /**
     * @return the PROXY settings or null
     */
    private static Proxy createProxy() {

        Configuration config = Config.getInstance();

        // Check PROXY enabled
        if (!config.getBoolean(PARAM_PROXY_ENABLED, false)) {
            return null;
        }

        // Proxy Settings
        // HOST
        String host = config.getString(PARAM_PROXY_HOST);
        if (host == null || host.isEmpty()) {
            throw new IllegalStateException("Proxy host property [" + PARAM_PROXY_HOST + "] has not been set.");
        }
        // PORT
        int port = config.getInt(PARAM_PROXY_PORT, 8080);
        System.out.println("Using PROXY with host [" + host + "] and port [" + port + "].");
        return new Proxy(Proxy.Type.HTTP, new InetSocketAddress(host, port));
    }

    /**
     * Check for PROXY Authentication.
     */
    private static void setupAuthentication() {

        // User and Password details
        Configuration config = Config.getInstance();
        final String user = config.getString(PARAM_PROXY_USER);
        final String pwd = config.getString(PARAM_PROXY_PWD);

        // If provideed setup an Authenticator
        if (user != null && pwd != null) {
            System.out.println("Using PROXY with Authentication [" + user + "].");
            // Setup Authenticator
            Authenticator authenticator = new Authenticator() {
                @Override
                public PasswordAuthentication getPasswordAuthentication() {
                    return (new PasswordAuthentication(user, pwd.toCharArray()));
                }
            };
            Authenticator.setDefault(authenticator);
        }

    }

    /**
     * Setup a custom trust manager for SSL.
     */
    private static void setupCustomSSL() {

        // Check setup CUSTOM SSL
        if (!Config.getInstance().getBoolean(PARAM_PROXY_CUSTOM_SSL, false)) {
            return;
        }

        try {
            // Set up a TrustManager that trusts everything
            SSLContext sslContext = SSLContext.getInstance("SSL");
            sslContext.init(null, new TrustManager[]{new MyTrustManager()}, new SecureRandom());
            // Set default SSL Factory
            HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new IllegalStateException("Could not setup custom SSL. " + e.getMessage());
        }
    }

    /**
     * Custom trust manager that trusts everything.
     * <p>
     * Can be used when going through a proxy that intercepts certificates and creates its own.
     * </p>
     */
    public static class MyTrustManager implements X509TrustManager {

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            System.out.println("getAcceptedIssuers =============");
            return null;
        }

        @Override
        public void checkClientTrusted(final X509Certificate[] certs, final String authType) {
            System.out.println("checkClientTrusted =============");
        }

        @Override
        public void checkServerTrusted(final X509Certificate[] certs, final String authType) {
            System.out.println("checkServerTrusted =============");
        }
    }
}
