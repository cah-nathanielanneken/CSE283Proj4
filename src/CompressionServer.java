import java.net.*; // for DatagramSocket, DatagramPacket, and InetAddress
import java.io.*; // for IOException
import java.nio.file.*;
import java.nio.charset.*;
import java.security.KeyStore;
import java.util.zip.*;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

public class CompressionServer {

	public static void main(String[] args) throws IOException {

		int servPort = Integer.parseInt(args[0]);

		String ksName = "keystore.jks";
		char ksPass[] = "password".toCharArray();
		char ctPass[] = "password".toCharArray();
		try {
			KeyStore ks = KeyStore.getInstance("JKS");
			ks.load(new FileInputStream(ksName), ksPass);
			KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
			kmf.init(ks, ctPass);
			SSLContext sc = SSLContext.getInstance("SSL");
			sc.init(kmf.getKeyManagers(), null, null);
			SSLServerSocketFactory ssf = sc.getServerSocketFactory();
			SSLServerSocket s = (SSLServerSocket) ssf
					.createServerSocket(servPort);

			while (true) {
				// Listen for a TCP connection request.
				SSLSocket c = (SSLSocket) s.accept();

				BufferedOutputStream out = new BufferedOutputStream(
						c.getOutputStream(), 1024);
				BufferedInputStream in = new BufferedInputStream(
						c.getInputStream(), 1024);

				byte[] byteBuffer = new byte[1024];
				int count = 0;
				while ((byteBuffer[count] = (byte) in.read()) != -2) {
					count++;
				}
				String newFile = new String(byteBuffer, 0, count, "US-ASCII");
				FileOutputStream writer = new FileOutputStream(newFile.trim());
				int buffSize = 0;
				while ((buffSize = in.read(byteBuffer, 0, 1024)) != -1) {
					int index = 0;
					if((index = (new String(byteBuffer, 0, buffSize, "US-ASCII")).indexOf("------MagicStringCSE283Miami")) == -1) {
						writer.write(byteBuffer, 0, buffSize);
					} else {
						writer.write(byteBuffer, 0, index);
						break;
					}
				}
				writer.flush();
				writer.close();

				ZipOutputStream outZip = new ZipOutputStream(
						new BufferedOutputStream(out));
				FileInputStream fin = new FileInputStream(newFile.trim());
				BufferedInputStream origin = new BufferedInputStream(fin, 1024);
				ZipEntry entry = new ZipEntry(newFile.trim());
				outZip.putNextEntry(entry);

				byteBuffer = new byte[1024];
				int bytes = 0;
				while ((bytes = origin.read(byteBuffer, 0, 1024)) != -1) {
					outZip.write(byteBuffer, 0, bytes);
				}
				origin.close();
				outZip.flush();
				outZip.close();
				out.flush();
				out.close();
			}
		} catch (Exception e) {
			System.err.println(e.toString());
		}
	}
}