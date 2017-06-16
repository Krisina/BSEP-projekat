package integrity_check_tools;

import java.io.IOException;
import java.io.InputStream;
import java.security.CodeSigner;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.List;
import java.util.Vector;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.Manifest;

import sun.security.util.DerInputStream;
import sun.security.util.DerValue;
import sun.security.x509.NetscapeCertTypeExtension;

public final class CheckJarIntegrity {
	
	private boolean hasExpiredCertificate = false;
	private boolean hasExpiringCertificate = false;
	private boolean notYetValidCertertificate = false;
	private boolean showcertificates = false;
	private boolean badKeyUsage = false;
	private boolean badExtendedKeyUsage = false;
	private boolean badNetscapeCertificateType = false;
	private static final long SIX_MONTHS = 180 * 24 * 60 * 60 * 1000L;
	private static final String META_INF = "META-INF/";

    // prefiks za nove potpise kod sertifikata
	private static final String SIGNATURE_PREFIX = META_INF + "SIG-";

	public boolean verifyJar(String jarName) throws Exception {
		boolean anySigned = false;
		boolean hasUnsignedEntry = false;
		JarFile jf = null;

		try {
			jf = new JarFile(jarName, true);
			Vector<JarEntry> entriesVec = new Vector<JarEntry>();
			byte[] buffer = new byte[8192];

			Enumeration<JarEntry> entries = jf.entries();
			while (entries.hasMoreElements()) {
				JarEntry je = entries.nextElement();
				entriesVec.addElement(je);
				InputStream is = null;
				try {
					is = jf.getInputStream(je);
					int n;
					while ((n = is.read(buffer, 0, buffer.length)) != -1) {
					}
				} finally {
					if (is != null) {
						is.close();
					}
				}
			}

			Manifest man = jf.getManifest();

			if (man != null) {
				Enumeration<JarEntry> e = entriesVec.elements();

				long now = System.currentTimeMillis();

				while (e.hasMoreElements()) {
					JarEntry je = e.nextElement();
					String name = je.getName();
					CodeSigner[] signers = je.getCodeSigners();

					boolean isSigned = (signers != null);
					anySigned |= isSigned;
					hasUnsignedEntry |= !je.isDirectory() && !isSigned && !signatureRelated(name);

					if (isSigned) {
						for (int i = 0; i < signers.length; i++) {
							Certificate cert = signers[i].getSignerCertPath().getCertificates().get(0);

							if (cert instanceof X509Certificate) {

								checkCertUsage((X509Certificate) cert, null);

								if (!showcertificates) {
									long notAfter = ((X509Certificate) cert).getNotAfter().getTime();

									if (notAfter < now) {
										hasExpiredCertificate = true;
									} else if (notAfter < now + SIX_MONTHS) {
										hasExpiringCertificate = true;
									}
								}
							}
						}
					}

				}
			}

			if (man == null)
				System.out.println("no manifest.");

			if (!anySigned) {
				System.out.println("jar is unsigned, signatures is missing)");
			} else {
				System.out.println("jar verified.");
				if (hasUnsignedEntry || hasExpiredCertificate || hasExpiringCertificate || badKeyUsage || badExtendedKeyUsage || badNetscapeCertificateType || notYetValidCertertificate) {

					System.out.println();
					System.out.println("Warning: ");
					if (badKeyUsage) {
						System.out.println("This jar contains entries whose signer certificate's KeyUsage extension doesn't allow code signing.");
					}
					if (badExtendedKeyUsage) {
						System.out.println("This jar contains entries whose signer certificate's ExtendedKeyUsage extension doesn't allow code signing.");
					}
					if (badNetscapeCertificateType) {
						System.out.println("This jar contains entries whose signer certificate's NetscapeCertType extension doesn't allow code signing.");
					}
					if (hasUnsignedEntry) {
						System.out.println("This jar contains unsigned entries which have not been integrity-checked. ");
					}
					if (hasExpiredCertificate) {
						System.out.println("This jar contains entries whose signer certificate has expired. ");
					}
					if (hasExpiringCertificate) {
						System.out.println("This jar contains entries whose signer certificate will expire within six months. ");
					}
					if (notYetValidCertertificate) {
						System.out.println("This jar contains entries whose signer certificate is not yet valid. ");
					}
				}
				return true;
			}
			System.exit(0);
		} catch (Exception e) {
			e.printStackTrace();
			System.out.println("jar signer: " + e);
		} finally {
			if (jf != null) {
				jf.close();
			}
		}

		return false;
	}

	private boolean signatureRelated(String name) {
		String ucName = name.toUpperCase();
		if (ucName.equals(JarFile.MANIFEST_NAME) || ucName.equals(META_INF)
				|| (ucName.startsWith(SIGNATURE_PREFIX) && ucName.indexOf("/") == ucName.lastIndexOf("/"))) {
			return true;
		}

		if (ucName.startsWith(META_INF) && isBlockOrSF(ucName)) {
			return (ucName.indexOf("/") == ucName.lastIndexOf("/"));
		}

		return false;
	}

	private boolean isBlockOrSF(String s) {
		if (s.endsWith(".SF") || s.endsWith(".DSA") || s.endsWith(".RSA")) {

			return true;
		}
		return false;
	}

	private void checkCertUsage(X509Certificate userCert, boolean[] bad) {

		// 1 = za KeyUsage, [0] ako moze da se koristi
		// 2 = za ExtendedKeyUsage i sadzi CODE_SIGNING
		// 3 = za NetscapeCertificateType i sadrzi OBJECT_SIGNING
		// 1,2,3 moraju biti ispravni

		if (bad != null) {
			bad[0] = bad[1] = bad[2] = false;
		}

		boolean[] keyUsage = userCert.getKeyUsage();
		if (keyUsage != null) {
			if (keyUsage.length < 1 || !keyUsage[0]) {
				if (bad != null) {
					bad[0] = true;
				} else {
					badKeyUsage = true;
				}
			}
		}

		try {
			List<String> xKeyUsage = userCert.getExtendedKeyUsage();
			if (xKeyUsage != null) {
				if (!xKeyUsage.contains("2.5.29.37.0") // ExtendedKeyUsage
						&& !xKeyUsage.contains("1.3.6.1.5.5.7.3.3")) { // CODE_SIGNING
					if (bad != null) {
						bad[1] = true;
					} else {
						badExtendedKeyUsage = true;
					}
				}
			}
		} catch (java.security.cert.CertificateParsingException e) {
		}

		try {
			// NetscapeCertificateType
			byte[] netscapeEx = userCert.getExtensionValue("2.16.840.1.113730.1.1");
			if (netscapeEx != null) {
				DerInputStream in = new DerInputStream(netscapeEx);
				byte[] encoded = in.getOctetString();
				encoded = new DerValue(encoded).getUnalignedBitString().toByteArray();

				NetscapeCertTypeExtension extn = new NetscapeCertTypeExtension(encoded);

				Boolean val = (Boolean) extn.get(NetscapeCertTypeExtension.OBJECT_SIGNING);
				if (!val) {
					if (bad != null) {
						bad[2] = true;
					} else {
						badNetscapeCertificateType = true;
					}
				}
			}
		} catch (IOException e) {
		}
	}
}