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

/**
 * @author krist
 *
 * Klasa za proveru Apk fajlova, kreiranje i ispitivanje sertifikata
 * 
 */

public final class CheckApkIntegrity {

	
	private static final long SIX_MONTHS = 180 * 24 * 60 * 60 * 1000L;
	
	private boolean showCertificates = false;
	private boolean expiredCertificate = false;
	private boolean expiringCertificate = false;
	private boolean notValidCertertificate = false;
	private boolean badKeyUse = false;
	private boolean badExtendedKeyUse = false;
	private boolean badNetscapeCertificateType = false;
	
    // prefiks za nove potpise kod sertifikata
	private static final String META_INF = "META-INF/";	
	private static final String SIGNATURE_PREFIX = META_INF + "SIG-";

	
	/**
	 * @param apkName - podrazumeva ime apk fajla
	 * @return
	 * @throws Exception
	 */
	
	public boolean verifyApk(String apkName) throws Exception {
		boolean anySigned = false;
		boolean hasUnsignedEntry = false;
		JarFile jf = null;

		try {
			
			// dodajemo novi apk fajl u bafer
			jf = new JarFile(apkName, true);
			Vector<JarEntry> entriesVector = new Vector<JarEntry>();
			byte[] buffer = new byte[8192];

			Enumeration<JarEntry> entries = jf.entries();
			
			// proverava da li postoji jos apk fajlova, ako da, preuzima sledeci apk fajl
			// i postavlja ga u bafer.
			// proces se ponavlja sve dok ne nadje ni jedan novi apk fajl
			
			while (entries.hasMoreElements()) {
				JarEntry je = entries.nextElement();
				entriesVector.addElement(je);
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
			
			// preuzimamo manifest
			Manifest manifest = jf.getManifest();

			if (manifest != null) {
				Enumeration<JarEntry> e = entriesVector.elements();
							
				long now = System.currentTimeMillis();

				while (e.hasMoreElements()) {
					
					// prosirujemo bafer, ako postoji manifest i apk fajl koji jos nije dodat u bafer.
					JarEntry je = e.nextElement();
					String name = je.getName();
					CodeSigner[] signers = je.getCodeSigners();
					
					// proveravamo postojanje potpisa sertifikata
					boolean isSigned = (signers != null);
					anySigned |= isSigned;
					hasUnsignedEntry |= !je.isDirectory() && !isSigned && !signatureRelated(name);
					
					//proveravamo da li je dati sertifikat jos validan
					if (isSigned) {
						for (int i = 0; i < signers.length; i++) {
							Certificate cert = signers[i].getSignerCertPath().getCertificates().get(0);

							if (cert instanceof X509Certificate) {

								checkCertUsage((X509Certificate) cert, null);

								if (!showCertificates) {
									long notAfter = ((X509Certificate) cert).getNotAfter().getTime();

									if (notAfter < now) {
										expiredCertificate = true;
									} else if (notAfter < now + SIX_MONTHS) {
										expiringCertificate = true;
									}
								}
							}
						}
					}

				}
			}
			
			// nedostaje manifest
			if (manifest == null)
				System.out.println("no manifest.");
			
			// proverava da li nam je apk fajl potpisan
			if (!anySigned) {
				System.out.println("jar is unsigned, signatures is missing)");
			} else {
				System.out.println("jar verified.");
				
				// Prijavljuje se odgovarajuca greska u zavisnosti od mogucih dole navedenih problema
				if (hasUnsignedEntry || expiredCertificate || expiringCertificate || badKeyUse || badExtendedKeyUse || badNetscapeCertificateType || notValidCertertificate) {

					System.out.println();
					System.out.println("Warning: ");
					if (badKeyUse) {
						System.out.println("This jar contains entries whose signer certificate's KeyUsage extension doesn't allow code signing.");
					}
					if (badExtendedKeyUse) {
						System.out.println("This jar contains entries whose signer certificate's ExtendedKeyUsage extension doesn't allow code signing.");
					}
					if (badNetscapeCertificateType) {
						System.out.println("This jar contains entries whose signer certificate's NetscapeCertType extension doesn't allow code signing.");
					}
					if (hasUnsignedEntry) {
						System.out.println("This jar contains unsigned entries which have not been integrity-checked. ");
					}
					if (expiredCertificate) {
						System.out.println("This jar contains entries whose signer certificate has expired. ");
					}
					if (expiringCertificate) {
						System.out.println("This jar contains entries whose signer certificate will expire within six months. ");
					}
					if (notValidCertertificate) {
						System.out.println("This jar contains entries whose signer certificate is not yet valid. ");
					}
				}
				return true;
			}
			System.exit(0);
		} catch (Exception e) {
			e.printStackTrace();
			// prikaz 
			System.out.println("jar signer: " + e);
		} finally {
			if (jf != null) {
				jf.close();
			}
		}

		return false;
	}

	/**
	 * @param name - odnosi se za pravljenje imena prefiksa za nove potpise kod sertifikata
	 * @return
	 */
	
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

	
	/**
	 * @param s - fajlovi sertifikata se mogu zavrsiti sa datim nastavcima
	 * @return
	 */
	
	private boolean isBlockOrSF(String s) {
		if (s.endsWith(".SF") || s.endsWith(".DSA") || s.endsWith(".RSA")) {

			return true;
		}
		return false;
	}

	/**
	 * @param userCertificate - koristi se za proveru ispravnosti sertifikata
	 * @param bad - koristi se za proveru ispravnosti sertifikata u zavisnosti od vrednosti
	 * koji moraju biti ispravni da bi sertifikat bio prihvacen
	 * 
	 * Vrednosti su:
	 * 1 - odnosi se na primenu kljuca (KeyUsage), ako ima vrednost [0], onda moze da se koristi
	 * 2 - odnosi se na ExtendedKeyUsage i potrebno je da sadzi CODE_SIGNING
	 * 3 - odnosi se na NetscapeCertificateType i potrebno je da sadzi OBJECT_SIGNING
	 */
	
	private void checkCertUsage(X509Certificate userCertificate, boolean[] bad) {
	

		if (bad != null) {
			bad[0] = bad[1] = bad[2] = false;
		}

		boolean[] keyUsage = userCertificate.getKeyUsage();
		if (keyUsage != null) {
			if (keyUsage.length < 1 || !keyUsage[0]) {
				if (bad != null) {
					bad[0] = true;
				} else {
					badKeyUse = true;
				}
			}
		}

		try {
			List<String> xKeyUsage = userCertificate.getExtendedKeyUsage();
			if (xKeyUsage != null) {
				if (!xKeyUsage.contains("2.5.29.37.0") // ExtendedKeyUsage
						&& !xKeyUsage.contains("1.3.6.1.5.5.7.3.3")) { // CODE_SIGNING
					if (bad != null) {
						bad[1] = true;
					} else {
						badExtendedKeyUse = true;
					}
				}
			}
		} catch (java.security.cert.CertificateParsingException e) {
		}

		try {
			// NetscapeCertificateType
			byte[] netscapeEx = userCertificate.getExtensionValue("2.16.840.1.113730.1.1");
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