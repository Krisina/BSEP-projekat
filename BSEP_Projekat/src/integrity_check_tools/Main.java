package integrity_check_tools;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import sun.security.pkcs.PKCS7;
import Decoder.BASE64Encoder;

/**
 * @author krist
 *
 * Ova klasa nam "izvlaci" sertifikat iz izabranog apk fajla i postavlja ga u temp folder.
 * 
 * Omogucuje vrsenje funkcionalnosti nad apk fajlova:
 * 1. -list - ispisuje nam sve Apk fajlove
 * 2. -verify - ispituje nam ispravnost apk fajla, da li je validan i da li ima odgovarajuci i 
 * ispravan sertifikat
 * 3. -compare - omogucuje poredjenje vise apk fajlova
 */

public class Main {

	// folder gde upisujemo sertifikate iz apk fajlova je temp
	public static String DEFAULT_FOLDER = "temp";

	/**
	 * @param args
	 * @throws IOException
	 */
	
	public static void main(String[] args) throws IOException {

		boolean isList = false;
		boolean isVerify = false;
		boolean isCompare = false;

		boolean countingApk = false;

		List<ApkObject> apkList = new ArrayList<ApkObject>();

		if (args.length > 0) {

			for (int i = 0; i < args.length; i++) {
				if (args[i].equals("-l") || args[i].equals("-list")) {
					isList = true;
					countingApk = true;
				} else if (args[i].equals("-v") || args[i].equals("-verify")) {
					countingApk = false;
					isVerify = true;
				} else if (args[i].equals("-c") || args[i].equals("-comparePubkey")) {
					countingApk = false;
					isCompare = true;
				} else if (countingApk) {
					apkList.add(new ApkObject(args[i]));
				}
			}
			
		// prikaz funksionalnosti
		} else {
			dispalyUsage();
		}

		// apk fajl mora da postoji
		if (apkList.size() > 0) {

			// ispravnost apk fajla
			// ako imamo samo jedan apk fajl, dobijamo obavestenje: "APKs refer to the same Android application"
			if (isVerify) {
				for (int i = 0; i < apkList.size(); i++) {
					CheckApkIntegrity check = new CheckApkIntegrity();
					try {
						boolean status = check.verifyApk(apkList.get(i).getFilePath());
						
						// proverava da li je apk fajl ispravan, u zavisnosti od toga korisnik 
						// dobija odgovarajuc odgovaor
						
						if (status) {
							System.out.println("[APK CHECKER] " + apkList.get(i).getFilePath() + " verification [  OK  ]");
						} else {
							System.out.println("[APK CHECKER] " + apkList.get(i).getFilePath() + " verification [  FAILURE  ]");
							return;
						}
					} catch (Exception e) {
						e.printStackTrace();
						return;
					}
				}
			}
			
			// poredimo 2 ili vise apk fajlova
			if (isCompare) {
				for (int i = 0; i < apkList.size(); i++) {
					try {
						// preuzimamo sertifikat iz Apk fajla i njegov javni kljuc
						extractCertificateFromApk(apkList.get(i).getFilePath());
						String publicKey = getPublicKey(DEFAULT_FOLDER + File.separator + "META-INF/CERT.RSA");
						apkList.get(i).setPublicKey(publicKey);
					} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
						e.printStackTrace();
						return;
					}
				}

				for (int i = 0; i < apkList.size(); i++) {
					if (i + 1 < apkList.size()) {
						// prijavljuje gresku ako su nam javni kljucevi razliciti
						if (!apkList.get(i).getPublicKey().equals(apkList.get(i + 1).getPublicKey())) {
							System.out.println("[APK CHECKER] apk public key not shared for " + apkList.get(i).getFilePath() + " and "
									+ apkList.get(i + 1).getFilePath() + " [  FAILURE  ]");
							return;
						} else {
							System.out.println("[APK CHECKER] apk public key shared for " + apkList.get(i).getFilePath() + " and "
									+ apkList.get(i + 1).getFilePath() + " [  OK  ]");
						}
					}
				}
			}
			// ispis
			System.out.println("[APK CHECKER] APKs refer to the same Android application");
		} else {
			System.out.println("Error apk list is empty");
		}
	}
	
	// sluzi za preuzimanje sertifikata iz apk fajla i postavlja se u temp folder
	// ime sertifikata je CERT.RSA

	public static void extractCertificateFromApk(String apkFile) throws IOException {

		File file = new File(apkFile);

		File folder = new File(DEFAULT_FOLDER);
		if (!folder.exists()) {
			folder.mkdir();
		}

		ZipInputStream zipStream = new ZipInputStream(new FileInputStream(file));
		ZipEntry zipEntry = zipStream.getNextEntry();

		byte[] buffer = new byte[1024];

		while (zipEntry != null) {

			String fileName = zipEntry.getName();

			if (fileName.equals("META-INF/CERT.RSA")) {

				File newFile = new File(DEFAULT_FOLDER + File.separator + fileName);

				new File(newFile.getParent()).mkdirs();

				FileOutputStream fos = new FileOutputStream(newFile);

				int len;
				while ((len = zipStream.read(buffer)) > 0) {
					fos.write(buffer, 0, len);
				}

				fos.close();

				break;
			}
			zipEntry = zipStream.getNextEntry();
		}

		zipStream.closeEntry();
		zipStream.close();

	}

	// sluzi za preuzimanje javnog kljuca iz apk fajla, odnosno sertifikata
	
	public static String getPublicKey(String certPath) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {

		File f = new File(certPath);
		FileInputStream is = new FileInputStream(f);

		ByteArrayOutputStream buffer = new ByteArrayOutputStream();

		int nRead;
		byte[] data = new byte[16384];

		while ((nRead = is.read(data, 0, data.length)) != -1) {
			buffer.write(data, 0, nRead);
		}

		buffer.flush();
		PKCS7 test = new PKCS7(buffer.toByteArray());
		X509Certificate[] certs = test.getCertificates();

		for (int i = 0; i < certs.length; i++) {
			if (certs[i] != null && certs[i].getPublicKey() != null) {
				return new BASE64Encoder().encode(certs[i].getPublicKey().getEncoded());
			}
		}
		return "";
	}

	private static void dispalyUsage() {
		System.out.println("Usage: java -jar integritychecktool.jar -l <apks> <options>");
		System.out.println("-l or -list of apk files");
		System.out.println("-v or -verify apk files");
		System.out.println("-c or -comparePublicKey of apks");
	}
}
