package integrity_check_tools;

public class ApkObject {

	private String filePath = "";

	private String publicKey = "";

	public ApkObject(String filePath) {
		this.filePath = filePath;
	}

	public String getFilePath() {
		return filePath;
	}

	public String getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(String publicKey) {
		this.publicKey = publicKey;
	}
}
